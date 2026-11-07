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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    TrustError, ValidationResult, Validator, cut_manifest, public_key_digest, sync_group,
};
use ndn_sync::{DataStore, MultiSvs, SvsConfig, SyncUpdate, spawn_multi_svs};
use parking_lot::Mutex;
use tokio::sync::{Notify, Semaphore, mpsc, oneshot};

use crate::collection::{self, Accepted, Child, Cut, Epoch, Members, Resolve, Rule, Summary};
use crate::error::{DataError, Refusal};
use crate::layer::{
    Age, Answer, BATCH_MAX, Change, Changes, DataLayer, Edit, Entries, Entry, Got, Hold,
    PutOptions, State,
};
use crate::merge::{
    Counting, MergeError, MergeRule, MergeRules, MergeState, Op, OpKind, Past, Value,
};
use crate::pieces::{self, Shape};
use crate::rt::{self, Instant};
use crate::seal::{self, Keys};
use crate::statement::{Audit, Breach, Custody, Lease, Prune, Snapshot};
use crate::tree::{Kind, Retain, Tree};
use crate::version::{
    Audience, BlockEntry, Content, Frontier, GROUP_MAX, Group, Keep, Parents, Payload, Seal, Seq,
    Timestamp, TypeId, Version, VersionId, Writer,
};
use crate::wire::{
    self, AuditAnswer, AuditAsk, BlockEntryBody, Branches, ChunksBody, CutBody, ExpiryRun,
    GrantAsk, HeadBody, HoldAsk, HoldBody, Inline, LeaseBody, MembersBody, NodeBody, PieceKind,
    PruneBody, Range, Record, SealedBody, Tomb, VersionBody, audit_ask_name, device_of, entry_name,
    grant_name, head_name, head_prefix, hold_ask_name, in_ranges, log_name, namespace_of,
    node_name, page_name, parse_audit_ask_name, parse_entry_name, parse_grant_name,
    parse_head_name, parse_head_prefix, parse_held_name, parse_hold_ask_name, parse_log_name,
    parse_piece_name, parse_range_name, parse_seal_key_name, parse_state_name, parse_summary_name,
    piece_name, piece_names, root_name, root_prefix, seal_key_name, seqs_of, state_name,
    subject_namespace,
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
    /// under custody leases (spec §13): it answers the hold asks and audits
    /// of the owner devices whose hold records name it a holder. Empty: the
    /// device is not a holder. A holder enrolled in a namespace it holds for
    /// is a device of that person: of every audience `Person` of that
    /// namespace admits, and able to sign the owner's records; a holder that
    /// must not read what it keeps is enrolled outside the namespaces it
    /// holds for (spec §13.4).
    pub hold_for: Vec<Name>,
    /// How many random pieces an audit asks each holder for.
    pub audit_pieces: usize,
    /// How far ahead of this device's clock another device's may run, as
    /// this device judges it: a holder's signed `Expired` audit answer for a
    /// version its writer kept until `t` is evidence of a broken lease only
    /// when `t` is more than this past this device's clock (spec §14.1), so
    /// a holder whose fast clock dropped the piece early is not framed.
    pub clock_skew: Duration,
    /// Where audits draw their randomness, and introductions their secrets
    /// and nonces (spec §19).
    pub entropy: Entropy,
    /// What the host does for introductions (spec §19): give this device's
    /// anchor and adopt another person's. `None`: [`Device::offer`] and
    /// [`Device::join`] answer [`DataError::Local`] naming this setting.
    pub introducer: Option<Arc<dyn crate::intro::Introducer>>,
}

impl Config {
    /// Defaults: SVS's reference timing, the standard merge rules, the
    /// system clock, 2 s Interests, a 4 s first look, 32 fetches in flight,
    /// not a holder, 16 pieces an audit, a day of clock skew, the operating
    /// system's randomness, no introducer.
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
            clock_skew: Duration::from_secs(24 * 60 * 60),
            entropy: Arc::new(|buf| {
                getrandom::getrandom(buf).expect("the operating system provides randomness")
            }),
            introducer: None,
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
            .field("clock_skew", &self.clock_skew)
            .field("introducer", &self.introducer.is_some())
            .finish_non_exhaustive()
    }
}

/// What a [`Device::release`] dropped, and what it kept.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Released {
    /// Large versions whose pieces were dropped.
    pub versions: u32,
    /// Pieces dropped.
    pub pieces: u32,
    /// Their octets.
    pub bytes: u64,
    /// The versions kept here, as too few holders proved they keep them,
    /// each with why.
    pub kept: Vec<(Name, String)>,
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
    /// a collection it does not name, and snapshots, keep nothing.
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
    /// Its operation, once its payload is opened (empty under the log
    /// rule).
    op: Bytes,
    wire: Bytes,
    /// The implicit digest of `wire`: the version's content address.
    digest: [u8; 32],
    /// Whether its payload came sealed.
    sealed: bool,
    /// The epoch its payload is sealed in.
    epoch: Option<Epoch>,
    /// Its payload in pieces, when it travels so (spec §4.1).
    chunks: Option<ChunksBody>,
    /// Whether `op` is its operation: inline, or in pieces held whole and
    /// opened ([`open_held`]). A merge version applies only opened; once
    /// applied, an operation in pieces is let go ([`Self::unloaded`]) and
    /// read again from the pieces when needed.
    opened: bool,
}

impl HeldVersion {
    /// A version as held: opened unless its payload is in pieces.
    fn new(
        version: Version,
        op: Bytes,
        wire: Bytes,
        sealed: bool,
        epoch: Option<Epoch>,
        chunks: Option<ChunksBody>,
    ) -> Self {
        HeldVersion {
            digest: wire::implicit_digest(&wire),
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
    /// pieces (up to 64 MiB) and is in memory: what is applied needs no
    /// operation until the state is computed anew, which opens it again
    /// from the pieces. `None` when there is nothing to let go.
    fn unloaded(&self) -> Option<Self> {
        (self.chunks.is_some() && self.opened).then(|| HeldVersion {
            version: self.version.clone(),
            op: Bytes::new(),
            wire: self.wire.clone(),
            digest: self.digest,
            sealed: self.sealed,
            epoch: self.epoch.clone(),
            chunks: self.chunks,
            opened: false,
        })
    }
}

/// A lease of a collection this device knows, the newest of its holder
/// device (by log seq, which the device's keys share).
struct LeaseHeld {
    /// The key that signed it.
    writer: Writer,
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

/// One line of owner-signed members records of a name (spec §6): its
/// collection's, or its folder's. The two are separate: revisions, parents,
/// merges and epochs count records of one kind only.
#[derive(Default)]
struct Line {
    /// The subject's own record in force: the merge of `records`.
    own: Option<Members>,
    /// The owner-signed records of the highest revision held, one per
    /// signer (its latest), with each record's seq in its signer's log.
    records: BTreeMap<Writer, (u64, Members)>,
    /// Every record of `records`' revision taken and every merge of them
    /// computed, by digest: the parents records of the next revision name.
    level: HashMap<[u8; 32], Members>,
    /// The same at the revision below `records`': the parents they may
    /// name, which their merge is made against (spec §6).
    parents: HashMap<[u8; 32], Members>,
    /// What `own`, a merge of concurrent records, leaves to resolve: a
    /// device of the audience resolves it with a new record.
    resolve: Resolve,
    /// Every epoch a held owner-signed record of the line names.
    epochs: BTreeMap<Epoch, Named>,
}

/// A folder as this device knows it (spec §6): the line of its records,
/// which govern every collection strictly under it.
#[derive(Default)]
struct Folder {
    line: Line,
    /// Its record in force: its own, narrowed by the folders above it
    /// ([`collection::effective`]).
    members: Option<Members>,
    /// The epochs of its records whose key this device destroyed (spec
    /// §14): a key granted again for one is refused.
    erased: BTreeSet<Epoch>,
}

impl Line {
    /// Take `record`, the record at seq `seq` of `signer`'s log, of this
    /// line: note the epoch it names; if it is of the highest revision
    /// held, merge it with the other signers' records of that revision
    /// against the parent they name, if held (spec §6); a record of the
    /// revision below is held as a parent they may name. The own record
    /// before, when the own record in force moved.
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
        let digest = record.as_parent().digest;
        match self.records.values().next().map(|(_, m)| m.revision) {
            // A late record of the revision below: a parent the held ones
            // may name.
            Some(r) if record.revision < r => {
                if record.revision.0 + 1 != r.0 || self.parents.contains_key(&digest) {
                    return None;
                }
                self.parents.insert(digest, record);
            }
            Some(r) if record.revision > r => {
                let level = std::mem::take(&mut self.level);
                self.parents = if record.revision.0 == r.0 + 1 {
                    level
                } else {
                    HashMap::new()
                };
                self.records.clear();
                self.level.insert(digest, record.clone());
                self.records.insert(signer.clone(), (seq, record));
            }
            _ => {
                if self.records.get(signer).is_some_and(|(s, _)| *s >= seq) {
                    return None;
                }
                self.level.insert(digest, record.clone());
                self.records.insert(signer.clone(), (seq, record));
            }
        }
        let records: Vec<Members> = self.records.values().map(|(_, m)| m.clone()).collect();
        let parents = &self.parents;
        let (merged, resolve) =
            Members::merge(&records, |p| parents.get(&p.digest)).expect("a record is held");
        self.resolve = resolve;
        if records.len() > 1 {
            self.level.insert(merged.as_parent().digest, merged.clone());
        }
        if self.own.as_ref() == Some(&merged) {
            return None;
        }
        Some(self.own.replace(merged))
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
    /// Versions of the collection held here that are not in the state's
    /// value, with why, by id: the rule's `NotCounted` answers, as its
    /// `counting_changed` moves them, and applies that failed (each inside
    /// the state's frontier). Rebuilt with the state.
    not_counted: BTreeMap<VersionId, String>,
    /// What the rule's check made of each version it checked
    /// ([`OpKind`]); a checked checkpoint covers its past (spec §5.2).
    /// Cleared with the state.
    kinds: HashMap<VersionId, OpKind>,
    /// Admitted versions (and sealed ones held locked) by the implicit
    /// digest of their packet, for [`Past::by_digest`]. An entry whose
    /// version is no longer held, or is refused, is checked away on lookup.
    by_digest: HashMap<[u8; 32], VersionId>,
    /// Pending versions in pieces found not whole: not looked for again
    /// until their pieces arrive ([`St::pieces_arrived`]) or the state is
    /// rebuilt, so an arrival costs no scan of every waiting version's
    /// pieces.
    unwhole: BTreeSet<VersionId>,
    /// The groups with a member held here not yet settled — neither every
    /// member counted, nor the group refused with none counted — which
    /// every application here judges again (spec §5.5).
    txns: BTreeSet<(Writer, u64)>,
    /// The members held here of groups not counted yet, with why: the group
    /// is incomplete or not readable here.
    group_waits: BTreeMap<VersionId, String>,
    /// The applied members held here of groups (with each one's group id)
    /// that were last told not counted, with why: their own rule's reason,
    /// or the group waiting on another member ([`St::regroup`]). Kept
    /// across a rebuild of the state, so that only changes are told.
    group_held: BTreeMap<VersionId, (u64, String)>,
    /// The applied members held back only by their group: left out of the
    /// value ([`MergeState::value`]) and of the newest, while the rule
    /// still sees them.
    excluded: BTreeSet<VersionId>,
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
    /// Per writer, its newest node of the collection verified here: what
    /// it lists and the keep bounds it states decide which of the writer's
    /// versions never apply here (spec §5.2, §7).
    listings: HashMap<Writer, Listing>,
    /// Admitted, not yet applied.
    pending: BTreeSet<VersionId>,
    /// Held while no members record is known.
    waiting: Vec<Arc<HeldVersion>>,
    /// Held but refused: by the newest members record — their keys are not
    /// writers, they lie outside a cut, or they are not sealed in a sealed
    /// collection — or by the collection's merge rule. A later revision
    /// that admits them admits them (and the rule judges them again).
    outsiders: Vec<Arc<HeldVersion>>,
    /// Verified, sealed in an epoch whose key this device does not hold
    /// (yet, or ever: it is not of the audience).
    locked: Vec<Locked>,
    /// The hold records of the owner's devices, the newest of each: its
    /// seq, its name, what it asks.
    holds: BTreeMap<Writer, (u64, Name, HoldBody)>,
    /// The leases on the collection, by holder device: one device counts
    /// once, whatever keys sign for it (spec §13.2).
    leases: BTreeMap<Name, LeaseHeld>,
    /// The prune records known (spec §14).
    prunes: Vec<Prune>,
    /// The keep and epoch of each version dropped as pruned, so the leases
    /// that held it can still be checked against it, and its epoch's key
    /// destroyed once the epoch is all pruned.
    pruned_keeps: HashMap<VersionId, (Keep, Option<Epoch>)>,
    /// Epochs whose key this device destroyed: every writer's versions
    /// sealed in them are pruned or cut (spec §14). Kept in the store, so a
    /// restart refuses their keys too.
    erased: BTreeSet<Epoch>,
    /// The date of this device's newest entry here: its next is dated no
    /// earlier (spec §4.1), so a time range finds its entries in order.
    last_dated: Option<Timestamp>,
    /// The batch delay of each of this device's versions here (zero
    /// unbatched) by seq, from the newest its head may state on: the
    /// freshness a head states is its newest version's (spec §5.3), and a
    /// head lists only the durable log (spec §4.2), so the versions after
    /// the durable head and the newest before it are kept.
    batches: BTreeMap<u64, Duration>,
    /// The revocation cuts of the revoked keys that write here, or that a
    /// version held here names as a parent, by key (spec §8): each accepts
    /// that key's runs for this collection's log. An entry of such a key
    /// that its cut does not accept, and that no exact re-admission brought
    /// in, never applies: nothing waits for it.
    revoked: HashMap<Writer, Cut>,
    /// The prune records of this device's own log that it did not write (a
    /// copy of its key signed them), by name: the versions they cover read
    /// as pruned, yet their bytes stay, and no epoch key is destroyed for
    /// them, so they come back if a cut refuses the prune (spec §8).
    foreign_prunes: BTreeSet<Name>,
}

/// Whether a rule makes a collection log-like: every member key appends,
/// and nothing merges (spec §5). The one-key rule is the log rule with a
/// single member and a signed head.
fn log_like(rule: &Rule) -> bool {
    matches!(rule, Rule::Log | Rule::OneKey)
}

/// The one key of one-key collection `coll` by its record in force, and
/// the device it belongs to; `None` when the rule is another, or the record
/// names no single key.
fn one_key(coll: &Coll) -> Option<(Writer, Name)> {
    let m = coll.members.as_ref()?;
    if m.rule != Rule::OneKey {
        return None;
    }
    let [key] = m.writers.as_slice() else {
        return None;
    };
    Some((Writer::new(key.clone()), device_of(key)?))
}

/// Whether version `id`, kept `keep`, expired at this device by `now`, its
/// own clock (spec §14.1): `Until(t)` with `t ≤ now`, or `LastN(n)` with
/// `n` newer versions of its writer known here (`cutoff(n)`: the seq of the
/// `n`-th newest, [`lastn_cutoff`]). Only a log-like collection's versions
/// expire; the caller checks the rule.
fn expires(keep: Keep, id: &VersionId, now: Timestamp, cutoff: impl FnOnce(u32) -> u64) -> bool {
    match keep {
        Keep::Until(t) => t <= now,
        Keep::LastN(n) => id.seq.0 < cutoff(n),
        Keep::Forever => false,
    }
}

/// The seq below which a writer's versions in `coll` are outside its last
/// `n` (every seq when `n` is 0, none while fewer than `n` are known).
fn lastn_cutoff(coll: &Coll, writer: &Writer, n: u32) -> u64 {
    if n == 0 {
        return u64::MAX;
    }
    coll.entries
        .get(writer)
        .and_then(|s| s.iter().rev().nth(n as usize - 1))
        .copied()
        .unwrap_or(0)
}

/// The date of the last entry of `v`: its block's last, else its own.
fn last_dated(v: &Version) -> Timestamp {
    match &v.payload {
        Payload::Block(entries) => entries.last().map_or(v.dated, |e| e.dated),
        _ => v.dated,
    }
}

/// What a dropped version leaves: its writer, keep and entry dates.
fn tomb_of(v: &Version) -> Tomb {
    Tomb {
        writer: v.id.writer.key().clone(),
        keep: v.keep,
        first: v.dated,
        last: Some(last_dated(v)),
    }
}

/// Every entry of `v` as [`Entry`]s: a block's entries in order, a single
/// entry as entry 0; none for a large version not read whole.
fn entries_of(v: &Version) -> Vec<Entry> {
    let entry = |index: u32, dated: Timestamp, content: &Content| Entry {
        name: entry_name(&v.name, index),
        id: v.id.clone(),
        index,
        dated,
        content: content.clone(),
    };
    match &v.payload {
        Payload::Entry(c) => vec![entry(0, v.dated, c)],
        Payload::Block(list) => list
            .iter()
            .enumerate()
            .map(|(i, e)| entry(i as u32, e.dated, &e.content))
            .collect(),
        Payload::Large { .. } => Vec::new(),
    }
}

/// An own block being filled (spec §4.1): entries of one type, keep class
/// and seal epoch, waiting at most the delay each accepted.
struct OpenBlock {
    type_id: TypeId,
    /// `Until` merged to the latest of its entries'; `Forever` or `LastN`
    /// equal across them.
    keep: Keep,
    /// The epoch its entries are sealed in.
    epoch: Option<Epoch>,
    /// The date of its first entry: the version's `Dated`.
    first: Timestamp,
    entries: Vec<BlockEntryBody>,
    /// The earliest arrival plus batch of its entries: when it closes.
    deadline: Instant,
    /// The longest delay its entries accepted.
    batch: Duration,
    /// The puts waiting for it to be signed.
    waiters: Vec<oneshot::Sender<Result<VersionId, DataError>>>,
}

/// What an own version carries, before it is signed.
enum Draft {
    /// One entry.
    Entry(Content),
    /// The operation the app built, for a merge collection's rule.
    Op(Bytes),
    /// A block: the date of its first entry, and its entries.
    Block {
        first: Timestamp,
        entries: Vec<BlockEntryBody>,
    },
}

/// Whether an entry kept `b` may share a block kept `a`: both until some
/// date, or the same keep.
fn same_keep_class(a: Keep, b: Keep) -> bool {
    matches!((a, b), (Keep::Until(_), Keep::Until(_))) || a == b
}

/// This device's signed head of a one-key collection it writes (spec §5.3).
struct SignedHead {
    seq: u64,
    digest: [u8; 32],
    wire: Bytes,
}

/// What this device verified of the heads of one key of another device's
/// one-key collection (spec §5.3).
struct SeenHead {
    /// The highest seq of the key verified: a lower one is a rollback.
    seq: u64,
    /// Whether `seq` was verified in this run, not restored from the store.
    this_run: bool,
    /// The last head of this run whose node checked out: its receipt, and
    /// the seqs that node lists.
    checked: Option<(Receipt, Vec<u64>)>,
    /// The last head of this run whose newest listed version was
    /// delivered: that version's seq and the head's receipt, from which
    /// that version was last known the newest.
    delivered: Option<(u64, Receipt)>,
}

/// A writer's newest node of a collection verified here (spec §5.2, §7):
/// its head, the seqs it lists, and the keep bounds it states.
struct Listing {
    head: u64,
    entries: Vec<(u64, u64)>,
    expiry: Vec<ExpiryRun>,
}

impl Listing {
    /// Whether the writer's version `seq`, when not held here, never
    /// applies here by `now`, this device's clock: it is at or below the
    /// node's head and the node does not list it, or lists it in a run
    /// whose keep bound passed.
    fn gone(&self, seq: u64, now: Timestamp) -> bool {
        seq <= self.head
            && (!in_ranges(&self.entries, seq) || self.bound(seq).is_some_and(|t| t <= now))
    }

    /// The keep bound the node states for `seq`, if a run of it lists it.
    fn bound(&self, seq: u64) -> Option<Timestamp> {
        let i = self
            .expiry
            .partition_point(|r| r.seqs.last().is_some_and(|(_, hi)| *hi < seq));
        self.expiry
            .get(i)
            .filter(|r| in_ranges(&r.seqs, seq))
            .map(|r| r.until)
    }

    /// The earliest keep bound it states after `now`: when more of what it
    /// lists may stop being waited for.
    fn next_bound(&self, now: Timestamp) -> Option<Timestamp> {
        self.expiry
            .iter()
            .map(|r| r.until)
            .filter(|t| *t > now)
            .min()
    }
}

/// When a head arrived, on this device's monotonic clock (a receipt does
/// not survive a restart), and the freshness it states.
#[derive(Clone, Copy)]
struct Receipt {
    at: Instant,
    freshness: Duration,
}

impl Receipt {
    /// The age of an answer this head confirmed the newest (spec §5.3):
    /// the time since it arrived plus the freshness it states.
    fn age(&self) -> Age {
        Age::Newest {
            unconfirmed_for: Instant::now().saturating_duration_since(self.at) + self.freshness,
        }
    }
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
            listings: &self.listings,
            locked: &self.locked,
            revoked: &self.revoked,
            admitted: &self.versions,
        }
    }

    /// Its versions held that are not in the state's value, with why,
    /// by id: the rule's `NotCounted`, applies that failed, and members of
    /// groups not counted.
    fn not_counted_list(&self) -> Vec<(VersionId, String)> {
        let mut all: BTreeMap<&VersionId, &String> = self.group_waits.iter().collect();
        all.extend(self.group_held.iter().map(|(id, (_, why))| (id, why)));
        all.extend(self.not_counted.iter());
        all.into_iter()
            .map(|(id, why)| (id.clone(), why.clone()))
            .collect()
    }

    /// Whether `id` is applied here: admitted, no longer pending, and —
    /// under a merge rule — run by a state this device holds (under a rule
    /// it does not know a version is delivered and never applied).
    fn applied_member(&self, id: &VersionId) -> bool {
        let merge = self
            .members
            .as_ref()
            .is_some_and(|m| matches!(m.rule, Rule::Merge { .. }));
        self.versions.contains_key(id)
            && !self.pending.contains(id)
            && !(merge && self.state.is_none())
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
    /// collection every tip is held (applied, or covered by a checkpoint
    /// that applied only once each of its parents was held as the packet it
    /// names); under the log rule a tip whose version expired goes without.
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

    /// Whether `id` is a version this device applied under the collection's
    /// merge rule: admitted, no longer waiting, inside the state's frontier.
    fn applies(&self, id: &VersionId) -> bool {
        self.state.is_some()
            && self.versions.contains_key(id)
            && !self.pending.contains(id)
            && self.applied.get(&id.writer).is_some_and(|a| *a >= id.seq.0)
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

    /// The epoch version `id` is sealed in (`None`: unsealed), if it is
    /// held here — admitted, locked, waiting or outside.
    fn epoch_of(&self, id: &VersionId) -> Option<Option<Epoch>> {
        if let Some(hv) = self.versions.get(id) {
            return Some(hv.epoch.clone());
        }
        if let Some(l) = self
            .locked
            .iter()
            .find(|l| l.writer == id.writer && l.seq == id.seq.0)
        {
            return Some(Some(l.epoch().clone()));
        }
        self.waiting
            .iter()
            .chain(&self.outsiders)
            .find(|hv| hv.version.id == *id)
            .map(|hv| hv.epoch.clone())
    }

    /// Whether a version sealed in epoch `e` was pruned here.
    fn pruned_in(&self, e: &Epoch) -> bool {
        self.pruned_keeps
            .values()
            .any(|(_, ep)| ep.as_ref() == Some(e))
    }

    /// Whether this collection is done with epoch `e` for its erasure (spec
    /// §14): every writer known to write into it left `e` (`moved_on`, of
    /// the writer and its seqs here), and every version of it known here
    /// is pruned, held and of another epoch (or unsealed), or not held and
    /// never applying. A version only a prune a copy of this device's key
    /// signed covers ([`Coll::foreign_prunes`]) counts as not pruned.
    fn left(&self, e: &Epoch, moved_on: impl Fn(&Writer, &BTreeSet<u64>) -> bool) -> bool {
        for (w, seqs) in &self.entries {
            if !moved_on(w, seqs) {
                tracing::debug!(epoch = ?e, writer = ?w, "erasure pending: a writer may still write in the epoch");
                return false;
            }
            for s in seqs {
                let id = VersionId {
                    writer: w.clone(),
                    seq: Seq(*s),
                };
                if let Some((_, ep)) = self.pruned_keeps.get(&id) {
                    // Pruned only by a copy of this device's key: its bytes
                    // are kept, and so is its epoch's key.
                    let foreign = self
                        .prunes
                        .iter()
                        .filter(|p| covers(p, &id))
                        .all(|p| self.foreign_prunes.contains(&p.name));
                    if foreign && ep.as_ref() == Some(e) {
                        return false;
                    }
                    continue;
                }
                match self.epoch_of(&id) {
                    Some(Some(x)) if x == *e => return false,
                    Some(_) => {}
                    None if self.skips(&id) => {}
                    None => return false,
                }
            }
        }
        true
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

    /// Mark every entry known here that its writer's newest node verified
    /// here shows never applies by `now` ([`Listing::gone`]), and that is
    /// not held, as one later versions need not wait for (spec §5.2).
    /// Log-like collections only. Whether it marked any.
    fn mark_gone(&mut self, now: Timestamp) -> bool {
        if self.members.as_ref().is_none_or(|m| !log_like(&m.rule)) {
            return false;
        }
        let mut gone: Vec<(Writer, Vec<u64>)> = Vec::new();
        for (w, l) in &self.listings {
            let Some(known) = self.entries.get(w) else {
                continue;
            };
            let skipped = self.skipped.get(w);
            let seqs: Vec<u64> = known
                .range(..=l.head)
                .copied()
                .filter(|s| skipped.is_none_or(|k| !k.contains(s)) && l.gone(*s, now))
                .filter(|s| {
                    !holds_entry(
                        self,
                        &VersionId {
                            writer: w.clone(),
                            seq: Seq(*s),
                        },
                    )
                })
                .collect();
            if !seqs.is_empty() {
                gone.push((w.clone(), seqs));
            }
        }
        let marked = !gone.is_empty();
        for (w, seqs) in gone {
            self.skipped.entry(w).or_default().extend(seqs);
        }
        marked
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
/// Answers to hold and audit asks a holder keeps signed, by the ask's name:
/// the same ask asked again (a replay) costs no work and no signature.
const ANSWERS_KEPT: usize = 1024;
/// Asker proofs a holder verifies at once, whoever claims to ask: what a
/// stranger's asks can cost it before they are refused.
const ASKS_VERIFYING: usize = 8;
/// Hold asks of one owner device a holder works on at once.
const HOLDS_PER_ASKER: usize = 1;
/// Audit asks of one owner device a holder answers at once.
const AUDITS_PER_ASKER: usize = 64;
/// How long a range read takes at most, in first looks
/// ([`Config::first_look`]): what withheld or unreachable blocks can cost a
/// reader before the blocks it did not reach are answered `missing` (spec
/// §5.4).
const RANGE_LOOKS: u32 = 8;
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

/// The most collections one application carries its groups to before it
/// leaves the rest to the next arrival ([`St::apply_ready`]): a bound on
/// work, never on what is counted.
const APPLY_ROUNDS: usize = 1 << 16;

/// How long a device whose announced change was not taken (not reached, or
/// its summary not processed in full) is left before it is asked again
/// ([`Inner::schedule`]); doubled each time up to [`REFRESH_PAUSE_MAX`], for
/// [`REFRESH_TRIES`] times. Liveness only: what counts is decided by the
/// versions held.
const REFRESH_PAUSE: Duration = Duration::from_secs(2);

/// The longest pause between two asks of a device not reached.
const REFRESH_PAUSE_MAX: Duration = Duration::from_secs(64);

/// How many times a device not reached is asked again.
const REFRESH_TRIES: u32 = 16;

/// How long the committer waits before it asks the store again for a flush
/// that failed ([`Inner::commit_rounds`]); doubled each time up to
/// [`COMMIT_RETRY_MAX`]. Nothing written since the last flush is published
/// meanwhile.
const COMMIT_RETRY: Duration = Duration::from_millis(100);

/// The longest pause between two flushes asked of a store that failed.
const COMMIT_RETRY_MAX: Duration = Duration::from_secs(30);

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
    /// A prune here dropped a version sealed in its folder epoch in force:
    /// the folder moves to a new epoch, so the pruned one can be erased
    /// (spec §14).
    Erase,
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
    /// A members, hold or lease record, or a prune record: the key that
    /// signed it and its implicit digest.
    Record {
        writer: Writer,
        digest: [u8; 32],
    },
    Snapshot(Snapshot),
    /// A version its writer pruned: dropped here, never served.
    Pruned(Prune),
    /// A version whose keep passed by this device's clock: dropped here,
    /// never served or stored again (spec §14.1).
    Expired(Tomb),
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

/// A collection this device keeps for its owner under a lease (spec §13).
struct Holding {
    /// The owner's hold record answered.
    hold: Name,
    /// Until when the owner asked.
    until: Timestamp,
    /// What the hold record asks to keep: the versions inside it are all
    /// this device stores of the collection (spec §13.2).
    at: Frontier,
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
    /// The head of the root last processed in full, in this run or an
    /// earlier one (kept in the store, [`walked_name`]).
    walked: u64,
    /// What this device followed or peeked at in the namespace when it
    /// walked that root: the walk took the folder records above these
    /// only, and the versions under them.
    toward: BTreeSet<Name>,
    /// Nodes and pages processed in full, by subject and page path.
    nodes: HashMap<(Name, Option<Bytes>), [u8; 32]>,
}

/// A namespace's sync group as this device takes part in it.
struct SyncGroup {
    /// The group's publish channel, once joined.
    tx: Option<mpsc::Sender<(Name, Option<Bytes>)>>,
    /// An announcement is wanted: the next commit round makes it, once
    /// what it announces is durable ([`Inner::commit_rounds`]).
    pending: bool,
    /// Devices heard in the group.
    members: BTreeSet<Name>,
    /// Devices being refreshed, and whether to refresh again after.
    busy: HashMap<Name, bool>,
    /// When the device last knew nothing newer was outstanding.
    confirmed: Option<Instant>,
    /// The group counter of this device's latest announcement in the group
    /// (from the join on): kept in the store before each announcement goes
    /// out ([`announced_name`]), so a restart starts above it.
    announced: u64,
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
    colls: HashMap<Name, Coll>,
    /// The folders whose records are held (spec §6).
    folders: HashMap<Name, Folder>,
    held: HashMap<Name, Held>,
    peers: HashMap<(Name, Name), Peer>,
    groups: HashMap<Name, SyncGroup>,
    follows: BTreeSet<Name>,
    watchers: Vec<Watcher>,
    refused: HashMap<Name, Refusal>,
    /// The log entries refused by a revocation, by name: each also in
    /// `refused`, as [`Refusal::OutsideCut`].
    cut_out: HashMap<Name, OutOfCut>,
    /// Entries a revocation cut lists, or re-admits, being fetched.
    cut_fetching: BTreeSet<Name>,
    /// Entries a trust context re-admits exactly that were not to be had
    /// when asked for: their digest, and how many times they were asked.
    readmitting: BTreeMap<Name, ([u8; 32], u32)>,
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
    /// Collections and folders of this namespace this device owes a new
    /// members record.
    owed: BTreeMap<Subject, Owed>,
    /// Groups a record held names that this device is to follow.
    to_follow: BTreeSet<Name>,
    /// Per group, the collections and folders whose own record in force
    /// names it a reader.
    sealed_to: HashMap<Name, BTreeSet<Subject>>,
    /// The collections this device holds for their owners.
    holding: BTreeMap<Name, Holding>,
    /// Large versions whose pieces are being fetched.
    fetching: BTreeSet<Name>,
    /// Merge versions in pieces a fetch found whole: not fetched again
    /// while they wait to open (for their epoch's key, or to apply).
    walked: BTreeSet<Name>,
    /// Merge versions in pieces a fetch did not find whole (yet): they no
    /// longer hold back the pieces of the versions in their past
    /// ([`St::wanted_pieces`]).
    unfound: BTreeSet<Name>,
    /// Descents of summaries under way ([`Descending`]): the pieces of the
    /// merge versions they bring are fetched once none is.
    descents: usize,
    /// Every group of versions a member of which is held here (in any
    /// state), by writer and id: its members by seq — more than one at a
    /// seq only when its writer equivocated there (spec §5.5).
    txns: HashMap<(Writer, u64), BTreeMap<u64, Vec<Member>>>,
    /// The first log entry taken here at each seq of each key, of any
    /// collection and any kind: a key's log is one sequence (spec §4).
    seqs: HashMap<(Writer, u64), Name>,
    /// Every seq at which a key signed more than one entry, with the names
    /// of those entries: equivocation, its evidence kept (spec §4, §5.5).
    equivocal: HashMap<Writer, BTreeMap<u64, Vec<Name>>>,
    /// The merge rules this device runs ([`Config::rules`]).
    rules: MergeRules,
    /// This device's writer.
    me: Writer,
    /// Own large versions whose pieces this device serves to no one while a
    /// release audits their holders (spec §13.3): an answer relayed from
    /// this device proves nothing.
    quarantine: BTreeSet<Name>,
    /// Per asker device, its hold and audit asks this holder is working on.
    asks: HashMap<Name, usize>,
    /// Answers to hold and audit asks signed, by the ask's name.
    answers: Kept<Bytes>,
    /// This device's wall clock (retention only).
    clock: Clock,
    /// Collections whose records this device takes without following
    /// their versions: one-key collections read by head and range (spec
    /// §5.3, §5.4), and any collection asked before its rule is known.
    peeks: BTreeSet<Name>,
    /// Own blocks being filled, by collection (spec §4.1).
    open: HashMap<Name, OpenBlock>,
    /// Own signed heads, by one-key collection.
    heads: HashMap<Name, SignedHead>,
    /// Heads verified of others' one-key collections, by collection and
    /// one key: a lower one of the same key is a rollback (kept in the
    /// store across restarts). Each key's device numbers its own log, so a
    /// key that takes over a collection has a floor of its own.
    seen: HashMap<(Name, Writer), SeenHead>,
    /// The earliest `Keep::Until` date the sweeper is armed for.
    sweep_at: Option<Timestamp>,
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
    /// Wakes the expiry sweeper: a version kept until earlier than it is
    /// armed for arrived.
    sweep: Arc<Notify>,
    /// Wakes the committer ([`Inner::commit_rounds`]): something was written that
    /// waits for the barrier, or an announcement is wanted.
    commit_wake: Arc<Notify>,
    /// Told after each commit round that moved [`St::durable`].
    committed: Notify,
    slots: Semaphore,
    /// Asker proofs being verified ([`ASKS_VERIFYING`]).
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
        Held::Snapshot(s) => Some(&s.id.writer),
        Held::Record { writer, .. } => Some(writer),
        Held::Locked => parse_log_name(name)
            .and_then(|l| st.colls.get(&l.subject?))
            .and_then(|coll| coll.locked.iter().find(|l| l.name == *name))
            .map(|l| &l.writer),
        Held::Pruned(_) | Held::Expired(_) => None,
    }
}

/// Why a one-key collection's head was not taken (spec §5.3).
#[derive(Debug)]
enum HeadRefusal {
    /// Its name, collection or seq do not match each other.
    NotItsName,
    /// Its signature does not verify to a trust anchor.
    NotVerified,
    /// It is not signed by the collection's one key.
    NotTheKey,
    /// Its seq is lower than one this device verified or holds (a replayed
    /// old head).
    Rollback { seq: u64, seen: u64 },
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
/// signature by `writer`, a key of `D`, verified) about collection `c` is
/// signed by a device of `c`'s namespace, so its owner (spec §3): `D` lies
/// under the namespace ([`crate::merge::owns`], the test a merge rule asks
/// too), and the trust context governing the record's name — the one the
/// validator verified it under, the held context whose namespace is the
/// longest prefix of it — is the namespace's own. A device under the
/// namespace that a longer held namespace governs (a `/home/bob` device,
/// for `/home`) is that namespace's device, not an owner.
fn owner_signed(keyring: &Keyring, entry: &Name, c: &Name, writer: &Writer) -> bool {
    crate::merge::owns(c, writer)
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

/// What a collection's versions wait for (spec §5.2): the entries known
/// here, which of them never apply, and its writers' newest nodes.
#[derive(Clone, Copy)]
struct Waits<'a> {
    /// The collection: cuts accept versions per collection.
    collection: &'a Name,
    members: Option<&'a Members>,
    entries: &'a HashMap<Writer, BTreeSet<u64>>,
    skipped: &'a HashMap<Writer, BTreeSet<u64>>,
    listings: &'a HashMap<Writer, Listing>,
    locked: &'a [Locked],
    /// The revocation cuts of keys writing here ([`Coll::revoked`]).
    revoked: &'a HashMap<Writer, Cut>,
    /// The versions admitted here.
    admitted: &'a BTreeMap<VersionId, Arc<HeldVersion>>,
}

impl Waits<'_> {
    /// Whether later versions of `id`'s writer, and versions naming `id` as
    /// a parent, need not wait for it: [`skipped_by`]; or its key is revoked
    /// and its cut does not accept it ([`Self::outside_cut`]); or, in a
    /// log-like collection, it is no entry known here though at or below the
    /// head of its writer's newest node verified here (which lists none
    /// such: every seq it lists is known), and it is not held.
    fn never(&self, id: &VersionId) -> bool {
        skipped_by(self.members, self.skipped, id)
            || self.outside_cut(id)
            || (self.members.is_some_and(|m| log_like(&m.rule))
                && self
                    .listings
                    .get(&id.writer)
                    .is_some_and(|l| id.seq.0 <= l.head)
                && self
                    .entries
                    .get(&id.writer)
                    .is_none_or(|e| !e.contains(&id.seq.0))
                && !self
                    .locked
                    .iter()
                    .any(|l| l.writer == id.writer && l.seq == id.seq.0))
    }

    /// Whether `id`'s key is revoked, its cut does not accept `id`, and no
    /// exact re-admission brought it in (it is not admitted here).
    fn outside_cut(&self, id: &VersionId) -> bool {
        self.revoked
            .get(&id.writer)
            .is_some_and(|cut| !cut.accept.contains(self.collection, id))
            && !self.admitted.contains_key(id)
    }

    /// The implicit digest of the packet held here at `id`: admitted, or
    /// held sealed and locked.
    fn digest_of(&self, id: &VersionId) -> Option<[u8; 32]> {
        self.admitted.get(id).map(|hv| hv.digest).or_else(|| {
            self.locked
                .iter()
                .find(|l| l.writer == id.writer && l.seq == id.seq.0)
                .map(|l| wire::implicit_digest(&l.wire))
        })
    }
}

/// The seq of `y` that a version naming `(y, t)` among its parents needs
/// applied: `t`; or, when `(y, t)` never applies (a cut does not list it,
/// it was refused for what it carries, it expired, or its writer's newest
/// node shows it never applies here), the highest version of `y` at or
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

/// The versions `id`, naming `parents`, waits for (spec §5.2): its writer's
/// previous entry here that applies at all, and each parent as far as it
/// applies ([`needed`]).
fn tips(w: &Waits, id: &VersionId, parents: &Frontier) -> Vec<VersionId> {
    let at = |writer: &Writer, s: u64| VersionId {
        writer: writer.clone(),
        seq: Seq(s),
    };
    let prev = w.entries.get(&id.writer).and_then(|e| {
        e.range(..id.seq.0)
            .rev()
            .find(|s| !w.never(&at(&id.writer, **s)))
            .copied()
    });
    prev.map(|s| at(&id.writer, s))
        .into_iter()
        .chain(parents.iter().filter_map(|(y, t)| {
            let need = needed(w, y, t.0);
            (need > 0).then(|| at(y, need))
        }))
        .collect()
}

/// Whether every version of `v`'s past that applies at all is held here as
/// a signed record, whole or not, opened or not (spec §5.2, a checkpoint's
/// readiness): inside `applied`, admitted, or held sealed and locked —
/// each with its own past held, down to what `applied` holds.
fn past_held(w: &Waits, applied: &BTreeMap<Writer, u64>, v: &Version) -> bool {
    let mut seen = BTreeSet::new();
    let mut todo = tips(w, &v.id, v.parents.frontier());
    while let Some(t) = todo.pop() {
        if applied.get(&t.writer).is_some_and(|a| *a >= t.seq.0) || !seen.insert(t.clone()) {
            continue;
        }
        if let Some(hv) = w.admitted.get(&t) {
            todo.extend(tips(w, &t, hv.version.parents.frontier()));
        } else if let Some(l) = w
            .locked
            .iter()
            .find(|l| l.writer == t.writer && l.seq == t.seq.0)
        {
            todo.extend(tips(w, &t, l.body.parents.frontier()));
        } else {
            return false;
        }
    }
    true
}

/// P of version `v` (spec §5.2): its parents joined with (its writer,
/// seq − 1). down(P) is what it was made over — for a checkpoint, what it
/// covers.
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

/// The past of a version as its rule sees it (spec §5.2): down
/// ([`past_frontier`]) — the versions inside it not refused by their key —
/// and, of those, the ones held here by the implicit digest of their packet:
/// admitted, held sealed, or held and refused for what they carry or for
/// their group (a version withdrawn after another was made over it is still
/// what that one was made over). Every reader holds those before it judges
/// a version over them: a parent that applies is applied first, and one
/// refused for what it carries is held to be refused. A version refused by
/// its key — a cut that does not list it, a key no writer, a revocation,
/// an issuer no longer trusted — is in no past, whether this device holds
/// it or not (a late reader never fetches it), so every reader answers
/// alike.
struct PastOf<'a> {
    within: Frontier,
    waits: Waits<'a>,
    by_digest: &'a HashMap<[u8; 32], VersionId>,
    /// The versions held and refused.
    outsiders: &'a [Arc<HeldVersion>],
    /// The entries a trust context refuses ([`St::cut_out`]).
    cut_out: &'a HashMap<Name, OutOfCut>,
}

impl<'a> PastOf<'a> {
    fn new(
        v: &Version,
        waits: Waits<'a>,
        by_digest: &'a HashMap<[u8; 32], VersionId>,
        outsiders: &'a [Arc<HeldVersion>],
        cut_out: &'a HashMap<Name, OutOfCut>,
    ) -> Self {
        PastOf {
            within: past_frontier(v),
            waits,
            by_digest,
            outsiders,
            cut_out,
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

    fn by_digest(&self, digest: &[u8; 32]) -> Option<VersionId> {
        if let Some(id) = self.by_digest.get(digest)
            && self.waits.digest_of(id) == Some(*digest)
            && self.contains(id)
        {
            return Some(id.clone());
        }
        self.outsiders
            .iter()
            .find(|hv| {
                hv.digest == *digest
                    && self.contains(&hv.version.id)
                    && !self.cut_out.contains_key(&hv.version.name)
            })
            .map(|hv| hv.version.id.clone())
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

/// An own version signed and not yet kept ([`Inner::sign_version`]).
struct Signed {
    c: Name,
    seq: u64,
    held: HeldVersion,
    pieces: Vec<pieces::Piece>,
    /// Whether its collection is log-like.
    log: bool,
    keep: Keep,
    dated: Timestamp,
    function: Option<Name>,
}

/// What a merge rule made of an own version.
struct Ruled {
    kind: OpKind,
    counting: Counting,
    /// Other versions whose counting changed, each with how it counts now.
    changed: Vec<(VersionId, Counting)>,
}

/// `state`'s ruling on `held`, opened, against `past`: checked, and with
/// `apply`, applied (else `Counted` is assumed).
fn rule_on(
    state: &mut (dyn MergeState + 'static),
    held: &HeldVersion,
    past: &PastOf<'_>,
    apply: bool,
) -> Result<Ruled, MergeError> {
    let op = Op {
        id: &held.version.id,
        digest: &held.digest,
        parents: held.version.parents.frontier(),
        past,
        bytes: &held.op,
    };
    let kind = state.check(&op)?;
    if !apply {
        return Ok(Ruled {
            kind,
            counting: Counting::Counted,
            changed: Vec::new(),
        });
    }
    let counting = state.apply(&op)?;
    Ok(Ruled {
        kind,
        counting,
        changed: state.counting_changed(),
    })
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
/// `store` holds (spec §4.1): assembled, each piece checked against its
/// manifest, and unsealed under its epoch's key from `keys` (looked for
/// first: it costs no read of the pieces).
fn open_held(store: &dyn DataStore, keys: &Keys, hv: &HeldVersion) -> Opening {
    let Some(chunks) = hv.chunks else {
        return Opening::Missing;
    };
    let key = match &hv.epoch {
        Some(e) => match keys.key(&hv.version.collection, e) {
            Some(key) => Some(key),
            None => return Opening::NoKey,
        },
        None => None,
    };
    let name = &hv.version.name;
    if !piece_names(name, &chunks).all(|p| store.contains(&p)) {
        return Opening::Missing;
    }
    let Some(payload) = pieces::assemble(name, &chunks, |p| store.get(p)) else {
        return Opening::Missing;
    };
    let op = match key {
        Some(key) => match seal::open_payload(&key, name, &payload) {
            Some(Inline::Fields(_, op)) => op,
            _ => return Opening::Bad,
        },
        None => match wire::decode_payload(Bytes::from(payload)) {
            Ok((_, op)) => op,
            Err(_) => return Opening::Bad,
        },
    };
    Opening::Opened(op)
}

/// One member of a group, as its signed record says.
struct Member {
    collection: Name,
    /// The count its own `Group` states.
    count: u32,
    /// Its keep: a group's versions are kept until pruned (spec §5.5).
    keep: Keep,
}

/// What a reader makes of a group, from its own signed versions and their
/// admission (spec §5.5).
#[derive(Clone, Debug, PartialEq, Eq)]
enum GroupVerdict {
    /// Refused for good — malformed, or a member refused — with the member
    /// and why: no member ever applies.
    Refused { member: Name, why: String },
    /// A member is held sealed and cannot be opened here, or its
    /// collection's rule is unknown here.
    Unreadable,
    /// A member is kept otherwise than until pruned: the group never
    /// counts, and nothing of it is refused (spec §5.5).
    Kept { member: Name, keep: Keep },
    /// A member is sealed in an epoch whose audience, as the records held
    /// here name it, does not admit every reader the group declares: the
    /// member, its epoch and the readers left out.
    Uncovered {
        member: Name,
        epoch: Epoch,
        out: Vec<Audience>,
    },
    /// Fewer than all members present.
    Incomplete { present: u32, count: u32 },
    /// Every member present. `next`: the lowest seq of a held member
    /// waiting to apply, once every such member is ready.
    Complete { next: Option<u64> },
}

impl GroupVerdict {
    /// What it says of its member at `seq`, waiting here.
    fn gate(&self, seq: u64) -> Gate {
        match self {
            GroupVerdict::Refused { member, why } => Gate::Stop(Refusal::Group {
                member: member.clone(),
                why: why.clone(),
            }),
            GroupVerdict::Unreadable => Gate::Wait(Some("group not readable here".into())),
            GroupVerdict::Kept { member, keep } => Gate::Wait(Some(format!(
                "group never counts: its member {member} is kept {keep:?}, and a group's \
                 versions are kept until pruned, so that every reader judges it alike; its \
                 writer puts the items again as a group kept until pruned"
            ))),
            GroupVerdict::Uncovered { member, epoch, out } => {
                let out: Vec<String> = out
                    .iter()
                    .map(|a| match a {
                        Audience::Person(n) => format!("person {n}"),
                        Audience::Device(n) => format!("device {n}"),
                        Audience::Group(n) => format!("group {n}"),
                    })
                    .collect();
                Gate::Wait(Some(format!(
                    "group waits: its member {member} is sealed in the epoch {} started at seq \
                     {}, whose readers do not include {}, whom its group declares; it counts \
                     once the owner adds them to that epoch, at every reader alike",
                    epoch.creator,
                    epoch.seq.0,
                    out.join(", ")
                )))
            }
            GroupVerdict::Incomplete { present, count } => {
                Gate::Wait(Some(format!("group incomplete: {present} of {count}")))
            }
            GroupVerdict::Complete { next, .. } if *next == Some(seq) => Gate::Go,
            GroupVerdict::Complete { .. } => Gate::Wait(None),
        }
    }
}

/// A group member as held here.
#[derive(Clone, Debug, PartialEq, Eq)]
enum MemberState {
    /// Applied: counted.
    Counted,
    /// Admitted, whole and opened, waiting to apply.
    Waiting,
    /// Not held as it must be to count: not held, not whole, or waiting for
    /// its collection's members record.
    Missing,
    /// Held sealed and not opened here, or under a rule unknown here.
    Unreadable,
    /// Refused for good, for this reason.
    Refused(Refusal),
    /// Refused only because its group was: held, and present.
    GroupRefused,
    /// Pruned by its writer: present for its group (spec §5.5).
    Dropped,
}

/// What a group lets its member waiting to apply do ([`Run`]).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Gate {
    /// Apply when ready.
    Go,
    /// Wait; with why it is not counted, if that is to be shown.
    Wait(Option<String>),
    /// Never apply: refused for this reason.
    Stop(Refusal),
}

/// The folder a collection is in: its name but the last component.
fn folder_of(c: &Name) -> Name {
    Name::from_components(c.components()[..c.len().saturating_sub(1)].iter().cloned())
}

/// What a [`Run`] did with one version, in order.
enum Ran {
    /// Applied: by the rule, with what it made of it; or, under the log
    /// rule or inside the record's `since`, taken without one (`Counted`).
    Applied(VersionId, Counting),
    /// Inside a checkpoint's past: in the frontier now, never applied to
    /// the rule (spec §5.2).
    Covered(VersionId),
    /// Refused for good — by the rule, or its payload in pieces does not
    /// open — and taken out of the admitted versions.
    Refused(Arc<HeldVersion>, Refusal),
    /// Applied earlier, and its counting changed: it counts now, or no
    /// longer (or for another reason), as the rule reports.
    Counting(VersionId, Counting),
}

/// What [`Run::take`] did with one version.
enum Took {
    Applied(OpKind),
    Refused,
    Waits,
}

/// One collection's pending versions run through its rule (spec §5.2):
/// each applied once its writer's earlier versions and its parents are; a
/// merge version only once whole and opened, only if it was made for the
/// rule in force, only over the very packets its parents name, and only if
/// its rule's check passes against its past; a checkpoint as soon as its
/// past is held, moving the frontier past what it covers. A member of a
/// group applies only as its group's verdict lets it ([`Gate`], spec
/// §5.5). Under the log rule (`state` `None`) versions apply without a
/// rule. The live state and [`St::value_at`] run the same procedure.
struct Run<'a> {
    members: &'a Members,
    entries: &'a HashMap<Writer, BTreeSet<u64>>,
    listings: &'a HashMap<Writer, Listing>,
    locked: &'a [Locked],
    revoked: &'a HashMap<Writer, Cut>,
    by_digest: &'a HashMap<[u8; 32], VersionId>,
    /// The entries a trust context refuses ([`St::cut_out`]).
    cut_out: &'a HashMap<Name, OutOfCut>,
    store: &'a dyn DataStore,
    keys: &'a Keys,
    /// What each group member's group lets it do.
    gates: &'a HashMap<VersionId, Gate>,
    state: Option<&'a mut (dyn MergeState + 'static)>,
    versions: &'a mut BTreeMap<VersionId, Arc<HeldVersion>>,
    skipped: &'a mut HashMap<Writer, BTreeSet<u64>>,
    applied: &'a mut BTreeMap<Writer, u64>,
    pending: &'a mut BTreeSet<VersionId>,
    kinds: &'a mut HashMap<VersionId, OpKind>,
    /// The versions held and refused: those refused in this run join them.
    outsiders: &'a mut Vec<Arc<HeldVersion>>,
    /// Pending versions found not whole ([`Coll::unwhole`]): not looked
    /// for again until their pieces arrive.
    unwhole: &'a mut BTreeSet<VersionId>,
    out: Vec<Ran>,
}

impl Run<'_> {
    fn waits(&self) -> Waits<'_> {
        Waits {
            collection: &self.members.collection,
            members: Some(self.members),
            entries: self.entries,
            skipped: self.skipped,
            listings: self.listings,
            locked: self.locked,
            revoked: self.revoked,
            admitted: self.versions,
        }
    }

    fn history(&self, id: &VersionId) -> bool {
        self.members.since.as_ref().is_some_and(|s| s.contains(id))
    }

    /// Whether `id`'s group, if it is of one, lets it apply now.
    fn gated(&self, id: &VersionId) -> bool {
        self.versions
            .get(id)
            .is_some_and(|hv| hv.version.group.is_none())
            || self.gates.get(id) == Some(&Gate::Go)
    }

    fn is_ready(&self, id: &VersionId) -> bool {
        self.pending.contains(id)
            && !self.unwhole.contains(id)
            && self.gated(id)
            && self
                .versions
                .get(id)
                .is_some_and(|hv| ready(&self.waits(), self.applied, &hv.version))
    }

    /// Apply everything that is ready; what was done, in order.
    fn run(mut self) -> Vec<Ran> {
        // A member of a group refused never applies.
        let stopped: Vec<(VersionId, Refusal)> = self
            .pending
            .iter()
            .filter_map(|id| match self.gates.get(id) {
                Some(Gate::Stop(why)) => Some((id.clone(), why.clone())),
                _ => None,
            })
            .collect();
        for (id, why) in stopped {
            self.refuse(&id, why);
        }
        let merge = self.state.is_some();
        if merge {
            self.other_rule();
            self.cover();
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
                match self.take(&id) {
                    Took::Applied(OpKind::Checkpoint) => {
                        moved = true;
                        break;
                    }
                    Took::Applied(OpKind::Edit) | Took::Refused => moved = true,
                    Took::Waits => {}
                }
            }
            let progressed = moved || (merge && self.checkpoint());
            if !progressed {
                break;
            }
        }
        self.out
    }

    /// Every pending version made for another rule than the one in force
    /// is refused (spec §5.1): what it carries is read only under its own.
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

    /// Whether each parent of `id`, of `kind`, is held here as the very
    /// packet it names (spec §5.2): `Ok(false)` while a parent that applies
    /// is not held yet. A parent that never applies is no tip of an edit's
    /// (it waits for what applies below it); a checkpoint cannot stand for
    /// one. Refused for good when a parent carries no digest, names another
    /// packet than the one held at its writer and seq, or — of a checkpoint
    /// — never applies: every reader holding the same packets decides alike,
    /// whatever order they arrived in.
    fn parents_hold(&self, id: &VersionId, kind: OpKind) -> Result<bool, Refusal> {
        let Some(hv) = self.versions.get(id) else {
            return Ok(false);
        };
        let w = self.waits();
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
                if kind == OpKind::Checkpoint {
                    return Err(Refusal::Parent {
                        parent,
                        why: "that version never applies here, and a checkpoint stands only \
                              for versions that apply"
                            .into(),
                    });
                }
                continue;
            }
            match w.digest_of(&parent) {
                None => return Ok(false),
                Some(held) if held != *digest => {
                    return Err(Refusal::Parent {
                        parent,
                        why: "the packet held there has another digest (its writer named a \
                              packet that does not exist, or that key signed two packets at one \
                              seq)"
                            .into(),
                    });
                }
                Some(_) => {}
            }
        }
        Ok(true)
    }

    /// Every pending version inside the frontier is covered by a
    /// checkpoint: it never applies to the rule.
    fn cover(&mut self) {
        let covered: Vec<VersionId> = self
            .pending
            .iter()
            .filter(|id| self.applied.get(&id.writer).is_some_and(|a| *a >= id.seq.0))
            .cloned()
            .collect();
        for id in covered {
            self.pending.remove(&id);
            self.out.push(Ran::Covered(id));
        }
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
    /// opened; refused when it does not open.
    fn whole(&mut self, id: &VersionId) -> Option<bool> {
        let hv = self.versions.get(id)?;
        if hv.opened {
            return Some(true);
        }
        match open_held(self.store, self.keys, hv) {
            Opening::Opened(op) => {
                let opened = HeldVersion {
                    version: hv.version.clone(),
                    op,
                    wire: hv.wire.clone(),
                    digest: hv.digest,
                    sealed: hv.sealed,
                    epoch: hv.epoch.clone(),
                    chunks: hv.chunks,
                    opened: true,
                };
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

    /// The rule's check of `id`, opened, against its past.
    fn check(&self, id: &VersionId) -> Result<OpKind, MergeError> {
        let hv = &self.versions[id];
        let past = PastOf::new(
            &hv.version,
            self.waits(),
            self.by_digest,
            self.outsiders,
            self.cut_out,
        );
        let op = Op {
            id,
            digest: &hv.digest,
            parents: hv.version.parents.frontier(),
            past: &past,
            bytes: &hv.op,
        };
        self.state.as_deref().expect("a merge run").check(&op)
    }

    /// Apply `id`: ready, or a checkpoint whose past is held.
    fn take(&mut self, id: &VersionId) -> Took {
        if self.state.is_none() || self.history(id) {
            self.pending.remove(id);
            self.applied.insert(id.writer.clone(), id.seq.0);
            self.out.push(Ran::Applied(id.clone(), Counting::Counted));
            return Took::Applied(OpKind::Edit);
        }
        match self.whole(id) {
            None => return Took::Waits,
            Some(false) => return Took::Refused,
            Some(true) => {}
        }
        let kind = match self.kinds.get(id) {
            Some(k) => Ok(*k),
            None => self.check(id),
        };
        let kind = match kind {
            Ok(k) => k,
            Err(e) => {
                tracing::debug!(?id, "refused by its rule's check: {e}");
                self.refuse(id, Refusal::Rule { why: e.0 });
                return Took::Refused;
            }
        };
        self.kinds.insert(id.clone(), kind);
        match self.parents_hold(id, kind) {
            Ok(true) => {}
            Ok(false) => return Took::Waits,
            Err(why) => {
                tracing::debug!(?id, %why, "refused");
                self.refuse(id, why);
                return Took::Refused;
            }
        }
        let hv = Arc::clone(&self.versions[id]);
        let done = {
            // Its past, from the fields, while the state is borrowed.
            let waits = Waits {
                collection: &self.members.collection,
                members: Some(self.members),
                entries: self.entries,
                skipped: self.skipped,
                listings: self.listings,
                locked: self.locked,
                revoked: self.revoked,
                admitted: self.versions,
            };
            let past = PastOf::new(
                &hv.version,
                waits,
                self.by_digest,
                self.outsiders,
                self.cut_out,
            );
            let op = Op {
                id,
                digest: &hv.digest,
                parents: hv.version.parents.frontier(),
                past: &past,
                bytes: &hv.op,
            };
            self.state.as_deref_mut().expect("a merge run").apply(&op)
        };
        // What the operation itself makes unacceptable its check refused,
        // from the operation and its past alone; apply meets the state,
        // which other writers' versions make, so what it answers never
        // refuses a version nor withdraws its group (spec §5.1): the
        // version is applied, not counted, with the reason.
        let counting = done.unwrap_or_else(|e| {
            tracing::debug!(?id, "not counted: its rule does not apply it here: {e}");
            Counting::NotCounted(format!(
                "its rule does not apply it to the state here: {}",
                e.0
            ))
        });
        self.pending.remove(id);
        // Applied, an operation in pieces is not kept in memory.
        if let Some(unloaded) = hv.unloaded() {
            self.versions.insert(id.clone(), Arc::new(unloaded));
        }
        if kind == OpKind::Checkpoint {
            // The frontier moves past everything the checkpoint covers:
            // each of its parents, held as the packet it names.
            for t in tips(&self.waits(), id, hv.version.parents.frontier()) {
                let a = self.applied.entry(t.writer).or_insert(0);
                *a = (*a).max(t.seq.0);
            }
        }
        let a = self.applied.entry(id.writer.clone()).or_insert(0);
        *a = (*a).max(id.seq.0);
        self.out.push(Ran::Applied(id.clone(), counting));
        let changed = self
            .state
            .as_deref_mut()
            .expect("a merge run")
            .counting_changed();
        self.out.extend(
            changed
                .into_iter()
                .map(|(id, counting)| Ran::Counting(id, counting)),
        );
        if kind == OpKind::Checkpoint {
            self.cover();
        }
        Took::Applied(kind)
    }

    /// Apply a checkpoint whose past is held, if one is pending: each
    /// pending version whose past is held is checked (once) to learn what
    /// it is. A check that fails before the version is ready refuses
    /// nothing: its rule judges it against its past applied, when it is
    /// ready (spec §5.2). Whether anything changed.
    fn checkpoint(&mut self) -> bool {
        let candidates: Vec<VersionId> = self
            .pending
            .iter()
            .filter(|id| {
                !self.unwhole.contains(id)
                    && self.kinds.get(id) != Some(&OpKind::Edit)
                    && !self.history(id)
                    && self.gated(id)
            })
            .cloned()
            .collect();
        for id in candidates {
            let held = self
                .versions
                .get(&id)
                .is_some_and(|hv| past_held(&self.waits(), self.applied, &hv.version));
            if !held {
                continue;
            }
            match self.whole(&id) {
                None => continue,
                Some(false) => return true,
                Some(true) => {}
            }
            if !self.kinds.contains_key(&id) {
                match self.check(&id) {
                    Ok(k) => {
                        self.kinds.insert(id.clone(), k);
                    }
                    Err(e) if self.is_ready(&id) => {
                        tracing::debug!(?id, "refused by its rule's check: {e}");
                        self.refuse(&id, Refusal::Rule { why: e.0 });
                        return true;
                    }
                    // Not ready: not a checkpoint now; its own turn decides.
                    Err(_) => {}
                }
            }
            if self.kinds.get(&id) == Some(&OpKind::Checkpoint)
                && !matches!(self.take(&id), Took::Waits)
            {
                return true;
            }
        }
        false
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

    /// Whether something followed or peeked at lies under `subject`. Under
    /// a root (a namespace) only its own data names count:
    /// `/home/bob/32=data/x` is under `/home/bob`'s root, not `/home`'s.
    fn toward(&self, subject: &Name) -> bool {
        let under = |s: &Name| {
            [&self.follows, &self.peeks].into_iter().any(|set| {
                set.range(s.clone()..)
                    .next()
                    .is_some_and(|t| t.has_prefix(s))
            })
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
        [&self.follows, &self.peeks].into_iter().any(|set| {
            set.range(subject.clone()..)
                .take_while(|t| t.has_prefix(subject))
                .filter_map(|t| t.components().get(subject.len()))
                .any(|c| {
                    path.iter()
                        .enumerate()
                        .all(|(depth, b)| wire::bucket_of(c, depth) == *b)
                })
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

    /// Deliver `v` again to every watcher of its collection it was
    /// delivered to before (its frontier holds it): it was withdrawn, and
    /// is taken back. The others had it delivered as it applied.
    fn tell_again(&mut self, v: &Version) {
        self.watchers.retain(|w| !w.tx.is_closed());
        for w in &self.watchers {
            if v.collection.has_prefix(&w.target) && w.since.contains(&v.id) {
                let _ = w.tx.send(Ok(Change::Version(v.clone())));
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
    /// signed by `signer` (a device of the subject's namespace,
    /// [`owner_signed`]), into its line — the collection's, or the folder's
    /// ([`Line::take`]) — and, if the subject's own record in force moved,
    /// read again every collection it governs under its record in force
    /// ([`Self::refold`]): the collection, or every collection under the
    /// folder. Owes a new record of this namespace's collections and
    /// folders where the merge leaves a reader to add or a removal undone,
    /// or where a group they are sealed to dropped a reader.
    fn accept_members(
        &mut self,
        seq: u64,
        body: MembersBody,
        signer: &Writer,
        rules: &MergeRules,
        me: &Writer,
    ) {
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
            true => self.refold_under(&c, rules, me),
            false => self.refold(&c, rules, me),
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

    /// Whether a version of a collection under folder `f` that reads in
    /// `f`'s epoch in force was pruned in that epoch, by any writer: a
    /// prune asking for its erasure, so the folder moves to a new epoch
    /// first (spec §14).
    fn folder_epoch_pruned(&self, f: &Name) -> bool {
        let Some(e) = self
            .folders
            .get(f)
            .and_then(|x| x.members.as_ref())
            .and_then(|m| m.epoch.as_ref())
        else {
            return false;
        };
        self.colls.iter().any(|(c, x)| {
            c.has_prefix(f)
                && c != f
                && x.members
                    .as_ref()
                    .is_some_and(|m| m.epoch.as_ref() == Some(e))
                && x.pruned_in(e)
        })
    }

    /// Owe, from the records and prunes held alone, what namespace `ns`'s
    /// collections and folders need signed (spec §6.1, §14): a new epoch of
    /// one sealed in its own epoch that outgrew its audience, and of a
    /// folder whose epoch in force a prune dropped a version of.
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
        for (f, x) in &self.folders {
            if !mine(f) {
                continue;
            }
            let why = if owes_epoch(x.line.own.as_ref(), x.members.as_ref(), &x.line.epochs) {
                Owed::Folder
            } else if self.folder_epoch_pruned(f) {
                Owed::Erase
            } else {
                continue;
            };
            let s = Subject {
                name: f.clone(),
                folder: true,
            };
            owed.push((s, why));
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
    fn ensure(&mut self, c: &Name, rules: &MergeRules, me: &Writer) {
        let coll = self.colls.entry(c.clone()).or_default();
        if coll.members.is_none() && !self.folders_above(c).is_empty() {
            self.refold(c, rules, me);
        }
    }

    /// Set collection `c`'s record in force anew ([`Self::effective`]) and,
    /// if it moved, read `c` again under it ([`Self::reread`]); with none
    /// left, its versions wait for one. Owes a new record of this
    /// namespace's collections sealed to `c` as a group when `c` dropped a
    /// reader, and of `c` itself when a folder above dropped a reader its
    /// own record lists (spec §6).
    fn refold(&mut self, c: &Name, rules: &MergeRules, me: &Writer) {
        let new = self.effective(c);
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
        if new.is_some() {
            self.reread(c, rules, me);
        }
    }

    /// After folder `f`'s own record moved: set the record in force of
    /// every folder at or under `f`, and of every collection under it known
    /// here or looked at ([`Self::refold`]). Owes a new record of a folder
    /// under `f` of this namespace whose own readers lost one to `f`.
    fn refold_under(&mut self, f: &Name, rules: &MergeRules, me: &Writer) {
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
            folder.members = new;
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
        let colls: BTreeSet<Name> = self
            .colls
            .keys()
            .chain(self.peeks.iter())
            .filter(|n| under(n))
            .cloned()
            .collect();
        for c in colls {
            self.refold(&c, rules, me);
        }
    }

    /// Read collection `c` again under its newest members record (spec
    /// §8): every version held is admitted or refused anew and the state is
    /// rebuilt from the admitted ones. A version applied before that is now
    /// refused outside a cut — the record's, or a revocation's
    /// ([`St::cut_out`]) — for its chain ([`Refusal::Untrusted`]), or for its
    /// group ([`Refusal::Group`]) is withdrawn and reported to the
    /// watchers; one applied before and still admitted is not delivered
    /// again.
    fn reread(&mut self, c: &Name, rules: &MergeRules, me: &Writer) {
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
        coll.mark_pruned();
        coll.state = match &members.rule {
            Rule::Merge { function } => rules.get(function).map(|r| r.start(c, me)),
            _ => None,
        };
        coll.kinds.clear();
        coll.unwhole.clear();
        let not_counted = std::mem::take(&mut coll.not_counted);
        // The groups of members told not counted: judged again once the
        // state is rebuilt, whether or not their members apply again.
        let held_groups: BTreeSet<(Writer, u64)> = coll
            .group_held
            .iter()
            .map(|(id, (g, _))| (id.writer.clone(), *g))
            .collect();
        let names: Vec<(VersionId, Name, bool)> = all
            .iter()
            .filter(|hv| delivered.contains(&hv.version.id))
            .map(|hv| {
                (
                    hv.version.id.clone(),
                    hv.version.name.clone(),
                    hv.version.group.is_some(),
                )
            })
            .collect();
        for hv in all {
            self.refused.remove(&hv.version.name);
            self.admit_one(hv);
        }
        let now = (self.clock)();
        if let Some(coll) = self.colls.get_mut(c) {
            coll.mark_gone(now);
        }
        self.apply_ready(c, &delivered);
        self.regroup(held_groups);
        // A member of a group withdrawn is withdrawn with its group: the
        // refused member itself names its own refusal (spec §5.5).
        let withdrawn: Vec<(VersionId, Refusal)> = names
            .into_iter()
            .filter_map(|(id, name, grouped)| match self.refused.get(&name) {
                Some(why @ Refusal::Group { .. }) => Some((id, why.clone())),
                Some(why @ (Refusal::OutsideCut(_) | Refusal::Untrusted { .. })) if grouped => {
                    let why = Refusal::Group {
                        member: name.clone(),
                        why: why.to_string(),
                    };
                    Some((id, why))
                }
                Some(why @ (Refusal::OutsideCut(_) | Refusal::Untrusted { .. })) => {
                    Some((id, why.clone()))
                }
                _ => None,
            })
            .collect();
        // What the rule counts changed only as the rebuilt state says:
        // `apply_ready` told what was not delivered before; the rest is
        // told here as it differs. A group member's counting is its
        // group's, told by [`Self::regroup`].
        let mut told = Vec::new();
        if let Some(coll) = self.colls.get(c) {
            let at = coll.at();
            let single = |id: &VersionId| {
                coll.versions
                    .get(id)
                    .is_some_and(|hv| hv.version.group.is_none())
            };
            for (id, why) in &coll.not_counted {
                if delivered.contains(id) && single(id) && not_counted.get(id) != Some(why) {
                    told.push(Change::NotCounted {
                        collection: c.clone(),
                        id: id.clone(),
                        why: why.clone(),
                    });
                }
            }
            for id in not_counted.keys() {
                if !coll.not_counted.contains_key(id) && at.contains(id) && single(id) {
                    told.push(Change::Counted {
                        collection: c.clone(),
                        id: id.clone(),
                    });
                }
            }
        }
        for change in told {
            self.tell(c, &change);
        }
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
        if let Some(g) = hv.version.group {
            self.note_member(&c, &hv.version.id, g, hv.version.keep);
        }
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
        // A merge rule takes one operation per version: a block carries
        // many (spec §4.1).
        if matches!(members.rule, Rule::Merge { .. })
            && matches!(hv.version.payload, Payload::Block(_))
        {
            tracing::debug!(id = ?hv.version.id, "refused: its payload is a block, in a merge collection");
            coll.skipped
                .entry(hv.version.id.writer.clone())
                .or_default()
                .insert(hv.version.id.seq.0);
            self.refused
                .insert(hv.version.name.clone(), Refusal::NotInline);
            coll.outsiders.push(hv);
            return false;
        }
        coll.by_digest.insert(hv.digest, hv.version.id.clone());
        coll.entries
            .entry(hv.version.id.writer.clone())
            .or_default()
            .insert(hv.version.id.seq.0);
        coll.pending.insert(hv.version.id.clone());
        coll.versions.insert(hv.version.id.clone(), hv);
        true
    }

    /// Admit a verified, opened version and apply what became ready. A
    /// member of a group refused as it arrives refuses its group: that is
    /// carried to its other members too.
    fn admit(&mut self, hv: Arc<HeldVersion>) {
        let c = hv.version.collection.clone();
        let grouped = hv.version.group.is_some();
        if self.admit_one(hv) || grouped {
            self.apply_ready(&c, &BTreeSet::new());
        }
    }

    /// Apply every pending version of `c` that is ready ([`Self::apply_one`]),
    /// and carry what that changes of its groups to their other collections
    /// (spec §5.5): a complete group's members apply together, in seq order,
    /// all within this call; a refused group's members never apply, and
    /// those applied before are withdrawn, in every collection of the group.
    /// `quiet` lists what `c` delivered before. Then every group whose
    /// members' counting may have moved is judged again ([`Self::regroup`]).
    fn apply_ready(&mut self, c: &Name, quiet: &BTreeSet<VersionId>) {
        let none = BTreeSet::new();
        let mut todo = VecDeque::from([c.clone()]);
        let mut queued = BTreeSet::from([c.clone()]);
        let mut rounds = 0usize;
        let mut touched = BTreeSet::new();
        while let Some(x) = todo.pop_front() {
            queued.remove(&x);
            rounds += 1;
            if rounds > APPLY_ROUNDS {
                tracing::warn!(collection = %c, "groups still moving after {APPLY_ROUNDS} rounds; the rest applies on the next arrival");
                break;
            }
            touched.extend(self.apply_one(&x, if x == *c { quiet } else { &none }));
            let active: Vec<(Writer, u64)> = self
                .colls
                .get(&x)
                .map(|k| k.txns.iter().cloned().collect())
                .unwrap_or_default();
            for key in active {
                let verdict = self.verdict(&key);
                let refused = matches!(verdict, GroupVerdict::Refused { .. });
                let members: Vec<(u64, Name)> = self
                    .txns
                    .get(&key)
                    .map(|m| {
                        m.iter()
                            .flat_map(|(s, ms)| ms.iter().map(|m| (*s, m.collection.clone())))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut settled = true;
                for (seq, y) in members {
                    let id = VersionId {
                        writer: key.0.clone(),
                        seq: Seq(seq),
                    };
                    match self.member_state(&y, &id) {
                        // Applied before its group was refused: withdrawn.
                        MemberState::Counted if refused => {
                            settled = false;
                            let (rules, me) = (self.rules.clone(), self.me.clone());
                            self.reread(&y, &rules, &me);
                        }
                        // Refused for a group no longer refused: admitted again.
                        MemberState::GroupRefused if !refused => {
                            settled = false;
                            let (rules, me) = (self.rules.clone(), self.me.clone());
                            self.reread(&y, &rules, &me);
                        }
                        state @ (MemberState::Waiting | MemberState::Unreadable) => {
                            if !refused || state == MemberState::Waiting {
                                settled = false;
                            }
                            // Only a member waiting in its collection —
                            // pending, or held sealed, under a record known
                            // — is acted on there.
                            let here = self.colls.get(&y).is_some_and(|k| {
                                k.members.is_some()
                                    && k.txns.contains(&key)
                                    && (k.pending.contains(&id)
                                        || k.locked
                                            .iter()
                                            .any(|l| l.writer == id.writer && l.seq == seq))
                            });
                            let told = self.colls.get(&y).and_then(|k| k.group_waits.get(&id));
                            let moves = here
                                && match verdict.gate(seq) {
                                    Gate::Go | Gate::Stop(_) => state == MemberState::Waiting,
                                    Gate::Wait(Some(why)) => told != Some(&why),
                                    Gate::Wait(None) => false,
                                };
                            if moves && queued.insert(y.clone()) {
                                todo.push_back(y);
                            }
                        }
                        MemberState::Missing if !refused => settled = false,
                        _ => {}
                    }
                }
                if settled && let Some(coll) = self.colls.get_mut(&x) {
                    coll.txns.remove(&key);
                }
            }
        }
        self.regroup(touched);
    }

    /// Apply every pending version of `c` that is ready ([`Run`]), as its
    /// group lets it, store it, and deliver it to the watchers unless
    /// `quiet` lists it (delivered before), with what the rule counts.
    /// Under a merge rule this device does not know, every pending version
    /// is stored and delivered and none applied: no state is read under
    /// another rule. The groups whose members applied, or whose counting
    /// moved, are returned: a group member's counting is told by
    /// [`Self::regroup`], once every collection of the group has run.
    fn apply_one(&mut self, c: &Name, quiet: &BTreeSet<VersionId>) -> BTreeSet<(Writer, u64)> {
        let mut touched = BTreeSet::new();
        let gates = self.gates(c);
        // A member held of a group not counted: its folder is followed, so
        // that the others arrive (spec §5.5).
        if gates.values().any(|g| matches!(g, Gate::Wait(Some(_)))) {
            let folder = folder_of(c);
            if !self.inside(&folder) {
                self.to_follow.insert(folder);
            }
        }
        let St {
            colls,
            watchers,
            refused,
            store,
            keys,
            cut_out,
            ..
        } = self;
        let Some(coll) = colls.get_mut(c) else {
            return touched;
        };
        let Coll {
            members,
            state,
            not_counted,
            group_waits,
            group_held,
            kinds,
            by_digest,
            versions,
            applied,
            entries,
            skipped,
            listings,
            locked,
            pending,
            revoked,
            outsiders,
            unwhole,
            ..
        } = coll;
        let Some(members) = members.as_ref() else {
            return touched;
        };
        let group_of = |versions: &BTreeMap<VersionId, Arc<HeldVersion>>, id: &VersionId| {
            versions
                .get(id)
                .and_then(|hv| hv.version.group)
                .map(|g| g.id)
        };
        // Each change, and the version whose delivery it follows (`None`:
        // every watcher of the collection is told).
        let mut changes: Vec<(Change, Option<VersionId>)> = Vec::new();
        let deliver = |hv: &HeldVersion, changes: &mut Vec<(Change, Option<VersionId>)>| {
            store.insert(hv.version.name.clone(), hv.wire.clone());
            if !quiet.contains(&hv.version.id) {
                changes.push((
                    Change::Version(hv.version.clone()),
                    Some(hv.version.id.clone()),
                ));
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
                listings,
                locked,
                revoked,
                by_digest,
                cut_out,
                store: &**store,
                keys,
                gates: &gates,
                state: state.as_deref_mut(),
                versions,
                skipped,
                applied,
                pending,
                kinds,
                outsiders,
                unwhole,
                out: Vec::new(),
            }
            .run();
            // Only what still waits is remembered not whole.
            unwhole.retain(|id| pending.contains(id));
            for r in ran {
                match r {
                    Ran::Applied(id, counting) => {
                        deliver(&versions[&id], &mut changes);
                        let group = group_of(versions, &id);
                        if let Some(g) = group {
                            touched.insert((id.writer.clone(), g));
                        }
                        if let Counting::NotCounted(why) = counting {
                            not_counted.insert(id.clone(), why.clone());
                            if group.is_none() && !quiet.contains(&id) {
                                changes.push((
                                    Change::NotCounted {
                                        collection: c.clone(),
                                        id: id.clone(),
                                        why,
                                    },
                                    Some(id),
                                ));
                            }
                        }
                    }
                    Ran::Covered(id) => {
                        deliver(&versions[&id], &mut changes);
                        if let Some(g) = group_of(versions, &id) {
                            touched.insert((id.writer.clone(), g));
                        }
                    }
                    Ran::Refused(hv, why) => {
                        tracing::debug!(id = ?hv.version.id, collection = %c, %why, "refused");
                        let id = hv.version.id.clone();
                        if matches!(why, Refusal::Group { .. }) && !quiet.contains(&id) {
                            changes.push((
                                Change::NotCounted {
                                    collection: c.clone(),
                                    id,
                                    why: format!("group refused: {why}"),
                                },
                                None,
                            ));
                        }
                        refused.insert(hv.version.name.clone(), why);
                    }
                    Ran::Counting(id, counting) => {
                        let group = group_of(versions, &id);
                        if let Some(g) = group {
                            touched.insert((id.writer.clone(), g));
                        }
                        let tell = group.is_none() && !quiet.contains(&id);
                        match counting {
                            Counting::Counted => {
                                if not_counted.remove(&id).is_some() && tell {
                                    changes.push((
                                        Change::Counted {
                                            collection: c.clone(),
                                            id,
                                        },
                                        None,
                                    ));
                                }
                            }
                            Counting::NotCounted(why) => {
                                if not_counted.get(&id) != Some(&why) {
                                    not_counted.insert(id.clone(), why.clone());
                                    if tell {
                                        changes.push((
                                            Change::NotCounted {
                                                collection: c.clone(),
                                                id: id.clone(),
                                                why,
                                            },
                                            Some(id),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Why each member of a group not counted waits, told when it
        // changes; counted once it applies.
        let waits = |id: &VersionId| {
            pending.contains(id)
                || locked
                    .iter()
                    .any(|l| l.writer == id.writer && l.seq == id.seq.0)
        };
        for (id, gate) in &gates {
            if let Gate::Wait(Some(why)) = gate
                && waits(id)
                && group_waits.get(id) != Some(why)
            {
                group_waits.insert(id.clone(), why.clone());
                changes.push((
                    Change::NotCounted {
                        collection: c.clone(),
                        id: id.clone(),
                        why: why.clone(),
                    },
                    Some(id.clone()),
                ));
            }
        }
        let gone: Vec<VersionId> = group_waits
            .keys()
            .filter(|id| !waits(id))
            .cloned()
            .collect();
        for id in gone {
            let why = group_waits.remove(&id);
            let applied_here = versions.contains_key(&id)
                && applied.get(&id.writer).is_some_and(|a| *a >= id.seq.0);
            // Told not counted while it waited; applied now, its group
            // judges whether it counts ([`St::regroup`]).
            if applied_here && let (Some(why), Some(g)) = (why, group_of(versions, &id)) {
                group_held.entry(id.clone()).or_insert((g, why));
                touched.insert((id.writer.clone(), g));
            }
        }
        watchers.retain(|w| !w.tx.is_closed());
        for (change, of) in changes {
            for w in watchers.iter() {
                let to =
                    c.has_prefix(&w.target) && of.as_ref().is_none_or(|id| !w.since.contains(id));
                if to {
                    let _ = w.tx.send(Ok(change.clone()));
                }
            }
        }
        touched
    }

    /// Note `id`, of `c`, kept `keep`, as a member of group `g` of its
    /// writer. A second entry its writer signed at that seq, in another
    /// collection, is noted beside it: the group is then malformed.
    fn note_member(&mut self, c: &Name, id: &VersionId, g: Group, keep: Keep) {
        let key = (id.writer.clone(), g.id);
        let at = self
            .txns
            .entry(key.clone())
            .or_default()
            .entry(id.seq.0)
            .or_default();
        if !at.iter().any(|m| m.collection == *c) {
            at.push(Member {
                collection: c.clone(),
                count: g.count,
                keep,
            });
        }
        self.colls.entry(c.clone()).or_default().txns.insert(key);
    }

    /// Judge again whether each group of `keys` counts (spec §5.5): a group
    /// counts only while every member applied here counts. While one does
    /// not — its rule does not count it, or its apply failed — every other
    /// applied member is held back: not counted, with "group waiting on
    /// <member>: <that member's reason>", and left out of its collection's
    /// value and newest. The rule still sees it: it is applied, and the
    /// rule's counting of every version is the rule's alone (the layer's
    /// holding back never feeds back into it). A member its rule does not
    /// count keeps its own reason. Each member is told as what it was last
    /// told changes: not counted with why, or counted again.
    fn regroup(&mut self, keys: BTreeSet<(Writer, u64)>) {
        for key in keys {
            let members: Vec<(VersionId, Name)> = self
                .txns
                .get(&key)
                .map(|m| {
                    m.iter()
                        .flat_map(|(s, ms)| {
                            ms.iter().map(|m| {
                                let id = VersionId {
                                    writer: key.0.clone(),
                                    seq: Seq(*s),
                                };
                                (id, m.collection.clone())
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            // The first member, in seq order, that does not count.
            let blocker = members.iter().find_map(|(id, c)| {
                let coll = self.colls.get(c)?;
                let why = coll.not_counted.get(id)?;
                coll.applied_member(id)
                    .then(|| format!("group waiting on {}: {why}", coll.versions[id].version.name))
            });
            let mut told: Vec<(Name, Change, VersionId)> = Vec::new();
            for (id, c) in &members {
                let Some(coll) = self.colls.get_mut(c) else {
                    continue;
                };
                if !coll.applied_member(id) {
                    // Waiting, refused or withdrawn: told so elsewhere.
                    coll.group_held.remove(id);
                    coll.excluded.remove(id);
                    continue;
                }
                let own = coll.not_counted.get(id).cloned();
                if own.is_none() && blocker.is_some() {
                    coll.excluded.insert(id.clone());
                } else {
                    coll.excluded.remove(id);
                }
                match own.or_else(|| blocker.clone()) {
                    Some(why) if coll.group_held.get(id).map(|(_, w)| w) != Some(&why) => {
                        coll.group_held.insert(id.clone(), (key.1, why.clone()));
                        let change = Change::NotCounted {
                            collection: c.clone(),
                            id: id.clone(),
                            why,
                        };
                        told.push((c.clone(), change, id.clone()));
                    }
                    None if coll.group_held.remove(id).is_some() => {
                        let change = Change::Counted {
                            collection: c.clone(),
                            id: id.clone(),
                        };
                        told.push((c.clone(), change, id.clone()));
                    }
                    _ => {}
                }
            }
            for (c, change, id) in told {
                match change {
                    Change::NotCounted { .. } => self.emit(&c, &change, &id.writer, id.seq.0),
                    _ => self.tell(&c, &change),
                }
            }
        }
    }

    /// Note the log entry `name`, signed by `writer` at `seq`: a key's log
    /// is one sequence across its collections and entry kinds (spec §4),
    /// so a second entry at a seq it already used, under another name, is
    /// equivocation. Both are kept, and it is reported to the watchers of
    /// both collections where both are versions. Whether it is such a
    /// second entry: once it is taken, the writer's groups over that seq
    /// are judged again ([`Self::regroup_seq`]).
    fn note_seq(&mut self, name: &Name, writer: &Writer, seq: u64, record: &Record) -> bool {
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
            && let Some(v) = self.held_version(&first)
        {
            let first = Box::new(v.clone());
            let second = Box::new(version_of(name, writer, seq, body.clone()));
            let mut told = vec![body.collection.clone()];
            if v.collection != body.collection {
                told.push(v.collection.clone());
            }
            for c in told {
                let change = Change::Equivocation {
                    collection: c.clone(),
                    first: first.clone(),
                    second: second.clone(),
                };
                self.tell(&c, &change);
            }
        }
        true
    }

    /// Judge again every group of `writer` over `seq` (spec §5.5): a second
    /// entry at that seq was taken.
    fn regroup_seq(&mut self, writer: &Writer, seq: u64) {
        let groups: Vec<((Writer, u64), Vec<Name>)> = self
            .txns
            .iter()
            .filter(|((w, gid), ms)| {
                w == writer
                    && seq >= *gid
                    && ms
                        .values()
                        .flatten()
                        .any(|m| seq - gid < u64::from(m.count))
            })
            .map(|(k, ms)| {
                let colls = ms.values().flatten().map(|m| m.collection.clone());
                (k.clone(), colls.collect())
            })
            .collect();
        for (key, colls) in groups {
            for c in &colls {
                self.colls
                    .entry(c.clone())
                    .or_default()
                    .txns
                    .insert(key.clone());
            }
            if let Some(c) = colls.first() {
                self.apply_ready(c, &BTreeSet::new());
            }
        }
    }

    /// Judge again every group of `writer` with a member in a collection
    /// of `folder` (spec §5.5): a node of the writer there was verified,
    /// and what it lists, or does not, may settle such a group.
    fn regroup_under(&mut self, writer: &Writer, folder: &Name) {
        let groups: Vec<((Writer, u64), Vec<Name>)> = self
            .txns
            .iter()
            .filter(|((w, _), ms)| {
                w == writer
                    && ms
                        .values()
                        .flatten()
                        .any(|m| folder_of(&m.collection) == *folder)
            })
            .map(|(k, ms)| {
                let colls = ms.values().flatten().map(|m| m.collection.clone());
                (k.clone(), colls.collect())
            })
            .collect();
        for (key, colls) in groups {
            for c in &colls {
                self.colls
                    .entry(c.clone())
                    .or_default()
                    .txns
                    .insert(key.clone());
            }
            if let Some(c) = colls.first() {
                self.apply_ready(c, &BTreeSet::new());
            }
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
                    .map(|lk| version_of(name, &lk.writer, lk.seq, lk.body.clone()))
            })
    }

    /// Whether `id`, a version of `c` this device knows of, was pruned by
    /// its writer: present for its group (spec §5.5). A prune is a signed
    /// record every reader of `c` fetches, and the writer's summary keeps
    /// listing what it pruned, so every reader knows it alike.
    fn dropped(&self, c: &Name, id: &VersionId) -> bool {
        let Some(device) = device_of(id.writer.key()) else {
            return false;
        };
        if matches!(
            self.held.get(&log_name(&device, Some(c), id.seq.0)),
            Some(Held::Pruned(_))
        ) {
            return true;
        }
        self.colls.get(c).is_some_and(|coll| {
            coll.entries
                .get(&id.writer)
                .is_some_and(|e| e.contains(&id.seq.0))
                && coll.pruned(id).is_some()
        })
    }

    /// How group member `id` of `c` is held here.
    fn member_state(&self, c: &Name, id: &VersionId) -> MemberState {
        let Some(coll) = self.colls.get(c) else {
            return MemberState::Missing;
        };
        let merge = coll
            .members
            .as_ref()
            .is_some_and(|m| matches!(m.rule, Rule::Merge { .. }));
        if let Some(hv) = coll.versions.get(id) {
            if merge && coll.state.is_none() {
                return MemberState::Unreadable;
            }
            if !coll.pending.contains(id) {
                return MemberState::Counted;
            }
            if merge && !hv.opened {
                let sealed_off = hv
                    .epoch
                    .as_ref()
                    .is_some_and(|e| self.keys.key(c, e).is_none());
                return match sealed_off {
                    true => MemberState::Unreadable,
                    false => MemberState::Missing,
                };
            }
            return MemberState::Waiting;
        }
        if let Some(hv) = coll.outsiders.iter().find(|hv| hv.version.id == *id) {
            return match self.refused.get(&hv.version.name) {
                Some(Refusal::Group { .. }) => MemberState::GroupRefused,
                Some(why) => MemberState::Refused(why.clone()),
                None => MemberState::Missing,
            };
        }
        if coll
            .locked
            .iter()
            .any(|l| l.writer == id.writer && l.seq == id.seq.0)
        {
            return MemberState::Unreadable;
        }
        // Taken and refused for what it carries (a payload that does not
        // open), not held.
        if let Some(device) = device_of(id.writer.key())
            && let Some(why) = self.refused.get(&log_name(&device, Some(c), id.seq.0))
        {
            return match why {
                Refusal::Group { .. } => MemberState::GroupRefused,
                why => MemberState::Refused(why.clone()),
            };
        }
        if self.dropped(c, id) {
            return MemberState::Dropped;
        }
        MemberState::Missing
    }

    /// The seal group member `id` of `c` declares, and the epoch it is
    /// sealed in, if it is held.
    fn sealing(&self, c: &Name, id: &VersionId) -> Option<(BTreeSet<Audience>, Option<Epoch>)> {
        let coll = self.colls.get(c)?;
        coll.versions
            .get(id)
            .or_else(|| {
                coll.outsiders
                    .iter()
                    .chain(&coll.waiting)
                    .find(|hv| hv.version.id == *id)
            })
            .map(|hv| (&hv.version.seal, hv.epoch.clone()))
            .or_else(|| {
                coll.locked
                    .iter()
                    .find(|l| l.writer == id.writer && l.seq == id.seq.0)
                    .map(|l| (&l.body.seal, Some(l.epoch().clone())))
            })
            .map(|(seal, epoch)| (seal.any_of.iter().cloned().collect(), epoch))
    }

    /// The readers of epoch `e` that a version of `c` is sealed in, as the
    /// records held here name it (spec §9): every reader a held record
    /// naming it lists (its audience is these and the device that started
    /// it). Records that only add readers keep an epoch, so it only grows
    /// as records arrive.
    fn epoch_readers(&self, c: &Name, e: &Epoch) -> Vec<Audience> {
        let s = self.seal_subject(c, e);
        self.line_of(&s)
            .and_then(|(epochs, _)| epochs.get(e))
            .map(|named| named.readers.clone())
            .unwrap_or_default()
    }

    /// Whether `w` signed an entry at `seq` in collection `x`, as every
    /// reader following `x` learns alike (spec §5.5): held here kept until
    /// pruned, or known (held, or listed by a node of `w` verified here,
    /// ever) and pruned by `w`'s prune record, or known in a merge
    /// collection (whose nodes list every entry). What was once known stays
    /// known: a node that later stops listing it takes nothing back. An
    /// entry kept for its last `n` or until a date may leave `w`'s listing
    /// before a later reader learns of it: it is no evidence; nor is one
    /// the trust context refuses (a copy of a revoked key wrote it, §8.1).
    fn signed_at(&self, x: &Name, w: &Writer, seq: u64) -> bool {
        let Some(coll) = self.colls.get(x) else {
            return false;
        };
        let id = VersionId {
            writer: w.clone(),
            seq: Seq(seq),
        };
        let ours = |name: &Name| !self.cut_out.contains_key(name);
        let held = coll
            .versions
            .get(&id)
            .into_iter()
            .chain(
                coll.waiting
                    .iter()
                    .chain(&coll.outsiders)
                    .filter(|hv| hv.version.id == id),
            )
            .any(|hv| hv.version.keep == Keep::Forever && ours(&hv.version.name))
            || coll.locked.iter().any(|l| {
                l.writer == *w && l.seq == seq && l.body.keep == Keep::Forever && ours(&l.name)
            });
        if held {
            return true;
        }
        let known = coll.entries.get(w).is_some_and(|e| e.contains(&seq));
        known
            && (coll.pruned(&id).is_some()
                || coll
                    .members
                    .as_ref()
                    .is_some_and(|m| matches!(m.rule, Rule::Merge { .. })))
    }

    /// The verdict on group `key` (its writer and id), from what every
    /// reader of its folder holds alike: its own signed versions and their
    /// admission, its writer's signed entries and listings under the
    /// folder, and the audiences of the epochs its members are sealed in
    /// (spec §5.5).
    fn verdict(&self, key: &(Writer, u64)) -> GroupVerdict {
        let (w, gid) = key;
        let Some(members) = self.txns.get(key) else {
            return GroupVerdict::Incomplete {
                present: 0,
                count: 0,
            };
        };
        let id = |seq: u64| VersionId {
            writer: w.clone(),
            seq: Seq(seq),
        };
        let name_of = |c: &Name, seq: u64| match device_of(w.key()) {
            Some(d) => log_name(&d, Some(c), seq),
            None => c.clone(),
        };
        let count = members.values().flatten().next().map_or(0, |m| m.count);
        let malformed = |member: Name, why: &str| GroupVerdict::Refused {
            member,
            why: format!("its group is malformed: {why}"),
        };
        let span = *gid..gid.saturating_add(u64::from(count));
        let mut folders = BTreeSet::new();
        let mut colls = BTreeSet::new();
        let mut seals: Option<BTreeSet<Audience>> = None;
        let mut expiring: Option<(Name, Keep)> = None;
        for (seq, ms) in members {
            if let [a, b, ..] = &ms[..] {
                return malformed(
                    name_of(&a.collection, *seq),
                    &format!(
                        "its writer signed two members at seq {seq}, in {} and {}",
                        a.collection, b.collection
                    ),
                );
            }
            for m in ms {
                let member = || name_of(&m.collection, *seq);
                if *seq < *gid || *seq - gid >= u64::from(m.count) {
                    return malformed(member(), "a member's seq lies outside the group");
                }
                if m.count != count {
                    return malformed(member(), "its members disagree on the group's count");
                }
                if m.keep != Keep::Forever && expiring.is_none() {
                    expiring = Some((member(), m.keep));
                }
                folders.insert(folder_of(&m.collection));
                if folders.len() > 1 {
                    return malformed(
                        member(),
                        "its members lie in collections of different folders",
                    );
                }
                if !colls.insert(m.collection.clone()) {
                    return malformed(member(), "two of its members are in one collection");
                }
                if let Some((seal, _)) = self.sealing(&m.collection, &id(*seq)) {
                    match &seals {
                        Some(s) if *s != seal => {
                            return malformed(member(), "its members declare different seals");
                        }
                        Some(_) => {}
                        None => seals = Some(seal),
                    }
                }
            }
        }
        let folder = folders.into_iter().next().expect("a member is held");
        // Its writer signed two entries at one of its seqs in collections
        // of its folder, as every reader of the folder learns alike from
        // the writer's own signed entries and listings there: no reader
        // could tell which one counts.
        let under: Vec<&Name> = self
            .colls
            .keys()
            .filter(|c| folder_of(c) == folder)
            .collect();
        for s in span.clone() {
            let at: Vec<&&Name> = under.iter().filter(|x| self.signed_at(x, w, s)).collect();
            if let [a, b, ..] = at[..] {
                return malformed(
                    name_of(a, s),
                    &format!(
                        "its writer signed two entries at seq {s}, in {a} and {b}, though a \
                         key's log is one sequence across its collections"
                    ),
                );
            }
        }
        let mut states = BTreeMap::new();
        for (seq, m) in members
            .iter()
            .flat_map(|(s, ms)| ms.iter().map(move |m| (s, m)))
        {
            let state = self.member_state(&m.collection, &id(*seq));
            if let MemberState::Refused(why) = &state {
                return GroupVerdict::Refused {
                    member: name_of(&m.collection, *seq),
                    why: why.to_string(),
                };
            }
            states.insert(*seq, state);
        }
        // A member kept otherwise than until pruned: the group never counts,
        // and nothing of it is refused — a reader that never learns of that
        // member (it left its writer's listing) waits alike (spec §5.5).
        if let Some((member, keep)) = expiring {
            return GroupVerdict::Kept { member, keep };
        }
        // The members' epochs: all sealed or none, and each epoch's
        // audience admitting every reader any member's epoch lists — taken
        // from the epochs used, never from the seal a writer declares —
        // else a reader could open some members and never others.
        // Audiences only grow, so this waits.
        let sealed: Vec<(Name, u64, Option<Epoch>)> = members
            .iter()
            .flat_map(|(s, ms)| ms.iter().map(move |m| (s, m)))
            .filter_map(|(s, m)| {
                let (_, e) = self.sealing(&m.collection, &id(*s))?;
                Some((m.collection.clone(), *s, e))
            })
            .collect();
        if let (Some(a), Some(b)) = (
            sealed.iter().find(|(_, _, e)| e.is_some()),
            sealed.iter().find(|(_, _, e)| e.is_none()),
        ) {
            return malformed(
                name_of(&b.0, b.1),
                &format!(
                    "its member in {} is sealed and its member in {} is not",
                    a.0, b.0
                ),
            );
        }
        let wanted: BTreeSet<Audience> = sealed
            .iter()
            .filter_map(|(c, _, e)| Some(self.epoch_readers(c, e.as_ref()?)))
            .flatten()
            .collect();
        for (c, s, e) in &sealed {
            let Some(e) = e else { continue };
            let mut audience = self.epoch_readers(c, e);
            audience.push(Audience::Device(e.creator.clone()));
            let out: Vec<Audience> = wanted
                .iter()
                .filter(|r| !collection::admitted(r, &audience))
                .cloned()
                .collect();
            if !out.is_empty() {
                return GroupVerdict::Uncovered {
                    member: name_of(c, *s),
                    epoch: e.clone(),
                    out,
                };
            }
        }
        if states.values().any(|s| *s == MemberState::Unreadable) {
            return GroupVerdict::Unreadable;
        }
        let mut present = 0;
        let mut all_ready = true;
        let mut next = None;
        for s in *gid..gid.saturating_add(u64::from(count)) {
            match states.get(&s) {
                Some(MemberState::Counted | MemberState::Dropped) => present += 1,
                Some(MemberState::Waiting) => {
                    present += 1;
                    let c = &members[&s][0].collection;
                    let coll = &self.colls[c];
                    let is_ready = coll
                        .versions
                        .get(&id(s))
                        .is_some_and(|hv| ready(&coll.waits(c), &coll.applied, &hv.version));
                    if !is_ready {
                        all_ready = false;
                    } else if next.is_none() {
                        next = Some(s);
                    }
                }
                Some(MemberState::GroupRefused) => {
                    present += 1;
                    all_ready = false;
                }
                Some(_) => {}
                None => {
                    // Not held as a member: pruned here, in a collection
                    // of the folder, it is present.
                    if under.iter().any(|c| self.dropped(c, &id(s))) {
                        present += 1;
                    }
                }
            }
        }
        if present < count {
            return GroupVerdict::Incomplete { present, count };
        }
        GroupVerdict::Complete {
            next: next.filter(|_| all_ready),
        }
    }

    /// What its group lets each group member of `c` waiting here — pending,
    /// or held sealed — do ([`Run`]).
    fn gates(&self, c: &Name) -> HashMap<VersionId, Gate> {
        let mut out = HashMap::new();
        let Some(coll) = self.colls.get(c) else {
            return out;
        };
        for key in &coll.txns {
            let Some(members) = self.txns.get(key) else {
                continue;
            };
            let mut verdict = None;
            for (seq, _) in members
                .iter()
                .filter(|(_, ms)| ms.iter().any(|m| m.collection == *c))
            {
                let id = VersionId {
                    writer: key.0.clone(),
                    seq: Seq(*seq),
                };
                let waits = coll.pending.contains(&id)
                    || coll
                        .locked
                        .iter()
                        .any(|l| l.writer == id.writer && l.seq == id.seq.0);
                if !waits {
                    continue;
                }
                let v = verdict.get_or_insert_with(|| self.verdict(key));
                out.insert(id, v.gate(*seq));
            }
        }
        out
    }

    /// Hold `key` as the key of epoch `e` of `c` if it matches the key
    /// check of the held record naming that epoch (spec §9), and open what
    /// it unlocks. Whether it matched. An epoch of folder `c`'s records is
    /// one key for every collection under it that reads in it (spec §6):
    /// it opens what each holds locked. The key of an epoch this device
    /// erased — a collection's or a folder's — is refused, unless a version
    /// sealed in it that no prune covers is held locked here (under the
    /// folder): a writer this device had not heard of wrote in the epoch,
    /// so its erasure was early, and the key is taken again (spec §14).
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
            if self.folders[c].erased.contains(e) {
                // Taken again only for a version sealed in it, under it,
                // that no prune covers and its record in force admits.
                let live = under.iter().any(|x| {
                    let coll = &self.colls[x];
                    coll.locked.iter().any(|l| {
                        let id = VersionId {
                            writer: l.writer.clone(),
                            seq: Seq(l.seq),
                        };
                        l.epoch() == e
                            && coll.pruned(&id).is_none()
                            && coll
                                .members
                                .as_ref()
                                .is_some_and(|m| m.refusal(&id).is_none())
                    })
                });
                if !live {
                    return false;
                }
                tracing::info!(folder = %c, epoch = ?e, "an erased folder epoch's key taken again: a version sealed in it that no prune covers arrived");
                self.folders
                    .get_mut(c)
                    .expect("held above")
                    .erased
                    .remove(e);
                self.store.remove(&erased_folder_name(c, e));
            }
            self.keys.hold(c.clone(), e.clone(), key);
            for x in under {
                self.unlock(&x);
                self.apply_ready(&x, &BTreeSet::new());
            }
            return true;
        }
        let Some(coll) = self.colls.get_mut(c) else {
            return false;
        };
        let Some(named) = coll.line.epochs.get(e) else {
            return false;
        };
        if seal::key_check(&key, c, e) != named.check {
            return false;
        }
        if coll.erased.contains(e) {
            let live = coll.locked.iter().any(|l| {
                let id = VersionId {
                    writer: l.writer.clone(),
                    seq: Seq(l.seq),
                };
                l.epoch() == e
                    && coll.pruned(&id).is_none()
                    && coll
                        .members
                        .as_ref()
                        .is_some_and(|m| m.refusal(&id).is_none())
            });
            if !live {
                return false;
            }
            tracing::info!(collection = %c, epoch = ?e, "an erased epoch's key taken again: a version sealed in it that no prune covers arrived");
            coll.erased.remove(e);
            self.store.remove(&erased_name(c, e));
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
            let version = version_of(&name, &writer, seq, body);
            self.held.insert(name, Held::Version(version.id.clone()));
            self.admit(Arc::new(HeldVersion::new(
                version, op, wire, true, epoch, chunks,
            )));
        }
    }

    /// Drop every version of log-like collection `c` that a known prune
    /// covers (spec §14): out of what the collection holds, its record and
    /// pieces out of the store, its name answered `Pruned` from now on; its
    /// keep and epoch remembered for the leases that held it. Watchers of a
    /// version that was delivered are told. Later versions no longer wait
    /// for it. A version only prunes a copy of this device's key signed
    /// cover ([`Coll::foreign_prunes`]) keeps its bytes in the store. Returns
    /// the names dropped for good, with what each leaves.
    fn drop_pruned(&mut self, c: &Name) -> Vec<(Name, Tomb)> {
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
        if coll.prunes.is_empty() || coll.members.as_ref().is_none_or(|m| !log_like(&m.rule)) {
            return Vec::new();
        }
        coll.mark_pruned();
        let at = coll.at();
        let prunes = coll.prunes.clone();
        let dropped = take_out(coll, |id, _| prunes.iter().any(|p| covers(p, id)));
        watchers.retain(|w| !w.tx.is_closed());
        let mut names = Vec::with_capacity(dropped.len());
        for (id, name, tomb, epoch) in dropped {
            let by = coll.pruned(&id).expect("covered").clone();
            coll.pruned_keeps.insert(id.clone(), (tomb.keep, epoch));
            refused.remove(&name);
            // Only prunes a copy of this device's key signed cover it: its
            // bytes stay, and no tombstone stands for it.
            let kept = coll
                .prunes
                .iter()
                .filter(|p| covers(p, &id))
                .all(|p| coll.foreign_prunes.contains(&p.name));
            if !kept {
                for (n, _) in store.scan_under(&name, 0) {
                    store.remove(&n);
                }
            }
            if at.contains(&id) {
                for w in watchers.iter() {
                    if c.has_prefix(&w.target) {
                        let _ = w.tx.send(Ok(Change::Pruned {
                            collection: c.clone(),
                            id: id.clone(),
                            by: by.clone(),
                        }));
                    }
                }
            }
            tracing::debug!(%name, kept, "dropped: its writer pruned it");
            held.insert(name.clone(), Held::Pruned(by));
            if !kept {
                names.push((name, tomb));
            }
        }
        names
    }

    /// Drop every version of `c` that expired here by this device's clock
    /// (spec §14.1): a log-like collection's versions only. Each goes out
    /// of what the collection holds, its record and pieces out of the
    /// store; a durable tombstone stays, its name answers `Expired` from now
    /// on, later versions no longer wait for it, and watchers it was
    /// delivered to are told. Returns the earliest `Keep::Until` date still
    /// held in `c`.
    fn expire(&mut self, c: &Name) -> Option<Timestamp> {
        let now = (self.clock)();
        let coll = self.colls.get(c)?;
        if coll.members.as_ref().is_none_or(|m| !log_like(&m.rule)) {
            return None;
        }
        let mut cutoffs: HashMap<(Writer, u32), u64> = HashMap::new();
        let mut lastn = |id: &VersionId, n: u32| -> u64 {
            *cutoffs
                .entry((id.writer.clone(), n))
                .or_insert_with(|| lastn_cutoff(coll, &id.writer, n))
        };
        // Which expire, decided before any is taken out.
        let ids: BTreeSet<VersionId> = coll
            .versions
            .values()
            .chain(&coll.waiting)
            .chain(&coll.outsiders)
            .map(|hv| (hv.version.id.clone(), hv.version.keep))
            .chain(coll.locked.iter().map(|l| {
                (
                    VersionId {
                        writer: l.writer.clone(),
                        seq: Seq(l.seq),
                    },
                    l.body.keep,
                )
            }))
            .filter(|(id, keep)| expires(*keep, id, now, |n| lastn(id, n)))
            .map(|(id, _)| id)
            .collect();
        if !ids.is_empty() {
            self.drop_expired(c, |id, _| ids.contains(id));
        }
        let coll = self.colls.get_mut(c)?;
        let marked = coll.mark_gone(now);
        let held = coll
            .versions
            .values()
            .map(|hv| hv.version.keep)
            .chain(coll.locked.iter().map(|l| l.body.keep))
            .filter_map(|k| match k {
                Keep::Until(t) => Some(t),
                _ => None,
            })
            .min();
        let bound = coll
            .listings
            .values()
            .filter_map(|l| l.next_bound(now))
            .min();
        if marked {
            self.apply_ready(c, &BTreeSet::new());
        }
        held.into_iter().chain(bound).min()
    }

    /// Drop version `name` (a log entry, or a piece of one) now if it
    /// expired by this device's clock: checked on every access (spec
    /// §14.1). Whether it is (now or before) dropped as expired.
    fn expire_named(&mut self, name: &Name) -> bool {
        let version = strip_piece(name);
        let (c, id) = match self.held.get(&version) {
            Some(Held::Expired(_)) => return true,
            Some(Held::Version(id)) => match parse_log_name(&version).and_then(|l| l.subject) {
                Some(c) => (c, id.clone()),
                None => return false,
            },
            Some(Held::Locked) => {
                let Some(c) = parse_log_name(&version).and_then(|l| l.subject) else {
                    return false;
                };
                let Some(id) = self.colls.get(&c).and_then(|x| version_id(x, &version)) else {
                    return false;
                };
                (c, id)
            }
            _ => return false,
        };
        let now = (self.clock)();
        let Some(coll) = self.colls.get(&c) else {
            return false;
        };
        if coll.members.as_ref().is_none_or(|m| !log_like(&m.rule)) {
            return false;
        }
        let keep = coll
            .versions
            .get(&id)
            .map(|hv| hv.version.keep)
            .or_else(|| {
                coll.locked
                    .iter()
                    .find(|l| l.name == version)
                    .map(|l| l.body.keep)
            });
        let Some(keep) = keep else { return false };
        if !expires(keep, &id, now, |n| lastn_cutoff(coll, &id.writer, n)) {
            return false;
        }
        self.drop_expired(&c, |x, _| *x == id);
        true
    }

    /// Take the versions of `c` that `gone` picks out as expired: tombstone,
    /// drop, tell (see [`Self::expire`]).
    fn drop_expired(&mut self, c: &Name, gone: impl Fn(&VersionId, Keep) -> bool) {
        let St {
            colls,
            held,
            refused,
            store,
            watchers,
            ..
        } = self;
        let Some(coll) = colls.get_mut(c) else {
            return;
        };
        let at = coll.at();
        let dropped = take_out(coll, gone);
        watchers.retain(|w| !w.tx.is_closed());
        for (id, name, tomb, _) in dropped {
            coll.skipped
                .entry(id.writer.clone())
                .or_default()
                .insert(id.seq.0);
            refused.remove(&name);
            for (n, _) in store.scan_under(&name, 0) {
                store.remove(&n);
            }
            store.insert(expired_name(&name), wire::encode_tomb(&tomb));
            if at.contains(&id) {
                for w in watchers.iter() {
                    if c.has_prefix(&w.target) {
                        let _ = w.tx.send(Ok(Change::Expired {
                            collection: c.clone(),
                            id: id.clone(),
                            keep: tomb.keep,
                        }));
                    }
                }
            }
            tracing::debug!(%name, keep = ?tomb.keep, "dropped: it expired by this device's clock");
            held.insert(name, Held::Expired(tomb));
        }
    }

    /// Take `body`, a node of `c` by `writer` verified here, as the
    /// writer's newest unless one with a higher head was (spec §5.2, §7);
    /// of the same head, the one verified last stands (a writer whose store
    /// came back with entries it had lost lists them again at its head):
    /// from now on, an entry of the writer at or below its head that it does
    /// not list, or lists in a run whose keep bound passed by this device's
    /// clock, is not waited for unless held — a seq never learned included.
    /// The caller expires `c` next, which marks them. Returns the earliest
    /// keep bound of the writer's newest node still ahead, for the sweeper.
    fn listing(&mut self, c: &Name, writer: &Writer, body: &NodeBody) -> Option<Timestamp> {
        let now = (self.clock)();
        let coll = self.colls.get_mut(c)?;
        if coll
            .listings
            .get(writer)
            .is_none_or(|l| l.head <= body.head)
        {
            coll.listings.insert(
                writer.clone(),
                Listing {
                    head: body.head,
                    entries: body.entries.clone(),
                    expiry: body.expiry.clone(),
                },
            );
        }
        coll.listings.get(writer)?.next_bound(now)
    }

    /// Why `c`'s state cannot be read here: its members record names a
    /// merge rule this program does not know (rules are matched by name).
    fn rule_unknown(&self, c: &Name, rules: &MergeRules) -> Option<DataError> {
        let members = self.colls.get(c)?.members.as_ref()?;
        match &members.rule {
            Rule::Merge { function } if rules.get(function).is_none() => {
                Some(DataError::RuleUnknown {
                    collection: c.clone(),
                    rule: function.clone(),
                })
            }
            _ => None,
        }
    }

    /// The merged value of `c` at exactly `at`, and the versions inside it
    /// not counted, from held versions by the same procedure as the live
    /// state ([`Run`]); `None` while some version inside `at` is not held
    /// (or not whole), or `c` has no merge rule this device knows.
    fn value_at(
        &self,
        c: &Name,
        at: &Frontier,
        rules: &MergeRules,
        me: &Writer,
    ) -> Option<(Value, Vec<(VersionId, String)>)> {
        let coll = self.colls.get(c)?;
        let members = coll.members.as_ref()?;
        let Rule::Merge { function } = &members.rule else {
            return None;
        };
        if *at == coll.at() {
            return coll
                .state
                .as_ref()
                .map(|s| (s.value(&coll.excluded), coll.not_counted_list()));
        }
        let mut state = rules.get(function)?.start(c, me);
        let mut versions = coll.versions.clone();
        let mut pending: BTreeSet<VersionId> = versions
            .keys()
            .filter(|id| at.contains(id))
            .cloned()
            .collect();
        let mut skipped = coll.skipped.clone();
        let mut applied = BTreeMap::new();
        let mut kinds = HashMap::new();
        let mut outsiders = coll.outsiders.clone();
        // A group's members inside `at` count as the group does now: all of
        // a complete one, none of a refused one, and none held back while
        // another member does not count ([`St::regroup`]).
        let gates: HashMap<VersionId, Gate> = pending
            .iter()
            .filter_map(|id| {
                let g = versions.get(id)?.version.group?;
                let gate = match self.verdict(&(id.writer.clone(), g.id)) {
                    GroupVerdict::Complete { .. } => Gate::Go,
                    GroupVerdict::Refused { member, why } => {
                        Gate::Stop(Refusal::Group { member, why })
                    }
                    _ => Gate::Wait(None),
                };
                Some((id.clone(), gate))
            })
            .collect();
        let ran = Run {
            members,
            entries: &coll.entries,
            listings: &coll.listings,
            locked: &coll.locked,
            revoked: &coll.revoked,
            by_digest: &coll.by_digest,
            cut_out: &self.cut_out,
            store: &*self.store,
            keys: &self.keys,
            gates: &gates,
            state: Some(&mut *state),
            versions: &mut versions,
            skipped: &mut skipped,
            applied: &mut applied,
            pending: &mut pending,
            kinds: &mut kinds,
            outsiders: &mut outsiders,
            unwhole: &mut BTreeSet::new(),
            out: Vec::new(),
        }
        .run();
        let reached: Frontier = applied
            .iter()
            .map(|(w, s)| VersionId {
                writer: w.clone(),
                seq: Seq(*s),
            })
            .collect();
        if reached != *at {
            return None;
        }
        let mut not_counted = BTreeMap::new();
        for r in ran {
            match r {
                Ran::Applied(id, Counting::NotCounted(why))
                | Ran::Counting(id, Counting::NotCounted(why)) => {
                    not_counted.insert(id, why);
                }
                Ran::Counting(id, Counting::Counted) => {
                    not_counted.remove(&id);
                }
                _ => {}
            }
        }
        let excluded: BTreeSet<VersionId> = coll
            .excluded
            .iter()
            .filter(|id| at.contains(id))
            .cloned()
            .collect();
        for id in &excluded {
            if let Some((_, why)) = coll.group_held.get(id) {
                not_counted.entry(id.clone()).or_insert_with(|| why.clone());
            }
        }
        Some((state.value(&excluded), not_counted.into_iter().collect()))
    }

    /// The devices, besides its writer's, whose versions of `c` held here
    /// are made over the version named `v` (their parents include it): each
    /// applied it, so holds its pieces and serves them under its own name
    /// ([`Inner::packet_for`]). A reader asks them when the writer does not
    /// answer, so a writer serving its pieces to one device only does not
    /// stall what others build over it (spec §13.1). By name.
    fn appliers(&self, c: &Name, v: &Name) -> Vec<Name> {
        let Some(coll) = self.colls.get(c) else {
            return Vec::new();
        };
        let Some(Held::Version(target)) = self.held.get(v) else {
            return Vec::new();
        };
        let writer = parse_log_name(v).map(|l| l.device);
        let devices: BTreeSet<Name> = coll
            .versions
            .values()
            .filter(|hv| {
                hv.version.id.writer != target.writer && hv.version.parents.contains(target)
            })
            .filter_map(|hv| parse_log_name(&hv.version.name).map(|l| l.device))
            .filter(|d| Some(d) != writer.as_ref())
            .collect();
        devices.into_iter().collect()
    }

    /// The versions of merge collection `c` in pieces this device is to
    /// fetch (spec §4.1): pending — admitted and neither applied nor
    /// covered by a checkpoint — not opened, and neither being fetched nor
    /// found whole already. A version in the past of another such version
    /// whose pieces are yet to be found waits for that one's: it may be a
    /// checkpoint covering it (spec §5.2), which opens and applies as soon
    /// as it is whole, and what a checkpoint covers is never fetched. Under
    /// a rule this device does not know, none: it applies nothing.
    fn wanted_pieces(&self, c: &Name) -> Vec<(Name, ChunksBody)> {
        let Some(coll) = self.colls.get(c) else {
            return Vec::new();
        };
        if coll.state.is_none() {
            return Vec::new();
        }
        let unopened: Vec<&HeldVersion> = coll
            .pending
            .iter()
            .filter_map(|id| coll.versions.get(id))
            .filter(|hv| !hv.opened && hv.chunks.is_some())
            .map(|hv| hv.as_ref())
            .collect();
        // In the past of a later unopened version (spec §5.2: its parents
        // and its writer's earlier entries) whose pieces are neither found
        // whole nor found missing yet.
        let later_unopened = |v: &VersionId| {
            unopened.iter().any(|w| {
                w.version.id != *v
                    && !self.walked.contains(&w.version.name)
                    && !self.unfound.contains(&w.version.name)
                    && (w.version.parents.contains(v)
                        || (w.version.id.writer == v.writer && v.seq < w.version.id.seq))
            })
        };
        unopened
            .iter()
            .filter(|hv| {
                !self.fetching.contains(&hv.version.name)
                    && !self.walked.contains(&hv.version.name)
                    && !self.unfound.contains(&hv.version.name)
                    && !later_unopened(&hv.version.id)
            })
            .filter_map(|hv| Some((hv.version.name.clone(), hv.chunks?)))
            .collect()
    }

    /// Every piece of version `v` of `c` was found: a merge version waiting
    /// for them opens and applies once ready.
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
        let window = config.window.max(1);
        let recipient = recipient_key(&keys, &device)?;
        let seal_keys = Keys::new(recipient);
        let clock = Arc::clone(&config.clock);
        let rules = config.rules.clone();
        let contexts = contexts_by_namespace(validator.keyring());
        let own_key = identity
            .signer
            .public_key()
            .map(|pk| public_key_digest(&pk));
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
                durable: 0,
                round: 0,
                round_done: 0,
                flush_wanted: false,
                trees: HashMap::new(),
                roots: HashMap::new(),
                colls: HashMap::new(),
                folders: HashMap::new(),
                held: HashMap::new(),
                peers: HashMap::new(),
                groups: HashMap::new(),
                follows: BTreeSet::new(),
                watchers: Vec::new(),
                refused: HashMap::new(),
                cut_out: HashMap::new(),
                cut_fetching: BTreeSet::new(),
                readmitting: BTreeMap::new(),
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
                walked: BTreeSet::new(),
                unfound: BTreeSet::new(),
                descents: 0,
                txns: HashMap::new(),
                seqs: HashMap::new(),
                equivocal: HashMap::new(),
                rules,
                me: Writer::new(identity.key.clone()),
                quarantine: BTreeSet::new(),
                asks: HashMap::new(),
                answers: Kept::new(ANSWERS_KEPT),
                clock,
                peeks: BTreeSet::new(),
                open: HashMap::new(),
                heads: HashMap::new(),
                seen: HashMap::new(),
                sweep_at: None,
                verified: HashMap::new(),
                suspected: BTreeMap::new(),
                contexts,
                intro: intro::Intros::new(),
            }),
            progress: Notify::new(),
            sweep: Arc::new(Notify::new()),
            commit_wake: Arc::new(Notify::new()),
            committed: Notify::new(),
            slots: Semaphore::new(window),
            verifying: Semaphore::new(ASKS_VERIFYING),
            signatures: AtomicU64::new(0),
            grants_asked: AtomicU64::new(0),
            grants_answered: AtomicU64::new(0),
            started: Instant::now(),
            serving: Mutex::new(None),
            stopped: AtomicBool::new(false),
            own_key,
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
        // Every entry held is judged again by the durable rule against the
        // trust contexts held now (spec §8): a key above its signer may
        // have been revoked while the device was off.
        inner.rejudge(Rejudge::All).await;
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
        // A holder makes itself heard in the groups of the namespaces it
        // holds for, so their owners' devices know to ask it (spec §13),
        // and takes up again what its leases promise.
        for hns in inner.config.hold_for.clone() {
            inner.join(&hns).await?;
            inner.publish(&hns);
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
        // Merge versions in pieces held from before wait for them.
        inner.fetch_wanted(true);
        inner.spawn_sweeper();
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
    /// still sealed), members, hold, lease and prune records, as runs of
    /// seqs per collection log `<D>/32=log/<C>`, and snapshots, under
    /// `<D>/32=log` — that it first verified strictly before
    /// `bound.held_before` (when set) and whose seq is at most
    /// `bound.upto` of its collection (when `upto` is given; a collection
    /// it does not name, and snapshots, are then left out). An entry whose
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
            for (name, held) in &st.held {
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

    /// Drop this device's own copies of the chunks of the large versions
    /// under `name` (a version's name, or a collection), the host's storage
    /// policy (the phone keeps only recent originals), on fresh evidence
    /// that enough other holders keep what stands for them (spec §13.3): at
    /// least the `copies` of this device's hold record of distinct holder
    /// devices it names, each with a live lease holding it, prove to a
    /// `whole` audit ask that they hold it whole. What stands for a log-like
    /// collection's version is the version itself; for a merge collection's,
    /// a checkpoint covering it that this device holds whole (spec §4.1):
    /// the version's pieces are never needed again where the checkpoint is.
    /// While they are asked, this device serves none of the proved
    /// versions' pieces to anyone, so a holder relaying them from this
    /// device proves nothing. The version records and their manifests stay;
    /// a later `get` reads the chunks from the holders. Versions not proved
    /// so stay, each with why ([`Released::kept`]); when none was released,
    /// [`DataError::NotHeld`] says why.
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
        // What to release: the versions in pieces under `name` this device
        // holds whole; and what proves each kept elsewhere (`provings`:
        // a version held whole here, what each proof is checked against,
        // with the named holders whose live leases hold it).
        let (targets, provings, merge, copies) = {
            let st = inner.st.lock();
            let Some(coll) = st.colls.get(&c) else {
                return Err(DataError::Unavailable { name: name.clone() });
            };
            let Some((_, _, hold)) = coll.holds.get(&inner.writer) else {
                return Err(DataError::NotHeld {
                    name: name.clone(),
                    why: format!("this device asked no holder to keep {c}"),
                });
            };
            let live = inner.live_leases(&st, &c);
            let holders = |id: &VersionId| -> Vec<Name> {
                live.iter()
                    .filter(|d| hold.holders.contains(d) && coll.leases[*d].body.holds.contains(id))
                    .cloned()
                    .collect()
            };
            let merge = coll
                .members
                .as_ref()
                .is_some_and(|m| matches!(m.rule, Rule::Merge { .. }));
            // The checkpoints applied here and held whole, with what each
            // covers: applied only once each of their parents was held as
            // the packet it names (spec §5.2), so they stand for exactly
            // what their writers applied. One checked and not applied — its
            // past not held yet, or refused — stands for nothing.
            let checkpoints: Vec<(&HeldVersion, Frontier)> = coll
                .kinds
                .iter()
                .filter(|(id, k)| {
                    **k == OpKind::Checkpoint && coll.applies(id) && inner.keeps(coll, id)
                })
                .filter_map(|(id, _)| coll.versions.get(id))
                .map(|hv| (hv.as_ref(), past_frontier(&hv.version)))
                .collect();
            let mut provings: Vec<(Name, Option<ChunksBody>, Vec<Name>)> = Vec::new();
            let mut targets: Vec<(Name, ChunksBody, Vec<usize>)> = Vec::new();
            for hv in coll.versions.values() {
                let Some(chunks) = hv.chunks else { continue };
                if only.as_ref().is_some_and(|n| *n != hv.version.name)
                    || !inner.store.contains(&hv.version.name)
                    || !inner.pieces_held(&hv.version.name, &chunks)
                {
                    continue;
                }
                let mut by = Vec::new();
                if merge {
                    for (cp, covers) in &checkpoints {
                        if !covers.contains(&hv.version.id) {
                            continue;
                        }
                        let i = match provings.iter().position(|(n, ..)| *n == cp.version.name) {
                            Some(i) => i,
                            None => {
                                provings.push((
                                    cp.version.name.clone(),
                                    cp.chunks,
                                    holders(&cp.version.id),
                                ));
                                provings.len() - 1
                            }
                        };
                        by.push(i);
                    }
                } else {
                    provings.push((
                        hv.version.name.clone(),
                        Some(chunks),
                        holders(&hv.version.id),
                    ));
                    by.push(provings.len() - 1);
                }
                targets.push((hv.version.name.clone(), chunks, by));
            }
            (targets, provings, merge, hold.copies.max(1) as usize)
        };
        let mut out = Released::default();
        if targets.is_empty() {
            return Ok(out);
        }
        // Fresh evidence, with this device's own copies of the proved
        // versions' pieces served to no one meanwhile.
        let proved: Vec<Vec<(Name, Result<(), String>)>> = {
            let _quarantine = Quarantine::new(inner, provings.iter().map(|(v, ..)| v.clone()));
            futures::future::join_all(provings.iter().map(|(v, chunks, holders)| {
                futures::future::join_all(holders.iter().map(move |h| async move {
                    (h.clone(), inner.proves_kept(h, v, chunks.as_ref()).await)
                }))
            }))
            .await
        };
        // Why each proving fell short, if it did.
        let short: Vec<Option<String>> = provings
            .iter()
            .zip(&proved)
            .map(|((v, _, holders), proofs)| {
                let kept = proofs.iter().filter(|(_, p)| p.is_ok()).count();
                if kept >= copies {
                    return None;
                }
                let mut why: Vec<String> = proofs
                    .iter()
                    .map(|(h, p)| match p {
                        Ok(()) => format!("{h} proved it keeps it whole"),
                        Err(e) => e.clone(),
                    })
                    .collect();
                if holders.is_empty() {
                    why.push("no holder the hold record names has a live lease holding it".into());
                }
                Some(format!(
                    "{kept} of the {copies} distinct holders asked for proved they keep {v} \
                     without this device ({})",
                    why.join("; ")
                ))
            })
            .collect();
        for (v, chunks, by) in targets {
            if !by.iter().any(|i| short[*i].is_none()) {
                let why = match (merge, by.is_empty()) {
                    (true, true) => format!(
                        "no checkpoint covering it is held here whole, so none is proved held by \
                         {copies} audited holders; write a checkpoint and hold it"
                    ),
                    (true, false) => format!(
                        "no checkpoint covering it is proved held by {copies} audited holders \
                         ({}); write a checkpoint and hold it",
                        by.iter()
                            .filter_map(|i| short[*i].as_deref())
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                    (false, _) => by
                        .iter()
                        .filter_map(|i| short[*i].clone())
                        .collect::<Vec<_>>()
                        .join("; "),
                };
                out.kept.push((v, why));
                continue;
            }
            out.versions += 1;
            for i in 0..Shape::of(chunks.size).chunks {
                let p = piece_name(&v, PieceKind::Chunk(i));
                if let Some(w) = inner.store.get(&p) {
                    inner.store.remove(&p);
                    out.pieces += 1;
                    out.bytes += w.len() as u64;
                }
            }
        }
        if out.versions == 0 {
            let why = out
                .kept
                .iter()
                .map(|(v, why)| format!("{v}: {why}"))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(DataError::NotHeld {
                name: name.clone(),
                why,
            });
        }
        Ok(out)
    }
}

/// A descent under way ([`Inner::refresh`]): counted in [`St::descents`]
/// while it lasts, whether it ends or is dropped, so the pieces it defers
/// are fetched once no descent is under way.
struct Descending<'a> {
    st: &'a Mutex<St>,
    ended: bool,
}

impl<'a> Descending<'a> {
    fn new(st: &'a Mutex<St>) -> Self {
        st.lock().descents += 1;
        Self { st, ended: false }
    }

    /// End it; whether it was the last descent under way.
    fn end(mut self) -> bool {
        self.ended = true;
        let mut st = self.st.lock();
        st.descents -= 1;
        st.descents == 0
    }
}

impl Drop for Descending<'_> {
    fn drop(&mut self) {
        if !self.ended {
            self.st.lock().descents -= 1;
        }
    }
}

/// Own versions whose pieces this device serves to no one while a release
/// asks their holders for proofs; served again when dropped.
struct Quarantine<'a> {
    inner: &'a Inner,
    versions: Vec<Name>,
}

impl<'a> Quarantine<'a> {
    fn new(inner: &'a Inner, versions: impl IntoIterator<Item = Name>) -> Self {
        let versions: Vec<Name> = versions.into_iter().collect();
        inner.st.lock().quarantine.extend(versions.iter().cloned());
        Quarantine { inner, versions }
    }
}

impl Drop for Quarantine<'_> {
    fn drop(&mut self) {
        let mut st = self.inner.st.lock();
        for v in &self.versions {
            st.quarantine.remove(v);
        }
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

/// A walked marker's value: the head walked (8 octets, big-endian), then
/// the `Name` TLV of each name it was walked toward — what this device
/// followed or peeked at in the namespace then, whose folder records above
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

/// Where the store keeps a tombstone for each own version this device
/// pruned (`/localhost/ndn-data/pruned/<log entry name>`, its value a
/// [`Tomb`]): the version is gone, and its summary keeps listing it by its
/// keep, as the log never changes.
fn tomb_prefix() -> Name {
    "/localhost/ndn-data/pruned".parse().expect("a valid name")
}

fn tomb_name(entry: &Name) -> Name {
    under(&tomb_prefix(), entry)
}

fn untomb(name: &Name) -> Option<Name> {
    over(&tomb_prefix(), name)
}

/// Where the store keeps a tombstone for each version this device dropped
/// as expired by its clock (`/localhost/ndn-data/expired/<log entry
/// name>`, its value a [`Tomb`]): it answers `Expired` and never stores the
/// version again, also after a restart (spec §14.1); an own version's
/// summary keeps listing it by its keep.
fn expired_prefix() -> Name {
    "/localhost/ndn-data/expired".parse().expect("a valid name")
}

fn expired_name(entry: &Name) -> Name {
    under(&expired_prefix(), entry)
}

fn unexpired(name: &Name) -> Option<Name> {
    over(&expired_prefix(), name)
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

/// Where the store keeps, for each one-key collection this device writes,
/// the seq and batch delay of its newest version
/// (`/localhost/ndn-data/batched/<collection>`, 16 octets: the seq and the
/// delay in milliseconds, big-endian), written with the version: the
/// freshness its head states at that seq is the same after a restart
/// (spec §5.3, §4.2).
fn batched_prefix() -> Name {
    "/localhost/ndn-data/batched".parse().expect("a valid name")
}

fn batched_name(c: &Name) -> Name {
    under(&batched_prefix(), c)
}

fn encode_batched(seq: u64, batch: Duration) -> Bytes {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(batch.as_millis() as u64).to_be_bytes());
    Bytes::from(out)
}

fn decode_batched(value: &[u8]) -> Option<(u64, Duration)> {
    let seq = u64::from_be_bytes(value.get(..8)?.try_into().ok()?);
    let ms = u64::from_be_bytes(value.get(8..16)?.try_into().ok()?);
    Some((seq, Duration::from_millis(ms)))
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

/// Where the store keeps a marker for each epoch whose key this device
/// destroyed (`/localhost/ndn-data/erased/<epoch>`), so a restart refuses
/// the key if granted again (spec §14).
fn erased_prefix() -> Name {
    "/localhost/ndn-data/erased".parse().expect("a valid name")
}

fn erased_name(c: &Name, e: &Epoch) -> Name {
    erased_prefix().append_component(ndn_packet::NameComponent::generic(wire::encode_epoch_of(
        c, e,
    )))
}

fn parse_erased_name(name: &Name) -> Option<(Name, Epoch)> {
    let prefix = erased_prefix();
    if !name.has_prefix(&prefix) || name.len() != prefix.len() + 1 {
        return None;
    }
    wire::decode_epoch_of(name.components()[prefix.len()].value.clone())
}

/// Where the store keeps a marker for each epoch of a folder's records
/// whose key this device destroyed
/// (`/localhost/ndn-data/erased-folder/<epoch>`): apart from collections'
/// markers, since a name may be both a folder and a collection (spec §6.1,
/// §14).
fn erased_folder_prefix() -> Name {
    "/localhost/ndn-data/erased-folder"
        .parse()
        .expect("a valid name")
}

fn erased_folder_name(f: &Name, e: &Epoch) -> Name {
    erased_folder_prefix().append_component(ndn_packet::NameComponent::generic(
        wire::encode_epoch_of(f, e),
    ))
}

fn parse_erased_folder_name(name: &Name) -> Option<(Name, Epoch)> {
    let prefix = erased_folder_prefix();
    if !name.has_prefix(&prefix) || name.len() != prefix.len() + 1 {
        return None;
    }
    wire::decode_epoch_of(name.components()[prefix.len()].value.clone())
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
    /// them as before; the epochs it erased come back first, so their keys
    /// stay refused; and any piece or record of a version a prune covers
    /// (stored by a walk that was under way when the prune arrived) is
    /// dropped.
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
        let mut tombs = Vec::new();
        let mut expired = Vec::new();
        let mut heads = Vec::new();
        let mut erased = Vec::new();
        let mut erased_folders = Vec::new();
        let mut pieces = Vec::new();
        let mut seen: HashMap<Name, (Timestamp, Option<[u8; 32]>)> = HashMap::new();
        let mut written: HashMap<Name, Bytes> = HashMap::new();
        let mut suspected = BTreeMap::new();
        let mut untrusted: HashMap<Name, String> = HashMap::new();
        let mut batched = Vec::new();
        for (name, wire) in self.store.scan_under(&Name::root(), 0) {
            if let Some(entry) = over(&verified_prefix(), &name) {
                match decode_verified(&wire) {
                    Some(v) => {
                        seen.insert(entry, v);
                    }
                    None => self.store.remove(&name),
                }
                continue;
            }
            if let Some(c) = over(&batched_prefix(), &name) {
                if let Some((seq, batch)) = decode_batched(&wire) {
                    batched.push((c, seq, batch));
                }
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
            if let Some(entry) = untomb(&name) {
                if let Some(l) = parse_log_name(&entry)
                    && l.device == self.device
                    && let Some(c) = l.subject
                {
                    tombs.push((c, l.seq, wire::decode_tomb(wire)));
                }
                continue;
            }
            if let Some(entry) = unexpired(&name) {
                if let Some(l) = parse_log_name(&entry)
                    && let Some(c) = l.subject.clone()
                    && let Some(tomb) = wire::decode_tomb(wire)
                {
                    expired.push((entry, c, l, tomb));
                }
                continue;
            }
            if let Some(ce) = parse_erased_name(&name) {
                erased.push(ce);
                continue;
            }
            if let Some(fe) = parse_erased_folder_name(&name) {
                erased_folders.push(fe);
                continue;
            }
            if let Some((d, c)) = parse_head_prefix(&name) {
                // Its signer, the one key it was verified as.
                let head = Data::decode(wire.clone()).ok().and_then(|data| {
                    let (hd, hc, s) = parse_head_name(&data.name)?;
                    let key = data.sig_info()?.key_locator_name()?;
                    let body = wire::decode_head(data.content()?.clone()).ok()?;
                    (hd == d && hc == c && body.seq == s && body.collection == c)
                        .then(|| (Writer::new((*key).clone()), body))
                });
                if let Some((key, body)) = head {
                    heads.push((d, c, key, body, wire));
                }
                continue;
            }
            if let Some(w) = parse_walked(&name, &wire) {
                walked.push(w);
                continue;
            }
            let Some(parsed) = parse_log_name(&name) else {
                match parse_piece_name(&name) {
                    Some(p) => pieces.push((name, p.version)),
                    None => roots.extend(kept_root(&name, &wire)),
                }
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
            // Own by name for now; by what it wrote once all is read.
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
        let wrote = |entry: &Name| legacy || written.contains_key(entry);
        // Members records first, by revision; then the other records (hold
        // records, then leases, then prunes), so that what they say is known
        // as the versions come back; then versions and snapshots.
        entries.sort_by_key(|(_, _, record, _, seq, _)| match record {
            Record::Members(b) => (0, b.revision, *seq),
            Record::Hold(_) => (1, 0, *seq),
            Record::Lease(_) => (1, 1, *seq),
            Record::Prune(_) => (1, 2, *seq),
            Record::Intro(_) => (1, 3, *seq),
            Record::Version(_) | Record::Snapshot(_) => (2, 0, *seq),
        });
        let rest = entries.split_off(
            entries.partition_point(|(_, _, record, ..)| matches!(record, Record::Members(_))),
        );
        let mut st = self.st.lock();
        // What the trust context refused for its chain stays withdrawn
        // until judged again ([`Self::rejudge`]); what a held trust context
        // revokes outside its cut stays refused across a restart (spec §8):
        // records are not taken, versions held as refused.
        for (name, wire, _, writer, _, _) in entries.iter().chain(&rest) {
            let digest = wire::implicit_digest(wire);
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
                        digest,
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
        for (c, e) in erased {
            st.colls.entry(c).or_default().erased.insert(e);
        }
        for (f, e) in erased_folders {
            st.folders.entry(f).or_default().erased.insert(e);
        }
        // What expired here comes back first, so none of it is taken again.
        for (entry, c, l, tomb) in expired {
            let writer = Writer::new(tomb.writer.clone());
            if l.device == self.device && wrote(&entry) {
                st.head = st.head.max(l.seq);
                let ns = namespace_of(&c).expect("a log entry's collection has a namespace");
                st.trees
                    .entry(ns.clone())
                    .or_insert_with(|| Tree::new(ns))
                    .add(
                        &c,
                        l.seq,
                        Kind::Version(Retain {
                            keep: tomb.keep,
                            dated: tomb.first,
                        }),
                    );
            }
            let coll = st.colls.entry(c).or_default();
            coll.entries
                .entry(writer.clone())
                .or_default()
                .insert(l.seq);
            coll.skipped.entry(writer).or_default().insert(l.seq);
            for (n, _) in self.store.scan_under(&entry, 0) {
                self.store.remove(&n);
            }
            st.held.insert(entry, Held::Expired(tomb));
        }
        // An own entry moves the log head, refused or not: this device
        // signed that seq. (In a store kept before own entries were
        // recorded, a refused one does not: it may be a copy's.)
        let take_all = |st: &mut St, list: Vec<(Name, Bytes, Record, Writer, u64, bool)>| {
            for (name, wire, record, writer, seq, mine) in list {
                if mine && !(legacy && st.cut_out.contains_key(&name)) {
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
        for (c, seq, tomb) in tombs {
            if !wrote(&log_name(&self.device, Some(&c), seq)) {
                continue;
            }
            st.head = st.head.max(seq);
            let ns = namespace_of(&c).expect("a log entry's collection has a namespace");
            // A tombstone an earlier revision kept empty lists its version
            // whatever its keep, as that revision did.
            let retain = tomb.map_or(Retain::ALWAYS, |t| Retain {
                keep: t.keep,
                dated: t.first,
            });
            st.trees
                .entry(ns.clone())
                .or_insert_with(|| Tree::new(ns))
                .add(&c, seq, Kind::Version(retain));
            let coll = st.colls.entry(c).or_default();
            coll.entries
                .entry(self.writer.clone())
                .or_default()
                .insert(seq);
            coll.mark_pruned();
        }
        // The newest head verified of each other device's one-key
        // collection, by its key, so a rolled-back one is still refused;
        // this device's own, so the same head is served again while its
        // node is unchanged.
        for (d, c, key, body, wire) in heads {
            if d == self.device {
                st.colls
                    .entry(c.clone())
                    .or_default()
                    .batches
                    .insert(body.seq, Duration::from_millis(body.freshness));
                st.heads.insert(
                    c,
                    SignedHead {
                        seq: body.seq,
                        digest: body.digest,
                        wire,
                    },
                );
            } else {
                st.seen.insert(
                    (c, key),
                    SeenHead {
                        seq: body.seq,
                        this_run: false,
                        checked: None,
                        delivered: None,
                    },
                );
            }
        }
        // The batch delay of the newest own version of each one-key
        // collection, stored with it: its head states it again.
        for (c, seq, batch) in batched {
            if seq <= st.head {
                st.colls.entry(c).or_default().batches.insert(seq, batch);
            }
        }
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
        // What a prune covers that the store still keeps: pieces a walk
        // stored after the prune dropped their version, and their records.
        for (name, version) in pieces {
            if pruned_name(&st, &version).is_some() {
                self.store.remove(&name);
            }
        }
        let pruned: Vec<Name> = st
            .held
            .iter()
            .filter(|(_, h)| matches!(h, Held::Pruned(_)))
            .map(|(n, _)| n.clone())
            .collect();
        for name in pruned {
            for (n, _) in self.store.scan_under(&name, 0) {
                self.store.remove(&n);
            }
        }
        // What expired while the device was off.
        let colls: Vec<Name> = st.colls.keys().cloned().collect();
        for c in colls {
            st.expire(&c);
        }
        // A group's reader dropped in the log re-read is history: the
        // records that moved its collections on are held too.
        // What the held records and prunes owe now is owed again, whatever
        // was owed when the device stopped (spec §6.1, §14).
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
                    members: BTreeSet::new(),
                    busy: HashMap::new(),
                    confirmed: None,
                    announced: local_seq,
                },
            );
            local_seq
        };
        let group = sync_group(ns);
        self.sync
            .register_prefix(&group)
            .await
            .map_err(|e| local(format!("cannot receive {group}: {e}")))?;
        let cfg = SvsConfig {
            // The group's counter only says "moved": it starts above every
            // announcement an earlier run made ([`announced_name`]) and
            // every durable entry of the log.
            local_seq,
            ..self.config.svs.clone()
        };
        let Some(mut handle) = self.svs.join(group.clone(), cfg).await else {
            return Err(local(format!("the sync driver did not join {group}")));
        };
        let pending = {
            let mut st = self.st.lock();
            let g = st.groups.get_mut(ns).expect("inserted above");
            g.tx = Some(handle.tx.clone());
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

    /// The namespaces this device follows (has joined the group of) that
    /// `device` may write into: its own, and those of whose collections or
    /// folders a members record held lists a writer of `device`'s namespace.
    fn written_by(&self, st: &St, device: &Name) -> BTreeSet<Name> {
        let dns = self.namespace_of_name(device);
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
    /// `c`'s own, and every namespace held here that its members record —
    /// its collection's or its folder's (spec §6) — names among the writers
    /// or readers (a group reader by the namespace of its collection).
    fn groups_of(&self, st: &St, c: &Name) -> Vec<Name> {
        let own = namespace_of(c).expect("a collection has a namespace");
        let mut out = vec![own];
        let records = [
            st.colls.get(c).and_then(|coll| coll.members.as_ref()),
            st.folders.get(c).and_then(|f| f.members.as_ref()),
        ];
        let named = records.into_iter().flatten().flat_map(|m| {
            m.writers
                .iter()
                .cloned()
                .chain(m.readers.iter().map(|a| match a {
                    Audience::Person(n) | Audience::Device(n) => n.clone(),
                    Audience::Group(g) => namespace_of(g).unwrap_or_else(|| g.clone()),
                }))
        });
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
                        (Owed::Merge, Resolve::Epoch)
                        | (Owed::Group | Owed::Folder | Owed::Erase, _) => true,
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
            let mut pause = REFRESH_PAUSE;
            let mut tries = 0;
            loop {
                let ok = inner.refresh(&ns, &device).await;
                // Again now; again later; or done.
                let next: Option<bool> = {
                    let mut st = inner.st.lock();
                    // A device whose announced change was not taken in full
                    // (not reached now: offline, restarted with its routes
                    // not yet back, a holder away) is asked again, later:
                    // its group counter will not move again for what it
                    // already announced, so nothing else would ask (spec
                    // §12); and a member of a group held here waits for it
                    // (spec §5.5).
                    let waits = !ok && tries < REFRESH_TRIES;
                    match st.groups.get_mut(&ns) {
                        None => None,
                        Some(g) => match g.busy.get_mut(&device) {
                            Some(again) if *again => {
                                *again = false;
                                Some(false)
                            }
                            Some(_) if waits => Some(true),
                            _ => {
                                g.busy.remove(&device);
                                if ok && g.busy.is_empty() {
                                    g.confirmed = Some(Instant::now());
                                }
                                None
                            }
                        },
                    }
                };
                match next {
                    None => break,
                    Some(false) => {}
                    Some(true) => {
                        tries += 1;
                        rt::sleep(pause).await;
                        pause = (pause * 2).min(REFRESH_PAUSE_MAX);
                    }
                }
            }
            inner.progress.notify_waiters();
            if !inner.st.lock().holding.is_empty() {
                inner.renew().await;
            }
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
    async fn commit_rounds(&self) {
        let mut pause = COMMIT_RETRY;
        loop {
            let (target, round, announce) = {
                let mut st = self.st.lock();
                let mut announce = Vec::new();
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
            match self.flush().await {
                Ok(()) => {
                    {
                        let mut st = self.st.lock();
                        st.durable = st.durable.max(target);
                        st.round_done = st.round_done.max(round);
                    }
                    self.committed.notify_waiters();
                    self.progress.notify_waiters();
                    for (ns, tx) in announce {
                        let _ = tx.send((sync_group(&ns), None)).await;
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
        // A revoked key's summaries are refused: what its cut accepts here
        // is fetched by name (spec §8).
        if new {
            self.fetch_cut_runs();
        }
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
    /// governing it ([`Self::ended`]): what it holds is not taken anyway.
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
                    .is_none_or(|p| !walked(p))
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
        let all = futures::future::join_all(missing.iter().map(|d| self.refresh(ns, d)));
        let _ = rt::timeout(self.config.first_look, all).await;
        self.not_walked(&self.st.lock(), ns, &relevant, &covers)
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

    /// Refresh in the background every device known to write into `ns`;
    /// ask again for what a trust context re-admits, or a revocation cut
    /// accepts, that was not to be had before (spec §8).
    fn refresh_group(self: &Arc<Self>, ns: &Name) {
        let devices = self.known_for(&self.st.lock(), ns);
        for d in devices {
            self.schedule(ns.clone(), d);
        }
        self.retry_readmissions();
        self.fetch_cut_runs();
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
    /// key revoked without a cut is refused unverified.
    async fn verify(&self, data: &Data) -> Result<Writer, Refusal> {
        let key = data
            .sig_info()
            .and_then(|s| s.key_locator_name())
            .ok_or(Refusal::BadSignature)?;
        match self.validator.validate_durable(data).await {
            ValidationResult::Valid(safe)
                if !matches!(safe.trust_path(), TrustPath::DigestSha256) =>
            {
                Ok(Writer::new((*key).clone()))
            }
            // The signing key itself (not an issuer above it) is revoked.
            ValidationResult::Invalid(TrustError::Revoked { name, .. })
                if name
                    .parse::<Name>()
                    .is_ok_and(|n| key_name_of(&n) == key_name_of(&key)) =>
            {
                let writer = Writer::new((*key).clone());
                let ctx = self.validator.keyring().context_for(&data.name);
                tracing::debug!(name = %data.name, key = %key, "refused: its key is revoked and the cut does not accept it");
                Err(Refusal::OutsideCut(revocation_cut_for(
                    &ctx,
                    &writer,
                    &log_prefix(&data.name),
                )))
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
            .validator
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
        // The pieces of merge versions it brings are fetched once it took
        // everything it lists: a checkpoint among them may cover the others
        // (spec §5.2), and what it covers is never fetched.
        let descending = Descending::new(&self.st);
        let head = body.head;
        // What the descent goes toward: what is followed or peeked at in
        // `ns` as it starts.
        let toward: BTreeSet<Name> = {
            let st = self.st.lock();
            st.follows
                .iter()
                .chain(&st.peeks)
                .filter(|t| namespace_of(t).as_ref() == Some(ns))
                .cloned()
                .collect()
        };
        let whole = self.descend(device, ns, &writer, body).await;
        if descending.end() {
            self.fetch_wanted(true);
        }
        if !whole {
            return false;
        }
        let mut st = self.st.lock();
        let peer = st.peers.entry(key).or_default();
        peer.root = Some(digest);
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
                // A collection peeked at: its records only (spec §5.3).
                let peeked = !inside && st.peeks.contains(&subject);
                if body.page.is_none() && (inside || peeked) {
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
                    if inside {
                        versions.extend(seqs_of(&body.entries));
                    }
                    // What the writer's newest node no longer lists, or
                    // lists with a keep bound passed, is not waited for, and
                    // what a newer entry ended is dropped.
                    let bound = st.listing(&subject, writer, &body);
                    st.expire(&subject);
                    if let Some(t) = bound {
                        self.arm_sweep(&mut st, Keep::Until(t));
                    }
                    // Learned entries may make held versions ready.
                    st.apply_ready(&subject, &BTreeSet::new());
                    // What the writer's node lists, or does not, may settle
                    // its groups in this folder or under it (spec §5.5).
                    st.regroup_under(writer, &folder_of(&subject));
                    st.regroup_under(writer, &subject);
                } else if body.page.is_none()
                    && st.toward(&subject)
                    && wire::check_collection_name(&subject).is_ok()
                {
                    // A name above what is followed or peeked at: its
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
                let now = (st.clock)();
                let coll = st.colls.get(&subject);
                versions
                    .into_iter()
                    .filter(|seq| {
                        let id = VersionId {
                            writer: writer.clone(),
                            seq: Seq(*seq),
                        };
                        // Neither pruned nor shown by the writer's newest
                        // node to have expired: a holder no longer has it.
                        coll.is_none_or(|c| {
                            c.pruned(&id).is_none()
                                && c.listings.get(writer).is_none_or(|l| !l.gone(*seq, now))
                        })
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
                // is kept for the next descent. Asked for by the digest its
                // parent lists: no cache answers with another packet of the
                // name (a writer whose store came back with entries it had
                // lost signs a node of the same head anew).
                let exact = name.clone().append_implicit_digest(digest);
                let data = self.fetch(exact, false).await?;
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

    /// Fetch, verify and take one log entry — by its name, else from each
    /// holder of a live lease on its collection ([`Self::fetch_entry`]);
    /// whether it is now held or refused. The log of a device whose key is
    /// suspected here is not fetched ([`Device::suspect`]).
    async fn take_fetched(self: &Arc<Self>, name: Name) -> bool {
        if parse_log_name(&name).is_some_and(|l| self.suspects_device(&self.st.lock(), &l.device)) {
            tracing::debug!(%name, "not fetched: its device's key is suspected here");
            return false;
        }
        let Some(data) = self.fetch_entry(&name, None).await else {
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
    /// another device (checked before the chain walk), a record that does
    /// not decode or is about another collection — is refused as a packet
    /// and nothing is kept against the name: whoever answers an Interest can
    /// make such a packet, and the genuine copy may still come from another
    /// source. Only what the genuine writer signed is decided against the
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
        let Some(record) = data
            .content()
            .and_then(|c| wire::decode_record(c.clone()).ok())
            .filter(|r| r.subject() == parsed.subject)
        else {
            return Err(Refusal::BadSignature);
        };
        // A lease names a holder a missing member of a group may be fetched
        // from.
        let leased = match &record {
            Record::Lease(b) => Some(b.collection.clone()),
            _ => None,
        };
        let (chase, fetch, withdrawn, again) = {
            let mut st = self.st.lock();
            let members = matches!(record, Record::Members(_));
            let key = key_name_of(writer.key());
            let fetch = self.take(
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
            // A merge version in pieces waits for them: fetched now, unless
            // a descent is under way — it fetches them once it took all it
            // lists, a checkpoint among them covering what it covers.
            let wanted = match (&parsed.subject, st.descents) {
                (Some(c), 0) => st.wanted_pieces(c),
                _ => Vec::new(),
            };
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
            let fetch: Vec<(Name, ChunksBody)> = fetch.into_iter().chain(wanted).collect();
            // Members of groups held here wait for others: what every
            // device writing into the namespace lists is looked at again,
            // now that a holder may serve what their writers no longer do.
            let again = leased
                .filter(|c| {
                    // A member waits in the folder: the one missing may be
                    // in the leased collection.
                    let folder = folder_of(c);
                    st.colls
                        .iter()
                        .any(|(x, k)| folder_of(x) == folder && !k.group_waits.is_empty())
                })
                .and_then(|c| namespace_of(&c))
                .map(|ns| {
                    let devices = self.known_for(&st, &ns);
                    (ns, devices)
                });
            (chase, fetch, (wake && withdrawn).then_some(key), again)
        };
        for c in chase {
            self.chase_keys(&c);
        }
        for (v, chunks) in fetch {
            self.spawn_pieces(v, chunks);
        }
        if let Some((ns, devices)) = again {
            for d in devices {
                self.schedule(ns.clone(), d);
            }
        }
        // Its key verifies again: what was withdrawn of it for its chain
        // may verify too (a new certificate of the key).
        if let Some(key) = withdrawn {
            let inner = Arc::clone(self);
            rt::spawn(async move {
                inner.rejudge(Rejudge::Withdrawn(Some(key))).await;
            });
        }
        self.settle().await;
        Ok(())
    }

    /// Ask, in the background, for every epoch key that a locked version of
    /// `c` needs, that is not held or being asked for, and that this device
    /// may hold ([`Self::may_hold`]).
    fn chase_keys(self: &Arc<Self>, c: &Name) {
        let asks: BTreeSet<(Name, Epoch)> = {
            let st = self.st.lock();
            let Some(coll) = st.colls.get(c) else { return };
            if coll.locked.is_empty() {
                return;
            }
            coll.locked
                .iter()
                .map(|l| l.epoch().clone())
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
    /// and snapshots are stored now; members, hold, lease and prune records
    /// once accepted (owner-signed, a holder's newest lease answering a hold
    /// record that names it, a prune of the signer's own writes); others'
    /// versions once applied — or now, when this device holds their log
    /// collection for its owner and the accepted hold record asks for them
    /// (spec §13.2). A version a known prune covers is dropped unseen.
    /// Returns a large version whose pieces this device, holding its
    /// collection, is to fetch.
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
                    collection: body.collection.clone(),
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
        // A key's log is one sequence across its collections and entry
        // kinds (spec §4): another entry at a seq it used is equivocation.
        // An entry the trust context refuses is a thief's (spec §8.1).
        let second =
            !st.cut_out.contains_key(&name) && st.note_seq(&name, &writer, parsed.seq, &record);
        if let (Record::Version(_), Some(c)) = (&record, &parsed.subject)
            && let Some(p) = st.colls.get(c).and_then(|x| x.pruned(&id)).cloned()
        {
            tracing::debug!(%name, "not taken: its writer pruned it");
            st.held.insert(name, Held::Pruned(p));
            return None;
        }
        // A holder keeps exactly what the accepted hold record asks of a
        // collection, whatever its rule: versions the record in force
        // admits, inside the record's frontier (spec §13.2).
        let keeps = parsed.subject.as_ref().is_some_and(|c| {
            let Some(h) = st.holding.get(c) else {
                return false;
            };
            st.colls
                .get(c)
                .and_then(|x| x.members.as_ref())
                .is_some_and(|m| m.refusal(&id).is_none() && h.at.contains(&id))
        });
        // How a log-like collection lists a version by its keep (spec §7).
        let retain = match (&record, &parsed.subject) {
            (Record::Version(body), Some(c))
                if st
                    .colls
                    .get(c)
                    .and_then(|x| x.members.as_ref())
                    .is_some_and(|m| log_like(&m.rule)) =>
            {
                Some(Retain {
                    keep: body.keep,
                    dated: body.dated,
                })
            }
            _ => None,
        };
        if let Some(c) = &parsed.subject {
            if mine {
                let ns = namespace_of(c).expect("a log entry's collection has a namespace");
                let kind = match record {
                    Record::Version(_) => Kind::Version(retain.unwrap_or(Retain::ALWAYS)),
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
        // A version of a log-like collection that expired here by this
        // device's clock is not taken, nor stored (spec §14.1).
        if let (Record::Version(body), Some(c), Some(r)) = (&record, &parsed.subject, retain)
            && let Some(coll) = st.colls.get(c)
            && expires(r.keep, &id, (st.clock)(), |n| {
                lastn_cutoff(coll, &id.writer, n)
            })
        {
            // A sealed payload is not opened to drop it: whether it is a
            // block, and its last entry's date, stay unknown.
            let last = body.sealed.is_none().then(|| {
                body.block
                    .as_ref()
                    .and_then(|b| b.last())
                    .map_or(body.dated, |e| {
                        Timestamp(body.dated.0.saturating_add(e.offset))
                    })
            });
            let tomb = Tomb {
                writer: writer.key().clone(),
                keep: r.keep,
                first: body.dated,
                last,
            };
            tracing::debug!(%name, "not taken: it expired by this device's clock");
            let coll = st.colls.get_mut(c).expect("held above");
            coll.entries
                .entry(writer.clone())
                .or_default()
                .insert(parsed.seq);
            coll.skipped
                .entry(writer.clone())
                .or_default()
                .insert(parsed.seq);
            for (n, _) in self.store.scan_under(&name, 0) {
                self.store.remove(&n);
            }
            self.store
                .insert(expired_name(&name), wire::encode_tomb(&tomb));
            st.held.insert(name, Held::Expired(tomb));
            // A member of a group that expired: its keep, which no group
            // member may have, refuses its group (spec §5.5).
            if let Some(g) = body.group {
                st.note_member(c, &id, g, r.keep);
                st.apply_ready(c, &BTreeSet::new());
            }
            return None;
        }
        if mine
            || matches!(record, Record::Snapshot(_))
            || (keeps && matches!(record, Record::Version(_)))
        {
            self.store.insert(name.clone(), wire.clone());
        }
        // A record a revocation refuses is held as refused and not taken
        // (a version is admitted as refused, [`St::admit_one`]).
        let digest = wire::implicit_digest(&wire);
        if st.cut_out.contains_key(&name) && !matches!(record, Record::Version(_)) {
            st.held.insert(name, Held::Record { writer, digest });
            return None;
        }
        match record {
            Record::Members(body) => {
                st.held.insert(
                    name.clone(),
                    Held::Record {
                        writer: writer.clone(),
                        digest,
                    },
                );
                let c = body.collection.clone();
                if owner_signed(self.validator.keyring(), &name, &c, &writer) {
                    self.store.insert(name.clone(), wire);
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
                // Under a folder in force with no record of its own, it is
                // read under the folder's (spec §6).
                st.ensure(&c, &self.config.rules, self.me());
                // Of a revoked key, its entries outside its cut never apply:
                // this version's and its parents' (spec §5.2, §8).
                let writers: Vec<Writer> = std::iter::once(writer.clone())
                    .chain(body.parents.iter().map(|(y, _)| y.clone()))
                    .collect();
                self.note_revoked_in(st, &c, writers);
                let seq = parsed.seq;
                let keep = body.keep;
                let sealed = body.sealed.is_some();
                let epoch = body.sealed.as_ref().map(|s| s.epoch.clone());
                let group = body.group;
                if let Some(g) = group {
                    st.note_member(&c, &id, g, keep);
                }
                let fetch = keeps
                    .then(|| body.chunks.map(|ch| (name.clone(), ch)))
                    .flatten();
                if let Some(s) = body.sealed.clone() {
                    let Some(key) = st.keys.key(&c, &s.epoch) else {
                        st.held.insert(name.clone(), Held::Locked);
                        let coll = st.colls.entry(c.clone()).or_default();
                        coll.by_digest.insert(digest, id.clone());
                        coll.locked.push(Locked {
                            name,
                            wire,
                            writer,
                            seq,
                            body,
                        });
                        if group.is_some() {
                            // Its group is not readable here, until it opens.
                            st.apply_ready(&c, &BTreeSet::new());
                        }
                        if second {
                            st.regroup_seq(&id.writer, seq);
                        }
                        return fetch;
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
                            if group.is_some() {
                                // Its group is refused with it.
                                st.apply_ready(&c, &BTreeSet::new());
                            }
                            return None;
                        };
                        open_into(&mut body, opened);
                    }
                }
                let op = body.op.clone();
                let chunks = body.chunks;
                let version = version_of(&name, &writer, seq, body);
                st.held
                    .insert(name.clone(), Held::Version(version.id.clone()));
                let in_folder_epoch = epoch
                    .as_ref()
                    .is_some_and(|e| st.seal_subject(&c, e).folder);
                st.admit(Arc::new(HeldVersion::new(
                    version, op, wire, sealed, epoch, chunks,
                )));
                if second {
                    st.regroup_seq(&id.writer, seq);
                }
                // A writer's version in a newer epoch may be what a pending
                // erasure waited for: of the collection's own epochs, or of
                // the folder's it is sealed in.
                if st.colls.get(&c).is_some_and(|x| !x.pruned_keeps.is_empty()) {
                    self.erase(st, &c);
                } else if in_folder_epoch {
                    self.erase_folders(st, &c);
                }
                // A newer version may end older ones' last N (spec §14.1).
                if matches!(keep, Keep::LastN(_)) {
                    st.expire(&c);
                }
                self.arm_sweep(st, keep);
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
                st.held.insert(
                    name.clone(),
                    Held::Record {
                        writer: writer.clone(),
                        digest,
                    },
                );
                let c = body.collection.clone();
                if !owner_signed(self.validator.keyring(), &name, &c, &writer) {
                    tracing::debug!(collection = %c, signer = ?writer, "hold record not signed by a device of the collection's namespace; ignored");
                    return None;
                }
                let coll = st.colls.entry(c).or_default();
                if coll
                    .holds
                    .get(&writer)
                    .is_none_or(|(s, _, _)| *s < parsed.seq)
                {
                    self.store.insert(name.clone(), wire);
                    coll.holds.insert(writer, (parsed.seq, name, body));
                }
                None
            }
            Record::Lease(body) => {
                st.held.insert(
                    name.clone(),
                    Held::Record {
                        writer: writer.clone(),
                        digest,
                    },
                );
                let c = body.collection.clone();
                if mine {
                    let at = st
                        .colls
                        .get(&c)
                        .and_then(|x| x.holds.values().find(|(_, n, _)| *n == body.hold))
                        .map(|(_, _, b)| b.at.clone());
                    let h = st.holding.entry(c.clone()).or_insert_with(|| Holding {
                        hold: body.hold.clone(),
                        until: body.until,
                        at: Frontier::new(),
                        lease: None,
                    });
                    h.hold = body.hold.clone();
                    h.lease = Some((body.holds.clone(), body.until));
                    if let Some(at) = at {
                        h.at = at;
                    }
                }
                let coll = st.colls.entry(c).or_default();
                // One device counts once, whatever keys it signs with: its
                // newest lease by log seq, which its keys share.
                let device = parsed.device;
                if coll.leases.get(&device).is_none_or(|l| l.seq < parsed.seq) {
                    let named = coll
                        .holds
                        .values()
                        .any(|(_, n, b)| *n == body.hold && b.holders.contains(&device));
                    if mine || named {
                        self.store.insert(name.clone(), wire);
                    }
                    coll.leases.insert(
                        device,
                        LeaseHeld {
                            writer,
                            seq: parsed.seq,
                            name,
                            body,
                            audit: Audit::NotAudited,
                        },
                    );
                }
                None
            }
            Record::Intro(body) => {
                self.take_intro(st, name, &parsed, wire, writer, body, digest);
                None
            }
            Record::Prune(body) => {
                st.held.insert(
                    name.clone(),
                    Held::Record {
                        writer: writer.clone(),
                        digest,
                    },
                );
                let c = parsed.subject.clone()?;
                // Prune reaches only its signer's own writes (spec §14), and
                // only entries its signer wrote before it: a seq at or past
                // the prune's own would swallow later versions.
                let own_key = body.upto.iter().all(|(w, _)| *w == writer);
                let own_entry = parse_log_name(&body.prefix)
                    .is_none_or(|l| l.device == parsed.device && l.subject.as_ref() == Some(&c));
                let before = body.upto.iter().all(|(_, s)| s.0 < parsed.seq);
                if !own_key || !own_entry {
                    tracing::debug!(%name, "a prune record that names another key's writes; ignored");
                    return None;
                }
                if !before {
                    tracing::debug!(%name, "a prune record reaching past its own seq; ignored");
                    return None;
                }
                let coll = st.colls.entry(c.clone()).or_default();
                // A prune of this device's own log that it did not write: a
                // copy of its key signed it. It applies to state and reads
                // until a cut refuses it, yet the versions' bytes stay here
                // (and it is not stored as this device's own), so they come
                // back when it is refused (spec §8, §14).
                if parsed.device == self.device && !mine {
                    tracing::warn!(%name, "a prune record of this device's own log that it did not write: a copy of its key signed it; the versions it covers are read as pruned, and kept, until a cut refuses it");
                    coll.foreign_prunes.insert(name.clone());
                } else {
                    self.store.insert(name.clone(), wire);
                }
                let prune = Prune {
                    id,
                    name,
                    prefix: body.prefix,
                    upto: body.upto,
                };
                coll.prunes.push(prune);
                let dropped = st.drop_pruned(&c);
                self.entomb(&dropped);
                self.erase(st, &c);
                // A prune in the epoch in force of a folder of this
                // namespace asks for its erasure: the folder moves to a new
                // epoch first, whoever pruned (spec §14).
                let folders: Vec<Name> = st
                    .folders
                    .keys()
                    .filter(|f| {
                        c.has_prefix(f) && *f != &c && namespace_of(f).as_ref() == Some(&self.ns)
                    })
                    .cloned()
                    .collect();
                for f in folders {
                    if st.folder_epoch_pruned(&f) {
                        st.owed
                            .entry(Subject {
                                name: f,
                                folder: true,
                            })
                            .or_insert(Owed::Erase);
                    }
                }
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
        for (name, held) in &st.held {
            if st.cut_out.contains_key(name) {
                continue;
            }
            let refused = match held {
                Held::Record { writer, digest } => self
                    .refusing(name, writer, || Some(*digest))
                    .map(|r| (writer, r)),
                Held::Snapshot(s) => self
                    .refusing(name, &s.id.writer, || {
                        self.store.get(name).map(|w| wire::implicit_digest(&w))
                    })
                    .map(|r| (&s.id.writer, r)),
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
    /// others; a hold, lease or prune record stops counting (what the prune
    /// dropped may be fetched again). This device's own entries too. Its
    /// packet stays in the store; one refused for its chain is marked so
    /// there ([`untrusted_name`]), for a restart.
    fn withdraw(&self, st: &mut St, found: Vec<(Name, Writer, [u8; 32], Refusal)>) {
        let mut reread = BTreeSet::new();
        let mut rebuild = BTreeMap::new();
        // Per collection, its frontier before, and the versions a refused
        // prune had dropped.
        let mut back: BTreeMap<Name, (Frontier, Vec<Name>)> = BTreeMap::new();
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
                let coll = st.colls.entry(c.clone()).or_default();
                coll.holds.retain(|_, (_, n, _)| *n != name);
                coll.leases.retain(|_, l| l.name != name);
                let prune = coll.prunes.iter().find(|p| p.name == name).cloned();
                coll.prunes.retain(|p| p.name != name);
                coll.foreign_prunes.remove(&name);
                if let Some(p) = &prune {
                    let others = &coll.prunes;
                    coll.pruned_keeps
                        .retain(|id, _| !covers(p, id) || others.iter().any(|q| covers(q, id)));
                }
                let at = coll.at();
                let dropped: Vec<Name> = st
                    .held
                    .iter()
                    .filter(|(_, h)| matches!(h, Held::Pruned(p) if p.name == name))
                    .map(|(n, _)| n.clone())
                    .collect();
                for n in &dropped {
                    st.held.remove(n);
                }
                back.entry(c.clone())
                    .or_insert_with(|| (at, Vec::new()))
                    .1
                    .extend(dropped);
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
        // What the refused prune dropped comes back where its bytes stayed
        // (this device's own versions, [`Coll::foreign_prunes`]); others'
        // are fetched again as their writer's listing or cut names them.
        for (_, names) in back.values_mut() {
            names.sort_by_key(|n| parse_log_name(n).map(|l| l.seq));
            for name in names.iter() {
                let Some(packet) = self.store.get(name) else {
                    continue;
                };
                let Some((key, record)) = Data::decode(packet.clone()).ok().and_then(|d| {
                    let key = d.sig_info()?.key_locator_name()?;
                    let record = wire::decode_record(d.content()?.clone()).ok()?;
                    Some(((*key).clone(), record))
                }) else {
                    continue;
                };
                let mine = st.verified.get(name).is_some_and(|v| v.own);
                tracing::info!(%name, "back: the prune that dropped it is refused by a cut");
                let _ = self.take(st, name.clone(), packet, Writer::new(key), record, mine);
            }
        }
        for c in reread {
            st.reread(&c, &self.config.rules, self.me());
        }
        // A version delivered before the prune is delivered again.
        for (c, (before, names)) in back {
            for name in names {
                let again = st.colls.get(&c).and_then(|coll| {
                    let hv = coll.versions.values().find(|hv| hv.version.name == name)?;
                    let id = &hv.version.id;
                    (before.contains(id)
                        && coll.applied.get(&id.writer).is_some_and(|a| *a >= id.seq.0))
                    .then(|| hv.version.clone())
                });
                if let Some(v) = again {
                    st.tell(&c, &Change::Version(v));
                }
            }
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
                let (result, missing) = self.validator.validate_durable_cached(&data).await;
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
                    st.reread(c, &self.config.rules, self.me());
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
        for (name, held) in &st.held {
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
                Rejudge::Namespace(ns) => withdrawn || keyring.context_for(name).namespace() == ns,
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
                let ctx = self.validator.keyring().context_for(name);
                if ctx.is_revoked(writer.key()) {
                    Verdict::Cut(revocation_cut_for(&ctx, writer, &log_prefix(name)))
                } else {
                    // Its key lapsed where Data of its role needs a cut.
                    Verdict::Chain(e.to_string())
                }
            }
            TrustError::Revoked { .. }
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
            self.validator.validate_durable(data).await,
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
        // `c` is read again whatever record comes back.
        if let Some(coll) = st.colls.get_mut(c) {
            coll.line = Line::default();
            coll.members = None;
        }
        if let Some(f) = st.folders.get_mut(c) {
            f.line = Line::default();
        }
        let (rules, me) = (&self.config.rules, self.me());
        for (_, seq, body, writer) in records {
            st.accept_members(seq, body, &writer, rules, me);
        }
        // A line left with no record moved nothing when taking: set what is
        // in force anew either way.
        if folder {
            st.refold_under(c, rules, me);
        }
        if st.colls.contains_key(c) {
            st.refold(c, rules, me);
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
    /// digest is `digest`, if given — by its name, else from each holder of
    /// a live lease on its collection.
    async fn fetch_entry(&self, name: &Name, digest: Option<[u8; 32]>) -> Option<Data> {
        let exact = digest.map_or_else(|| name.clone(), |d| name.clone().append_implicit_digest(d));
        if let Some(d) = self.fetch(exact, false).await {
            return Some(d);
        }
        let holders = match parse_log_name(name).and_then(|l| l.subject) {
            Some(c) => self.holders_of(&self.st.lock(), &c),
            None => Vec::new(),
        };
        for h in holders {
            if let Some(d) = self.fetch_held(name, &h).await
                && digest.is_none_or(|x| wire::implicit_digest(d.raw()) == x)
            {
                return Some(d);
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
    /// at that name are never asked for.
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
                                let id = VersionId {
                                    writer: writer.clone(),
                                    seq: Seq(seq),
                                };
                                if held.contains_key(&name)
                                    || refused.contains_key(&name)
                                    || cut_fetching.contains(&name)
                                    || coll.pruned(&id).is_some()
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
            stream::iter(names)
                .map(|(name, writer, exact)| async move {
                    // Exactly the bytes re-admitted, or those the cut's
                    // manifest lists, by full name: other bytes at the
                    // name are not asked for.
                    let digest = match exact {
                        Some(d) => Some(Some(d)),
                        None => inner.cut_digest(&name, &writer).await,
                    };
                    if let Some(digest) = digest
                        && let Some(d) = inner.fetch_entry(&name, digest).await
                        && let Err(why) = inner.take_data(&name, d).await
                    {
                        tracing::debug!(%name, "an entry its revocation cut accepts is refused: {why}");
                    }
                    inner.st.lock().cut_fetching.remove(&name);
                })
                .buffer_unordered(inner.config.window)
                .collect::<Vec<_>>()
                .await;
            inner.progress.notify_waiters();
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
        let signed = self.sign_members(c, seq, record)?;
        self.keep_members(st, c, signed);
        Ok(())
    }

    /// Sign `record`, a members record of `c`, as the own log's entry at
    /// `seq`, with the key of the epoch it starts; nothing is kept.
    fn sign_members(
        &self,
        c: &Name,
        seq: u64,
        (body, key): (MembersBody, Option<ContentKey>),
    ) -> Result<(LogEntry, Option<(Epoch, ContentKey)>), DataError> {
        let entry = self.sign_entry(Some(c), seq, wire::encode_members(&body))?;
        Ok((entry, body.epoch.zip(key)))
    }

    /// Keep a members record of `c` [`Self::sign_members`] signed, and the
    /// key of the epoch it starts.
    fn keep_members(
        &self,
        st: &mut St,
        c: &Name,
        (entry, made): (LogEntry, Option<(Epoch, ContentKey)>),
    ) {
        self.keep_entry(st, entry);
        if let Some((e, key)) = made {
            self.keep_made_key(st, c, e, key);
        }
    }

    /// Whether this device may write into `c` now, sealed in `epoch`: its
    /// key is a writer by the record in force, and that record's epoch is
    /// `epoch` (else it moved while the key was asked for: ask again), one
    /// that has not outgrown its audience ([`outgrown`]: a reader the
    /// record in force no longer admits may hold its key, so nothing is
    /// sealed in it until a device of the audience moves `c` to a new
    /// epoch; ask again then, spec §6.1).
    fn writable(&self, st: &St, c: &Name, epoch: Option<&Epoch>) -> Result<(), DataError> {
        let Some(members) = st.colls.get(c).and_then(|x| x.members.as_ref()) else {
            return Err(DataError::Unavailable { name: c.clone() });
        };
        if !members
            .writers
            .iter()
            .any(|p| self.writer.key().has_prefix(p))
        {
            return Err(DataError::NotAllowed {
                collection: c.clone(),
                writer: self.writer.clone(),
            });
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
        Ok(())
    }

    /// The date of an own entry of log-like `c` taken now: the clock, or
    /// the date of the previous entry if the clock is behind it (spec §4.1),
    /// so a time range finds them in order.
    fn date(&self, st: &St, c: &Name) -> Timestamp {
        let now = (self.config.clock)();
        let last = st.colls.get(c).and_then(|x| x.last_dated);
        let open = st.open.get(c).and_then(|o| {
            o.entries
                .last()
                .map(|e| Timestamp(o.first.0.saturating_add(e.offset)))
        });
        [Some(now), last, open]
            .into_iter()
            .flatten()
            .max()
            .unwrap_or(now)
    }

    /// Sign `draft` into `c` as a new own version (the record in force
    /// checked by [`Self::writable`]), sealed with `key`, and hold it; a
    /// payload larger than [`wire::INLINE_MAX`] travels in pieces. A merge
    /// collection's entry is the operation its rule makes of the fields
    /// (or the one the app built), checked and applied by the rule against
    /// the state before anything is kept: one the rule refuses is
    /// [`DataError::BadRequest`], with nothing stored, published or
    /// counted in the log's head. Refused for any reason once the edit
    /// may have touched the state, the collection is read again
    /// ([`St::reread`]): its state is the one its versions make, without
    /// the refused edit.
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
        batch: Duration,
    ) -> Result<VersionId, DataError> {
        // Refused before the edit touches the state.
        let seq = self.next_seq(st)?;
        let judged = self
            .sign_in(st, c, seq, key, type_id, keep, draft, None)
            .and_then(|signed| Ok((self.judge_own(st, &signed, true)?, signed)));
        match judged {
            Ok((judged, signed)) => Ok(self.commit(st, ns, signed, batch, judged)),
            Err(e) => {
                st.reread(c, &self.config.rules, self.me());
                Err(e)
            }
        }
    }

    /// Refuse the host's default record of `c`, a collection of this
    /// namespace with no record in force here, while a device of the
    /// namespace known here has not been walked ([`Self::unsynced`]): a
    /// folder record above `c` that device may hold governs `c`, and a
    /// default record would narrow `c` for good (spec §6.1).
    /// [`DataError::NotReady`]: put again once they are reached.
    async fn default_allowed(self: &Arc<Self>, c: &Name) -> Result<(), DataError> {
        // A walk took the folder records above `c` only if it went toward
        // `c`'s folder: toward a name under it, or followed a folder above.
        let folder = folder_of(c);
        let missing = self
            .unsynced(
                &self.ns,
                |d| self.namespace_of_name(d) == self.ns,
                |t| t.has_prefix(&folder) || folder.has_prefix(t),
            )
            .await;
        if missing.is_empty() {
            return Ok(());
        }
        let devices: Vec<String> = missing.iter().map(ToString::to_string).collect();
        Err(DataError::NotReady {
            name: c.clone(),
            why: format!(
                "it has no members record here, and this device has not yet walked the summary \
                 of {}, which may hold a folder record governing it; no default record is \
                 signed, since one would narrow the collection for good. Bring that device \
                 online and put again; if it is lost, mark its key suspected or revoke it \
                 (it is not waited for then)",
                devices.join(", ")
            ),
        })
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
    /// it starts; and judge it, checked and applied, on a state of its own
    /// that its rule starts empty — the state the record starts. The
    /// version, its ruling and that state; nothing is kept. One the rule
    /// refuses is [`DataError::BadRequest`].
    #[allow(clippy::too_many_arguments)]
    fn sign_fresh(
        &self,
        c: &Name,
        seq: u64,
        body: &MembersBody,
        made: Option<&ContentKey>,
        draft: Draft,
        (type_id, keep): (TypeId, Keep),
        group: Option<Group>,
    ) -> Result<(Signed, Ruled, Box<dyn MergeState>), DataError> {
        // The host default merges with `/merge/yrs` ([`Self::default_members`]).
        let function = crate::merge::Yrs::new().function().clone();
        let Some(rule) = self.config.rules.get(&function) else {
            return Err(DataError::RuleUnknown {
                collection: c.clone(),
                rule: function,
            });
        };
        let mut temp = rule.start(c, self.me());
        let key = body.epoch.clone().zip(made.cloned());
        let under = Under {
            readers: body.readers.clone(),
            function: Some(function.clone()),
            parents: Parents::new(),
        };
        let signed = self.sign_version(
            c,
            seq,
            under,
            Some(&mut *temp),
            key.as_ref(),
            (type_id, keep, (self.config.clock)()),
            draft,
            group,
        )?;
        let (empty, none) = (Coll::default(), HashMap::new());
        let past = PastOf::new(
            &signed.held.version,
            empty.waits(c),
            &empty.by_digest,
            &[],
            &none,
        );
        let ruled =
            rule_on(&mut *temp, &signed.held, &past, true).map_err(|e| DataError::BadRequest {
                name: c.clone(),
                why: format!(
                    "{c} merges with {function}, whose rule refuses this operation ({e}); \
                     nothing was written: put an operation the rule takes"
                ),
            })?;
        Ok((signed, ruled, temp))
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
        let (signed, ruled, temp) =
            self.sign_fresh(c, seq, &body, made.as_ref(), draft, options, None)?;
        let record = self.sign_members(c, base, (body, made))?;
        self.keep_members(st, c, record);
        self.start_fresh(st, c, temp);
        Ok(self.commit(st, ns, signed, Duration::ZERO, Some(ruled)))
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
        group: Option<Group>,
    ) -> Result<Signed, DataError> {
        let log = st.colls[c]
            .members
            .as_ref()
            .is_some_and(|m| log_like(&m.rule));
        let dated = match (&draft, log) {
            (Draft::Block { first, .. }, _) => *first,
            (_, true) => self.date(st, c),
            (_, false) => (self.config.clock)(),
        };
        let coll = st.colls.get_mut(c).expect("members known");
        let members = coll.members.as_ref().expect("members known");
        let under = Under {
            readers: members.readers.clone(),
            function: match &members.rule {
                Rule::Merge { function } => Some(function.clone()),
                Rule::Log | Rule::OneKey => None,
            },
            parents: coll.parents(),
        };
        self.sign_version(
            c,
            seq,
            under,
            coll.state.as_deref_mut(),
            key,
            (type_id, keep, dated),
            draft,
            group,
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
        state: Option<&mut (dyn MergeState + 'static)>,
        key: Option<&(Epoch, ContentKey)>,
        (type_id, keep, dated): (TypeId, Keep, Timestamp),
        draft: Draft,
        group: Option<Group>,
    ) -> Result<Signed, DataError> {
        let (content, block, built) = match draft {
            Draft::Entry(content) => (content, None, None),
            Draft::Op(op) => (Content::new(), None, Some(op)),
            Draft::Block { entries, .. } => (Content::new(), Some(entries), None),
        };
        let log = under.function.is_none();
        let op = match &under.function {
            Some(function) => {
                let Some(state) = state else {
                    return Err(DataError::RuleUnknown {
                        collection: c.clone(),
                        rule: function.clone(),
                    });
                };
                match built {
                    Some(op) => op,
                    None => state.edit(&content).map_err(|e| DataError::BadRequest {
                        name: c.clone(),
                        why: format!(
                            "{c} merges with {function}, which makes no operation of these \
                             fields ({e}); put the operation its rule takes (put_op)"
                        ),
                    })?,
                }
            }
            None => Bytes::new(),
        };
        let name = log_name(&self.device, Some(c), seq);
        let payload = match (key, &block) {
            (Some((_, k)), Some(b)) => seal::seal_bytes(k, &name, &wire::encode_block(b)),
            (Some((_, k)), None) => seal::seal_payload(k, &name, &content, &op),
            (None, None) => wire::encode_payload(&content, &op),
            // An unsealed block stands in the record itself.
            (None, Some(_)) => Bytes::new(),
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
        let (chunks, pieces) = if block.is_none() && payload.len() > wire::INLINE_MAX {
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
            group,
            rule: under.function.clone(),
            fields,
            op: record_op,
            sealed,
            chunks,
            block,
        };
        let wire = self.sign(DataBuilder::new(name.clone(), &wire::encode_version(&body)))?;
        let epoch = body.sealed.as_ref().map(|s| s.epoch.clone());
        let version = version_of(&name, &self.writer, seq, body);
        let held = HeldVersion {
            opened: true,
            ..HeldVersion::new(version, op, wire, key.is_some(), epoch, chunks)
        };
        Ok(Signed {
            c: c.clone(),
            seq,
            held,
            pieces,
            log,
            keep,
            dated,
            function: under.function,
        })
    }

    /// The rule's judgement of `signed`, an own version of a merge
    /// collection, against its past — here the state's frontier and this
    /// writer's earlier log, as every reader will judge it — by the
    /// collection's state: checked, and with `apply`, applied. One the rule
    /// refuses is [`DataError::BadRequest`]. `None` under the log rule.
    fn judge_own(
        &self,
        st: &mut St,
        signed: &Signed,
        apply: bool,
    ) -> Result<Option<Ruled>, DataError> {
        let Some(function) = &signed.function else {
            return Ok(None);
        };
        let c = &signed.c;
        let St { colls, cut_out, .. } = st;
        let Coll {
            members,
            state,
            entries,
            skipped,
            listings,
            locked,
            revoked,
            versions,
            by_digest,
            outsiders,
            ..
        } = colls.get_mut(c).expect("members known");
        let Some(state) = state.as_deref_mut() else {
            return Err(DataError::RuleUnknown {
                collection: c.clone(),
                rule: function.clone(),
            });
        };
        // Its past, as every reader will see it (spec §5.2).
        let waits = Waits {
            collection: c,
            members: members.as_ref(),
            entries,
            skipped,
            listings,
            locked,
            revoked,
            admitted: versions,
        };
        let judged = rule_on(
            state,
            &signed.held,
            &PastOf::new(&signed.held.version, waits, by_digest, outsiders, cut_out),
            apply,
        );
        judged.map(Some).map_err(|e| DataError::BadRequest {
            name: c.clone(),
            why: format!(
                "{c} merges with {function}, whose rule refuses this operation ({e}); nothing \
                 was written: put an operation the rule takes"
            ),
        })
    }

    /// Keep `signed`, an own version judged (`judged`, under a merge rule):
    /// its seq is the log's head, it and its pieces are stored, listed in
    /// the summary, applied, and delivered. Its id.
    fn commit(
        &self,
        st: &mut St,
        ns: &Name,
        signed: Signed,
        batch: Duration,
        judged: Option<Ruled>,
    ) -> VersionId {
        let Signed {
            c,
            seq,
            held,
            pieces,
            log,
            keep,
            dated,
            ..
        } = signed;
        let version = held.version.clone();
        let id = version.id.clone();
        let name = version.name.clone();
        // Each change of counting, with the version it is about; a group
        // member's is its group's ([`St::regroup`]).
        let mut told: Vec<(Change, VersionId)> = Vec::new();
        let mut touched = BTreeSet::new();
        if let Some(g) = version.group {
            touched.insert((id.writer.clone(), g.id));
        }
        if let Some(Ruled {
            kind,
            counting,
            changed,
        }) = judged
        {
            let coll = st.colls.get_mut(&c).expect("members known");
            coll.kinds.insert(id.clone(), kind);
            if let Counting::NotCounted(why) = counting {
                coll.not_counted.insert(id.clone(), why.clone());
                if version.group.is_none() {
                    let change = Change::NotCounted {
                        collection: c.clone(),
                        id: id.clone(),
                        why,
                    };
                    told.push((change, id.clone()));
                }
            }
            for (other, counting) in changed {
                let group = coll
                    .versions
                    .get(&other)
                    .and_then(|hv| hv.version.group)
                    .map(|g| g.id);
                if let Some(g) = group {
                    touched.insert((other.writer.clone(), g));
                }
                let change = match counting {
                    Counting::Counted => {
                        coll.not_counted
                            .remove(&other)
                            .is_some()
                            .then(|| Change::Counted {
                                collection: c.clone(),
                                id: other.clone(),
                            })
                    }
                    Counting::NotCounted(why) => {
                        (coll.not_counted.get(&other) != Some(&why)).then(|| {
                            coll.not_counted.insert(other.clone(), why.clone());
                            Change::NotCounted {
                                collection: c.clone(),
                                id: other.clone(),
                                why,
                            }
                        })
                    }
                };
                if let Some(change) = change.filter(|_| group.is_none()) {
                    told.push((change, other));
                }
            }
        }
        st.head = st.head.max(seq);
        for p in pieces {
            self.store.insert(p.name, p.wire);
        }
        self.store.insert(name.clone(), held.wire.clone());
        self.note_written(st, &name, &held.wire);
        st.held.insert(name, Held::Version(id.clone()));
        let retain = match log {
            true => Retain { keep, dated },
            false => Retain::ALWAYS,
        };
        st.trees
            .entry(ns.clone())
            .or_insert_with(|| Tree::new(ns.clone()))
            .add(&c, seq, Kind::Version(retain));
        if let Some(g) = version.group {
            st.note_member(&c, &id, g, version.keep);
        }
        let coll = st.colls.get_mut(&c).expect("members known");
        coll.entries
            .entry(id.writer.clone())
            .or_default()
            .insert(seq);
        coll.applied.insert(id.writer.clone(), seq);
        if log {
            coll.last_dated = Some(last_dated(&version));
        }
        coll.batches.insert(seq, batch);
        // Stored with the version, so the head of a one-key collection
        // states the same freshness at the same seq after a restart.
        if coll
            .members
            .as_ref()
            .is_some_and(|m| matches!(m.rule, Rule::OneKey))
        {
            self.store
                .insert(batched_name(&c), encode_batched(seq, batch));
        }
        coll.by_digest.insert(held.digest, id.clone());
        // An own operation in pieces is not kept in memory once applied.
        let held = match held.unloaded() {
            Some(unloaded) => unloaded,
            None => held,
        };
        coll.versions.insert(id.clone(), Arc::new(held));
        st.emit(&c, &Change::Version(version), &id.writer, seq);
        for (change, about) in told {
            match &change {
                Change::NotCounted { .. } => st.emit(&c, &change, &about.writer, about.seq.0),
                _ => st.tell(&c, &change),
            }
        }
        st.regroup(touched);
        self.arm_sweep(st, keep);
        // A newer version may end older ones' last N (spec §14.1).
        if matches!(keep, Keep::LastN(_)) {
            st.expire(&c);
        }
        id
    }

    /// Add an entry to the open block of `c` (spec §4.1), closing the open
    /// one first when the entry's type, keep class or seal epoch differs
    /// from its, or when the entry would make its `Block` encoding exceed
    /// [`wire::INLINE_MAX`]. The receiver of the block's id once signed;
    /// whether a block closed; and the deadline to arm a timer for, when
    /// this entry moves the block's close earlier (`deadline`: its arrival
    /// plus `delay`, the caller's to compute, as only it can refuse one the
    /// clock cannot hold).
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn add_to_block(
        &self,
        st: &mut St,
        c: &Name,
        content: Content,
        type_id: TypeId,
        keep: Keep,
        epoch: Option<Epoch>,
        delay: Duration,
        deadline: Instant,
    ) -> (
        oneshot::Receiver<Result<VersionId, DataError>>,
        bool,
        Option<Instant>,
    ) {
        let dated = self.date(st, c);
        let mut closed = false;
        if let Some(open) = st.open.get(c) {
            let differs =
                open.type_id != type_id || !same_keep_class(open.keep, keep) || open.epoch != epoch;
            let mut entries = open.entries.clone();
            entries.push(BlockEntryBody {
                offset: dated.0 - open.first.0,
                fields: content.clone(),
            });
            if differs || wire::encode_block(&entries).len() > wire::INLINE_MAX {
                closed = self.close_block(st, c).is_some();
            }
        }
        let (tx, rx) = oneshot::channel();
        let arm = match st.open.get_mut(c) {
            Some(open) => {
                open.entries.push(BlockEntryBody {
                    offset: dated.0 - open.first.0,
                    fields: content,
                });
                if let (Keep::Until(a), Keep::Until(b)) = (open.keep, keep) {
                    open.keep = Keep::Until(a.max(b));
                }
                open.batch = open.batch.max(delay);
                open.waiters.push(tx);
                (deadline < open.deadline).then(|| {
                    open.deadline = deadline;
                    deadline
                })
            }
            None => {
                st.open.insert(
                    c.clone(),
                    OpenBlock {
                        type_id,
                        keep,
                        epoch,
                        first: dated,
                        entries: vec![BlockEntryBody {
                            offset: 0,
                            fields: content,
                        }],
                        deadline,
                        batch: delay,
                        waiters: vec![tx],
                    },
                );
                Some(deadline)
            }
        };
        (rx, closed, arm)
    }

    /// Close the open block of `c`, if any: sign it as one version (the
    /// record in force checked again) and tell every put waiting for it.
    /// Its id, when signed.
    fn close_block(&self, st: &mut St, c: &Name) -> Option<VersionId> {
        let open = st.open.remove(c)?;
        let signed = self
            .writable(st, c, open.epoch.as_ref())
            .and_then(|()| match &open.epoch {
                Some(e) => st
                    .keys
                    .key(c, e)
                    .map(|k| Some((e.clone(), k)))
                    .ok_or_else(|| DataError::Unavailable { name: c.clone() }),
                None => Ok(None),
            })
            .and_then(|key| {
                let ns = namespace_of(c).expect("a collection has a namespace");
                self.write(
                    st,
                    c,
                    &ns,
                    key.as_ref(),
                    open.type_id,
                    open.keep,
                    Draft::Block {
                        first: open.first,
                        entries: open.entries,
                    },
                    open.batch,
                )
            });
        if let Err(e) = &signed {
            tracing::debug!(collection = %c, "a block was not signed: {e}");
        }
        for w in open.waiters {
            let _ = w.send(signed.clone());
        }
        signed.ok()
    }

    /// Close the open block of `c` at `at` if it is still due by then (a
    /// later entry may have closed it, or a block opened since closes
    /// later, on its own timer), and announce it.
    fn arm_block(self: &Arc<Self>, c: Name, at: Instant) {
        let weak = Arc::downgrade(self);
        rt::spawn(async move {
            rt::sleep(at.saturating_duration_since(Instant::now())).await;
            let Some(inner) = weak.upgrade() else { return };
            let closed = {
                let mut st = inner.st.lock();
                st.open.get(&c).is_some_and(|o| o.deadline <= at)
                    && inner.close_block(&mut st, &c).is_some()
            };
            if closed && let Err(e) = inner.publish_about(&c, &[]).await {
                tracing::debug!(collection = %c, "a block is not announced: {e}");
            }
        });
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
            folder: false,
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
        if let Some((holder, ask)) = parse_hold_ask_name(&name)
            && holder == self.device
        {
            // Taking a hold verifies the asker and fetches the owner's record
            // and the collection: its own task.
            rt::spawn(async move {
                let reply = self.accept_hold(&name, ask).await;
                self.reply(&name, responder, reply).await;
            });
            return;
        }
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
            // Answering verifies the asker first: its own task.
            rt::spawn(async move {
                let reply = self.audit_answer(&name, &ask).await;
                self.reply(&name, responder, reply).await;
            });
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
        // Own log entries and pieces of own versions; of a collection this
        // device holds for its owner, every entry and piece it keeps
        // (readers ask it for them under its own name, `32=held`); and of a
        // merge collection, the entry and pieces of each version it applied,
        // which those whose versions are made over it ask it for (spec
        // §13.1): a writer serving its pieces to some devices only does not
        // stall the rest. Nothing a known prune covers (by the prune records
        // restored, not only the versions held), and no piece of an own
        // version a release is auditing its holders for. Nothing expired
        // here either (spec §14.1), checked as it is asked for.
        let log = parse_log_name(name).or_else(|| parse_piece_name(name).map(|p| p.log));
        if let Some(parsed) = log {
            let mut st = self.st.lock();
            let version = strip_piece(name);
            if pruned_name(&st, &version).is_some()
                || matches!(st.held.get(&version), Some(Held::Pruned(_)))
                || st.expire_named(&version)
            {
                return None;
            }
            if parsed.device == self.device {
                // Published once durable (spec §4.2): above the durable
                // head, a power loss could take it after a peer saw it.
                if parsed.seq > st.durable {
                    return None;
                }
                let quarantined = version != *name && st.quarantine.contains(&version);
                return (!quarantined).then(|| self.store.get(name)).flatten();
            }
            let held = parsed.subject.as_ref().is_some_and(|c| {
                st.holding.contains_key(c)
                    || matches!(st.held.get(&version), Some(Held::Version(id))
                        if st.colls.get(c).is_some_and(|coll| coll.applies(id)))
            });
            return held.then(|| self.store.get(name)).flatten();
        }
        // The head of a one-key collection this device writes (spec §5.3):
        // the newest by its discovery name, any other only by its own.
        let head = match parse_head_prefix(name) {
            Some((d, c)) if can_be_prefix => Some((d, c, None)),
            _ => parse_head_name(name).map(|(d, c, s)| (d, c, Some(s))),
        };
        if let Some((device, c, seq)) = head {
            if device != self.device {
                return None;
            }
            let mut st = self.st.lock();
            let (s, wire) = self.head(&mut st, &c)?;
            return seq.is_none_or(|q| q == s).then_some(wire);
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

    /// The signed head of one-key collection `c`, if this device's key is
    /// its one key (spec §5.3): its node's head and digest as the log up to
    /// its durable head fixes them (spec §4.2), and the batch delay of the
    /// newest version that node lists as freshness (also the packet's
    /// FreshnessPeriod). Signed only when asked for and the node changed;
    /// the head's seq and packet.
    fn head(&self, st: &mut St, c: &Name) -> Option<(u64, Bytes)> {
        let coll = st.colls.get(c)?;
        let (key, _) = one_key(coll)?;
        if key != self.writer {
            return None;
        }
        let ns = namespace_of(c)?;
        let durable = st.durable;
        let (seq, node) =
            st.trees
                .get_mut(&ns)?
                .node_at(&self.device, self.writer.key(), c, durable)?;
        let coll = st.colls.get_mut(c)?;
        // What the head states of the newest version it lists; the delays
        // of older versions are no longer stated by any head.
        let freshness = match coll.batches.range(..=seq).next_back() {
            Some((&s, &batch)) => {
                coll.batches = coll.batches.split_off(&s);
                batch
            }
            None => Duration::ZERO,
        };
        let digest = wire::implicit_digest(&node);
        if let Some(h) = st.heads.get(c)
            && h.seq == seq
            && h.digest == digest
        {
            return Some((seq, h.wire.clone()));
        }
        let body = HeadBody {
            collection: c.clone(),
            seq,
            digest,
            freshness: freshness.as_millis() as u64,
        };
        let builder = DataBuilder::new(head_name(&self.device, c, seq), &wire::encode_head(&body))
            .freshness(freshness);
        let wire = self.sign(builder).ok()?;
        self.store
            .insert(head_prefix(&self.device, c), wire.clone());
        st.heads.insert(
            c.clone(),
            SignedHead {
                seq,
                digest,
                wire: wire.clone(),
            },
        );
        Some((seq, wire))
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
    /// that subject's record in force when it seals.
    fn may_hold(&self, st: &St, c: &Name, e: &Epoch, device: &Name, dns: &Name) -> bool {
        let Some((epochs, record)) = st.line_of(&st.seal_subject(c, e)) else {
            return false;
        };
        let Some(named) = epochs.get(e) else {
            return false;
        };
        self.admits(st, &named.readers, Some(&e.creator), device, dns)
            && record.is_some_and(|m| m.epoch.is_none() || self.admits_record(st, m, device, dns))
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
        self.grants_answered.fetch_add(1, Ordering::Relaxed);
        Some(wire)
    }

    /// Get the key of epoch `e` of `c` (spec §9) — asked of the subject
    /// whose record names it ([`St::seal_subject`]): `c`, or the folder
    /// above it whose epoch it is, so one ask serves every collection that
    /// reads in a folder's epoch — from the epoch's creator, then from
    /// every other device known to write into `c`'s namespace. A granted
    /// key is taken only if it matches the key check of the held record
    /// naming the epoch. Opens what it unlocks. Whether the key is held now.
    async fn obtain(self: &Arc<Self>, c: &Name, e: &Epoch) -> bool {
        let Some(ns) = namespace_of(c) else {
            return false;
        };
        let (c, seal_key) = {
            let mut st = self.st.lock();
            if st.keys.key(c, e).is_some() {
                return true;
            }
            let s = st.seal_subject(c, e);
            if !st
                .line_of(&s)
                .is_some_and(|(epochs, _)| epochs.contains_key(e))
            {
                // Nothing to check a key against: no record held names it.
                return false;
            }
            if !st.asking.insert((s.name.clone(), e.clone())) {
                return false;
            }
            (
                s.name,
                seal_key_name(&self.device, &st.keys.recipient.public()),
            )
        };
        let c = &c;
        self.grants_asked.fetch_add(1, Ordering::Relaxed);
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
        if got {
            // Merge versions in pieces it unlocked wait for them; a group
            // member it opened may make its folder followed.
            self.fetch_wanted(true);
            self.settle().await;
        } else {
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
                // Never read under another rule.
                let Some(state) = &coll.state else {
                    return Err(DataError::RuleUnknown {
                        collection: c.clone(),
                        rule: function.clone(),
                    });
                };
                Ok(Got::State(State {
                    name: state_name(c, &at),
                    collection: c.clone(),
                    at,
                    value: state.value(&coll.excluded),
                    not_counted: coll.not_counted_list(),
                }))
            }
            Rule::Log => {
                let since = members.since.as_ref();
                // A member its group holds back is not the newest.
                let applied: Vec<&Version> = coll
                    .versions
                    .values()
                    .map(|hv| &hv.version)
                    .filter(|v| at.contains(&v.id) && !since.is_some_and(|s| s.contains(&v.id)))
                    .filter(|v| !coll.excluded.contains(&v.id))
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
            // The one key's newest version held here, by seq: what its
            // head would name, as of the last one this device verified.
            Rule::OneKey => {
                let since = members.since.as_ref();
                // A member of a group counts once its group does.
                coll.versions
                    .values()
                    .map(|hv| &hv.version)
                    .filter(|v| !since.is_some_and(|s| s.contains(&v.id)))
                    .filter(|v| v.group.is_none() || !coll.pending.contains(&v.id))
                    .filter(|v| !coll.excluded.contains(&v.id))
                    .max_by(|a, b| a.id.seq.cmp(&b.id.seq))
                    .map(|v| Got::Version(v.clone()))
                    .ok_or_else(|| DataError::Unavailable { name: c.clone() })
            }
        }
    }

    /// A log entry by name, read whole (a large payload from its pieces).
    async fn get_log_entry(self: &Arc<Self>, name: &Name) -> Result<Answer, DataError> {
        let a = self.log_entry(name, true).await;
        self.whole(a).await
    }

    /// The log entry named `name`, verified, not read whole: held here, or
    /// fetched — by name (its writer, or a cache), else from each holder of
    /// a live lease on its collection (`32=held`). A packet that is not its
    /// writer's (a forged or spliced block, another signer's, one that does
    /// not decode) is dropped and the next source asked
    /// ([`Self::take_data`]); a refusal kept against the name is a decision
    /// on the genuine writer's own packet. `follow`: follow its collection
    /// first; else only peek at it, taking its records (spec §5.3).
    async fn log_entry(self: &Arc<Self>, name: &Name, follow: bool) -> Result<Answer, DataError> {
        let answer = |st: &mut St| -> Option<Result<Answer, DataError>> {
            // A version whose keep passed is dropped as it is asked for.
            st.expire_named(name);
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
                Held::Record { .. } => Err(DataError::NotFound { name: name.clone() }),
                Held::Pruned(by) => Err(DataError::Pruned {
                    name: name.clone(),
                    by: by.clone(),
                }),
                Held::Expired(t) => Err(DataError::Expired {
                    name: name.clone(),
                    keep: t.keep,
                }),
            })
        };
        if let Some(a) = answer(&mut self.st.lock()) {
            return a;
        }
        let parsed =
            parse_log_name(name).ok_or_else(|| DataError::NotFound { name: name.clone() })?;
        if let Some(c) = &parsed.subject {
            if follow {
                self.look(c).await?;
            } else {
                self.peek(c).await?;
            }
        }
        if let Some(a) = answer(&mut self.st.lock()) {
            return a;
        }
        let holders = match &parsed.subject {
            Some(c) => self.holders_of(&self.st.lock(), c),
            None => Vec::new(),
        };
        let mut failed = DataError::Unavailable { name: name.clone() };
        let mut taken = false;
        for source in std::iter::once(None).chain(holders.iter().map(Some)) {
            let data = match source {
                None => self.fetch(name.clone(), false).await,
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
                    peer.root = None;
                    peer.nodes.retain(|(s, _), _| !c.has_prefix(s));
                }
            }
            let _ = rt::timeout(self.config.first_look, self.refresh(&ns, &parsed.device)).await;
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

    /// Take the records of `c` without following its versions (spec
    /// §5.3): its members record is what a one-key read needs, and a range
    /// read fetches only the blocks it asks for. The first time, and again
    /// for as long as no members record of it is held (its writers may have
    /// been unreachable before), look at what every device known to write
    /// into its namespace holds of it, for at most the first-look time.
    async fn peek(self: &Arc<Self>, c: &Name) -> Result<(), DataError> {
        check_collection(c)?;
        let ns = namespace_of(c).expect("checked above");
        let look = {
            let mut st = self.st.lock();
            let new = !st.inside(c) && st.peeks.insert(c.clone());
            st.ensure(c, &self.config.rules, self.me());
            let unknown = st.colls.get(c).is_none_or(|x| x.members.is_none());
            if new || unknown {
                for ((_, pns), peer) in st.peers.iter_mut() {
                    if *pns == ns {
                        peer.root = None;
                        peer.nodes.retain(|(s, _), _| !c.has_prefix(s));
                    }
                }
            }
            new || unknown
        };
        self.join(&ns).await?;
        if look {
            let devices = self.known_for(&self.st.lock(), &ns);
            let all = futures::future::join_all(devices.iter().map(|d| self.refresh(&ns, d)));
            let _ = rt::timeout(self.config.first_look, all).await;
        }
        let c2 = c.clone();
        self.wait_for(|st| st.colls.get(&c2).is_some_and(|x| x.members.is_some()))
            .await;
        Ok(())
    }

    /// Take `data` as the head of `key`'s one-key collection `c` of device
    /// `device` (spec §5.3): signed by exactly the one key, for `c`, its seq
    /// its name's, and not lower than one of that key verified here or than
    /// a seq of that key known here (held, listed by a verified node, or
    /// tombstoned) — a rollback, refused also after a restart, as the
    /// newest head of each key verified is kept in the store. Its receipt
    /// counts only once the node it names checks out ([`Self::head_of`]).
    async fn accept_head(
        &self,
        c: &Name,
        key: &Writer,
        device: &Name,
        data: &Data,
    ) -> Result<HeadBody, HeadRefusal> {
        let named = parse_head_name(&data.name);
        let Some((_, _, seq)) = named.filter(|(d, hc, _)| d == device && hc == c) else {
            return Err(HeadRefusal::NotItsName);
        };
        let signer = self
            .verify(data)
            .await
            .map_err(|_| HeadRefusal::NotVerified)?;
        if signer != *key {
            return Err(HeadRefusal::NotTheKey);
        }
        let body = data
            .content()
            .and_then(|b| wire::decode_head(b.clone()).ok())
            .filter(|b| b.collection == *c && b.seq == seq)
            .ok_or(HeadRefusal::NotItsName)?;
        let mut st = self.st.lock();
        let slot = (c.clone(), key.clone());
        let verified = st.seen.get(&slot).map(|h| h.seq);
        let known = st.colls.get(c).map_or(0, |x| {
            let listed = x.entries.get(key).and_then(|s| s.last().copied());
            let held = x
                .versions
                .keys()
                .rfind(|id| id.writer == *key)
                .map(|id| id.seq.0);
            listed.max(held).unwrap_or(0)
        });
        let floor = verified.unwrap_or(0).max(known);
        if seq < floor {
            return Err(HeadRefusal::Rollback { seq, seen: floor });
        }
        if verified.is_none_or(|v| seq > v) {
            self.store
                .insert(head_prefix(device, c), data.raw().clone());
        }
        let h = st.seen.entry(slot).or_insert(SeenHead {
            seq,
            this_run: true,
            checked: None,
            delivered: None,
        });
        h.seq = seq;
        h.this_run = true;
        Ok(body)
    }

    /// Fetch the head of `key`'s one-key collection `c` from its device
    /// (`<D>/32=summary/<C>/32=head`, MustBeFresh), take it
    /// ([`Self::accept_head`]), then fetch the node it names by name and
    /// check it against the head's digest. The seqs the node lists, and the
    /// head's receipt, recorded only now that its node checked out.
    async fn head_of(
        self: &Arc<Self>,
        c: &Name,
        key: &Writer,
        device: &Name,
    ) -> Option<(Vec<u64>, Receipt)> {
        let data = self.fetch(head_prefix(device, c), true).await?;
        let at = Instant::now();
        let body = match self.accept_head(c, key, device, &data).await {
            Ok(b) => b,
            Err(HeadRefusal::Rollback { seq, seen }) => {
                tracing::warn!(collection = %c, seq, seen, "refused: a head older than one verified, or than a version held (rollback)");
                return None;
            }
            Err(why) => {
                tracing::debug!(name = %data.name, ?why, "refused: a head of a one-key collection");
                return None;
            }
        };
        let receipt = Receipt {
            at,
            freshness: Duration::from_millis(body.freshness),
        };
        let seq = body.seq;
        let node_name = node_name(device, c, seq);
        let node = self.fetch(node_name.clone(), false).await?;
        if wire::implicit_digest(node.raw()) != body.digest {
            tracing::debug!(%node_name, "not the node its head names; ignored");
            return None;
        }
        let nb = node
            .content()
            .and_then(|b| wire::decode_node(b.clone()).ok())?;
        if nb.subject != *c || nb.writer != *key.key() || nb.head != seq || nb.page.is_some() {
            tracing::debug!(%node_name, "a node that does not match its head; ignored");
            return None;
        }
        let listed: Vec<u64> = seqs_of(&nb.entries).collect();
        let mut st = self.st.lock();
        if let Some(h) = st.seen.get_mut(&(c.clone(), key.clone()))
            && h.seq == seq
        {
            h.checked = Some((receipt, listed.clone()));
        }
        let coll = st.colls.entry(c.clone()).or_default();
        coll.entries
            .entry(key.clone())
            .or_default()
            .extend(listed.iter().copied());
        let bound = st.listing(c, key, &nb);
        st.expire(c);
        if let Some(t) = bound {
            self.arm_sweep(&mut st, Keep::Until(t));
        }
        st.apply_ready(c, &BTreeSet::new());
        Some((listed, receipt))
    }

    /// `get(C)` of a one-key collection (spec §5.3): its head, the node it
    /// names, the newest version that node lists — from the store, by
    /// name, or from a holder — aged from that head's receipt. With no head
    /// (or no version) to be had, the newest version held here
    /// ([`Self::newest_held`]): stale, never wrong.
    async fn newest_one_key(
        self: &Arc<Self>,
        c: &Name,
        key: &Writer,
        device: &Name,
    ) -> Result<Answer, DataError> {
        if *key == self.writer {
            let got = self.newest(&self.st.lock(), c)?;
            return Ok(Answer {
                got,
                age: Age::Newest {
                    unconfirmed_for: Duration::ZERO,
                },
            });
        }
        if let Some((listed, receipt)) = self.head_of(c, key, device).await
            && let Some(&newest) = listed.last()
        {
            match self
                .log_entry(&log_name(device, Some(c), newest), false)
                .await
            {
                Ok(Answer {
                    got: Got::Version(v),
                    ..
                }) => {
                    if let Some(h) = self.st.lock().seen.get_mut(&(c.clone(), key.clone()))
                        && h.delivered.is_none_or(|(_, r)| r.at <= receipt.at)
                    {
                        h.delivered = Some((newest, receipt));
                    }
                    return Ok(Answer {
                        got: Got::Version(v),
                        age: receipt.age(),
                    });
                }
                Err(e @ DataError::Expired { .. }) => return Err(e),
                other => {
                    tracing::debug!(collection = %c, newest, ?other, "the newest version its head names is not to be had; answering from what is held");
                }
            }
        }
        self.newest_held(&self.st.lock(), c, key)
    }

    /// `get(C)` of `key`'s one-key collection `c` from the newest version
    /// of the key held here (spec §5.3), its age how long ago it was last
    /// known the newest: from the receipt of the last head of this run that
    /// named it the newest and delivered it. A version no head of this run
    /// named the newest, while a head of the key verified in this run went
    /// past its seq, has no age this device can bound: `Unavailable` (ask
    /// again later). With no such head, the age of a log collection.
    fn newest_held(&self, st: &St, c: &Name, key: &Writer) -> Result<Answer, DataError> {
        let got = self.newest(st, c)?;
        let seq = match &got {
            Got::Version(v) if v.id.writer == *key => Some(v.id.seq.0),
            _ => None,
        };
        let seen = st.seen.get(&(c.clone(), key.clone()));
        if let Some((s, receipt)) = seen.and_then(|h| h.delivered)
            && Some(s) == seq
        {
            return Ok(Answer {
                got,
                age: receipt.age(),
            });
        }
        if let Some(h) = seen.filter(|h| h.this_run && seq.is_none_or(|s| h.seq > s)) {
            tracing::debug!(collection = %c, head = h.seq, held = ?seq, "a head verified in this run went past the newest version held, which no head of this run named the newest: its age is unknown");
            return Err(DataError::Unavailable { name: c.clone() });
        }
        Ok(Answer {
            got,
            age: self.age(st, c),
        })
    }

    /// `get` of an entry's name `<V>/32=entry/seg=<index>` (spec §4.1): the
    /// version `V`, verified as any log entry, and that one entry of it.
    async fn get_entry(
        self: &Arc<Self>,
        name: &Name,
        version: &Name,
        index: u32,
    ) -> Result<Answer, DataError> {
        let a = self.log_entry(version, false).await;
        // An error about the block names what was asked for: the entry.
        let asked = |e: DataError| match e {
            DataError::Expired { keep, .. } => DataError::Expired {
                name: name.clone(),
                keep,
            },
            DataError::Pruned { by, .. } => DataError::Pruned {
                name: name.clone(),
                by,
            },
            DataError::NotFound { .. } => DataError::NotFound { name: name.clone() },
            DataError::Unavailable { .. } => DataError::Unavailable { name: name.clone() },
            DataError::Sealed { .. } => DataError::Sealed { name: name.clone() },
            other => other,
        };
        let Got::Version(v) = self.whole(a).await.map_err(asked)?.got else {
            return Err(DataError::NotFound { name: name.clone() });
        };
        let entry = entries_of(&v)
            .into_iter()
            .nth(index as usize)
            .ok_or_else(|| DataError::NotFound { name: name.clone() })?;
        Ok(Answer {
            got: Got::Entries(Entries {
                collection: v.collection.clone(),
                writer: v.id.writer.clone(),
                entries: vec![entry],
                missing: Vec::new(),
                expired: Vec::new(),
                large: Vec::new(),
            }),
            age: Age::Exact,
        })
    }

    /// One listed block of a range read (spec §5.4), not read whole.
    async fn probe(self: &Arc<Self>, c: &Name, device: &Name, seq: u64) -> Probe {
        let name = log_name(device, Some(c), seq);
        match self.log_entry(&name, false).await {
            Ok(Answer {
                got: Got::Version(v),
                ..
            }) => match v.payload {
                Payload::Large { .. } => Probe::Large(v.id, v.dated),
                _ => Probe::Read(Box::new(v)),
            },
            Err(DataError::Expired { .. }) => match self.st.lock().held.get(&name) {
                Some(Held::Expired(t)) => Probe::Expired(t.first, t.last),
                _ => Probe::Missing,
            },
            Err(DataError::Pruned { .. }) => Probe::Pruned,
            _ => Probe::Missing,
        }
    }

    /// `get` of a range name `<C>/32=range/<R>` of a one-key collection
    /// (spec §5.4): the head, the node it names (its `Entries`: every live
    /// block's seq), then by seq the blocks in the range, or by time a
    /// search of the listed seqs (interpolation on the blocks' dates,
    /// alternating with bisection) for the first block whose last entry is
    /// `≥ from` and the last whose first is `< to`, each probe a block
    /// fetched and verified, then the blocks between. Only those blocks
    /// are fetched: the collection is not followed. It answers within
    /// [`RANGE_LOOKS`] first looks: what was not probed by then is missing.
    async fn get_range(
        self: &Arc<Self>,
        name: &Name,
        c: &Name,
        range: Range,
    ) -> Result<Answer, DataError> {
        let deadline =
            Instant::now().checked_add(self.config.first_look.saturating_mul(RANGE_LOOKS));
        self.peek(c).await?;
        let (key, device) = {
            let st = self.st.lock();
            let Some(coll) = st.colls.get(c) else {
                return Err(DataError::Unavailable { name: name.clone() });
            };
            let Some(m) = coll.members.as_ref() else {
                return Err(DataError::Unavailable { name: name.clone() });
            };
            if m.rule != Rule::OneKey {
                return Err(DataError::BadRequest {
                    name: name.clone(),
                    why: format!(
                        "range reads read one key's stream, and {c} is not a one-key collection; \
                         read its versions by name, or watch it"
                    ),
                });
            }
            let Some(k) = one_key(coll) else {
                return Err(DataError::BadRequest {
                    name: name.clone(),
                    why: format!(
                        "range reads read one key's stream, and the members record of {c} names \
                         no single key <D>/KEY/<id>; its owner names the one key that writes"
                    ),
                });
            };
            if self.sealed_off(&st, c) {
                return Err(DataError::Sealed { name: name.clone() });
            }
            k
        };
        let own = key == self.writer;
        let listed = match own {
            true => None,
            false => self.head_of(c, &key, &device).await,
        };
        let (seqs, age) = {
            let st = self.st.lock();
            let coll = st.colls.get(c);
            let known = || -> Vec<u64> {
                coll.and_then(|x| x.entries.get(&key))
                    .map(|s| s.iter().copied().collect())
                    .unwrap_or_default()
            };
            match (own, listed) {
                (true, _) => (
                    known(),
                    Age::Newest {
                        unconfirmed_for: Duration::ZERO,
                    },
                ),
                (false, Some((l, receipt))) => (l, receipt.age()),
                // No head: what the last head of the one key checked in
                // this run listed, aged from its receipt; else every seq of
                // the key known here, with the age of a log collection.
                (false, None) => match st
                    .seen
                    .get(&(c.clone(), key.clone()))
                    .and_then(|h| h.checked.as_ref())
                    .filter(|(_, l)| !l.is_empty())
                {
                    Some((receipt, l)) => (l.clone(), receipt.age()),
                    None => (known(), self.age(&st, c)),
                },
            }
        };
        // Blocks this device dropped as expired are no longer listed by the
        // writer's node (listing by keep), yet a range read reports them in
        // `expired`: their tombstones place them by seq and by dates.
        let seqs: Vec<u64> = {
            let st = self.st.lock();
            let mut all: BTreeSet<u64> = seqs.into_iter().collect();
            if let Some(known) = st.colls.get(c).and_then(|x| x.entries.get(&key)) {
                all.extend(known.iter().copied().filter(|s| {
                    matches!(
                        st.held.get(&log_name(&device, Some(c), *s)),
                        Some(Held::Expired(_))
                    )
                }));
            }
            all.into_iter().collect()
        };
        let mut probes: HashMap<u64, Probe> = HashMap::new();
        let picked: Vec<u64> = match range {
            Range::Seqs(lo, hi) => seqs.into_iter().filter(|s| (lo..=hi).contains(s)).collect(),
            Range::Times(from, to) => {
                let n = seqs.len();
                if n > 0 {
                    // Anchors for interpolation: the first and the last.
                    let anchors: BTreeSet<u64> = [seqs[0], seqs[n - 1]].into();
                    self.probe_all(
                        c,
                        &device,
                        anchors.into_iter().collect(),
                        &mut probes,
                        deadline,
                    )
                    .await;
                }
                let (lo, _) = self
                    .search(
                        c,
                        &device,
                        &seqs,
                        &mut probes,
                        (0, n),
                        from,
                        deadline,
                        |b| b.1 >= from,
                    )
                    .await;
                let (_, hi) = self
                    .search(c, &device, &seqs, &mut probes, (lo, n), to, deadline, |b| {
                        b.0 >= to
                    })
                    .await;
                seqs[lo..hi].to_vec()
            }
        };
        let todo: Vec<u64> = picked
            .iter()
            .copied()
            .filter(|s| !probes.contains_key(s))
            .collect();
        // What the deadline leaves unprobed is missing.
        self.probe_all(c, &device, todo, &mut probes, deadline)
            .await;
        let id = |s: u64| VersionId {
            writer: key.clone(),
            seq: Seq(s),
        };
        let within = |d: Timestamp| match range {
            Range::Seqs(..) => true,
            Range::Times(from, to) => from <= d && d < to,
        };
        let mut out = Entries {
            collection: c.clone(),
            writer: key.clone(),
            entries: Vec::new(),
            missing: Vec::new(),
            expired: Vec::new(),
            large: Vec::new(),
        };
        for s in picked {
            match probes.remove(&s).unwrap_or(Probe::Missing) {
                Probe::Read(v) => out
                    .entries
                    .extend(entries_of(&v).into_iter().filter(|e| within(e.dated))),
                Probe::Large(vid, dated) if within(dated) => out.large.push(vid),
                Probe::Large(..) => {}
                Probe::Expired(..) => out.expired.push(id(s)),
                Probe::Missing => out.missing.push(id(s)),
                // Its writer dropped it: no longer part of the stream.
                Probe::Pruned => {}
            }
        }
        Ok(Answer {
            got: Got::Entries(out),
            age,
        })
    }

    /// Probe the listed blocks `todo` of a range read (spec §5.4), the
    /// configured window of them at once, into `probes`, until `deadline`
    /// (`None`: none this device's clock can hold). Whether every one was
    /// probed by then.
    async fn probe_all(
        self: &Arc<Self>,
        c: &Name,
        device: &Name,
        todo: Vec<u64>,
        probes: &mut HashMap<u64, Probe>,
        deadline: Option<Instant>,
    ) -> bool {
        let mut fetching = stream::iter(todo)
            .map(|s| async move { (s, self.probe(c, device, s).await) })
            .buffer_unordered(self.config.window.max(1));
        loop {
            let left = deadline.map_or(Duration::MAX, |d| {
                d.saturating_duration_since(Instant::now())
            });
            match rt::timeout(left, fetching.next()).await {
                Ok(Some((s, p))) => {
                    probes.insert(s, p);
                }
                Ok(None) => return true,
                Err(_) => return false,
            }
        }
    }

    /// The first index in `lo..hi` of `seqs` whose block's dates satisfy
    /// `pred` (monotone along the stream for an honest writer), searched by
    /// probing blocks: interpolation on `target` between the nearest known
    /// dates, alternating with bisection so a skewed stream costs at most
    /// twice the bisection's probes. Each round probes the guess alone; only
    /// when it does not answer does the round widen, probing at once the
    /// window's worth of indices nearest it not probed yet
    /// ([`Self::probe_all`]), and take the nearest that answers. When none
    /// answers, the rest of `lo..hi` is not probed: it is counted missing,
    /// and the caller takes it in whole — so a round costs one probe while
    /// probes answer, withheld blocks cost one window more, not a probe
    /// each, and `deadline` bounds the whole. Returns `(lo, hi)` narrowed:
    /// equal when found.
    #[allow(clippy::too_many_arguments)]
    async fn search(
        self: &Arc<Self>,
        c: &Name,
        device: &Name,
        seqs: &[u64],
        probes: &mut HashMap<u64, Probe>,
        (mut lo, mut hi): (usize, usize),
        target: Timestamp,
        deadline: Option<Instant>,
        pred: impl Fn((Timestamp, Timestamp)) -> bool,
    ) -> (usize, usize) {
        let window = self.config.window.max(1);
        let mut round = 0usize;
        while lo < hi {
            round += 1;
            let known = |i: usize, probes: &HashMap<u64, Probe>| probes.get(&seqs[i])?.dates();
            // Interpolate between the nearest known dates around the window.
            let below = (0..lo)
                .rev()
                .find_map(|i| known(i, probes).map(|d| (i, d.1)));
            let above = (hi..seqs.len()).find_map(|i| known(i, probes).map(|d| (i, d.0)));
            let guess = match (round % 2, below, above) {
                (1, Some((i, a)), Some((j, b))) if b > a => {
                    let span = (b.0 - a.0) as u128;
                    let off = (target.0.saturating_sub(a.0) as u128).min(span);
                    let at = i as u128 + (off * (j - i) as u128) / span;
                    (at as usize).clamp(lo, hi - 1)
                }
                _ => lo + (hi - lo) / 2,
            };
            // The guess; on a miss, the nearest indices in the interval, a
            // window of them at once.
            let order = || (guess..hi).chain((lo..guess).rev());
            if !probes.contains_key(&seqs[guess]) {
                self.probe_all(c, device, vec![seqs[guess]], probes, deadline)
                    .await;
            }
            if known(guess, probes).is_none() {
                let batch: Vec<u64> = order()
                    .map(|i| seqs[i])
                    .filter(|s| !probes.contains_key(s))
                    .take(window)
                    .collect();
                self.probe_all(c, device, batch, probes, deadline).await;
            }
            let Some((i, d)) = order().find_map(|i| known(i, probes).map(|d| (i, d))) else {
                for s in &seqs[lo..hi] {
                    probes.entry(*s).or_insert(Probe::Missing);
                }
                return (lo, hi);
            };
            if pred(d) {
                hi = i;
            } else {
                lo = i + 1;
            }
        }
        (lo, hi)
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

/// What a range read found of one listed block (spec §5.4).
enum Probe {
    /// Verified: a block, or a version of one entry.
    Read(Box<Version>),
    /// A version in pieces, and its date: read it by name.
    Large(VersionId, Timestamp),
    /// Expired here: the dates of its first and last entry (`None`: a
    /// sealed block dropped unopened, its last date unknown).
    Expired(Timestamp, Option<Timestamp>),
    /// Pruned by its writer.
    Pruned,
    /// No path answered with it, verified.
    Missing,
}

impl Probe {
    /// The dates of its first and last entry, if known. An expired block
    /// whose last date is unknown may reach any later date: a time search
    /// takes it as overlapping every range from its first entry on, so a
    /// range read lists it under `expired`.
    fn dates(&self) -> Option<(Timestamp, Timestamp)> {
        match self {
            Probe::Read(v) => Some((v.dated, last_dated(v))),
            Probe::Large(_, d) => Some((*d, *d)),
            Probe::Expired(a, b) => Some((*a, b.unwrap_or(Timestamp(u64::MAX)))),
            Probe::Pruned | Probe::Missing => None,
        }
    }
}

/// How an audit checks one piece: the digest the holder's answer must have,
/// and the keep its version's writer signed.
struct Ask {
    piece: Name,
    digest: [u8; 32],
    keep: Keep,
}

/// One ask of an asker device a holder is working on ([`Inner::ask_slot`]).
struct AskSlot<'a> {
    inner: &'a Inner,
    asker: Name,
}

impl Drop for AskSlot<'_> {
    fn drop(&mut self) {
        let mut st = self.inner.st.lock();
        if let Some(n) = st.asks.get_mut(&self.asker) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                st.asks.remove(&self.asker);
            }
        }
    }
}

/// What one audit ask came to (spec §13.3).
enum Asked {
    /// Signed by the holder and the piece: its packet.
    Piece(Bytes),
    /// Signed evidence of a broken promise.
    Breach(Breach),
    /// The holder named a record ending the piece's version, which the
    /// auditor verified and took: not the holder's to keep.
    Excused,
    /// No answer, or none that is evidence: no verdict.
    Unanswered,
}

/// An audit answer judged on its own: a verdict, or a record the holder
/// names as ending the piece's version, for the auditor to verify.
enum Judged {
    Done(Asked),
    PrunedBy(Bytes),
    RefusedBy(Bytes),
}

/// Judge a holder's signed answer to `ask` (`None`: no signed answer came
/// back; `Some(None)`: one that is no answer) (spec §13.3) by this device's
/// clock `now`. A piece that is not the piece, or a signed `Missing`, is
/// evidence. `Expired` — the holder dropped it by its own clock — is
/// evidence only when the keep its writer signed proves it false: kept
/// `Forever`, or `Until(t)` with `t` more than `skew` past `now`. Within the
/// skew, or kept for the last `n` (the holder may know newer versions), it
/// is no answer: an honest holder is not framed by an auditor whose clock is
/// behind (spec §14.1).
fn judge(answer: Option<Option<AuditAnswer>>, ask: &Ask, now: Timestamp, skew: Duration) -> Judged {
    let unexpired = match ask.keep {
        Keep::Forever => true,
        Keep::Until(t) => {
            t.0.saturating_sub(now.0) > u64::try_from(skew.as_millis()).unwrap_or(u64::MAX)
        }
        Keep::LastN(_) => false,
    };
    Judged::Done(match answer {
        Some(Some(AuditAnswer::Expired)) if unexpired => Asked::Breach(Breach::Expired),
        None | Some(Some(AuditAnswer::Expired)) => Asked::Unanswered,
        Some(Some(AuditAnswer::Piece(w))) if wire::implicit_digest(&w) == ask.digest => {
            Asked::Piece(w)
        }
        Some(Some(AuditAnswer::Missing)) => Asked::Breach(Breach::Missing),
        Some(Some(AuditAnswer::PrunedBy(w))) => return Judged::PrunedBy(w),
        Some(Some(AuditAnswer::RefusedBy(w))) => return Judged::RefusedBy(w),
        Some(_) => Asked::Breach(Breach::Wrong),
    })
}

impl Inner {
    // ---- large payloads -----------------------------------------------------------------------

    /// The holder devices to fetch `c`'s packets from by `32=held` when
    /// their writer does not answer: every other device whose lease answers
    /// a hold record held here that names it, live by its own signed date
    /// (capped by keep by its holder) on this device's clock. Unlike the
    /// leases counted for custody ([`Self::live_leases`]) this needs no
    /// version's keep known here: a reader that holds little of `c` (a
    /// range read, a one-key `get`) still finds the holders, and everything
    /// fetched from them is verified as from anywhere else.
    fn holders_of(&self, st: &St, c: &Name) -> Vec<Name> {
        let now = (self.config.clock)();
        let Some(coll) = st.colls.get(c) else {
            return Vec::new();
        };
        coll.leases
            .iter()
            .filter(|(d, l)| {
                **d != self.device
                    && l.body.until > now
                    && coll.holds.values().any(|(_, n, h)| {
                        *n == l.body.hold && h.holders.contains(d) && l.body.until <= h.until
                    })
            })
            .map(|(d, _)| d.clone())
            .collect()
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
    /// which source answered (`None`: its writer by name; `Some(d)`: device
    /// `d` under its own name — a holder of `c`, or, in a merge collection,
    /// a device whose versions are made over the piece's version and so
    /// applied it, [`St::appliers`]). The store answers first whatever
    /// `first` says.
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
        let (holders, appliers) = {
            let st = self.st.lock();
            (self.holders_of(&st, c), st.appliers(c, &strip_piece(name)))
        };
        // An Interest for this device's own name goes nowhere useful: its
        // own pieces it released are asked of the holders only.
        let own = parse_piece_name(name).is_some_and(|p| p.log.device == self.device);
        let mut sources: Vec<Option<Name>> = if own { Vec::new() } else { vec![None] };
        sources.extend(holders.into_iter().map(Some));
        for d in appliers {
            if d != self.device && !sources.contains(&Some(d.clone())) {
                sources.push(Some(d));
            }
        }
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
            // A walk under way when a prune arrived stores nothing of what
            // the prune covers (spec §14).
            let mut st = self.st.lock();
            if pruned_name(&st, &strip_piece(name)).is_some() {
                tracing::debug!(%name, "fetched after its version was pruned; not kept");
                return None;
            }
            if st.expire_named(&strip_piece(name)) {
                tracing::debug!(%name, "fetched after its version expired here; not kept");
                return None;
            }
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

    /// Whether every piece of the large version `v` is in the store (a
    /// presence check: no piece is read).
    fn pieces_held(&self, v: &Name, chunks: &ChunksBody) -> bool {
        piece_names(v, chunks).all(|p| self.store.contains(&p))
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
        // A payload in pieces is one entry: a block always travels inline.
        let fields = match epoch {
            Some(e) => {
                let key = self.st.lock().keys.key(&v.collection, &e).ok_or_else(|| {
                    DataError::Sealed {
                        name: v.name.clone(),
                    }
                })?;
                match seal::open_payload(&key, &v.name, &payload) {
                    Some(Inline::Fields(fields, _)) => fields,
                    _ => return Err(bad()),
                }
            }
            None => {
                wire::decode_payload(Bytes::from(payload))
                    .map_err(|_| bad())?
                    .0
            }
        };
        Ok(Version {
            payload: Payload::Entry(fields),
            ..v
        })
    }

    /// Fetch, in the background, the pieces every merge version held here
    /// waits for ([`St::wanted_pieces`]) — not while a descent is under
    /// way: it fetches them when it ends, once what it brought is taken.
    /// `retry`: also those whose pieces a fetch did not find (asked again
    /// on what may have changed since: a descent, a key, a start).
    fn fetch_wanted(self: &Arc<Self>, retry: bool) {
        let wanted: Vec<(Name, ChunksBody)> = {
            let mut st = self.st.lock();
            if st.descents > 0 {
                return;
            }
            if retry {
                st.unfound.clear();
            }
            st.colls.keys().flat_map(|c| st.wanted_pieces(c)).collect()
        };
        for (v, chunks) in wanted {
            self.spawn_pieces(v, chunks);
        }
    }

    /// Fetch every piece of the large version `v` in the background — as a
    /// holder of its collection, or as a reader of a merge collection whose
    /// version waits for them — then open and apply what waited, and renew
    /// this device's leases.
    fn spawn_pieces(self: &Arc<Self>, v: Name, chunks: ChunksBody) {
        if !self.st.lock().fetching.insert(v.clone()) {
            return;
        }
        let inner = Arc::clone(self);
        rt::spawn(async move {
            let c = parse_log_name(&v).and_then(|l| l.subject);
            let whole = match &c {
                Some(c) => inner.walk_pieces(&v, c, chunks, false).await.is_some(),
                None => false,
            };
            {
                let mut st = inner.st.lock();
                st.fetching.remove(&v);
                match (&c, whole) {
                    (Some(c), true) => {
                        st.unfound.remove(&v);
                        st.pieces_arrived(c, &v);
                    }
                    _ => {
                        tracing::debug!(name = %v, "not every piece of a held version is to be had yet");
                        st.unfound.insert(v.clone());
                    }
                }
            }
            inner.progress.notify_waiters();
            // What it opened (a checkpoint, maybe, covering older versions)
            // or did not find decides which pieces are fetched next.
            inner.fetch_wanted(false);
            inner.renew().await;
        });
    }

    // ---- prune and erasure --------------------------------------------------------------------

    /// Keep a tombstone for each own version among `dropped` that was just
    /// pruned: its summary goes on listing it, by its keep, after a restart.
    fn entomb(&self, dropped: &[(Name, Tomb)]) {
        for (n, tomb) in dropped {
            if parse_log_name(n).is_some_and(|l| l.device == self.device) {
                self.store.insert(tomb_name(n), wire::encode_tomb(tomb));
            }
        }
    }

    // ---- expiry -------------------------------------------------------------------------------

    /// Arm the sweeper for a version kept `keep` just taken, if it is kept
    /// until earlier than the sweeper wakes for.
    fn arm_sweep(&self, st: &mut St, keep: Keep) {
        if let Keep::Until(t) = keep
            && st.sweep_at.is_none_or(|s| t < s)
        {
            st.sweep_at = Some(t);
            self.sweep.notify_one();
        }
    }

    /// Drop what expires on time (spec §14.1): a task that wakes at the
    /// earliest `Keep::Until` this device holds (or when an earlier one
    /// arrives), reads its clock again, and expires what passed. Ends with
    /// the device.
    fn spawn_sweeper(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let sweep = Arc::clone(&self.sweep);
        rt::spawn(async move {
            loop {
                let (next, now) = {
                    let Some(inner) = weak.upgrade() else { return };
                    let mut st = inner.st.lock();
                    let colls: Vec<Name> = st.colls.keys().cloned().collect();
                    let next = colls.iter().filter_map(|c| st.expire(c)).min();
                    st.sweep_at = next;
                    (next, (inner.config.clock)())
                };
                let woken = sweep.notified();
                match next {
                    Some(t) => {
                        let wait = Duration::from_millis(t.0.saturating_sub(now.0).max(1));
                        let _ = rt::timeout(wait, woken).await;
                    }
                    None => woken.await,
                }
            }
        });
    }

    /// Destroy the keys of epochs no version needs any more (spec §14): of
    /// `c`'s own records ([`Self::erase_own`]), and of the records of every
    /// folder at or above `c` ([`Self::erase_folders`]).
    fn erase(&self, st: &mut St, c: &Name) {
        self.erase_own(st, c);
        self.erase_folders(st, c);
    }

    /// Destroy the key of every epoch of `c` whose versions are all pruned
    /// or cut, as the signed records held show (spec §14): not the epoch of
    /// the record in force; at least one of its versions pruned; every
    /// version of `c` this device knows of held (so its epoch is known) and
    /// pruned, refused, or of another epoch; and every writer known to write
    /// into `c` done with the epoch — this device itself, a key the record
    /// in force admits no further version of (cut, or no writer), or one
    /// that wrote a version in the record in force's epoch ([`Coll::left`]).
    /// Until then the erasure is pending: a writer that has not moved on
    /// may still write into the epoch. Erased: [`Self::destroy_key`].
    fn erase_own(&self, st: &mut St, c: &Name) {
        let Some(coll) = st.colls.get(c) else {
            return;
        };
        let Some(members) = coll.members.as_ref() else {
            return;
        };
        let current = members.epoch.clone();
        // Whether writer `w` is done with every epoch before the current
        // one: it writes no more here, or it already wrote in the current.
        let moved_on = |w: &Writer, seqs: &BTreeSet<u64>| {
            *w == self.writer
                || members
                    .refusal(&VersionId {
                        writer: w.clone(),
                        seq: Seq(u64::MAX),
                    })
                    .is_some()
                || seqs.iter().any(|s| {
                    coll.epoch_of(&VersionId {
                        writer: w.clone(),
                        seq: Seq(*s),
                    }) == Some(current.clone())
                })
        };
        let gone: Vec<Epoch> = coll
            .line
            .epochs
            .keys()
            .filter(|e| {
                Some(*e) != current.as_ref()
                    && !coll.erased.contains(e)
                    && st.keys.key(c, e).is_some()
                    && coll.pruned_in(e)
                    && coll.left(e, moved_on)
            })
            .cloned()
            .collect();
        if gone.is_empty() {
            return;
        }
        let coll = st.colls.get_mut(c).expect("held above");
        for e in &gone {
            coll.erased.insert(e.clone());
        }
        for e in gone {
            let marker = erased_name(c, &e);
            self.destroy_key(st, c, &e, marker);
        }
    }

    /// [`Self::erase_folder`] for every folder at or above `c`.
    fn erase_folders(&self, st: &mut St, c: &Name) {
        let folders: Vec<Name> = st
            .folders
            .keys()
            .filter(|f| c.has_prefix(f))
            .cloned()
            .collect();
        for f in folders {
            self.erase_folder(st, &f);
        }
    }

    /// Destroy the key of every epoch of folder `f`'s records that no
    /// collection under it needs any more (spec §14), by the rule of
    /// [`Self::erase_own`] across every collection under `f`: not the
    /// epoch of the folder's record in force; a version sealed in it
    /// pruned in a collection under `f`; in every collection under `f`
    /// known here, every version known pruned, refused, or of another
    /// epoch; and every writer known to write under `f` done with the epoch
    /// — this device, a key the folder's record in force admits no further
    /// version of, or one with a version in the folder's epoch in force in
    /// a collection that reads in it. Until then the erasure is pending; so
    /// it is while a collection under `f` may not be known here — `f` not
    /// followed whole, or a device known to write into its namespace not
    /// walked in full ([`Self::not_walked`]). Erased:
    /// [`Self::destroy_key`], under the folder's own marker.
    fn erase_folder(&self, st: &mut St, f: &Name) {
        let Some(folder) = st.folders.get(f) else {
            return;
        };
        let Some(members) = folder.members.as_ref() else {
            return;
        };
        let current = members.epoch.clone();
        let candidates: Vec<&Epoch> = folder
            .line
            .epochs
            .keys()
            .filter(|e| {
                Some(*e) != current.as_ref()
                    && !folder.erased.contains(e)
                    && st.keys.key(f, e).is_some()
            })
            .collect();
        if candidates.is_empty() {
            return;
        }
        let Some(ns) = namespace_of(f) else {
            return;
        };
        if !st.inside(f)
            || !self
                .not_walked(st, &ns, |_| true, |t| f.has_prefix(t))
                .is_empty()
        {
            tracing::debug!(folder = %f, "folder erasure pending: a collection under it may not be known here");
            return;
        }
        let under: Vec<&Coll> = st
            .colls
            .iter()
            .filter(|(x, _)| x.has_prefix(f) && *x != f)
            .map(|(_, x)| x)
            .collect();
        // Whether writer `w` is done with every epoch of the folder before
        // the one in force.
        let moved_on = |w: &Writer, _: &BTreeSet<u64>| {
            *w == self.writer
                || members
                    .refusal(&VersionId {
                        writer: w.clone(),
                        seq: Seq(u64::MAX),
                    })
                    .is_some()
                || under
                    .iter()
                    .filter(|coll| coll.members.as_ref().is_some_and(|m| m.epoch == current))
                    .any(|coll| {
                        coll.entries.get(w).is_some_and(|seqs| {
                            seqs.iter().any(|s| {
                                coll.epoch_of(&VersionId {
                                    writer: w.clone(),
                                    seq: Seq(*s),
                                }) == Some(current.clone())
                            })
                        })
                    })
        };
        let gone: Vec<Epoch> = candidates
            .into_iter()
            .filter(|e| {
                under.iter().any(|coll| coll.pruned_in(e))
                    && under.iter().all(|coll| coll.left(e, moved_on))
            })
            .cloned()
            .collect();
        if gone.is_empty() {
            return;
        }
        let folder = st.folders.get_mut(f).expect("held above");
        for e in &gone {
            folder.erased.insert(e.clone());
        }
        for e in gone {
            let marker = erased_folder_name(f, &e);
            self.destroy_key(st, f, &e, marker);
        }
    }

    /// Destroy the key of epoch `e` of `subject`'s records (a collection's,
    /// or a folder's): the held key, the key this device made, every grant
    /// it keeps of that epoch, stored or signed for others; and keep
    /// `marker` in the store, so a restart refuses the key if granted again
    /// (spec §14).
    fn destroy_key(&self, st: &mut St, subject: &Name, e: &Epoch, marker: Name) {
        self.store.insert(marker, Bytes::new());
        st.keys.forget(subject, e);
        self.store.remove(&made_key_name(&self.device, subject, e));
        for (n, _) in self.store.scan_under(&Name::root(), 0) {
            if let Some((_, ask)) = parse_grant_name(&n)
                && ask.collection == *subject
                && ask.epoch == *e
            {
                self.store.remove(&n);
            }
        }
        st.grants.retain(|n| {
            parse_grant_name(n).is_none_or(|(_, ask)| ask.collection != *subject || ask.epoch != *e)
        });
        tracing::info!(%subject, epoch = ?e, "erased: every writer's versions of the epoch are pruned or cut; its key is destroyed");
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
            && let Some(l) = coll.leases.get(&self.device)
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

    /// Fetch back what this holder lost of `c` of what its accepted hold
    /// record asks: records from what it holds in memory, pieces from their
    /// writer or other holders.
    async fn repair_held(self: &Arc<Self>, c: &Name) {
        let large: Vec<(Name, ChunksBody)> = {
            let st = self.st.lock();
            let (Some(coll), Some(h)) = (st.colls.get(c), st.holding.get(c)) else {
                return;
            };
            let Some(m) = coll.members.as_ref() else {
                return;
            };
            let mut large = Vec::new();
            let asked = |id: &VersionId| h.at.contains(id) && m.refusal(id).is_none();
            for hv in coll.versions.values().filter(|hv| asked(&hv.version.id)) {
                if !self.store.contains(&hv.version.name) {
                    self.store.insert(hv.version.name.clone(), hv.wire.clone());
                }
                if let Some(ch) = hv.chunks {
                    large.push((hv.version.name.clone(), ch));
                }
            }
            for l in &coll.locked {
                let id = VersionId {
                    writer: l.writer.clone(),
                    seq: Seq(l.seq),
                };
                if !asked(&id) {
                    continue;
                }
                if !self.store.contains(&l.name) {
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

    /// The device an ask's proof claims asks, by its key locator, and the
    /// proof's packet: unverified, for the checks that cost nothing.
    fn claimed_asker(proof: &Bytes) -> Option<(Data, Name)> {
        let data = Data::decode(proof.clone()).ok()?;
        let key = data.sig_info()?.key_locator_name()?;
        let asker = device_of(&key)?;
        Some((data, asker))
    }

    /// Whether `proof` is `asker`'s, for the ask whose binding is
    /// `binding`: named `<asker>/32=ask/<binding>` and signed by a key of
    /// `asker` that verifies to a trust anchor. At most [`ASKS_VERIFYING`]
    /// proofs are verified at once.
    async fn proves(&self, proof: &Data, asker: &Name, binding: &[u8; 32]) -> bool {
        if *proof.name != wire::ask_name(asker, binding) {
            return false;
        }
        let Ok(_turn) = self.verifying.acquire().await else {
            return false;
        };
        self.verify(proof)
            .await
            .is_ok_and(|w| device_of(w.key()).as_ref() == Some(asker))
    }

    /// Count one more ask of `asker` in progress, if it has fewer than
    /// `limit`; the slot is given back when dropped.
    fn ask_slot(&self, asker: &Name, limit: usize) -> Option<AskSlot<'_>> {
        let mut st = self.st.lock();
        let n = st.asks.entry(asker.clone()).or_default();
        if *n >= limit {
            tracing::debug!(%asker, "ask refused: the asker has as many in progress as it may");
            return None;
        }
        *n += 1;
        Some(AskSlot {
            inner: self,
            asker: asker.clone(),
        })
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

    /// Answer a hold ask (spec §13.2): from the owner device that signed
    /// the hold record it names (its proof verified), for a namespace this
    /// device holds for, a record naming this device a holder and asking
    /// past now. Hold the collection, take it and every piece of it inside
    /// the record's frontier (fetching back what was lost), and answer with
    /// the lease, signed. One ask of each asker at a time; the same ask
    /// asked again gets the same answer. `None` (a Nack) otherwise, and a
    /// stranger's ask costs nothing but its parse.
    async fn accept_hold(self: &Arc<Self>, name: &Name, ask: HoldAsk) -> Option<Bytes> {
        if let Some(r) = self.st.lock().answers.get(name) {
            return Some(r.clone());
        }
        let record = &ask.record;
        let parsed = parse_log_name(record)?;
        let c = parsed.subject.clone()?;
        let ns = namespace_of(&c)?;
        if !self.config.hold_for.contains(&ns) {
            tracing::debug!(collection = %c, "hold refused: this device holds for none of its namespace");
            return None;
        }
        let (proof, asker) = Self::claimed_asker(&ask.asker)?;
        if asker != parsed.device {
            tracing::debug!(%record, %asker, "hold refused: only the device that signed the hold record asks for it");
            return None;
        }
        let _slot = self.ask_slot(&asker, HOLDS_PER_ASKER)?;
        if !self
            .proves(&proof, &asker, &ask.binding(&self.device))
            .await
        {
            tracing::debug!(%record, %asker, "hold refused: the asker's proof does not verify");
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
            tracing::debug!(%record, "hold refused: not an owner device's newest hold record");
            return None;
        };
        if !body.holders.contains(&self.device) {
            tracing::debug!(%record, "hold refused: the record does not name this device a holder");
            return None;
        }
        if body.until <= (self.config.clock)() {
            tracing::debug!(%record, "hold refused: it asks for nothing past now");
            return None;
        }
        {
            let mut st = self.st.lock();
            let h = st.holding.entry(c.clone()).or_insert_with(|| Holding {
                hold: record.clone(),
                until: body.until,
                at: body.at.clone(),
                lease: None,
            });
            h.hold = record.clone();
            h.until = body.until;
            h.at = body.at.clone();
        }
        self.look(&c).await.ok()?;
        // See what every device writing into the namespace has now: the
        // asker moved since a first look, and another holder's lease names
        // where a lost piece may still be (re-replication).
        let devices = self.known_for(&self.st.lock(), &ns);
        futures::future::join_all(devices.iter().map(|d| self.refresh(&ns, d))).await;
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
        // The lease is an own log entry, and what it says is held is in the
        // store: answered once both are durable (spec §4.2).
        let seq = Data::decode(lease.clone())
            .ok()
            .and_then(|d| parse_log_name(&d.name))?
            .seq;
        if !self.published(seq).await {
            return None;
        }
        let reply = DataBuilder::new(name.clone(), &lease).sign_digest_sha256();
        self.st.lock().answers.insert(name.clone(), reply.clone());
        Some(reply)
    }

    /// Answer an audit ask of a collection this device holds (spec §13.3),
    /// from an owner device whose hold record held here names this device a
    /// holder (its proof verified): the piece asked for, from the store;
    /// to a `whole` ask, the proof over every piece of the version; else
    /// why it is not held — the prune record that ended its version, the
    /// members record that refuses it, or that it is missing. Signed by the
    /// device key, under the ask's own name, so no cache answers it and
    /// nothing answers it but this device; the same ask asked again gets
    /// the same packet. `None` (a Nack) otherwise, at no signature's cost.
    async fn audit_answer(self: &Arc<Self>, name: &Name, ask: &AuditAsk) -> Option<Bytes> {
        if let Some(r) = self.st.lock().answers.get(name) {
            return Some(r.clone());
        }
        let log =
            parse_log_name(&ask.piece).or_else(|| parse_piece_name(&ask.piece).map(|p| p.log))?;
        let c = log.subject?;
        let (proof, asker) = Self::claimed_asker(&ask.asker)?;
        {
            let st = self.st.lock();
            let owner = st.holding.contains_key(&c)
                && st.colls.get(&c).is_some_and(|coll| {
                    coll.holds.iter().any(|(w, (_, _, b))| {
                        device_of(w.key()).as_ref() == Some(&asker)
                            && b.holders.contains(&self.device)
                    })
                });
            if !owner {
                tracing::debug!(collection = %c, %asker, "audit refused: no hold record held here from the asker names this device");
                return None;
            }
        }
        let _slot = self.ask_slot(&asker, AUDITS_PER_ASKER)?;
        if !self
            .proves(&proof, &asker, &ask.binding(&self.device))
            .await
        {
            tracing::debug!(collection = %c, %asker, "audit refused: the asker's proof does not verify");
            return None;
        }
        // What the answer proves held is answered once the store holds it
        // durably (spec §4.2): a power loss does not take what a holder
        // just proved it keeps.
        if !self.barrier().await {
            return None;
        }
        let answer = self.audit_content(&c, ask);
        let wire = self
            .sign(
                DataBuilder::new(name.clone(), &wire::encode_audit_answer(&answer))
                    .freshness(Duration::ZERO),
            )
            .ok()?;
        self.st.lock().answers.insert(name.clone(), wire.clone());
        Some(wire)
    }

    /// What this holder answers `ask` of `c` with ([`Self::audit_answer`]).
    fn audit_content(&self, c: &Name, ask: &AuditAsk) -> AuditAnswer {
        let mut st = self.st.lock();
        let version = strip_piece(&ask.piece);
        // Dropped as expired by this device's own clock: it says so, which
        // is evidence only if the version's signed keep proves it false
        // (spec §13.3).
        if st.expire_named(&version) {
            return AuditAnswer::Expired;
        }
        let prune = pruned_name(&st, &version).or_else(|| match st.held.get(&version) {
            Some(Held::Pruned(p)) => Some(p.clone()),
            _ => None,
        });
        if let Some(p) = prune {
            return match self.store.get(&p.name) {
                Some(w) => AuditAnswer::PrunedBy(w),
                None => AuditAnswer::Missing,
            };
        }
        if matches!(
            st.refused.get(&version),
            Some(Refusal::NotMember | Refusal::OutsideCut(_))
        ) && let Some(coll) = st.colls.get(c)
        {
            // An owner-signed record this holder holds of the revision in
            // force that refuses the version, which the auditor checks: of
            // the first level that refuses it — the collection, or a folder
            // above it (spec §6) — else of the collection.
            let id = version_id(coll, &version);
            let lines = std::iter::once(&coll.line).chain(st.folder_lines_above(c));
            let refusing = lines
                .filter(|line| {
                    line.own.as_ref().is_some_and(|m| {
                        !m.writers.is_empty()
                            && id.as_ref().is_some_and(|id| m.refusal_in(c, id).is_some())
                    })
                })
                .chain(std::iter::once(&coll.line));
            let record = refusing
                .flat_map(|line| line.records.values().map(|(seq, m)| (*seq, m)))
                .find_map(|(seq, m)| {
                    let device = device_of(m.owner.key())?;
                    self.store.get(&log_name(&device, Some(&m.collection), seq))
                });
            if let Some(w) = record {
                return AuditAnswer::RefusedBy(w);
            }
        }
        if !ask.whole {
            return self
                .store
                .get(&ask.piece)
                .map_or(AuditAnswer::Missing, AuditAnswer::Piece);
        }
        let chunks = st.colls.get(c).and_then(|coll| {
            coll.versions
                .values()
                .find(|hv| hv.version.name == version)
                .map(|hv| hv.chunks)
                .or_else(|| {
                    coll.locked
                        .iter()
                        .find(|l| l.name == version)
                        .map(|l| l.body.chunks)
                })
        });
        drop(st);
        // A version inline is whole in its record alone.
        let Some(chunks) = chunks else {
            return AuditAnswer::Missing;
        };
        let mut wires = Vec::new();
        let pieces = chunks.iter().flat_map(|ch| piece_names(&version, ch));
        for n in std::iter::once(version.clone()).chain(pieces) {
            match self.store.get(&n) {
                Some(w) => wires.push(w),
                None => return AuditAnswer::Missing,
            }
        }
        AuditAnswer::Proof(wire::version_proof(
            &ask.nonce,
            wires.iter().map(|w| w.as_ref()),
        ))
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

    /// Every piece the lease of holder device `holder` on `c` promises
    /// (spec §13.3): of each version inside it that applies by this device's
    /// records and whose keep has not passed, its log entry and, in pieces,
    /// every manifest node and chunk — each with the digest the holder's
    /// answer must have. Manifest nodes not in the store are fetched
    /// (checked against the record) to learn the chunks' digests, from the
    /// writer, the holders, and at last from the audited holder itself
    /// through an audit ask: its answer is evidence like any other. A node
    /// no one produces leaves the audit unverified, never passed.
    async fn promised(self: &Arc<Self>, c: &Name, holder: &Name) -> Promised {
        let now = (self.config.clock)();
        let mut out = Promised::default();
        let versions: Vec<(Name, [u8; 32], Option<ChunksBody>, Keep)> = {
            let st = self.st.lock();
            let Some(coll) = st.colls.get(c) else {
                return out;
            };
            let Some(lease) = coll.leases.get(holder) else {
                return out;
            };
            let mut list = Vec::new();
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
                    list.push((name, wire::implicit_digest(&w), chunks, keep));
                }
            }
            list
        };
        'versions: for (name, digest, chunks, keep) in versions {
            let Some(chunks) = chunks else {
                out.asks.push(Ask {
                    piece: name,
                    digest,
                    keep,
                });
                continue;
            };
            let shape = Shape::of(chunks.size);
            let mut digests: HashMap<PieceKind, [u8; 32]> = HashMap::new();
            digests.insert(PieceKind::Manifest(0), chunks.root);
            for k in shape.manifests() {
                let kind = PieceKind::Manifest(k);
                let Some(expected) = digests.get(&kind).copied() else {
                    continue 'versions;
                };
                let node = piece_name(&name, kind);
                let ask = Ask {
                    piece: node.clone(),
                    digest: expected,
                    keep,
                };
                let w = match self.get_piece(c, &node, &expected).await {
                    Some(w) => w,
                    None => match self.check_piece(c, holder, &ask).await {
                        Asked::Piece(w) => w,
                        Asked::Breach(breach) => {
                            out.broken.get_or_insert((node, breach));
                            continue 'versions;
                        }
                        Asked::Excused => continue 'versions,
                        Asked::Unanswered => {
                            tracing::debug!(%name, "no one produces its manifest: the audit is unverified");
                            out.unverified += 1;
                            continue 'versions;
                        }
                    },
                };
                let Some(listed) = pieces::open_node(&shape, k, &w, &expected) else {
                    tracing::debug!(%name, "its writer's manifest does not list its chunks; not audited");
                    continue 'versions;
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
            out.asks.push(Ask {
                piece: name.clone(),
                digest,
                keep,
            });
            let mut pieces: Vec<(PieceKind, [u8; 32])> = digests.into_iter().collect();
            pieces.sort();
            out.asks.extend(pieces.into_iter().map(|(k, d)| Ask {
                piece: piece_name(&name, k),
                digest: d,
                keep,
            }));
        }
        out
    }

    /// Ask holder device `holder` for `piece` under a fresh nonce, with this
    /// device's proof of asking; or, `whole`, for the proof over every
    /// piece of the version `piece` names. The nonce asked under, and the
    /// answer: `None` when no answer signed by the holder came back,
    /// `Some(None)` when one did that is no answer.
    async fn ask_holder(
        &self,
        holder: &Name,
        piece: &Name,
        whole: bool,
    ) -> Option<([u8; wire::NONCE_LEN], Option<AuditAnswer>)> {
        let mut ask = AuditAsk {
            nonce: self.nonce(),
            piece: piece.clone(),
            whole,
            asker: Bytes::new(),
        };
        ask.asker = self.ask_proof(&ask.binding(holder))?;
        let name = audit_ask_name(holder, &ask);
        let data = self.fetch(name.clone(), false).await?;
        if *data.name != name {
            return None;
        }
        let signer = self.verify(&data).await.ok()?;
        if device_of(signer.key()).as_ref() != Some(holder) {
            return None;
        }
        let answer = data
            .content()
            .and_then(|b| wire::decode_audit_answer(b.clone()).ok());
        Some((ask.nonce, answer))
    }

    /// Ask `holder` for the piece of `c` that `ask` names, and judge the
    /// answer (spec §13.3): the piece; a signed `Missing`, bytes that are
    /// not the piece, or `Expired` that the piece's keep proves false —
    /// evidence, as this device's records say the piece should be there; a
    /// record the holder names as ending the piece's version, which this
    /// device verifies and takes: excused when it does end it, evidence when
    /// a verified prune does not; or nothing that is evidence.
    async fn check_piece(self: &Arc<Self>, c: &Name, holder: &Name, ask: &Ask) -> Asked {
        let answer = self
            .ask_holder(holder, &ask.piece, false)
            .await
            .map(|(_, a)| a);
        let now = (self.config.clock)();
        match judge(answer, ask, now, self.config.clock_skew) {
            Judged::Done(asked) => asked,
            Judged::PrunedBy(w) => self.excused_by_prune(c, &ask.piece, w).await,
            Judged::RefusedBy(w) => self.excused_by_members(c, &ask.piece, w).await,
        }
    }

    /// A holder's answer that the prune record `wire` ended `piece`'s
    /// version: verified and taken, it excuses the piece if it covers it.
    async fn excused_by_prune(self: &Arc<Self>, c: &Name, piece: &Name, wire: Bytes) -> Asked {
        let version = strip_piece(piece);
        let Ok(data) = Data::decode(wire) else {
            return Asked::Breach(Breach::Wrong);
        };
        let name = (*data.name).clone();
        let (Some(p), Some(v)) = (parse_log_name(&name), parse_log_name(&version)) else {
            return Asked::Breach(Breach::Wrong);
        };
        if p.device != v.device || p.subject.as_ref() != Some(c) {
            // Only the version's own writer prunes it.
            return Asked::Breach(Breach::Wrong);
        }
        if self.take_data(&name, data).await.is_err() {
            // Not verified here (yet): no verdict either way.
            return Asked::Unanswered;
        }
        if pruned_name(&self.st.lock(), &version).is_some() {
            Asked::Excused
        } else {
            Asked::Breach(Breach::Wrong)
        }
    }

    /// A holder's answer that the members record `wire` — of the collection,
    /// or of a folder above it (spec §6) — refuses `piece`'s version:
    /// verified and taken, it excuses the piece if the record in force here
    /// now refuses the version; if it still admits it, the two devices'
    /// views differ and nothing is evidence.
    async fn excused_by_members(self: &Arc<Self>, c: &Name, piece: &Name, wire: Bytes) -> Asked {
        let version = strip_piece(piece);
        let Ok(data) = Data::decode(wire) else {
            return Asked::Breach(Breach::Wrong);
        };
        let name = (*data.name).clone();
        if parse_log_name(&name).is_none_or(|l| l.subject.is_none_or(|s| !c.has_prefix(&s))) {
            return Asked::Breach(Breach::Wrong);
        }
        if self.take_data(&name, data).await.is_err() {
            return Asked::Unanswered;
        }
        let st = self.st.lock();
        let refused = st.colls.get(c).is_some_and(|coll| {
            version_id(coll, &version).is_some_and(|id| {
                coll.members
                    .as_ref()
                    .is_some_and(|m| m.refusal(&id).is_some())
            })
        });
        if refused {
            Asked::Excused
        } else {
            Asked::Unanswered
        }
    }

    /// Audit the lease of holder device `holder` on `c` (spec §13.3): ask
    /// for random pieces of what it promises, each under a fresh nonce, and
    /// judge every answer ([`Self::check_piece`]). Broken on evidence;
    /// unanswered when an ask got no answer that is evidence, or a version's
    /// pieces could not be listed; kept otherwise. The verdict is kept with
    /// the lease.
    async fn audit(self: &Arc<Self>, c: &Name, holder: &Name) -> Audit {
        let promised = self.promised(c, holder).await;
        let mut all = promised.asks;
        let k = self.config.audit_pieces.min(all.len());
        let mut picked = Vec::with_capacity(k);
        for _ in 0..k {
            let i = self.draw(all.len());
            picked.push(all.swap_remove(i));
        }
        let answers: Vec<(Name, Asked)> = stream::iter(picked)
            .map(|a| async move {
                let asked = self.check_piece(c, holder, &a).await;
                (a.piece, asked)
            })
            .buffer_unordered(self.config.window)
            .collect()
            .await;
        let asked = answers.len() as u32 + promised.unverified;
        let answered = answers
            .iter()
            .filter(|(_, a)| matches!(a, Asked::Piece(_)))
            .count() as u32;
        let unanswered =
            promised.unverified > 0 || answers.iter().any(|(_, a)| matches!(a, Asked::Unanswered));
        let breach = promised
            .broken
            .into_iter()
            .chain(answers.into_iter().filter_map(|(p, a)| match a {
                Asked::Breach(b) => Some((p, b)),
                _ => None,
            }))
            .min_by(|a, b| a.0.cmp(&b.0));
        let audit = match breach {
            Some((piece, breach)) => Audit::Broken { piece, breach },
            None if unanswered => Audit::Unanswered { asked, answered },
            None => Audit::Kept { pieces: answered },
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
        tracing::debug!(collection = %c, %holder, ?audit, "audited");
        audit
    }

    /// Ask holder device `holder` to hold `c` under the hold record
    /// `record`, with this device's proof of asking; whether it answered
    /// with a lease, which is then taken.
    async fn ask_hold(self: &Arc<Self>, holder: &Name, record: &Name) -> bool {
        // The holder fetches the record from this device, which serves it
        // once it is durable (spec §4.2).
        if let Some(l) = parse_log_name(record)
            && l.device == self.device
            && !self.published(l.seq).await
        {
            return false;
        }
        let mut ask = HoldAsk {
            record: record.clone(),
            nonce: self.nonce(),
            asker: Bytes::new(),
        };
        let Some(proof) = self.ask_proof(&ask.binding(holder)) else {
            return false;
        };
        ask.asker = proof;
        let name = hold_ask_name(holder, &ask);
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

    /// Whether holder device `holder` proves, to a fresh `whole` audit ask,
    /// that it keeps version `v` whole — its record and, in pieces
    /// (`chunks`), every piece (spec §13.3, release): its signed proof is
    /// the one this device computes from its own copy. Why not, if not.
    async fn proves_kept(
        &self,
        holder: &Name,
        v: &Name,
        chunks: Option<&ChunksBody>,
    ) -> Result<(), String> {
        let Some((nonce, answer)) = self.ask_holder(holder, v, true).await else {
            return Err(format!("{holder} did not answer"));
        };
        let proof = match answer {
            Some(AuditAnswer::Proof(p)) => p,
            Some(AuditAnswer::Missing) => {
                return Err(format!("{holder} signed that it does not keep every piece"));
            }
            Some(AuditAnswer::PrunedBy(_) | AuditAnswer::RefusedBy(_)) => {
                return Err(format!(
                    "{holder} keeps none of it, naming a record that ends it"
                ));
            }
            Some(AuditAnswer::Expired) => {
                return Err(format!("{holder} dropped it as expired by its clock"));
            }
            _ => return Err(format!("{holder} signed an answer that is no proof")),
        };
        let mut wires = Vec::new();
        let pieces = chunks.iter().flat_map(|ch| piece_names(v, ch));
        for n in std::iter::once(v.clone()).chain(pieces) {
            match self.store.get(&n) {
                Some(w) => wires.push(w),
                None => {
                    return Err("this device no longer holds every piece to check against".into());
                }
            }
        }
        if wire::version_proof(&nonce, wires.iter().map(|w| w.as_ref())) == proof {
            Ok(())
        } else {
            Err(format!("{holder}'s proof is not of the version's pieces"))
        }
    }

    /// The holder devices whose leases of `c` this device counts (spec
    /// §13.2): not this device, live by its clock, answering a hold record
    /// held here that names the device, and not refused. One per device.
    fn live_leases(&self, st: &St, c: &Name) -> Vec<Name> {
        let now = (self.config.clock)();
        let Some(coll) = st.colls.get(c) else {
            return Vec::new();
        };
        coll.leases
            .iter()
            .filter(|(d, l)| {
                **d != self.device && l.body.until > now && {
                    let why = lease_refusal(coll, d, &l.body);
                    if let Some(why) = why {
                        tracing::debug!(lease = %l.name, "lease not counted: {why}");
                    }
                    why.is_none()
                }
            })
            .map(|(d, _)| d.clone())
            .collect()
    }

    fn lease_of(&self, st: &St, c: &Name, holder: &Name) -> Option<Lease> {
        let l = st.colls.get(c)?.leases.get(holder)?;
        Some(Lease {
            holder: l.writer.clone(),
            name: l.name.clone(),
            prefix: c.clone(),
            holds: l.body.holds.clone(),
            until: l.body.until,
            audit: l.audit.clone(),
        })
    }
}

/// What a lease's audit asks for ([`Inner::promised`]).
#[derive(Default)]
struct Promised {
    /// The pieces to draw from.
    asks: Vec<Ask>,
    /// Evidence found while listing them: a manifest node the holder signed
    /// it does not hold, or that is not the node.
    broken: Option<(Name, Breach)>,
    /// Versions whose pieces no one could list: the audit cannot pass.
    unverified: u32,
}

/// The id of the version named `name` of `coll`, if this device holds it in
/// any state (applied, waiting, refused, locked).
fn version_id(coll: &Coll, name: &Name) -> Option<VersionId> {
    coll.versions
        .values()
        .chain(&coll.waiting)
        .chain(&coll.outsiders)
        .find(|hv| hv.version.name == *name)
        .map(|hv| hv.version.id.clone())
        .or_else(|| {
            coll.locked
                .iter()
                .find(|l| l.name == *name)
                .map(|l| VersionId {
                    writer: l.writer.clone(),
                    seq: Seq(l.seq),
                })
        })
}

/// Whether `coll` holds version `id` in any state (applied, waiting,
/// refused, locked).
fn holds_entry(coll: &Coll, id: &VersionId) -> bool {
    coll.versions.contains_key(id)
        || coll
            .waiting
            .iter()
            .chain(&coll.outsiders)
            .any(|hv| hv.version.id == *id)
        || coll
            .locked
            .iter()
            .any(|l| l.writer == id.writer && l.seq == id.seq.0)
}

/// Take out of `coll` every version `gone` picks (by id and keep), in any
/// state: with its name, what it leaves, and its epoch.
fn take_out(
    coll: &mut Coll,
    gone: impl Fn(&VersionId, Keep) -> bool,
) -> Vec<(VersionId, Name, Tomb, Option<Epoch>)> {
    let mut out = Vec::new();
    let ids: Vec<VersionId> = coll
        .versions
        .values()
        .filter(|hv| gone(&hv.version.id, hv.version.keep))
        .map(|hv| hv.version.id.clone())
        .collect();
    for id in ids {
        let hv = coll.versions.remove(&id).expect("listed above");
        coll.pending.remove(&id);
        out.push((
            id,
            hv.version.name.clone(),
            tomb_of(&hv.version),
            hv.epoch.clone(),
        ));
    }
    for list in [&mut coll.waiting, &mut coll.outsiders] {
        list.retain(|hv| {
            if !gone(&hv.version.id, hv.version.keep) {
                return true;
            }
            out.push((
                hv.version.id.clone(),
                hv.version.name.clone(),
                tomb_of(&hv.version),
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
        if !gone(&id, l.body.keep) {
            return true;
        }
        // Sealed and never opened: its last entry's date is unknown.
        let tomb = Tomb {
            writer: l.writer.key().clone(),
            keep: l.body.keep,
            first: l.body.dated,
            last: None,
        };
        out.push((id, l.name.clone(), tomb, Some(l.epoch().clone())));
        false
    });
    out
}

/// A sealed payload opened: its fields and operation, or its block, into
/// the record's body.
fn open_into(body: &mut VersionBody, opened: Inline) {
    match opened {
        Inline::Fields(fields, op) => {
            body.fields = fields;
            body.op = op;
        }
        Inline::Block(entries) => body.block = Some(entries),
    }
}

/// Why a reader does not count holder device `holder`'s lease (spec
/// §13.2), if it does not: the owner's hold record it answers is not held,
/// does not name the device a holder, or is passed by the lease's date; or
/// the lease promises past the latest keep of the versions it holds (or that
/// keep is not known yet).
fn lease_refusal(coll: &Coll, holder: &Name, l: &LeaseBody) -> Option<&'static str> {
    let Some((_, _, hold)) = coll.holds.values().find(|(_, n, _)| *n == l.hold) else {
        return Some("the owner's hold record it answers is not held here");
    };
    if !hold.holders.contains(holder) {
        return Some("the owner's hold record it answers does not name its device a holder");
    }
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
/// with, pruned it. A prune covers versions only: a record or snapshot held
/// under the name is covered by none.
fn pruned_name(st: &St, name: &Name) -> Option<Prune> {
    if matches!(
        st.held.get(name),
        Some(Held::Record { .. } | Held::Snapshot(_))
    ) {
        return None;
    }
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

/// The prefix a revocation cut's range names for the log entry `entry`:
/// its collection's log `<D>/32=log/<C>` (or `<D>/32=log`, a snapshot),
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
/// runs for that log, in collection `C` (of the snapshot log `<D>/32=log`,
/// under that prefix), signed by the context's anchor key (spec §8). Empty
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

/// The packet of the log entry `name` held here, opened or sealed.
fn held_wire(st: &St, name: &Name) -> Option<Bytes> {
    let coll = st.colls.get(&parse_log_name(name)?.subject?)?;
    coll.versions
        .values()
        .chain(&coll.waiting)
        .chain(&coll.outsiders)
        .find(|hv| hv.version.name == *name)
        .map(|hv| hv.wire.clone())
        .or_else(|| {
            coll.locked
                .iter()
                .find(|l| l.name == *name)
                .map(|l| l.wire.clone())
        })
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
        group: body.group,
        rule: body.rule,
        payload: match (body.chunks, body.block) {
            (Some(c), _) => Payload::Large { size: c.size },
            (None, Some(entries)) => Payload::Block(
                entries
                    .into_iter()
                    .map(|e| BlockEntry {
                        dated: Timestamp(body.dated.0.saturating_add(e.offset)),
                        content: e.fields,
                    })
                    .collect(),
            ),
            (None, None) => Payload::Entry(body.fields),
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

impl Device {
    /// [`DataLayer::put_group`]: every check first — the items, then each
    /// collection's record in force (looked at, and its key obtained), then
    /// each item's operation by its rule — and only once all pass, under
    /// one lock: the records this namespace's collections without one need
    /// ([`Inner::default_members`]), then the group, at consecutive seqs.
    /// Refused, nothing is written: no seq taken, nothing stored or
    /// published (spec §5.5).
    async fn put_items(
        &self,
        items: Vec<(Name, Edit)>,
        options: PutOptions,
    ) -> Result<Vec<VersionId>, DataError> {
        let inner = &self.inner;
        let refuse = |name: &Name, why: String| DataError::BadRequest {
            name: name.clone(),
            why,
        };
        let Some((first, _)) = items.first() else {
            return Err(refuse(
                &inner.device,
                "a group holds at least one version, and put_group was given none; put_group \
                 with one item or more"
                    .into(),
            ));
        };
        let count = match u32::try_from(items.len()) {
            Ok(n) if n <= GROUP_MAX => n,
            _ => {
                return Err(refuse(
                    first,
                    format!(
                        "a group holds at most {GROUP_MAX} versions, and put_group was given {}; \
                         split it into groups a reader may count apart",
                        items.len()
                    ),
                ));
            }
        };
        if options.batch.is_some() {
            return Err(refuse(
                first,
                "a group is signed at once, never batched into blocks; put_group without batch"
                    .into(),
            ));
        }
        if options.keep != Keep::Forever {
            return Err(refuse(
                first,
                format!(
                    "a group's versions are kept until pruned, and put_group was given keep {:?}: \
                     a member that expires would leave a reader that never held it unable to \
                     tell the group complete; put_group with Keep::Forever, or put the items \
                     that expire one by one",
                    options.keep
                ),
            ));
        }
        let folder = folder_of(first);
        let mut seen = BTreeSet::new();
        for (c, _) in &items {
            check_collection(c)?;
            if !seen.insert(c.clone()) {
                return Err(refuse(
                    c,
                    format!(
                        "{c} comes twice in the group, which holds one version per collection; \
                         merge the two items into one"
                    ),
                ));
            }
            if folder_of(c) != folder {
                return Err(refuse(
                    c,
                    format!(
                        "{c} is not in {folder}, where {first} is: a group's collections are all \
                         of one folder; put the items of other folders in groups of their own"
                    ),
                ));
            }
        }
        // Each collection's record in force, looked at as `put` looks; a
        // collection of this namespace with none gets the host's default,
        // signed only once everything passes.
        let mut fresh = BTreeSet::new();
        let mut keys = Vec::with_capacity(items.len());
        for (c, _) in &items {
            let ns = namespace_of(c).expect("checked above");
            inner.look(c).await?;
            inner.st.lock().ensure(c, &inner.config.rules, inner.me());
            if ns != inner.ns {
                let c = c.clone();
                inner
                    .wait_for(|st| st.colls.get(&c).is_some_and(|coll| coll.members.is_some()))
                    .await;
            }
            let has = {
                let mut st = inner.st.lock();
                st.ensure(c, &inner.config.rules, inner.me());
                st.colls.get(c).is_some_and(|x| x.members.is_some())
            };
            if has {
                keys.push(inner.write_key(c).await?);
                continue;
            }
            if ns != inner.ns {
                let heard = !inner.known_for(&inner.st.lock(), &ns).is_empty();
                return Err(if heard {
                    DataError::NotAllowed {
                        collection: c.clone(),
                        writer: inner.writer.clone(),
                    }
                } else {
                    DataError::Unavailable { name: c.clone() }
                });
            }
            // Its default record waits until nothing a device of the
            // namespace holds can govern it (spec §6.1).
            inner.default_allowed(c).await?;
            fresh.insert(c.clone());
            keys.push(None);
        }
        let PutOptions { type_id, keep, .. } = options;
        let ids = self.sign_group(&items, &keys, &fresh, type_id, keep, count)?;
        for (c, _) in &items {
            inner.publish_about(c, &[]).await?;
        }
        Ok(ids)
    }

    /// The locked part of [`Self::put_items`]: check every item against its
    /// collection's record in force (`keys`: their epoch keys; `fresh`: the
    /// collections of this namespace with no record yet), then sign and
    /// judge the group, and keep it only if every item passes.
    fn sign_group(
        &self,
        items: &[(Name, Edit)],
        keys: &[Option<(Epoch, ContentKey)>],
        fresh: &BTreeSet<Name>,
        type_id: TypeId,
        keep: Keep,
        count: u32,
    ) -> Result<Vec<VersionId>, DataError> {
        let inner = &self.inner;
        let refuse = |name: &Name, why: String| DataError::BadRequest {
            name: name.clone(),
            why,
        };
        let first = &items[0].0;
        let mut st = inner.st.lock();
        // What each collection is written under, as it stands now.
        let mut audiences: Vec<BTreeSet<Audience>> = Vec::with_capacity(items.len());
        for ((c, edit), key) in items.iter().zip(keys) {
            if fresh.contains(c) {
                // A record arrived meanwhile, or versions written under one
                // this device does not hold: put_group again under it.
                inner.fresh(&st, c)?;
                audiences.push([Audience::Person(inner.ns.clone())].into_iter().collect());
                continue;
            }
            inner.writable(&st, c, key.as_ref().map(|(e, _)| e))?;
            let coll = &st.colls[c];
            let members = coll.members.as_ref().expect("members known");
            match (&members.rule, edit) {
                (Rule::Merge { function }, _) if coll.state.is_none() => {
                    return Err(DataError::RuleUnknown {
                        collection: c.clone(),
                        rule: function.clone(),
                    });
                }
                (Rule::Log | Rule::OneKey, Edit::Op(_)) => {
                    return Err(refuse(
                        c,
                        format!(
                            "{c} is a log collection: its versions carry fields, not a merge \
                             rule's operation; give its item as fields"
                        ),
                    ));
                }
                _ => {}
            }
            audiences.push(members.readers.iter().cloned().collect());
        }
        if let Some(i) = audiences.iter().position(|a| *a != audiences[0]) {
            return Err(refuse(
                &items[i].0,
                format!(
                    "{} is read by another audience than {first} (one was narrowed, say), so a \
                     reader of one could never count the group; share them alike, or put them \
                     in separate groups",
                    items[i].0
                ),
            ));
        }
        // What is open closes first: dates and seqs stay in order.
        for (c, _) in items {
            if !fresh.contains(c) {
                inner.close_block(&mut st, c);
            }
        }
        // The seqs to come: the records needed, then the group.
        let base = inner.next_seq(&st)?;
        let records: Vec<(Name, (MembersBody, Option<ContentKey>))> = fresh
            .iter()
            .zip(base..)
            .map(|(c, seq)| (c.clone(), inner.default_members(c, seq)))
            .collect();
        let gid = base + records.len() as u64;
        if gid.checked_add(u64::from(count)).is_none() {
            return Err(local(format!(
                "{} has too few seqs left in its log for a group of {count}; enroll the device \
                 again under a new name",
                inner.device
            )));
        }
        let group = Group { id: gid, count };
        // Signed and judged; nothing kept yet. A collection whose state an
        // edit or an application changed is read again if the group is
        // refused; a fresh collection's operation is judged on a state of
        // its own ([`Inner::sign_fresh`]), dropped if the group is refused.
        let mut temps: HashMap<Name, (Box<dyn MergeState>, Ruled)> = HashMap::new();
        let mut touched = Vec::new();
        let mut signed = Vec::with_capacity(items.len());
        let restore = |st: &mut St, touched: &[Name]| {
            for c in touched {
                st.reread(c, &inner.config.rules, inner.me());
            }
        };
        for (i, ((c, edit), key)) in items.iter().zip(keys).enumerate() {
            let seq = gid + i as u64;
            let draft = match edit {
                Edit::Fields(content) => Draft::Entry(content.clone()),
                Edit::Op(op) => Draft::Op(op.clone()),
            };
            let made = match records.iter().find(|(r, _)| r == c) {
                Some((_, (body, made_key))) => inner
                    .sign_fresh(
                        c,
                        seq,
                        body,
                        made_key.as_ref(),
                        draft,
                        (type_id.clone(), keep),
                        Some(group),
                    )
                    .map(|(s, r, temp)| {
                        temps.insert(c.clone(), (temp, r));
                        s
                    }),
                None => {
                    touched.push(c.clone());
                    inner.sign_in(
                        &mut st,
                        c,
                        seq,
                        key.as_ref(),
                        type_id.clone(),
                        keep,
                        draft,
                        Some(group),
                    )
                }
            };
            match made {
                Ok(s) => signed.push(s),
                Err(e) => {
                    restore(&mut st, &touched);
                    return Err(e);
                }
            }
        }
        // Every other operation checked before any is applied, then
        // applied: what a rule refuses refuses the group.
        let mut ruled = Vec::with_capacity(signed.len());
        for apply in [false, true] {
            ruled.clear();
            for s in signed.iter().filter(|s| !temps.contains_key(&s.c)) {
                match inner.judge_own(&mut st, s, apply) {
                    Ok(r) => ruled.push(r),
                    Err(e) => {
                        restore(&mut st, &touched);
                        return Err(e);
                    }
                }
            }
        }
        // The records the fresh collections need, signed before anything is
        // kept.
        let mut entries = Vec::with_capacity(records.len());
        for ((c, record), seq) in records.into_iter().zip(base..) {
            match inner.sign_members(&c, seq, record) {
                Ok(entry) => entries.push((c, entry)),
                Err(e) => {
                    restore(&mut st, &touched);
                    return Err(e);
                }
            }
        }
        // Kept: the records, then the group; nothing fails from here.
        for (c, entry) in entries {
            inner.keep_members(&mut st, &c, entry);
        }
        debug_assert_eq!(st.head + 1, gid);
        let mut ruled = ruled.into_iter();
        let mut ids = Vec::with_capacity(signed.len());
        for s in signed {
            let r = match temps.remove(&s.c) {
                Some((temp, r)) => {
                    inner.start_fresh(&mut st, &s.c, temp);
                    Some(r)
                }
                None => ruled
                    .next()
                    .expect("one ruling per item of a collection held"),
            };
            let ns = namespace_of(&s.c).expect("checked above");
            ids.push(inner.commit(&mut st, &ns, s, Duration::ZERO, r));
        }
        Ok(ids)
    }

    /// [`DataLayer::put`] and [`DataLayer::put_op`]: sign `draft` into
    /// `collection` (its record first, for a collection of this namespace
    /// that has none), batched into a block when asked and the rule allows.
    async fn put_draft(
        &self,
        collection: &Name,
        draft: Draft,
        options: PutOptions,
    ) -> Result<VersionId, DataError> {
        let inner = &self.inner;
        check_collection(collection)?;
        if let Some(delay) = options.batch.filter(|d| *d > BATCH_MAX) {
            return Err(DataError::BadRequest {
                name: collection.clone(),
                why: format!(
                    "a batch delay of {delay:?} is longer than the {BATCH_MAX:?} an entry may wait \
                     unsigned (a one-key head states it as the freshness readers add to every \
                     answer's age); put with a batch of at most {BATCH_MAX:?}, or without batch"
                ),
            });
        }
        let ns = namespace_of(collection).expect("checked above");
        inner.look(collection).await?;
        // Under a folder in force the collection writes under the record in
        // force over it, and no default record of its own is signed (spec
        // §6).
        inner
            .st
            .lock()
            .ensure(collection, &inner.config.rules, inner.me());
        if ns != inner.ns {
            let c = collection.clone();
            inner
                .wait_for(|st| st.colls.get(&c).is_some_and(|coll| coll.members.is_some()))
                .await;
        }
        let fresh = {
            let mut st = inner.st.lock();
            st.ensure(collection, &inner.config.rules, inner.me());
            let none = st.colls.get(collection).is_none_or(|c| c.members.is_none());
            if none && ns != inner.ns {
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
            none
        };
        // A collection of this namespace that no record governs gets the
        // host's default, once nothing a device of the namespace holds can
        // govern it (spec §6.1), signed with its first version and only once
        // that version is judged (spec §5).
        let draft = match fresh {
            false => draft,
            true => {
                inner.default_allowed(collection).await?;
                let written = {
                    let mut st = inner.st.lock();
                    st.ensure(collection, &inner.config.rules, inner.me());
                    match st.colls.get(collection).is_none_or(|c| c.members.is_none()) {
                        // A record arrived meanwhile: written under it.
                        false => Err(draft),
                        true if options.batch.is_some() => {
                            return Err(DataError::BadRequest {
                                name: collection.clone(),
                                why: format!(
                                    "{collection} has no members record yet, and the one it \
                                     gets merges its versions, one operation per version: its \
                                     entries are not batched into blocks; put without batch, or \
                                     share it as a log collection first"
                                ),
                            });
                        }
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
        let key = inner.write_key(collection).await?;
        let PutOptions {
            type_id,
            keep,
            batch,
        } = options;
        // An entry larger than a block carries goes alone (in pieces).
        let alone = |content: &Content| {
            wire::encode_block(&[BlockEntryBody {
                offset: 0,
                fields: content.clone(),
            }])
            .len()
                > wire::INLINE_MAX
        };
        // An unbatched version's id; or the block a batched entry waits
        // for, when its timer is to be armed, and whether a block closed.
        let step = {
            let mut st = inner.st.lock();
            inner.writable(&st, collection, key.as_ref().map(|(e, _)| e))?;
            let rule = st.colls[collection]
                .members
                .as_ref()
                .expect("members known")
                .rule
                .clone();
            match (batch, draft) {
                (_, Draft::Op(_)) if log_like(&rule) => {
                    return Err(DataError::BadRequest {
                        name: collection.clone(),
                        why: format!(
                            "{collection} is a log collection: its versions carry fields, not a \
                             merge rule's operation; put the fields"
                        ),
                    });
                }
                (Some(_), _) if !log_like(&rule) => {
                    return Err(DataError::BadRequest {
                        name: collection.clone(),
                        why: format!(
                            "{collection} merges its versions, and a merge collection carries one \
                             operation per version: its entries are not batched into blocks; \
                             put without batch"
                        ),
                    });
                }
                (Some(delay), Draft::Entry(content)) if !alone(&content) => {
                    let Some(deadline) = Instant::now().checked_add(delay) else {
                        return Err(DataError::BadRequest {
                            name: collection.clone(),
                            why: format!(
                                "this device's clock cannot hold a deadline {delay:?} from now; \
                                 put with a shorter batch, or without batch"
                            ),
                        });
                    };
                    let epoch = key.as_ref().map(|(e, _)| e.clone());
                    let (rx, closed, arm) = inner.add_to_block(
                        &mut st, collection, content, type_id, keep, epoch, delay, deadline,
                    );
                    Err((rx, arm, closed))
                }
                (_, draft) => {
                    // What is open closes first: dates and seqs stay in order.
                    inner.close_block(&mut st, collection);
                    Ok(inner.write(
                        &mut st,
                        collection,
                        &ns,
                        key.as_ref(),
                        type_id,
                        keep,
                        draft,
                        Duration::ZERO,
                    )?)
                }
            }
        };
        match step {
            Ok(id) => {
                inner.publish_about(collection, &[]).await?;
                Ok(id)
            }
            Err((rx, arm, closed)) => {
                if let Some(at) = arm {
                    inner.arm_block(collection.clone(), at);
                }
                if closed {
                    inner.publish_about(collection, &[]).await?;
                }
                rx.await.map_err(|_| {
                    local("the device shut down before the block carrying the entry was signed")
                })?
            }
        }
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
            if inner.sealed_off(&inner.st.lock(), &c) {
                return Err(DataError::Sealed { name: name.clone() });
            }
            let unknown = |st: &St| st.rule_unknown(&c, &rules);
            if !inner
                .wait_for(|st| value(st).is_some() || unknown(st).is_some())
                .await
            {
                return Err(DataError::Unavailable { name: name.clone() });
            }
            let st = inner.st.lock();
            if let Some(e) = unknown(&st) {
                return Err(e);
            }
            let (value, not_counted) =
                value(&st).ok_or_else(|| DataError::Unavailable { name: name.clone() })?;
            return Ok(Answer {
                got: Got::State(State {
                    name: name.clone(),
                    collection: c,
                    at,
                    value,
                    not_counted,
                }),
                age: Age::Exact,
            });
        }
        if let Some((version, index)) = parse_entry_name(name) {
            return inner.get_entry(name, &version, index).await;
        }
        if let Some(range) = parse_range_name(name) {
            return match range {
                Ok((c, range)) => inner.get_range(name, &c, range).await,
                Err(why) => Err(DataError::BadName {
                    name: name.clone(),
                    why: why.0,
                }),
            };
        }
        if parse_log_name(name).is_some() {
            return inner.get_log_entry(name).await;
        }
        check_collection(name)?;
        // The rule decides how the newest is found: a one-key collection's
        // by its head, without following its versions (spec §5.3).
        let peek = {
            let st = inner.st.lock();
            !st.inside(name) && st.colls.get(name).is_none_or(|x| x.members.is_none())
        };
        if peek {
            inner.peek(name).await?;
        }
        let one = {
            let st = inner.st.lock();
            if inner.sealed_off(&st, name) {
                return Err(DataError::Sealed { name: name.clone() });
            }
            st.colls.get(name).and_then(one_key)
        };
        if let Some((key, device)) = one {
            let a = inner.newest_one_key(name, &key, &device).await;
            return inner.whole(a).await;
        }
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

    async fn put_group(
        &self,
        items: Vec<(Name, Edit)>,
        options: PutOptions,
    ) -> Result<Vec<VersionId>, DataError> {
        self.put_items(items, options).await
    }

    async fn watch(&self, collection: &Name, since: &Frontier) -> Result<Changes, DataError> {
        let inner = &self.inner;
        inner.follow(collection).await?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        {
            let mut st = inner.st.lock();
            // Each collection under the target, in order: what it holds
            // applied, each with why when it does not count (its rule's
            // reason, or its group's), and the group members waiting for
            // their group, as not counted. A version not applied yet is
            // delivered once it applies, as it would have been had the
            // watch begun earlier, so none is delivered twice.
            let mut listed: Vec<(&Name, &VersionId, Change)> = Vec::new();
            for (c, coll) in st.colls.iter().filter(|(c, _)| c.has_prefix(collection)) {
                for hv in coll.versions.values() {
                    let v = &hv.version;
                    if since.contains(&v.id) || coll.pending.contains(&v.id) {
                        continue;
                    }
                    listed.push((c, &v.id, Change::Version(v.clone())));
                    let why = coll
                        .not_counted
                        .get(&v.id)
                        .or_else(|| coll.group_held.get(&v.id).map(|(_, why)| why));
                    if let Some(why) = why {
                        listed.push((
                            c,
                            &v.id,
                            Change::NotCounted {
                                collection: c.clone(),
                                id: v.id.clone(),
                                why: why.clone(),
                            },
                        ));
                    }
                }
                for (id, why) in coll
                    .group_waits
                    .iter()
                    .filter(|(id, _)| !since.contains(id))
                {
                    listed.push((
                        c,
                        id,
                        Change::NotCounted {
                            collection: c.clone(),
                            id: id.clone(),
                            why: why.clone(),
                        },
                    ));
                }
            }
            // Stable: a version comes before why it is not counted.
            listed.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
            for (_, _, change) in listed {
                let _ = tx.send(Ok(change));
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
                // An entry's name is immutable, so it pins as it is; a
                // range read's answer grows with the stream.
                Got::Entries(_) if wire::parse_entry_name(name).is_some() => name.clone(),
                Got::Entries(_) => {
                    return Err(DataError::BadRequest {
                        name: name.clone(),
                        why: "a range read's answer grows with its stream, so a snapshot cannot \
                              pin it; pin the blocks it read, by their names"
                            .into(),
                    });
                }
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
        // The holders are the owner's choice, in data: each copy is kept by
        // a distinct holder device the record names (spec §13.2).
        let mut holders = want.holders.clone();
        holders.sort();
        holders.dedup();
        if let Some(h) = holders
            .iter()
            .find(|h| !wire::is_device_name(h) || **h == inner.device)
        {
            return Err(DataError::BadRequest {
                name: prefix.clone(),
                why: format!(
                    "{h} cannot hold it for this device: a holder is another device, named \
                     <namespace>/…/<device> without keyword components; name the devices that \
                     keep it"
                ),
            });
        }
        if holders.len() < want.copies as usize {
            return Err(DataError::BadRequest {
                name: prefix.clone(),
                why: format!(
                    "{} copies asked of {} holders named; each copy is kept by a distinct holder \
                     device, so name at least {} holders",
                    want.copies,
                    holders.len(),
                    want.copies
                ),
            });
        }
        inner.look(prefix).await?;
        // The custody policy, in data: the hold record this device signs,
        // again only when what it asks changed.
        let (record, at, signed) = {
            let mut st = inner.st.lock();
            let coll = st.colls.entry(prefix.clone()).or_default();
            let at = coll.at();
            match coll.holds.get(&inner.writer) {
                Some((_, n, b))
                    if b.copies == want.copies
                        && b.until == want.until
                        && b.at == at
                        && b.holders == holders =>
                {
                    (n.clone(), at, false)
                }
                _ => {
                    let body = HoldBody {
                        collection: prefix.clone(),
                        copies: want.copies,
                        until: want.until,
                        at: at.clone(),
                        holders: holders.clone(),
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
        let verdicts = futures::future::join_all(live.iter().map(|h| inner.audit(prefix, h))).await;
        let broken: Vec<Lease> = live
            .iter()
            .zip(verdicts)
            .filter(|(_, a)| !a.kept())
            .filter_map(|(h, _)| inner.lease_of(&inner.st.lock(), prefix, h))
            .collect();
        // Repair: ask every named holder whose lease is not live, not kept
        // or holds less than was asked (a holder asked again fetches back
        // what it lost), at once, and audit what they answer.
        let holding = |st: &St, h: &Name| -> bool {
            st.colls.get(prefix).is_some_and(|coll| {
                coll.leases
                    .get(h)
                    .is_some_and(|l| l.audit.kept() && reaches(coll, &l.body.holds, &at))
            })
        };
        let ask: Vec<Name> = {
            let st = inner.st.lock();
            let counted: Vec<Name> = inner
                .live_leases(&st, prefix)
                .into_iter()
                .filter(|h| holding(&st, h))
                .collect();
            if counted.len() >= want.copies as usize {
                Vec::new()
            } else {
                holders
                    .iter()
                    .filter(|d| !counted.contains(d))
                    .cloned()
                    .collect()
            }
        };
        let answered: Vec<Name> = stream::iter(ask)
            .map(|d| {
                let record = &record;
                async move { inner.ask_hold(&d, record).await.then_some(d) }
            })
            .buffer_unordered(inner.config.window)
            .filter_map(|d| async move { d })
            .collect()
            .await;
        let fresh: Vec<Name> = {
            let st = inner.st.lock();
            let live = inner.live_leases(&st, prefix);
            answered.into_iter().filter(|d| live.contains(d)).collect()
        };
        futures::future::join_all(fresh.iter().map(|h| inner.audit(prefix, h))).await;
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
                Some(Rule::Log | Rule::OneKey) => {}
            }
            let Some(mine) = upto.get(&inner.writer) else {
                // Up to nothing of this key: nothing to drop.
                return Ok(());
            };
            if mine.0 > st.head {
                return Err(DataError::BadRequest {
                    name: prefix.clone(),
                    why: format!(
                        "a prune up to seq {} reaches past this device's newest entry, seq {}: it \
                         would drop the versions it puts next; prune up to seq {} at most",
                        mine.0, st.head, st.head
                    ),
                });
            }
            let body = PruneBody {
                prefix: prefix.clone(),
                upto: upto.clone(),
            };
            inner.append(&mut st, Some(&c), wire::encode_prune(&body))?;
        }
        inner.publish_about(&c, &[]).await?;
        // A prune in a folder's epoch in force owes the folder a new epoch
        // (taken above): signed now (spec §14).
        inner.settle().await;
        Ok(())
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
            members,
        )
        .await
    }

    async fn share_folder(
        &self,
        folder: &Name,
        members: crate::layer::Share,
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
}

impl Device {
    /// [`DataLayer::share`] and [`DataLayer::share_folder`]: sign the next
    /// members record of subject `s` — a collection, or a folder governing
    /// every collection under it (spec §6) — owned by this namespace.
    async fn share_subject(
        &self,
        s: Subject,
        members: crate::layer::Share,
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
        // A one-key collection is written by exactly one key (spec §5.3):
        // named as a key, or as this device (its key).
        let writers = match (&members.rule, members.writers.as_slice()) {
            (Rule::OneKey, [w]) if *w == inner.device => vec![inner.writer.key().clone()],
            (Rule::OneKey, [w]) if device_of(w).is_some_and(|d| wire::is_device_name(&d)) => {
                vec![w.clone()]
            }
            (Rule::OneKey, _) => {
                return Err(DataError::BadRequest {
                    name: name.clone(),
                    why: "a one-key collection is written by exactly one key: name the one key \
                          that writes, <D>/KEY/<id>, or this device"
                        .into(),
                });
            }
            _ => members.writers,
        };
        // What lies under the subject is looked at: every device known to
        // write into the namespace, walked for at most the first-look time.
        inner.look(name).await?;
        let own_record = |st: &St| match s.folder {
            true => st.folders.get(name).and_then(|f| f.line.own.clone()),
            false => st.colls.get(name).and_then(|c| c.line.own.clone()),
        };
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
        let before = inner.groups_of(&inner.st.lock(), name);
        {
            let mut st = inner.st.lock();
            if !s.folder {
                widens(&st, name, &writers, &members.readers)?;
            }
            let current = own_record(&st);
            let record = inner.next_members(
                &st,
                &s,
                current.as_ref(),
                members.rule,
                writers,
                members.readers,
                false,
            );
            inner.append_members(&mut st, name, record)?;
        }
        inner.publish_about(name, &before).await?;
        // A collection sealed to this one as a group moves to a new epoch
        // with it, and a merge this record left unresolved is resolved; so
        // does a collection with readers of its own that a folder record
        // dropped one of.
        inner.settle().await;
        Ok(())
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
            expiry: Vec::new(),
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

    /// Start `device` on a forwarder that delivers nothing, its wall clock
    /// reading `clock`.
    async fn start_at(
        device: &Name,
        keys: &Arc<SecurityManager>,
        validator: &Arc<Validator>,
        store: &Arc<dyn DataStore>,
        clock: &Arc<AtomicU64>,
    ) -> Result<Device, DataError> {
        let conn: Arc<dyn Connection> = Arc::new(Unconnected);
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
        // Whether `device` (its key `<device>/KEY/1`) signing a members
        // record about `collection` is an owner, by `keyring`.
        let signed = |keyring: &Keyring, device: &str, collection: &str| {
            let c = n(collection);
            let entry = log_name(&n(device), Some(&c), 1);
            let writer = Writer::new(n(device).append("KEY").append("1"));
            owner_signed(keyring, &entry, &c, &writer)
        };
        let both = Keyring::new();
        both.adopt(context("/home"));
        both.adopt(context("/home/bob"));
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
        only_home.adopt(context("/home"));
        assert!(signed(&only_home, laptop, "/home/32=data/x"));
        assert!(!signed(&only_home, laptop, "/home/bob/32=data/x"));
        // No context held: nobody owns anything.
        assert!(!signed(&Keyring::new(), hub, "/home/32=data/x"));
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
                folder: false,
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
            group: None,
            rule: None,
            fields: Content::new(),
            op: Bytes::new(),
            sealed,
            chunks: None,
            block: None,
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

    // ---- custody, prune and erasure against crafted packets (the slice-3 review) -------------

    /// Hand `dev` the log entry `seq` of `device` about `c` carrying
    /// `record`, signed (unchecked) by `key`; why it is refused, if it is.
    fn hand_as(
        dev: &Device,
        device: &Name,
        key: &Name,
        c: &Name,
        seq: u64,
        record: Record,
    ) -> Option<Refusal> {
        let name = log_name(device, Some(c), seq);
        let content = wire::encode_record(&record);
        let packet = DataBuilder::new(name.clone(), &content).sign_sync(
            ndn_packet::SignatureType::SignatureEd25519,
            Some(key),
            |_| Bytes::from_static(&[0; 64]),
        );
        let mut st = dev.inner.st.lock();
        dev.inner.take(
            &mut st,
            name.clone(),
            packet,
            Writer::new(key.clone()),
            record,
            false,
        );
        st.refused.get(&name).cloned()
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

    #[tokio::test]
    async fn one_holder_device_counts_once_whatever_keys_sign_its_leases() {
        let dev = device_in("/alice/phone", &["/alice"]).await;
        let c = n("/alice/32=data/photos");
        dev.share(&c, share_of(Rule::Log, &["/alice"], Vec::new()))
            .await
            .unwrap();
        let (laptop, repo) = (n("/alice/laptop"), n("/alice/repo"));
        // The laptop's record names the repo, and the phone too: a device
        // still counts no lease of its own.
        let hold = HoldBody {
            collection: c.clone(),
            copies: 2,
            until: LATER,
            at: Frontier::new(),
            holders: vec![n("/alice/phone"), repo.clone()],
        };
        assert_eq!(hand(&dev, &laptop, &c, 1, Record::Hold(hold)), None);
        let lease = || {
            Record::Lease(LeaseBody {
                collection: c.clone(),
                hold: log_name(&laptop, Some(&c), 1),
                until: LATER,
                holds: Frontier::new(),
            })
        };
        // The repo after a key rotation: its old key's lease still live.
        hand_as(&dev, &repo, &n("/alice/repo/KEY/1"), &c, 3, lease());
        hand_as(&dev, &repo, &n("/alice/repo/KEY/2"), &c, 4, lease());
        // The phone itself, under a key it signed with before.
        let phone = n("/alice/phone");
        hand_as(&dev, &phone, &n("/alice/phone/KEY/0"), &c, 5, lease());
        let st = dev.inner.st.lock();
        let live = dev.inner.live_leases(&st, &c);
        assert_eq!(
            live.len(),
            1,
            "one holder device, two keys, and the owner device itself count as one copy: {live:?}"
        );
        assert_eq!(dev.inner.holders_of(&st, &c), vec![repo]);
        drop(st);
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_prune_past_its_writers_head_is_refused_and_ignored() {
        let dev = device_in("/alice/laptop", &["/alice"]).await;
        let c = n("/alice/32=data/photos");
        dev.share(&c, share_of(Rule::Log, &["/alice"], Vec::new()))
            .await
            .unwrap();
        let head = dev.inner.st.lock().head;
        let refused = dev.prune(&c, &upto("/alice/laptop/KEY/1", head + 3)).await;
        assert!(
            refused.is_err(),
            "a prune up to past the log head would swallow the next puts: {refused:?}"
        );
        // Signed elsewhere: a prune at seq 5 reaching seq 9 covers nothing
        // above 4, so the writer's next version stays.
        let phone = n("/alice/phone");
        let prune = PruneBody {
            prefix: c.clone(),
            upto: upto("/alice/phone/KEY/1", 9),
        };
        hand(&dev, &phone, &c, 5, Record::Prune(prune));
        hand(&dev, &phone, &c, 6, Record::Version(version_body(&c, None)));
        assert!(
            matches!(
                dev.inner.st.lock().held.get(&log_name(&phone, Some(&c), 6)),
                Some(Held::Version(_))
            ),
            "a version written after the prune is not pruned by it"
        );
        dev.shutdown();
    }

    #[tokio::test]
    async fn an_epoch_key_is_destroyed_only_once_every_writer_left_the_epoch() {
        let device = n("/alice/laptop");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.adopt_context(context("/alice")));
        let (keys, store): (_, Arc<dyn DataStore>) =
            (keys_of(&device), Arc::new(MemoryStore::new()));
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        let c = n("/alice/32=data/plan");
        let person = |s: &str| Audience::Person(n(s));
        let epoch_now = |dev: &Device| {
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
        dev.share(
            &c,
            share_of(
                Rule::Log,
                &["/alice"],
                vec![person("/alice"), person("/bob")],
            ),
        )
        .await
        .unwrap();
        let (first, first_key) = epoch_now(&dev);
        let sealed = |device: &Name, seq: u64, e: &Epoch, k: &ContentKey| {
            let name = log_name(device, Some(&c), seq);
            Record::Version(version_body(
                &c,
                Some(SealedBody {
                    epoch: e.clone(),
                    ciphertext: seal::seal_payload(k, &name, &Content::new(), b""),
                }),
            ))
        };
        let (phone, tablet) = (n("/alice/phone"), n("/alice/tablet"));
        assert_eq!(
            hand(&dev, &phone, &c, 1, sealed(&phone, 1, &first, &first_key)),
            None
        );
        assert_eq!(
            hand(&dev, &tablet, &c, 1, sealed(&tablet, 1, &first, &first_key)),
            None
        );
        // Bob removed: a new epoch.
        dev.share(&c, share_of(Rule::Log, &["/alice"], vec![person("/alice")]))
            .await
            .unwrap();
        let (second, second_key) = epoch_now(&dev);
        // The phone moves on and prunes its version of the first epoch; the
        // tablet, which has not heard of the second, prunes its own.
        assert_eq!(
            hand(&dev, &phone, &c, 2, sealed(&phone, 2, &second, &second_key)),
            None
        );
        let prune = |key: &str, seq| {
            Record::Prune(PruneBody {
                prefix: c.clone(),
                upto: upto(key, seq),
            })
        };
        hand(&dev, &phone, &c, 3, prune("/alice/phone/KEY/1", 1));
        hand(&dev, &tablet, &c, 2, prune("/alice/tablet/KEY/1", 1));
        assert!(
            dev.inner.st.lock().keys.key(&c, &first).is_some(),
            "the tablet may still write in the first epoch: its erasure waits"
        );
        // It did, offline: its version opens.
        assert_eq!(
            hand(&dev, &tablet, &c, 3, sealed(&tablet, 3, &first, &first_key)),
            None
        );
        assert!(matches!(
            dev.inner
                .st
                .lock()
                .held
                .get(&log_name(&tablet, Some(&c), 3)),
            Some(Held::Version(_))
        ));
        // It moves on and prunes that one too: now the epoch goes.
        assert_eq!(
            hand(
                &dev,
                &tablet,
                &c,
                4,
                sealed(&tablet, 4, &second, &second_key)
            ),
            None
        );
        hand(&dev, &tablet, &c, 5, prune("/alice/tablet/KEY/1", 3));
        assert!(
            dev.inner.st.lock().keys.key(&c, &first).is_none(),
            "every writer left the first epoch and pruned all of it"
        );
        // The erasure outlives a restart: the key, granted again, is refused.
        dev.shutdown();
        drop(dev);
        let again = start(&device, &keys, &validator, &store).await.unwrap();
        {
            let mut st = again.inner.st.lock();
            assert!(st.colls[&c].erased.contains(&first));
            assert!(!st.take_key(&c, &first, first_key.clone()));
        }
        again.shutdown();
    }

    #[tokio::test]
    async fn pruned_pieces_do_not_come_back_from_an_in_flight_walk() {
        let device = n("/alice/repo");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.adopt_context(context("/alice")));
        let (keys, store): (_, Arc<dyn DataStore>) =
            (keys_of(&device), Arc::new(MemoryStore::new()));
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        let c = n("/alice/32=data/photos");
        dev.share(&c, share_of(Rule::Log, &["/alice"], Vec::new()))
            .await
            .unwrap();
        let phone = n("/alice/phone");
        let hold = HoldBody {
            collection: c.clone(),
            copies: 1,
            until: LATER,
            at: Frontier::new(),
            holders: vec![device.clone()],
        };
        assert_eq!(hand(&dev, &phone, &c, 1, Record::Hold(hold)), None);
        // The repo holds the photos: its own lease, which a restart reads back.
        let lease = LeaseBody {
            collection: c.clone(),
            hold: log_name(&phone, Some(&c), 1),
            until: LATER,
            holds: Frontier::new(),
        };
        assert_eq!(hand(&dev, &device, &c, 7, Record::Lease(lease)), None);
        dev.inner.st.lock().holding.insert(
            c.clone(),
            Holding {
                hold: log_name(&phone, Some(&c), 1),
                until: LATER,
                at: upto("/alice/phone/KEY/1", 2),
                lease: None,
            },
        );
        let v = log_name(&phone, Some(&c), 2);
        let (pieces, chunks) = pieces::split(&v, &[7u8; 3 * wire::CHUNK]);
        let mut body = version_body(&c, None);
        body.chunks = Some(chunks);
        assert_eq!(hand(&dev, &phone, &c, 2, Record::Version(body)), None);
        for p in &pieces {
            store.insert(p.name.clone(), p.wire.clone());
        }
        let prune = PruneBody {
            prefix: v.clone(),
            upto: upto("/alice/phone/KEY/1", 2),
        };
        hand(&dev, &phone, &c, 3, Record::Prune(prune));
        assert!(
            store.scan_under(&v, 0).is_empty(),
            "the prune drops every piece"
        );
        // A walk that started before the prune stores two pieces after it.
        for p in pieces.iter().take(2) {
            store.insert(p.name.clone(), p.wire.clone());
        }
        dev.shutdown();
        drop(dev);
        let again = start(&device, &keys, &validator, &store).await.unwrap();
        for p in &pieces {
            assert_eq!(
                again.inner.packet_for(&p.name, false),
                None,
                "a pruned piece is never served: {}",
                p.name
            );
        }
        assert!(
            store.scan_under(&v, 0).is_empty(),
            "a restart drops the pieces of a pruned version"
        );
        again.shutdown();
    }

    #[tokio::test]
    async fn an_audit_ask_from_no_owner_device_costs_the_holder_no_signature() {
        let dev = device_in("/alice/repo", &["/alice", "/mallory"]).await;
        let c = n("/alice/32=data/photos");
        let phone = n("/alice/phone");
        let hold = HoldBody {
            collection: c.clone(),
            copies: 1,
            until: LATER,
            at: Frontier::new(),
            holders: vec![n("/alice/repo")],
        };
        assert_eq!(hand(&dev, &phone, &c, 1, Record::Hold(hold)), None);
        dev.inner.st.lock().holding.insert(
            c.clone(),
            Holding {
                hold: log_name(&phone, Some(&c), 1),
                until: LATER,
                at: Frontier::new(),
                lease: None,
            },
        );
        // An ask whose proof claims `key` signed it (its signature is
        // zeros: it verifies for no one).
        let ask_by = |key: &str| {
            let mut ask = AuditAsk {
                nonce: [3; wire::NONCE_LEN],
                piece: log_name(&phone, Some(&c), 2),
                whole: false,
                asker: Bytes::new(),
            };
            let asker = device_of(&n(key)).unwrap();
            ask.asker =
                DataBuilder::new(wire::ask_name(&asker, &ask.binding(&n("/alice/repo"))), &[])
                    .sign_sync(
                        ndn_packet::SignatureType::SignatureEd25519,
                        Some(&n(key)),
                        |_| Bytes::from_static(&[0; 64]),
                    );
            (audit_ask_name(&n("/alice/repo"), &ask), ask)
        };
        let before = dev.signatures();
        // A device no hold record held here names an auditor.
        let (name, ask) = ask_by("/mallory/box/KEY/1");
        assert_eq!(
            dev.inner.audit_answer(&name, &ask).await,
            None,
            "a stranger's audit ask is not answered"
        );
        // The owner device's name, without its key.
        let (name, ask) = ask_by("/alice/phone/KEY/1");
        assert_eq!(
            dev.inner.audit_answer(&name, &ask).await,
            None,
            "an ask whose proof does not verify is not answered"
        );
        assert_eq!(dev.signatures(), before, "nor signed for");
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_holder_stores_no_record_it_did_not_accept() {
        let device = n("/alice/repo");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        for ns in ["/alice", "/mallory"] {
            assert!(validator.adopt_context(context(ns)));
        }
        let (keys, store): (_, Arc<dyn DataStore>) =
            (keys_of(&device), Arc::new(MemoryStore::new()));
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        let c = n("/alice/32=data/photos");
        dev.inner.st.lock().holding.insert(
            c.clone(),
            Holding {
                hold: log_name(&n("/alice/phone"), Some(&c), 1),
                until: LATER,
                at: upto("/alice/phone/KEY/1", 9),
                lease: None,
            },
        );
        // A hold record of Alice's photos, signed by a device of Mallory's.
        let mallory = n("/mallory/box");
        let hold = HoldBody {
            collection: c.clone(),
            copies: 1,
            until: LATER,
            at: Frontier::new(),
            holders: vec![device.clone()],
        };
        hand(&dev, &mallory, &c, 1, Record::Hold(hold));
        assert_eq!(
            store.get(&log_name(&mallory, Some(&c), 1)),
            None,
            "a hold record no owner signed is not stored"
        );
        // A version while the collection's members record is unknown.
        let phone = n("/alice/phone");
        hand(&dev, &phone, &c, 2, Record::Version(version_body(&c, None)));
        assert_eq!(
            store.get(&log_name(&phone, Some(&c), 2)),
            None,
            "a version no members record admitted yet is not stored"
        );
        dev.shutdown();
    }

    #[tokio::test]
    async fn an_audit_lists_every_piece_of_a_version_whose_manifest_it_lacks() {
        let dev = device_in("/alice/phone", &["/alice"]).await;
        let c = n("/alice/32=data/photos");
        dev.share(&c, share_of(Rule::Log, &["/alice"], Vec::new()))
            .await
            .unwrap();
        let laptop = n("/alice/laptop");
        let hold = HoldBody {
            collection: c.clone(),
            copies: 1,
            until: LATER,
            at: Frontier::new(),
            holders: vec![n("/alice/repo")],
        };
        assert_eq!(hand(&dev, &laptop, &c, 1, Record::Hold(hold)), None);
        let v = log_name(&laptop, Some(&c), 2);
        let (_, chunks) = pieces::split(&v, &[7u8; 3 * wire::CHUNK]);
        let mut body = version_body(&c, None);
        body.chunks = Some(chunks);
        assert_eq!(hand(&dev, &laptop, &c, 2, Record::Version(body)), None);
        let repo = Writer::new(n("/alice/repo/KEY/1"));
        let lease = LeaseBody {
            collection: c.clone(),
            hold: log_name(&laptop, Some(&c), 1),
            until: LATER,
            holds: upto("/alice/laptop/KEY/1", 2),
        };
        hand_as(
            &dev,
            &n("/alice/repo"),
            repo.key(),
            &c,
            3,
            Record::Lease(lease),
        );
        // Nothing answers: neither the writer nor the holder, asked through
        // the audit itself, serves the manifest.
        let promised = dev.inner.promised(&c, &n("/alice/repo")).await;
        assert_eq!(
            promised.unverified, 1,
            "a version whose pieces no one lists leaves the audit unverified, not passed"
        );
        let audit = dev.inner.audit(&c, &n("/alice/repo")).await;
        assert!(!audit.kept(), "{audit:?}");
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_lease_counts_only_from_a_holder_its_hold_record_names() {
        let dev = device_in("/alice/phone", &["/alice", "/mallory"]).await;
        let c = n("/alice/32=data/photos");
        dev.share(&c, share_of(Rule::Log, &["/alice"], Vec::new()))
            .await
            .unwrap();
        let laptop = n("/alice/laptop");
        let hold = HoldBody {
            collection: c.clone(),
            copies: 2,
            until: LATER,
            at: Frontier::new(),
            holders: vec![n("/alice/repo")],
        };
        assert_eq!(hand(&dev, &laptop, &c, 1, Record::Hold(hold)), None);
        // A device with a valid certificate that nobody chose answers with a lease.
        let lease = LeaseBody {
            collection: c.clone(),
            hold: log_name(&laptop, Some(&c), 1),
            until: LATER,
            holds: Frontier::new(),
        };
        hand(&dev, &n("/mallory/box"), &c, 1, Record::Lease(lease));
        let st = dev.inner.st.lock();
        assert!(
            dev.inner.live_leases(&st, &c).is_empty(),
            "a lease counts only from a holder the owner's hold record names"
        );
        assert!(dev.inner.holders_of(&st, &c).is_empty());
        drop(st);
        dev.shutdown();
    }

    // ---- slice 4: blocks, one key, expiry, range reads --------------------------------------

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

    /// A block of `c` carrying a reading per entry, offsets a minute apart.
    fn block(c: &Name, readings: &[&'static str]) -> VersionBody {
        VersionBody {
            block: Some(
                readings
                    .iter()
                    .enumerate()
                    .map(|(i, r)| BlockEntryBody {
                        offset: i as u64 * 60_000,
                        fields: Content::new().with("t", Bytes::from_static(r.as_bytes())),
                    })
                    .collect(),
            ),
            ..version_body(c, None)
        }
    }

    #[tokio::test]
    async fn a_block_entry_verifies_only_through_the_blocks_signature() {
        let ns = n("/sam");
        let (authority, issuer, anchor) = authority(&ns).await;
        let (sensor, reader) = (n("/sam/sensor"), n("/rita/phone"));
        let (sensor_keys, key, cert) = device_key(&authority, &issuer, &sensor).await;
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.add_trust_anchor(anchor));
        assert!(validator.adopt_context(context("/rita")));
        validator.cert_cache().insert(cert);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&reader, &keys_of(&reader), &validator, &store)
            .await
            .unwrap();
        let c = n("/sam/32=data/temps");
        let (a, b) = (
            log_name(&sensor, Some(&c), 4),
            log_name(&sensor, Some(&c), 5),
        );
        let genuine = block(&c, &["20.5", "20.7"]);
        let (wire_a, sig_a) = signed(&sensor_keys, &key, &a, &wire::encode_version(&genuine));
        // The holder alters one entry, or splices in another block's, and
        // keeps the block's signature.
        let forged = block(&c, &["20.5", "99.9"]);
        let mut spliced = genuine.clone();
        spliced.block.as_mut().unwrap()[1] = block(&c, &["18.0", "18.2"]).block.unwrap()[1].clone();
        for (what, body) in [("forged", forged), ("spliced", spliced)] {
            let sig = sig_a.clone();
            let signer = sensor_keys.get_signer_sync(&key).unwrap();
            let wire = DataBuilder::new(a.clone(), &wire::encode_version(&body)).sign_sync(
                signer.sig_type(),
                Some(&key),
                |_| sig,
            );
            let refused = dev.inner.take_data(&a, Data::decode(wire).unwrap()).await;
            assert_eq!(refused, Err(Refusal::BadSignature), "a {what} entry");
            assert!(
                !dev.inner.st.lock().held.contains_key(&a),
                "a {what} block is not held, so the block may be fetched elsewhere"
            );
        }
        // Another block's whole packet under this block's name: refused too.
        let (wire_b, _) = signed(
            &sensor_keys,
            &key,
            &b,
            &wire::encode_version(&block(&c, &["18.0"])),
        );
        assert!(
            dev.inner
                .take_data(&a, Data::decode(wire_b).unwrap())
                .await
                .is_err()
        );
        dev.inner
            .take_data(&a, Data::decode(wire_a).unwrap())
            .await
            .expect("the genuine block is taken");
        let st = dev.inner.st.lock();
        let held = st.colls[&c]
            .waiting
            .iter()
            .find(|hv| hv.version.name == a)
            .expect("held, waiting for its collection's record");
        let Payload::Block(entries) = &held.version.payload else {
            panic!("a block is read as a block");
        };
        let read: Vec<_> = entries
            .iter()
            .map(|e| e.content.get("t").cloned())
            .collect();
        assert_eq!(
            read,
            vec![
                Some(Bytes::from_static(b"20.5")),
                Some(Bytes::from_static(b"20.7"))
            ]
        );
        assert!(entries[0].dated < entries[1].dated);
        drop(st);
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_rolled_back_head_is_refused_also_after_a_restart() {
        let ns = n("/sam");
        let (authority, issuer, anchor) = authority(&ns).await;
        let (sensor, reader) = (n("/sam/sensor"), n("/rita/phone"));
        let (sensor_keys, key, cert) = device_key(&authority, &issuer, &sensor).await;
        // Another key of the same device, certified too.
        let other = sensor_keys
            .generate_ed25519(sensor.clone().append("KEY").append("2"))
            .unwrap();
        let public = sensor_keys
            .get_signer_sync(&other)
            .unwrap()
            .public_key()
            .unwrap();
        let other_cert = authority
            .certify(&other, public, &issuer, VALIDITY_MS)
            .await
            .unwrap();
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.add_trust_anchor(anchor));
        assert!(validator.adopt_context(context("/rita")));
        validator.cert_cache().insert(cert);
        validator.cert_cache().insert(other_cert);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let reader_keys = keys_of(&reader);
        let c = n("/sam/32=data/temps");
        let head = |signer: &Name, seq: u64| {
            let body = HeadBody {
                collection: c.clone(),
                seq,
                digest: [seq as u8; 32],
                freshness: 60_000,
            };
            let name = head_name(&sensor, &c, seq);
            let (wire, _) = signed(&sensor_keys, signer, &name, &wire::encode_head(&body));
            Data::decode(wire).unwrap()
        };
        let one = Writer::new(key.clone());
        let first = start(&reader, &reader_keys, &validator, &store)
            .await
            .unwrap();
        let accept = |dev: &Device, d: Data| {
            let (inner, c, one, sensor) = (
                Arc::clone(&dev.inner),
                c.clone(),
                one.clone(),
                sensor.clone(),
            );
            async move { inner.accept_head(&c, &one, &sensor, &d).await }
        };
        accept(&first, head(&key, 5))
            .await
            .expect("a first head is taken");
        assert!(
            matches!(
                accept(&first, head(&other, 9)).await,
                Err(HeadRefusal::NotTheKey)
            ),
            "a head signed by any key but the one key is refused"
        );
        first.shutdown();
        drop(first);

        let again = start(&reader, &reader_keys, &validator, &store)
            .await
            .unwrap();
        let refused = accept(&again, head(&key, 3)).await;
        assert!(
            matches!(refused, Err(HeadRefusal::Rollback { seq: 3, seen: 5 })),
            "a head below the one verified before the restart is refused: {refused:?}"
        );
        accept(&again, head(&key, 5))
            .await
            .expect("the same head is taken");
        accept(&again, head(&key, 8))
            .await
            .expect("a newer head is taken");
        again.shutdown();
    }

    #[tokio::test]
    async fn a_heads_rollback_floor_is_its_own_keys() {
        let ns = n("/sam");
        let (authority, issuer, anchor) = authority(&ns).await;
        let (old, spare, reader) = (n("/sam/sensor"), n("/sam/spare"), n("/rita/phone"));
        let (old_keys, old_key, old_cert) = device_key(&authority, &issuer, &old).await;
        let (spare_keys, spare_key, spare_cert) = device_key(&authority, &issuer, &spare).await;
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.add_trust_anchor(anchor));
        assert!(validator.adopt_context(context("/rita")));
        validator.cert_cache().insert(old_cert);
        validator.cert_cache().insert(spare_cert);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let reader_keys = keys_of(&reader);
        let c = n("/sam/32=data/temps");
        let head = |keys: &SecurityManager, key: &Name, device: &Name, seq: u64| {
            let body = HeadBody {
                collection: c.clone(),
                seq,
                digest: [seq as u8; 32],
                freshness: 60_000,
            };
            let name = head_name(device, &c, seq);
            let (wire, _) = signed(keys, key, &name, &wire::encode_head(&body));
            Data::decode(wire).unwrap()
        };
        let accept = |dev: &Device, key: &Name, device: &Name, d: Data| {
            let (inner, c, one, device) = (
                Arc::clone(&dev.inner),
                c.clone(),
                Writer::new(key.clone()),
                device.clone(),
            );
            async move { inner.accept_head(&c, &one, &device, &d).await }
        };
        let first = start(&reader, &reader_keys, &validator, &store)
            .await
            .unwrap();
        accept(&first, &old_key, &old, head(&old_keys, &old_key, &old, 50))
            .await
            .expect("the first one key's head is taken");
        // The owner hands the collection to a spare sensor, whose log is
        // numbered from its own start.
        accept(
            &first,
            &spare_key,
            &spare,
            head(&spare_keys, &spare_key, &spare, 3),
        )
        .await
        .expect("a head of the new one key is not held below the old key's seqs");
        // A seq of the key known here (a verified node, version or
        // tombstone) is a floor for its heads.
        first
            .inner
            .st
            .lock()
            .colls
            .entry(c.clone())
            .or_default()
            .entries
            .entry(Writer::new(spare_key.clone()))
            .or_default()
            .insert(7);
        let refused = accept(
            &first,
            &spare_key,
            &spare,
            head(&spare_keys, &spare_key, &spare, 6),
        )
        .await;
        assert!(
            matches!(refused, Err(HeadRefusal::Rollback { .. })),
            "a head below a seq of its key known here is a rollback: {refused:?}"
        );
        first.shutdown();
        drop(first);

        let again = start(&reader, &reader_keys, &validator, &store)
            .await
            .unwrap();
        for (keys, key, device, seq) in [
            (&old_keys, &old_key, &old, 49),
            (&spare_keys, &spare_key, &spare, 2),
        ] {
            let refused = accept(&again, key, device, head(keys, key, device, seq)).await;
            assert!(
                matches!(refused, Err(HeadRefusal::Rollback { .. })),
                "each key's floor survives a restart: {key} {refused:?}"
            );
        }
        accept(
            &again,
            &spare_key,
            &spare,
            head(&spare_keys, &spare_key, &spare, 3),
        )
        .await
        .expect("the new key's same head is taken again");
        again.shutdown();
    }

    /// The members record of one-key collection `c` naming `key`, taken by
    /// `dev` as its owner's.
    fn one_key_record(dev: &Device, c: &Name, key: &Name) {
        let body = MembersBody {
            collection: c.clone(),
            folder: false,
            revision: 1,
            rule: Rule::OneKey,
            writers: vec![key.clone()],
            readers: Vec::new(),
            cuts: Vec::new(),
            epoch: None,
            key_check: None,
            since: None,
            parent: None,
        };
        let owner = Writer::new(n("/sam/owner/KEY/1"));
        let mut st = dev.inner.st.lock();
        st.accept_members(1, body, &owner, &dev.inner.config.rules, dev.inner.me());
    }

    #[tokio::test]
    async fn an_older_version_never_takes_the_age_of_a_newer_head() {
        let ns = n("/sam");
        let (authority, issuer, anchor) = authority(&ns).await;
        let (sensor, reader) = (n("/sam/sensor"), n("/rita/phone"));
        let (sensor_keys, key, cert) = device_key(&authority, &issuer, &sensor).await;
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.add_trust_anchor(anchor));
        assert!(validator.adopt_context(context("/rita")));
        validator.cert_cache().insert(cert);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&reader, &keys_of(&reader), &validator, &store)
            .await
            .unwrap();
        let c = n("/sam/32=data/temps");
        let one = Writer::new(key.clone());
        one_key_record(&dev, &c, &key);
        // Version 1 of the one key, held and applied.
        hand(
            &dev,
            &sensor,
            &c,
            1,
            Record::Version(version_body(&c, None)),
        );
        // A head of seq 5 arrives and verifies; the node it names, and
        // version 5, are withheld.
        let body = HeadBody {
            collection: c.clone(),
            seq: 5,
            digest: [5; 32],
            freshness: 60_000,
        };
        let (wire, _) = signed(
            &sensor_keys,
            &key,
            &head_name(&sensor, &c, 5),
            &wire::encode_head(&body),
        );
        dev.inner
            .accept_head(&c, &one, &sensor, &Data::decode(wire).unwrap())
            .await
            .expect("the head is taken");
        // Version 1 was never confirmed the newest in this run, and a head
        // verified since says the log went past it: no age bounds it.
        match dev.inner.newest_one_key(&c, &one, &sensor).await {
            Ok(Answer {
                got: Got::Version(v),
                age,
            }) if v.id.seq.0 < 5 => panic!(
                "version {} answered with {age:?}, the age of a newer head",
                v.id.seq.0
            ),
            Ok(other) => panic!("answered {other:?}"),
            Err(e) => assert_eq!(e.next(), crate::NextStep::RetryLater, "{e}"),
        }
        // Had a head of this run named version 1 the newest and delivered
        // it, version 1 is answered, aged from that head's receipt.
        let confirmed = Receipt {
            at: Instant::now(),
            freshness: Duration::from_secs(1),
        };
        dev.inner
            .st
            .lock()
            .seen
            .get_mut(&(c.clone(), one.clone()))
            .expect("the head is kept")
            .delivered = Some((1, confirmed));
        tokio::time::sleep(Duration::from_millis(20)).await;
        let since = confirmed.at.elapsed() + confirmed.freshness;
        match dev.inner.newest_one_key(&c, &one, &sensor).await {
            Ok(Answer {
                got: Got::Version(v),
                age: Age::Newest { unconfirmed_for },
            }) => {
                assert_eq!(v.id.seq.0, 1);
                assert!(
                    unconfirmed_for >= since,
                    "aged from the head that named it the newest: {unconfirmed_for:?}"
                );
            }
            other => panic!("a version confirmed the newest is answered: {other:?}"),
        }
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
        assert!(validator.adopt_context(context("/rita")));
        validator.cert_cache().insert(cert);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&reader, &keys_of(&reader), &validator, &store)
            .await
            .unwrap();
        let c = n("/sam/32=data/temps");
        let a = log_name(&sensor, Some(&c), 4);
        let content = wire::encode_version(&block(&c, &["20.5"]));
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

    /// A device of `/alice` whose wall clock reads `clock`, on a forwarder
    /// that delivers nothing, keeping what it holds in `store`.
    async fn device_at(
        device: &Name,
        keys: &Arc<SecurityManager>,
        store: &Arc<dyn DataStore>,
        clock: &Arc<AtomicU64>,
    ) -> Device {
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        let ns = Name::from_components(device.components()[..1].iter().cloned());
        assert!(validator.adopt_context(context(&ns.to_string())));
        let conn: Arc<dyn Connection> = Arc::new(Unconnected);
        let read = Arc::clone(clock);
        let config = Config {
            clock: Arc::new(move || Timestamp(read.load(Ordering::Relaxed))),
            ..Config::new()
        };
        Device::start(
            Transport {
                node: Node::from_connection(Arc::clone(&conn)),
                sync: conn,
            },
            device.clone(),
            Arc::clone(keys),
            validator,
            Arc::clone(store),
            config,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn an_expired_version_is_dropped_answers_expired_and_is_not_stored_when_fetched_late() {
        let laptop = n("/alice/laptop");
        let keys = keys_of(&laptop);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let clock = Arc::new(AtomicU64::new(1_000));
        let dev = device_at(&laptop, &keys, &store, &clock).await;
        let c = n("/alice/32=data/readings");
        dev.share(&c, share_of(Rule::Log, &["/alice"], Vec::new()))
            .await
            .unwrap();
        let mut changes = dev.watch(&c, &Frontier::new()).await.unwrap();
        let phone = n("/alice/phone");
        let kept = |until: u64| VersionBody {
            keep: Keep::Until(Timestamp(until)),
            dated: Timestamp(900),
            ..version_body(&c, None)
        };
        let name = log_name(&phone, Some(&c), 1);
        assert_eq!(
            hand(&dev, &phone, &c, 1, Record::Version(kept(2_000))),
            None
        );
        assert!(store.contains(&name), "applied, so kept");

        clock.store(2_000, Ordering::Relaxed);
        let Err(e @ DataError::Expired { keep, .. }) = dev.get(&name).await else {
            panic!("a version past its keep is answered as expired");
        };
        assert_eq!(keep, Keep::Until(Timestamp(2_000)));
        assert_eq!((e.next(), e.retry()), (crate::NextStep::None, false));
        assert!(!store.contains(&name), "its record is dropped");
        let ask = AuditAsk {
            nonce: [0; wire::NONCE_LEN],
            piece: name.clone(),
            whole: false,
            asker: Bytes::new(),
        };
        assert_eq!(dev.inner.audit_content(&c, &ask), AuditAnswer::Expired);
        assert_eq!(dev.inner.packet_for(&name, false), None, "nor served");
        let mut seen = Vec::new();
        while let Ok(Some(Ok(change))) =
            tokio::time::timeout(Duration::from_millis(50), changes.next()).await
        {
            seen.push(change);
        }
        let id = VersionId {
            writer: Writer::new(phone.clone().append("KEY").append("1")),
            seq: Seq(1),
        };
        assert!(
            seen.iter()
                .any(|ch| matches!(ch, Change::Expired { collection, id: i, .. } if *i == id && *collection == c)),
            "its watcher is told: {seen:?}"
        );

        // Fetched after it expired here: neither taken nor stored.
        let late = log_name(&phone, Some(&c), 2);
        hand(&dev, &phone, &c, 2, Record::Version(kept(1_500)));
        assert!(!store.contains(&late));
        assert!(matches!(
            dev.get(&late).await,
            Err(DataError::Expired { .. })
        ));
        dev.shutdown();
        drop(dev);

        // After a restart, still expired, still not stored.
        let again = device_at(&laptop, &keys, &store, &clock).await;
        for v in [&name, &late] {
            assert!(matches!(again.get(v).await, Err(DataError::Expired { .. })));
            assert!(!store.contains(v));
        }
        again.shutdown();
    }

    fn reading(t: u64) -> Content {
        Content::new().with("t", Bytes::from(t.to_string()))
    }

    fn options(batch: Option<Duration>) -> PutOptions {
        PutOptions {
            type_id: crate::TypeId {
                name: n("/types/reading"),
                revision: 1,
            },
            keep: Keep::Forever,
            batch,
        }
    }

    #[tokio::test]
    async fn a_one_key_collection_is_written_by_exactly_one_key() {
        let sensor = n("/sam/sensor");
        let clock = Arc::new(AtomicU64::new(100));
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = device_at(&sensor, &keys_of(&sensor), &store, &clock).await;
        let c = n("/sam/32=data/temps");
        for writers in [&["/sam"][..], &["/sam/sensor/KEY/1", "/sam/other/KEY/1"]] {
            let Err(e @ DataError::BadRequest { .. }) = dev
                .share(&c, share_of(Rule::OneKey, writers, Vec::new()))
                .await
            else {
                panic!("a one-key collection shared with {writers:?}");
            };
            assert_eq!(e.next(), crate::NextStep::FixRequest);
        }
        dev.share(&c, share_of(Rule::OneKey, &["/sam/sensor"], Vec::new()))
            .await
            .unwrap();
        let writers = dev.inner.st.lock().colls[&c]
            .members
            .as_ref()
            .map(|m| m.writers.clone());
        assert_eq!(
            writers,
            Some(vec![dev.writer().key().clone()]),
            "this device's key"
        );
        let merge = n("/sam/32=data/notes");
        let Err(e @ DataError::BadRequest { .. }) = dev
            .put(&merge, reading(1), options(Some(Duration::from_millis(1))))
            .await
        else {
            panic!("a batch into a merge collection");
        };
        assert_eq!(e.next(), crate::NextStep::FixRequest);
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_range_read_returns_exactly_the_entries_in_range() {
        let sensor = n("/sam/sensor");
        let clock = Arc::new(AtomicU64::new(100));
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = device_at(&sensor, &keys_of(&sensor), &store, &clock).await;
        let c = n("/sam/32=data/temps");
        dev.share(&c, share_of(Rule::OneKey, &["/sam/sensor"], Vec::new()))
            .await
            .unwrap();
        for t in (100..=1_000).step_by(100) {
            clock.store(t, Ordering::Relaxed);
            dev.put(&c, reading(t), options(None)).await.unwrap();
        }
        // Three entries of one block, dated alike.
        clock.store(1_100, Ordering::Relaxed);
        let batch = Some(Duration::from_millis(20));
        let ids = futures::future::join_all(
            (0..3).map(|i| dev.put(&c, reading(1_100 + i), options(batch))),
        )
        .await;
        let block = ids[0].clone().unwrap();
        assert!(ids.iter().all(|id| id.as_ref() == Ok(&block)), "one block");
        // A clock gone back still dates entries in order.
        clock.store(50, Ordering::Relaxed);
        dev.put(&c, reading(1_200), options(None)).await.unwrap();

        let read = |range: Range| {
            let dev = dev.clone();
            let name = wire::range_name(&c, &range);
            async move {
                match dev.get(&name).await.unwrap().got {
                    Got::Entries(e) => e,
                    other => panic!("a range read answered {other:?}"),
                }
            }
        };
        let values = |e: &Entries| -> Vec<String> {
            e.entries
                .iter()
                .map(|x| String::from_utf8(x.content.get("t").unwrap().to_vec()).unwrap())
                .collect()
        };
        let times = read(Range::Times(Timestamp(300), Timestamp(750))).await;
        assert_eq!(values(&times), ["300", "400", "500", "600", "700"]);
        assert!(times.missing.is_empty() && times.expired.is_empty() && times.large.is_empty());
        let last = read(Range::Times(Timestamp(1_100), Timestamp(u64::MAX))).await;
        assert_eq!(values(&last), ["1100", "1101", "1102", "1200"]);
        assert!(
            last.entries.windows(2).all(|w| w[0].dated <= w[1].dated),
            "dated in order"
        );
        let none = read(Range::Times(Timestamp(0), Timestamp(100))).await;
        assert!(none.entries.is_empty());
        // By seq: exactly the blocks in range; an entry read by its name.
        let s = block.seq.0;
        let by_seq = read(Range::Seqs(s, s)).await;
        assert_eq!(values(&by_seq), ["1100", "1101", "1102"]);
        let one = &by_seq.entries[1];
        let Got::Entries(e) = dev.get(&one.name).await.unwrap().got else {
            panic!("an entry's name answers its entry");
        };
        assert_eq!(e.entries, vec![one.clone()]);
        // A malformed range name says how one is formed.
        let bad = c
            .clone()
            .append_component(ndn_packet::NameComponent::keyword(Bytes::from_static(
                b"range",
            )));
        assert!(matches!(
            dev.get(&bad).await,
            Err(DataError::BadName { .. })
        ));
        dev.shutdown();
    }

    #[tokio::test(start_paused = true)]
    async fn a_range_read_of_withheld_blocks_answers_within_its_bound() {
        let (sensor, reader) = (n("/sam/sensor"), n("/rita/phone"));
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.adopt_context(context("/rita")));
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&reader, &keys_of(&reader), &validator, &store)
            .await
            .unwrap();
        let c = n("/sam/32=data/temps");
        let key = sensor.clone().append("KEY").append("1");
        one_key_record(&dev, &c, &key);
        // A node of the sensor listed these blocks; the sensor sleeps, and
        // every path withholds them.
        let listed: BTreeSet<u64> = (1..=64).collect();
        dev.inner
            .st
            .lock()
            .colls
            .get_mut(&c)
            .expect("its record is held")
            .entries
            .insert(Writer::new(key.clone()), listed.clone());
        let t0 = Instant::now();
        let name = wire::range_name(&c, &Range::Times(Timestamp(0), Timestamp(u64::MAX)));
        let Got::Entries(e) = dev.get(&name).await.unwrap().got else {
            panic!("a range read answers entries");
        };
        let took = t0.elapsed();
        assert!(
            took <= dev.inner.config.first_look * RANGE_LOOKS,
            "a range read answers within its bound: {took:?}"
        );
        let missing: BTreeSet<u64> = e.missing.iter().map(|id| id.seq.0).collect();
        assert_eq!(missing, listed, "what it did not reach is missing");
        assert!(e.entries.is_empty() && e.expired.is_empty() && e.large.is_empty());
        dev.shutdown();
    }

    #[tokio::test(start_paused = true)]
    async fn a_sealed_block_expired_unopened_is_listed_expired_where_it_may_overlap() {
        let (sensor, reader) = (n("/sam/sensor"), n("/rita/phone"));
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.adopt_context(context("/rita")));
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&reader, &keys_of(&reader), &validator, &store)
            .await
            .unwrap();
        let c = n("/sam/32=data/temps");
        let key = sensor.clone().append("KEY").append("1");
        one_key_record(&dev, &c, &key);
        // A sealed block expires while locked: its last date is unknown.
        let mut coll = Coll::default();
        coll.locked.push(Locked {
            name: log_name(&sensor, Some(&c), 2),
            wire: Bytes::new(),
            writer: Writer::new(key.clone()),
            seq: 2,
            body: VersionBody {
                dated: Timestamp(200),
                ..version_body(
                    &c,
                    Some(SealedBody {
                        epoch: Epoch {
                            creator: n("/sam/owner"),
                            seq: Seq(1),
                        },
                        ciphertext: Bytes::new(),
                    }),
                )
            },
        });
        let (_, _, locked, _) = take_out(&mut coll, |_, _| true).remove(0);
        assert_eq!(locked.last, None, "a locked block's last date is unknown");
        let tomb = |first: u64, last: Option<u64>| Tomb {
            writer: key.clone(),
            keep: Keep::Until(Timestamp(1)),
            first: Timestamp(first),
            last: last.map(Timestamp),
        };
        {
            let mut st = dev.inner.st.lock();
            for (seq, t) in [
                (1, tomb(100, Some(150))),
                (2, locked),
                (3, tomb(900, Some(950))),
            ] {
                st.held
                    .insert(log_name(&sensor, Some(&c), seq), Held::Expired(t));
            }
            st.colls
                .get_mut(&c)
                .expect("its record is held")
                .entries
                .insert(Writer::new(key.clone()), [1, 2, 3].into());
        }
        // From after its first date: it may still overlap the range.
        let name = wire::range_name(&c, &Range::Times(Timestamp(300), Timestamp(800)));
        let Got::Entries(e) = dev.get(&name).await.unwrap().got else {
            panic!("a range read answers entries");
        };
        assert!(
            e.expired.iter().any(|id| id.seq.0 == 2),
            "listed expired: {e:?}"
        );
        dev.shutdown();
    }

    /// `key`'s version `seq` of `c`, written by `device`, kept forever and
    /// naming `parent` of its own writer, as a reader holds it.
    fn held_at(
        c: &Name,
        device: &Name,
        key: &Name,
        seq: u64,
        parent: Option<u64>,
    ) -> Arc<HeldVersion> {
        let writer = Writer::new(key.clone());
        let parents = parent
            .map(|p| {
                let id = VersionId {
                    writer: writer.clone(),
                    seq: Seq(p),
                };
                (id, None)
            })
            .into_iter()
            .collect();
        Arc::new(HeldVersion::new(
            Version {
                id: VersionId {
                    writer,
                    seq: Seq(seq),
                },
                name: log_name(device, Some(c), seq),
                collection: c.clone(),
                parents,
                type_id: TypeId {
                    name: n("/types/reading"),
                    revision: 1,
                },
                seal: Seal { any_of: Vec::new() },
                keep: Keep::Forever,
                dated: Timestamp(0),
                group: None,
                rule: None,
                payload: Payload::Entry(Content::new()),
            },
            Bytes::new(),
            Bytes::new(),
            false,
            None,
            None,
        ))
    }

    /// `key`'s node of `c` at `head`, listing `entries`, stating `expiry`.
    fn node_of(
        c: &Name,
        key: &Name,
        head: u64,
        entries: Vec<(u64, u64)>,
        expiry: Vec<ExpiryRun>,
    ) -> NodeBody {
        NodeBody {
            subject: c.clone(),
            writer: key.clone(),
            head,
            page: None,
            entries,
            members: Vec::new(),
            expiry,
            branches: Branches::Children(Vec::new()),
        }
    }

    #[tokio::test]
    async fn a_reader_stops_waiting_for_listed_versions_it_never_held_once_their_keep_bound_passes()
    {
        let (sensor, reader) = (n("/sam/sensor"), n("/rita/phone"));
        let clock = Arc::new(AtomicU64::new(1_000));
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = device_at(&reader, &keys_of(&reader), &store, &clock).await;
        let c = n("/sam/32=data/soil");
        let key = sensor.clone().append("KEY").append("1");
        one_key_record(&dev, &c, &key);
        let writer = Writer::new(key.clone());
        let last = VersionId {
            writer: writer.clone(),
            seq: Seq(7),
        };
        let bound = Timestamp(5_000);
        {
            let mut st = dev.inner.st.lock();
            // The writer's newest node lists 2–6, kept until at most the
            // bound, and 7, kept forever, naming 6; only 7 is held here.
            st.colls
                .get_mut(&c)
                .expect("its record is held")
                .entries
                .entry(writer.clone())
                .or_default()
                .extend(2..=7);
            let runs = vec![ExpiryRun {
                seqs: vec![(2, 6)],
                until: bound,
            }];
            st.listing(&c, &writer, &node_of(&c, &key, 7, vec![(2, 7)], runs));
            let wake = st.expire(&c);
            assert!(
                wake.is_some_and(|t| t <= bound),
                "the sweeper wakes by the bound: {wake:?}"
            );
            st.admit(held_at(&c, &sensor, &key, 7, Some(6)));
            assert!(
                !st.colls[&c].at().contains(&last),
                "waits while the bound is ahead"
            );
        }
        clock.store(bound.0, Ordering::Relaxed);
        {
            let mut st = dev.inner.st.lock();
            st.expire(&c);
            assert!(
                st.colls[&c].at().contains(&last),
                "applied once this device's clock passes the bound"
            );
        }
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_reader_does_not_wait_for_a_parent_its_writer_no_longer_lists_and_it_never_learned() {
        let (sensor, reader) = (n("/sam/sensor"), n("/rita/phone"));
        let clock = Arc::new(AtomicU64::new(1_000));
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = device_at(&reader, &keys_of(&reader), &store, &clock).await;
        let c = n("/sam/32=data/soil");
        let key = sensor.clone().append("KEY").append("1");
        one_key_record(&dev, &c, &key);
        let writer = Writer::new(key.clone());
        let id = |s: u64| VersionId {
            writer: writer.clone(),
            seq: Seq(s),
        };
        let mut st = dev.inner.st.lock();
        // The writer's newest node, at 8, lists 7 and 8 only: 2–6 expired
        // before it, and this reader never learned them.
        st.colls
            .get_mut(&c)
            .expect("its record is held")
            .entries
            .entry(writer.clone())
            .or_default()
            .extend([7, 8]);
        st.listing(&c, &writer, &node_of(&c, &key, 8, vec![(7, 8)], Vec::new()));
        st.expire(&c);
        st.admit(held_at(&c, &sensor, &key, 7, Some(6)));
        assert!(st.colls[&c].at().contains(&id(7)), "7 does not wait for 6");
        st.admit(held_at(&c, &sensor, &key, 8, Some(7)));
        assert!(st.colls[&c].at().contains(&id(8)));
        // A parent above the node's head may still come: it is waited for.
        st.admit(held_at(&c, &sensor, &key, 10, Some(9)));
        assert!(
            !st.colls[&c].at().contains(&id(10)),
            "10 waits for 9, above the newest node's head"
        );
        drop(st);
        dev.shutdown();
    }

    #[tokio::test(start_paused = true)]
    async fn a_batched_entry_waits_no_longer_than_its_delay() {
        let sensor = n("/sam/sensor");
        let clock = Arc::new(AtomicU64::new(100));
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = device_at(&sensor, &keys_of(&sensor), &store, &clock).await;
        let c = n("/sam/32=data/temps");
        dev.share(&c, share_of(Rule::OneKey, &["/sam/sensor"], Vec::new()))
            .await
            .unwrap();
        let t0 = Instant::now();
        let first = {
            let (dev, c) = (dev.clone(), c.clone());
            tokio::spawn(async move {
                let id = dev
                    .put(&c, reading(1), options(Some(Duration::from_secs(10))))
                    .await;
                (id, Instant::now())
            })
        };
        tokio::time::sleep(Duration::from_secs(1)).await;
        let second = dev
            .put(&c, reading(2), options(Some(Duration::from_secs(2))))
            .await
            .unwrap();
        let at2 = Instant::now();
        let (first, at1) = first.await.unwrap();
        assert_eq!(first.unwrap(), second, "the two share one block");
        assert!(
            at2 - t0 <= Duration::from_secs(3),
            "the second waited its 2 s"
        );
        assert!(at1 - t0 <= Duration::from_secs(3), "the first no longer");
        let st = dev.inner.st.lock();
        let v = &st.colls[&c].versions[&second].version;
        assert!(matches!(&v.payload, Payload::Block(e) if e.len() == 2));
        drop(st);
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_batch_delay_beyond_the_maximum_is_refused_saying_how() {
        let sensor = n("/sam/sensor");
        let clock = Arc::new(AtomicU64::new(100));
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = device_at(&sensor, &keys_of(&sensor), &store, &clock).await;
        let c = n("/sam/32=data/temps");
        dev.share(&c, share_of(Rule::OneKey, &["/sam/sensor"], Vec::new()))
            .await
            .unwrap();
        for batch in [BATCH_MAX + Duration::from_millis(1), Duration::MAX] {
            let Err(e @ DataError::BadRequest { .. }) =
                dev.put(&c, reading(1), options(Some(batch))).await
            else {
                panic!("a batch of {batch:?} is refused");
            };
            assert_eq!(e.next(), crate::NextStep::FixRequest);
        }
        // Nothing was left half done: the device still writes.
        dev.put(&c, reading(2), options(None))
            .await
            .expect("a put after a refused one");
        dev.shutdown();
    }

    #[test]
    fn an_expired_audit_answer_is_evidence_only_when_its_keep_proves_it_false() {
        let now = Timestamp(1_000_000_000);
        let skew = Config::new().clock_skew;
        let ask = |keep: Keep| Ask {
            piece: n("/sam/sensor/32=log/sam/32=data/temps/seq=1"),
            digest: [7; 32],
            keep,
        };
        let expired = |keep: Keep| judge(Some(Some(AuditAnswer::Expired)), &ask(keep), now, skew);
        let far = Timestamp(now.0 + 2 * skew.as_millis() as u64);
        for keep in [Keep::Forever, Keep::Until(far)] {
            assert!(
                matches!(expired(keep), Judged::Done(Asked::Breach(_))),
                "{keep:?}: no clock skew explains it"
            );
        }
        // A holder whose clock runs ahead by less than the skew, or one
        // that may know newer versions, is not framed.
        let near = Timestamp(now.0 + skew.as_millis() as u64 / 2);
        for keep in [Keep::Until(near), Keep::Until(now), Keep::LastN(3)] {
            assert!(
                matches!(expired(keep), Judged::Done(Asked::Unanswered)),
                "{keep:?}"
            );
        }
        // A holder that signs it lost the piece broke its lease.
        assert!(matches!(
            judge(
                Some(Some(AuditAnswer::Missing)),
                &ask(Keep::Forever),
                now,
                skew
            ),
            Judged::Done(Asked::Breach(_))
        ));
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
            let (authority, issuer, anchor) = authority(&n("/sam")).await;
            let phone = n("/sam/phone");
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
            assert!(validator.adopt_context(context("/rita")));
            assert!(validator.adopt_context(sam_context(&anchor, 1, None)));
            validator.cert_cache().insert(cert.clone());
            let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
            let tab = n("/rita/tab");
            let tab_keys = keys_of(&tab);
            let clock = Arc::new(AtomicU64::new(1_000));
            let dev = start_at(&tab, &tab_keys, &validator, &store, &clock)
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
    async fn versions_a_copy_of_its_key_pruned_come_back_at_their_writer_once_a_cut_refuses_it() {
        let (authority, issuer, anchor) = authority(&n("/sam")).await;
        let phone = n("/sam/phone");
        let (keys, key, cert) = device_key(&authority, &issuer, &phone).await;
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.adopt_context(sam_context(&anchor, 1, None)));
        validator.cert_cache().insert(cert);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&phone, &keys, &validator, &store).await.unwrap();
        let c = n("/sam/32=data/notes");
        dev.share(&c, share_of(Rule::Log, &["/sam"], Vec::new()))
            .await
            .unwrap();
        let mut names = Vec::new();
        for t in 1..=2 {
            let id = dev.put(&c, reading(t), options(None)).await.unwrap();
            names.push(log_name(&phone, Some(&c), id.seq.0));
        }
        let head = parse_log_name(&names[1]).unwrap().seq;
        // A copy of its key prunes both, at a seq this device never wrote.
        let thief = log_name(&phone, Some(&c), head + 1);
        let prune = Record::Prune(PruneBody {
            prefix: c.clone(),
            upto: frontier_of(dev.writer(), head),
        });
        let (packet, _) = signed(&keys, &key, &thief, &wire::encode_record(&prune));
        dev.inner
            .take_data(&thief, Data::decode(packet).unwrap())
            .await
            .expect("its key signed it");
        for name in &names {
            assert!(
                matches!(dev.get(name).await, Err(DataError::Pruned { .. })),
                "read as pruned until a cut refuses the prune"
            );
            assert!(store.get(name).is_some(), "its bytes stay at its writer");
        }
        // The cut accepts what this device wrote, not the prune.
        let mut cut = RevocationCut::new(key.clone());
        cut.add_run(&log_prefix(&thief), 1, head);
        validator
            .keyring()
            .adopt_update(sam_context(&anchor, 2, Some(cut)))
            .unwrap();
        until(&dev, |st| {
            names
                .iter()
                .all(|n| matches!(st.held.get(n), Some(Held::Version(_))))
        })
        .await;
        for name in &names {
            assert!(dev.get(name).await.is_ok(), "{name} is back");
        }
        assert!(outside_cut(dev.get(&thief).await));
        assert_eq!(
            dev.inner.st.lock().colls[&c].applied.get(dev.writer()),
            Some(&head)
        );
        dev.shutdown();
    }

    #[tokio::test]
    async fn a_writer_serves_its_re_admitted_version_by_name_and_digest() {
        let (authority, issuer, anchor) = authority(&n("/sam")).await;
        let phone = n("/sam/phone");
        let (keys, key, cert) = device_key(&authority, &issuer, &phone).await;
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        assert!(validator.adopt_context(sam_context(&anchor, 1, None)));
        validator.cert_cache().insert(cert);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let dev = start(&phone, &keys, &validator, &store).await.unwrap();
        let c = n("/sam/32=data/notes");
        dev.share(&c, share_of(Rule::Log, &["/sam"], Vec::new()))
            .await
            .unwrap();
        let id = dev.put(&c, reading(1), options(None)).await.unwrap();
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
            assert!(validator.adopt_context(sam_context(&anchor, 1, None)));
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
            own.dev
                .put(&own.c, reading(t), options(None))
                .await
                .unwrap();
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
            own.dev
                .put(&own.c, reading(t), options(None))
                .await
                .unwrap();
        }
        let head = own.dev.inner.st.lock().head;
        // As an earlier release kept it: no record of what it wrote.
        for (n, _) in own.store.scan_under(&written_prefix(), 0) {
            own.store.remove(&n);
        }
        let c = own.c.clone();
        let again = own.restart().await;
        assert_eq!(again.inner.st.lock().head, head);
        let id = again.put(&c, reading(3), options(None)).await.unwrap();
        assert_eq!(id.seq.0, head + 1, "it never signs a seq it used");
        again.shutdown();
    }

    #[tokio::test]
    async fn an_entry_at_the_last_seq_under_its_name_never_makes_its_next_write_wrap() {
        let own = OwnLog::new().await;
        own.dev
            .put(&own.c, reading(1), options(None))
            .await
            .unwrap();
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
        let id = again.put(&c, reading(2), options(None)).await.unwrap();
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
        assert!(validator.adopt_context(context("/rita")));
        assert!(validator.adopt_context(sam_context(&anchor, 1, None)));
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
        dev.share_folder(&f, share_of(Rule::Log, &["/alice", "/bob"], Vec::new()))
            .await
            .unwrap();
        dev.put(&c, reading(1), options(None)).await.unwrap();
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
            ),
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
                share_of(Rule::Log, &["/alice"], vec![Audience::Person(n("/bob"))]),
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
            ids.push(laptop.put(c, reading(1), options(None)).await.unwrap());
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
        dev.share_folder(&f, share_of(Rule::Log, &["/alice", "/bob"], Vec::new()))
            .await
            .unwrap();
        assert_eq!(hand(&dev, &bob, &c1, 1, version(&c1)), None);
        assert_eq!(hand(&dev, &bob, &c2, 2, version(&c2)), None);
        dev.share_folder(&f, share_of(Rule::Log, &["/alice"], Vec::new()))
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
        dev.share_folder(&f, share_of(Rule::Log, &["/alice", "/bob"], Vec::new()))
            .await
            .unwrap();
        let first = dev.inner.st.lock().folders[&f].line.own.clone().unwrap();
        // The laptop removes Bob; the phone, from the same record, adds Carol.
        dev.share_folder(&f, share_of(Rule::Log, &["/alice"], Vec::new()))
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
            ),
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
        dev.share_folder(&f, share_of(Rule::Log, &["/alice"], vec![person("/alice")]))
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
        assert!(validator.adopt_context(context("/alice")));
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
            assert!(validator.adopt_context(context(ns)));
        }
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let keys = keys_of(&device);
        let dev = start(&device, &keys, &validator, &store).await.unwrap();
        let f = n("/alice/32=data/notebook");
        let c = f.clone().append("cover");
        dev.share_folder(
            &f,
            share_of(Rule::Log, &["/alice"], vec![Audience::Person(n("/bob"))]),
        )
        .await
        .unwrap();
        dev.put(&c, reading(1), options(None)).await.unwrap();
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

    #[tokio::test]
    async fn an_entry_a_writers_node_of_the_same_head_lists_again_is_wanted_again() {
        let dev = device_in("/bob/phone", &["/alice", "/bob"]).await;
        let c = n("/alice/32=data/notebook/page1");
        let writer = Writer::new(n("/alice/laptop/KEY/1"));
        let node = |entries: Vec<(u64, u64)>| NodeBody {
            subject: c.clone(),
            writer: writer.key().clone(),
            head: 6,
            page: None,
            entries,
            members: Vec::new(),
            expiry: Vec::new(),
            branches: Branches::Children(Vec::new()),
        };
        let mut st = dev.inner.st.lock();
        st.colls.entry(c.clone()).or_default();
        let now = (st.clock)();
        // Its store lost seq 4: the node it signed at head 6 lists only 6.
        st.listing(&c, &writer, &node(vec![(6, 6)]));
        assert!(st.colls[&c].listings[&writer].gone(4, now));
        // Back, a node of the same head lists it again.
        st.listing(&c, &writer, &node(vec![(4, 4), (6, 6)]));
        assert!(!st.colls[&c].listings[&writer].gone(4, now));
        drop(st);
        dev.shutdown();
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod merge_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod group_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod merge_review_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod folder_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod admission_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod durability_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod watch_tests;

mod intro;
