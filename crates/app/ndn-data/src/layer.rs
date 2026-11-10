//! The seven verbs, as one device's [`DataLayer`].
//!
//! Each verb maps one-to-one onto the model; nothing is added for
//! convenience. Deliberately absent: open/close/seek (versions are whole
//! values), mkdir (a collection exists when its first version is put),
//! locks and transactions (per-writer logs, merge rules, snapshots), ACLs
//! (members record and seal, edited by `share`), sync settings (`watch` is
//! sync), accounts (keys belong to devices), routes and cache control.

use std::pin::Pin;
use std::time::Duration;

use futures_core::Stream;
use ndn_foundation_types::Name;

use crate::collection::{Rule, Summary};
use crate::error::{DataError, Refusal};
use crate::merge::Value;
use crate::statement::{Custody, Prune, Snapshot};
use crate::version::{
    Audience, Content, Frontier, Keep, Timestamp, TypeId, Version, VersionId, Writer,
};

/// The longest batch delay a [`put`](DataLayer::put) accepts (spec §4.1):
/// an entry waits unsigned at most this long, and a one-key head states its
/// writer's delay as the freshness readers add to every answer's age
/// (spec §5.3). A day.
pub const BATCH_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// One version of a [`put_group`](DataLayer::put_group).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Edit {
    /// Fields, as [`put`](DataLayer::put) takes them.
    Fields(Content),
    /// The operation the app built, as [`put_op`](DataLayer::put_op) takes
    /// it (merge collections only).
    Op(bytes::Bytes),
}

/// The options of a [`put`](DataLayer::put).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PutOptions {
    /// The type the writer understands and writes.
    pub type_id: TypeId,
    /// The retention chosen now, at write.
    pub keep: Keep,
    /// The delay this producer accepts so that several entries share one
    /// signature in a block (model change M6, spec §4.1); `None` signs the
    /// version alone. A block closes at the earliest of its entries'
    /// arrival plus this delay, so no entry waits longer. Log and one-key
    /// collections only; at most [`BATCH_MAX`].
    pub batch: Option<Duration>,
}

/// Why a held, verified version is not in a state's value (spec §15).
///
/// The two kinds differ in how they end: the layer's own wait ends when
/// what it waits for arrives, and the version then counts
/// ([`Change::Counted`]); a rule's exclusion does not end by waiting.
/// `Display` is the bare reason.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NotCounted {
    /// The layer's own wait: its group is incomplete ("group incomplete: 1
    /// of 2"), not readable here, or waits for its readers' epoch, or a
    /// basis or pieces are still arriving. It ends: the version then counts
    /// and [`Change::Counted`] follows.
    Waits(String),
    /// A rule's own exclusion (its [`Counting::NotCounted`]), an apply that
    /// failed, a group refused or held back by a member its rule excludes:
    /// it does not end by waiting.
    ///
    /// [`Counting::NotCounted`]: crate::merge::Counting::NotCounted
    Excluded(String),
}

impl NotCounted {
    /// The reason, as a bare string, whichever kind it is.
    pub fn reason(&self) -> &str {
        match self {
            NotCounted::Waits(why) | NotCounted::Excluded(why) => why,
        }
    }
}

impl std::fmt::Display for NotCounted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

/// A merged value at a frontier, for a collection with a merge rule (model
/// change M10). Filled by slice 1.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct State {
    /// A name for exactly this state; a [`Snapshot`] pins it so it can be
    /// cited.
    pub name: Name,
    /// The collection.
    pub collection: Name,
    /// The versions the state is computed from.
    pub at: Frontier,
    /// The merged value, as the collection's rule defines it.
    pub value: Value,
    /// Versions of the collection held here that are not in `value`, with
    /// why (sorted by id): the rule's `NotCounted` (inside `at`), as
    /// [`NotCounted::Excluded`], and members of incomplete or unreadable
    /// groups, as [`NotCounted::Waits`].
    pub not_counted: Vec<(VersionId, NotCounted)>,
}

/// One entry of a block (or the one entry of a version that is no block),
/// verified through its block's signature (spec §4.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Entry {
    /// Its name, `<V>/32=entry/seg=<index>` ([`crate::wire::entry_name`]).
    pub name: Name,
    /// The block (version) carrying it.
    pub id: VersionId,
    /// Its 0-based index in the block.
    pub index: u32,
    /// Its date: the block's plus its offset. Display and indexing only.
    pub dated: Timestamp,
    /// The content.
    pub content: Content,
}

/// The entries a range read (or an entry's name) found, from one key's
/// stream (spec §5.4).
///
/// Complete exactly when `missing` is empty: relative to the summary node
/// the one key's head named, every block it lists within the bounds is
/// accounted for — read, expired here, or in pieces.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Entries {
    /// The collection.
    pub collection: Name,
    /// The one key that writes it.
    pub writer: Writer,
    /// The entries in the bounds, in (seq, index) order, each from a block
    /// of `writer` verified here.
    pub entries: Vec<Entry>,
    /// Listed blocks within the bounds that no path answered.
    pub missing: Vec<VersionId>,
    /// Blocks within the bounds this device knows expired.
    pub expired: Vec<VersionId>,
    /// Versions within the bounds that travel in pieces: read them by name.
    pub large: Vec<VersionId>,
}

/// What a [`get`](DataLayer::get) found.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Got {
    /// One exact version: asked by its name, or the newest of a one-key or
    /// log collection.
    Version(Version),
    /// The merged state of a merge collection, or a state named exactly.
    State(State),
    /// A snapshot, asked by its name.
    Snapshot(Snapshot),
    /// Entries of a one-key collection's blocks: a range read
    /// (`<C>/32=range/<R>`, [`crate::wire::range_name`]), or one entry by
    /// its name.
    Entries(Entries),
}

/// How old an answer may be (model invariant 5, "stale, never wrong").
///
/// Measured on the reader's own monotonic clock, so no wall clock — skewed,
/// lying or right — changes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Age {
    /// An exact name: the answer is immutable and cannot be stale.
    Exact,
    /// The newest by the collection's rule, as of the newest summary this
    /// device has verified.
    Newest {
        /// How long since any path last confirmed that summary is still the
        /// newest; zero when confirmed while answering.
        unconfirmed_for: Duration,
    },
}

/// The answer to a [`get`](DataLayer::get).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Answer {
    /// What was found.
    pub got: Got,
    /// How old it may be.
    pub age: Age,
}

/// One item of a [`watch`](DataLayer::watch).
///
/// Every change names the collection it is about
/// ([`collection`](Change::collection)), so one watch of a folder is one
/// stream for every collection under it, those created after the watch
/// began included, each change tagged (spec §15).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Change {
    /// A verified summary of the watched collection or folder, or of a
    /// node below it (a sub-folder or a collection) whose digest changed.
    /// Its tag is the node it summarises.
    Summary(Summary),
    /// A verified version beyond the watched frontier. Its tag is its
    /// collection.
    Version(Version),
    /// A version delivered earlier is no longer accepted (open item "before
    /// a cut arrives"): a cut that arrived later refuses it — a members
    /// record that removed its writer, or a trust context that revoked its
    /// key — or a trust context adopted later refuses its signer's
    /// certificate chain (an issuer above its key revoked). Sent to every
    /// watcher of the collection, whatever its frontier.
    Withdrawn {
        /// The version's collection.
        collection: Name,
        /// The version.
        id: VersionId,
        /// Why, as a `get` of it now answers: [`Refusal::OutsideCut`] with
        /// the cut that refuses it, or [`Refusal::Untrusted`] when its
        /// chain is refused (no cut excuses that, and no re-admission by
        /// name and digest applies; it comes back as a version if its key's
        /// chain verifies again).
        why: Refusal,
    },
    /// A version delivered earlier was pruned by its writer: the reader
    /// dropped it, and a `get` of it answers [`DataError::Pruned`]. Filled
    /// by slice 3.
    Pruned {
        /// The version's collection.
        collection: Name,
        /// The version.
        id: VersionId,
        /// The prune record that covers it.
        by: Prune,
    },
    /// A version delivered earlier expired by this device's clock (spec
    /// §14.1): the device dropped it, and a `get` of it answers
    /// [`DataError::Expired`].
    Expired {
        /// The version's collection.
        collection: Name,
        /// The version.
        id: VersionId,
        /// Its keep.
        keep: Keep,
    },
    /// Two different versions with one `(writer, seq)`: evidence against that
    /// key (model invariant 2). Readers keep both and report. Told once for
    /// each collection the two versions are in: when they are in two
    /// collections, a watcher of both is told twice, once tagged with each,
    /// and each telling carries the other collection's version by name and
    /// id only ([`Equivocal::Elsewhere`]): a watch shows the content of what
    /// lies under what it watches, never another collection's.
    Equivocation {
        /// The collection it is told for: `first`'s or `second`'s.
        collection: Name,
        /// The version seen first.
        first: Equivocal,
        /// The conflicting version.
        second: Equivocal,
    },
    /// A held, verified version that is not in the state: the rule's
    /// [`NotCounted`](crate::merge::Counting::NotCounted), or its group is
    /// incomplete or not readable here. Shown, never dropped. A version
    /// whose reason moves from a [`NotCounted::Waits`] to an
    /// [`NotCounted::Excluded`] (or back) is told again.
    NotCounted {
        /// The version's collection.
        collection: Name,
        /// The version.
        id: VersionId,
        /// Why it is not in the state.
        why: NotCounted,
    },
    /// A version reported [`NotCounted`](Change::NotCounted) now counts.
    Counted {
        /// The version's collection.
        collection: Name,
        /// The version.
        id: VersionId,
    },
    /// The value of a merge collection changed with no version delivered:
    /// `bases`, covered versions that versions applied here were made over
    /// (spec §5.2, covered versions as a basis), arrived after those
    /// versions applied without them, and the rule merged them again
    /// against them. Told to every watcher of the collection, whatever its
    /// frontier, only when the value changed; `get` the collection for its
    /// value now.
    Remerged {
        /// The collection.
        collection: Name,
        /// The bases handed, as the rule took them.
        bases: Vec<VersionId>,
    },
    /// The watcher fell behind: it left [`Config::watch_queue`] changes
    /// unread, so the changes after it were dropped until it read what was
    /// queued, and delivery then went on (spec §15). Never a silent loss:
    /// it comes after every change delivered before the gap. Read again —
    /// watch anew from the frontier held (what was missed is listed), or
    /// `get` what is shown. Its tag is the watched name.
    ///
    /// [`Config::watch_queue`]: crate::Config::watch_queue
    Lagged {
        /// The watched collection or folder.
        collection: Name,
    },
    /// A collection under the watched folder this device does not follow:
    /// `writer`, outside the collection's namespace, already made it follow
    /// as many collections of that namespace as
    /// [`Config::writer_collections`] allows one writer (spec §15). Its
    /// versions are not fetched; told once per writer and collection.
    ///
    /// [`Config::writer_collections`]: crate::Config::writer_collections
    Untracked {
        /// The collection not followed.
        collection: Name,
        /// The writer whose new collection it is.
        writer: Writer,
        /// Why, and what to do: follow the collection by its name to read
        /// it, or have the folder's owner remove the writer.
        why: String,
    },
    /// Persons' namespaces (`/user/<0xA1: …>`) the members record of
    /// `collection` — a folder or a collection — lists as writers, or by
    /// cuts, that this device does not adopt for it: past the most one
    /// subject adopts, or the most the device adopts for all folders
    /// together (spec §6.3). Their versions in `collection` are refused
    /// while not adopted. Told when the namespaces left out change.
    NotAdopted {
        /// The folder or collection whose record lists them.
        collection: Name,
        /// The namespaces not adopted for it.
        namespaces: Vec<Name>,
        /// Why, and what to do: the owner lists too many writers; have it
        /// list fewer, or adopt those namespaces on the device's node.
        why: String,
    },
    /// The members record in force over `collection` changed (spec §6.1,
    /// §15): a folder's (`collection` is the folder) or a collection's,
    /// whoever signed it — this device ([`share_folder`], an introduction's
    /// admission), another device of the owner, or a merge of concurrent
    /// records. `share` is what [`members`](DataLayer::members) answers for
    /// `collection` now. Told to a watch of `collection` itself, and to a
    /// watch of a folder above it when `collection` is a folder or has a
    /// record of its own; a collection that only inherits is told on its
    /// own watch, its folder's change included. A watch's listing starts
    /// with the record in force over each such name held here.
    ///
    /// [`share_folder`]: DataLayer::share_folder
    Members {
        /// The folder or collection whose record in force changed.
        collection: Name,
        /// Its record in force now.
        share: Share,
    },
}

/// One of the two versions of an [`Change::Equivocation`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Equivocal {
    /// A version of the collection the change is told for, whole.
    Here(Box<Version>),
    /// A version of another collection, by its name and id only: neither
    /// its content nor anything opened of it.
    Elsewhere {
        /// The version's own name (its log entry).
        name: Name,
        /// `(writer, seq)`: the change's other version's too.
        id: VersionId,
    },
}

impl Equivocal {
    /// `v`, as told to a watcher of collection `told`: whole when it is of
    /// `told`, else by name and id.
    pub fn of(v: &Version, told: &Name) -> Self {
        if v.collection == *told {
            Equivocal::Here(Box::new(v.clone()))
        } else {
            Equivocal::Elsewhere {
                name: v.name.clone(),
                id: v.id.clone(),
            }
        }
    }

    /// The version's own name.
    pub fn name(&self) -> &Name {
        match self {
            Equivocal::Here(v) => &v.name,
            Equivocal::Elsewhere { name, .. } => name,
        }
    }

    /// The version's id.
    pub fn id(&self) -> &VersionId {
        match self {
            Equivocal::Here(v) => &v.id,
            Equivocal::Elsewhere { id, .. } => id,
        }
    }
}

impl Change {
    /// The collection the change is about — for a
    /// [`Summary`](Change::Summary), the node it summarises (the watched
    /// name or a name below it): the tag that tells apart the collections of
    /// one folder watch.
    pub fn collection(&self) -> &Name {
        match self {
            Change::Summary(s) => &s.collection,
            Change::Version(v) => &v.collection,
            Change::Withdrawn { collection, .. }
            | Change::Pruned { collection, .. }
            | Change::Expired { collection, .. }
            | Change::Equivocation { collection, .. }
            | Change::NotCounted { collection, .. }
            | Change::Counted { collection, .. }
            | Change::Remerged { collection, .. }
            | Change::Lagged { collection }
            | Change::Untracked { collection, .. }
            | Change::NotAdopted { collection, .. }
            | Change::Members { collection, .. } => collection,
        }
    }
}

/// The stream a [`watch`](DataLayer::watch) returns. It ends only when the
/// layer shuts down.
pub type Changes = Pin<Box<dyn Stream<Item = Result<Change, DataError>> + Send>>;

/// What a [`hold`](DataLayer::hold) asks for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Hold {
    /// How many holders, each a distinct device, must keep it.
    pub copies: u32,
    /// Until when; each lease is capped by the data's keep.
    pub until: Timestamp,
    /// The holder devices the owner chooses, by name: at least `copies` of
    /// them, none of them this device. Only they are asked, and only their
    /// leases count (spec §13.2).
    pub holders: Vec<Name>,
}

/// The new content of a collection's members record, for
/// [`share`](DataLayer::share).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Share {
    /// What "newest" means. Set when the collection is first shared; the
    /// host sets it by policy for collections a person never shared.
    pub rule: Rule,
    /// Key-name prefixes that may write.
    pub writers: Vec<Name>,
    /// Who may read.
    pub readers: Vec<Audience>,
}

impl Share {
    /// The writers, readers and rule of `m`.
    pub fn of(m: &crate::Members) -> Self {
        Share {
            rule: m.rule.clone(),
            writers: m.writers.clone(),
            readers: m.readers.clone(),
        }
    }
}

/// What [`share_folder`](DataLayer::share_folder) signs: the whole new
/// content of the folder's members record, or a change to the record in
/// force when the device signs it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Sharing {
    /// The whole new content.
    Whole(Share),
    /// A change applied to the folder's own record in force at the moment
    /// the device signs, under its lock: a member added meanwhile — by an
    /// introduction's admission, or by a record of another device of the
    /// owner — stays. The rule stays the record's.
    Change(ShareChange),
}

impl From<Share> for Sharing {
    fn from(share: Share) -> Self {
        Sharing::Whole(share)
    }
}

impl From<ShareChange> for Sharing {
    fn from(change: ShareChange) -> Self {
        Sharing::Change(change)
    }
}

/// A change to a folder's members record ([`Sharing::Change`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ShareChange {
    /// Writer prefixes to add; one a listed writer covers already adds
    /// nothing.
    pub add_writers: Vec<Name>,
    /// Writer prefixes to remove, exactly as listed; one neither listed nor
    /// covered removes nothing. Removing cuts as a whole record removing it
    /// does.
    pub remove_writers: Vec<Name>,
    /// Readers to add; one admitted already, or any reader of a folder not
    /// sealed (which every reader reads), adds nothing.
    pub add_readers: Vec<Audience>,
    /// Readers to remove, exactly as listed; one neither listed nor
    /// admitted removes nothing. Removing moves the folder to a new epoch.
    pub remove_readers: Vec<Audience>,
}

/// One device's data layer: the seven verbs, signing with this device's
/// key.
///
/// Code mostly uses `get`, `put` and `watch`, plus `snapshot` when several
/// things change together. `hold`, `prune` and `share` run on host policy,
/// or when the person makes that gesture. No implementation exists yet; the
/// conformance cases in `ndn-sim` (`ndn-data-conformance`) are written
/// against this trait.
/// The futures are `Send` natively; on wasm32 (one thread, non-`Send`
/// timers) they are not.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait DataLayer: Send + Sync {
    /// `get(name) → version or state + age`.
    ///
    /// An exact version, state or snapshot by its name; or, by a
    /// collection's name, the newest by its rule — for a merge collection,
    /// the merged state at a frontier — with how stale it may be. A
    /// function's answer is a `get` on its name (slice 6). Readers that know
    /// a prune covering the name answer [`DataError::Pruned`]. When no path
    /// answers, older verified data is returned with its [`Age`] rather than
    /// an error. A merge collection whose rule this device does not know
    /// is held and answered [`DataError::RuleUnknown`], never read under
    /// another rule. Filled by slice 1.
    async fn get(&self, name: &Name) -> Result<Answer, DataError>;

    /// `put(collection, content, {type, keep}) → (writer, seq)`.
    ///
    /// A new immutable version from this device's key, naming as parents the
    /// frontier this device has seen. The collection's members and the trust
    /// schema decide whether this key may write; the collection's seal
    /// applies. Fields of the current state that `options.type_id` does not
    /// know are kept. With `options.batch`, the call returns once the block
    /// carrying the entry is signed, with that block's id. In a merge
    /// collection the rule makes the operation of the fields and checks and
    /// applies it, as [`put_op`](Self::put_op) does. Filled by slice 1.
    async fn put(
        &self,
        collection: &Name,
        content: Content,
        options: PutOptions,
    ) -> Result<VersionId, DataError>;

    /// `put`, with the operation the app built: a new version of the merge
    /// collection `collection` carrying `op` as its `MergeOp`, its parents
    /// the state's frontier. The collection's rule checks and applies it
    /// first; one it refuses is [`DataError::BadRequest`] with the rule's
    /// reason, and nothing is signed into the log. Merge collections whose
    /// rule this device knows only ([`DataError::RuleUnknown`] otherwise; a
    /// log or one-key collection is [`DataError::BadRequest`]).
    async fn put_op(
        &self,
        collection: &Name,
        op: bytes::Bytes,
        options: PutOptions,
    ) -> Result<VersionId, DataError>;

    /// `put` several versions as one group, counted all or none (spec
    /// §5.5): one version per item, each in its own collection, all
    /// collections of one folder (the same parent name), signed under one
    /// lock at consecutive seqs of this device's log. A reader counts them
    /// only once it holds and reads all of them, and none of them when any
    /// is refused. Refused — with nothing written — when there are no items
    /// or more than [`GROUP_MAX`](crate::GROUP_MAX), a collection comes
    /// twice, the collections are not of one folder, their records in force
    /// list different readers, `options.batch` is set, or an item's rule
    /// refuses its operation ([`DataError::BadRequest`]); an item's rule
    /// unknown here ([`DataError::RuleUnknown`]); a collection not writable
    /// here (that collection's own error). The ids, in item order.
    async fn put_group(
        &self,
        items: Vec<(Name, Edit)>,
        options: PutOptions,
    ) -> Result<Vec<VersionId>, DataError>;

    /// `watch(collection | folder, since F) → summary, new versions…`.
    ///
    /// Listing, history and live updates in one: what the collection holds
    /// beyond `since`, then everything new. Given a folder, one stream for
    /// every collection under it, those created after the watch began
    /// included, by any writer, every change tagged with its collection
    /// ([`Change::collection`]); `since` filters each collection alike. The
    /// listing shows what is applied (with [`Change::NotCounted`] for what
    /// is held but not counted) and the equivocation evidence held; a
    /// version not applied yet comes once it applies, so no version comes
    /// twice. Nested summaries let it descend only into children that
    /// changed. A watcher that leaves too many changes unread is told
    /// [`Change::Lagged`] rather than queued for without bound.
    async fn watch(&self, collection: &Name, since: &Frontier) -> Result<Changes, DataError>;

    /// `snapshot(names | collections) → snapshot`.
    ///
    /// One signed record pinning, for each name, the exact version it names
    /// or the collection's current state. Publishing it is the atomic
    /// multi-object change; it also makes a merged state citable. Filled by
    /// slice 2.
    async fn snapshot(&self, of: &[Name]) -> Result<Snapshot, DataError>;

    /// `hold(prefix, {copies, until, holders}) → custody`.
    ///
    /// Ask the holder devices the owner names to keep the collection
    /// `prefix` and get their signed leases back, never beyond the data's
    /// keep. Each call audits every live lease (random pieces, fresh nonces)
    /// and repairs: a named holder whose lease is broken, unanswered or
    /// missing is asked, until `copies` distinct holder devices hold it
    /// kept. Only a device of the collection's namespace asks
    /// ([`DataError::NotOwner`] otherwise); fewer holders than copies, or a
    /// holder that is no device or this device itself, is
    /// [`DataError::BadRequest`]. Filled by slice 3.
    async fn hold(&self, prefix: &Name, want: Hold) -> Result<Custody, DataError>;

    /// `prune(prefix, upto)`.
    ///
    /// Drop this writer's own versions of the collection `prefix` (or the
    /// one version `prefix` names) up to `upto`; the record spreads like
    /// data and ends the leases it covers. Versions by other keys are
    /// refused with [`DataError::NotOwnWrites`]; a merge collection's
    /// versions with [`DataError::NotPrunable`]; up to past this device's
    /// newest entry with [`DataError::BadRequest`]. Sealed data is erased by
    /// destroying its epoch's key once every writer's versions of the epoch
    /// are pruned or cut. Filled by slice 3.
    async fn prune(&self, prefix: &Name, upto: &Frontier) -> Result<(), DataError>;

    /// `share(collection, {readers, writers})`.
    ///
    /// Sign a new members record. Adding grants reading keys or write
    /// membership; removing a writer is a [`Cut`](crate::Cut) at what this device had
    /// seen of it — inside stays, the rest is refused — and removing a reader
    /// moves reading to a new epoch. Only the owner's key may do it. Under a
    /// folder whose record is in force, a record that would widen it — a
    /// writer its writers do not cover, a reader its readers do not admit —
    /// is refused with [`DataError::BadRequest`]: share the folder instead.
    /// Filled by slice 2.
    async fn share(&self, collection: &Name, members: Share) -> Result<(), DataError>;

    /// `share_folder(folder, {readers, writers} | change)`.
    ///
    /// Sign a new members record of `folder` (a name with at least one
    /// component after `32=data`), which governs every collection under it
    /// (spec §6): a collection writes and reads by its own record narrowed
    /// by every folder's above it, and one with no own writers or readers
    /// takes the folder's (sealed in the folder's epoch, one key for every
    /// collection that inherits it). Removing a writer cuts it at exactly
    /// the versions of its keys this device holds verified in every
    /// collection under the folder; removing a reader moves the folder to a
    /// new epoch. Only the owner's devices may do it
    /// ([`DataError::NotOwner`]).
    ///
    /// [`Sharing::Whole`] gives the whole new content; [`Sharing::Change`]
    /// adds and removes writers and readers of the folder's own record in
    /// force when the device signs, under its lock, so a member added
    /// meanwhile stays (spec §15). A change is refused
    /// ([`DataError::BadRequest`], nothing signed) that removes a writer or
    /// reader not listed but covered by one listed, or that would leave no
    /// writer or a sealed folder no reader; with no record of the folder
    /// held here it is [`DataError::NotReady`]. A change that changes
    /// nothing signs nothing.
    async fn share_folder(&self, folder: &Name, members: Sharing) -> Result<(), DataError>;

    /// `members(folder | collection) → {rule, writers, readers}`.
    ///
    /// The members record in force over `name` (spec §6.1, §15): of a
    /// folder, its own record narrowed by the folders above it; of a
    /// collection, its own narrowed by the folders above it, which for a
    /// collection with no record of its own is its nearest folder's. A name
    /// with a folder record held answers the folder's. Whoever signed it —
    /// this device, an introduction's admission, another device of the
    /// owner — and its changes come as [`Change::Members`] on a watch.
    /// [`DataError::NotReady`] when no record over `name` is held here,
    /// saying what to do.
    async fn members(&self, name: &Name) -> Result<Share, DataError>;
}
