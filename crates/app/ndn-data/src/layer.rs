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

use crate::collection::{Cut, Rule, Summary};
use crate::error::DataError;
use crate::statement::{Custody, Snapshot};
use crate::version::{Audience, Content, Frontier, Keep, Timestamp, TypeId, Version, VersionId};

/// The options of a [`put`](DataLayer::put).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PutOptions {
    /// The type the writer understands and writes.
    pub type_id: TypeId,
    /// The retention chosen now, at write.
    pub keep: Keep,
    /// The delay this producer accepts so that several entries share one
    /// signature in a block (model change M6); `None` signs the version
    /// alone. Filled by slice 4.
    pub batch: Option<Duration>,
}

/// A merged value at a frontier, for a collection with the merge rule (model
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
    /// The merged value.
    pub value: Content,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Change {
    /// A verified summary of the collection, or of a child whose digest
    /// changed.
    Summary(Summary),
    /// A verified version beyond the watched frontier.
    Version(Version),
    /// A version delivered earlier is no longer accepted: a cut that arrived
    /// later refuses it (open item "before a cut arrives"). Filled by slice 2.
    Withdrawn {
        /// The version.
        id: VersionId,
        /// The cut that refuses it.
        cut: Cut,
    },
    /// Two different versions with one `(writer, seq)`: evidence against that
    /// key (model invariant 2). Readers keep both and report.
    Equivocation {
        /// The version seen first.
        first: Box<Version>,
        /// The conflicting version.
        second: Box<Version>,
    },
}

/// The stream a [`watch`](DataLayer::watch) returns. It ends only when the
/// layer shuts down.
pub type Changes = Pin<Box<dyn Stream<Item = Result<Change, DataError>> + Send>>;

/// What a [`hold`](DataLayer::hold) asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hold {
    /// How many holders.
    pub copies: u32,
    /// Until when; each lease is capped by the data's keep.
    pub until: Timestamp,
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
    /// Versions outside a cut the owner signs back in. Filled by slice 5.
    pub readmit: Vec<VersionId>,
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
    /// an error. Filled by slice 1.
    async fn get(&self, name: &Name) -> Result<Answer, DataError>;

    /// `put(collection, content, {type, keep}) → (writer, seq)`.
    ///
    /// A new immutable version from this device's key, naming as parents the
    /// frontier this device has seen. The collection's members and the trust
    /// schema decide whether this key may write; the collection's seal
    /// applies. Fields of the current state that `options.type_id` does not
    /// know are kept. With `options.batch`, the call returns once the block
    /// carrying the entry is signed, with that block's id. Filled by slice 1.
    async fn put(
        &self,
        collection: &Name,
        content: Content,
        options: PutOptions,
    ) -> Result<VersionId, DataError>;

    /// `watch(collection, since F) → summary, new versions…`.
    ///
    /// Listing, history and live updates in one: what the collection holds
    /// beyond `since`, then everything new. Nested summaries let it descend
    /// only into children that changed. Filled by slice 1.
    async fn watch(&self, collection: &Name, since: &Frontier) -> Result<Changes, DataError>;

    /// `snapshot(names | collections) → snapshot`.
    ///
    /// One signed record pinning, for each name, the exact version it names
    /// or the collection's current state. Publishing it is the atomic
    /// multi-object change; it also makes a merged state citable. Filled by
    /// slice 2.
    async fn snapshot(&self, of: &[Name]) -> Result<Snapshot, DataError>;

    /// `hold(prefix, {copies, until}) → custody`.
    ///
    /// Ask holders to keep what is under `prefix`, and get their signed
    /// leases back, never beyond the data's keep. Filled by slice 3.
    async fn hold(&self, prefix: &Name, want: Hold) -> Result<Custody, DataError>;

    /// `prune(prefix, upto)`.
    ///
    /// Drop this writer's own versions under `prefix` up to `upto`; the
    /// record spreads like data and ends the leases it covers. Versions by
    /// other keys are refused with [`DataError::NotOwnWrites`]. Sealed data
    /// is erased by destroying its key. Filled by slice 3.
    async fn prune(&self, prefix: &Name, upto: &Frontier) -> Result<(), DataError>;

    /// `share(collection, {readers, writers})`.
    ///
    /// Sign a new members record. Adding grants reading keys or write
    /// membership; removing a writer is a [`Cut`] at what this device had
    /// seen of it — inside stays, the rest is refused — and removing a reader
    /// moves reading to a new epoch. Only the owner's key may do it. Filled
    /// by slice 2.
    async fn share(&self, collection: &Name, members: Share) -> Result<(), DataError>;
}
