//! Versions that say something about other versions: [`Snapshot`],
//! [`Custody`] (made of [`Lease`]s) and [`Prune`]. Each is itself a signed
//! version and spreads like data.

use ndn_foundation_types::Name;

use crate::version::{Frontier, Timestamp, VersionId, Writer};

/// A signed record naming exact versions or exact states (model primitive
/// "Snapshot").
///
/// Publishing one is the atomic multi-object change. For a merge collection
/// it names a merged state so the state can be cited: [`get`] on a pinned
/// name answers the same thing however the collection grows later (model
/// change M10). Filled by slice 2.
///
/// [`get`]: crate::DataLayer::get
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Snapshot {
    /// The snapshot's own id.
    pub id: VersionId,
    /// The snapshot's name: what a link to it carries.
    pub name: Name,
    /// The pinned names: each an exact version's name or an exact state's
    /// name ([`State::name`](crate::State::name)).
    pub pins: Vec<Name>,
}

/// A signed promise by one holder (model primitive "Custody").
///
/// Holder `holder` keeps what lies under `prefix` until `until`, never beyond
/// the data's own [`Keep`](crate::Keep), and the lease ends for anything an
/// authorised [`Prune`] covers (model change M5). Filled by slice 3.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Lease {
    /// The holder's key, which signs the lease.
    pub holder: Writer,
    /// What it keeps.
    pub prefix: Name,
    /// Until when, capped by the data's keep.
    pub until: Timestamp,
}

/// The leases a [`hold`](crate::DataLayer::hold) obtained.
///
/// Durability is the set of live leases. The owner audits them by fetching
/// random pieces from each holder; a lease nobody can serve counts as broken
/// and repair starts. Filled by slice 3.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Custody {
    /// The prefix held.
    pub prefix: Name,
    /// One lease per holder that accepted.
    pub leases: Vec<Lease>,
}

/// A signed record dropping the pruner's own versions under a prefix up to a
/// point (model primitive "Prune").
///
/// It covers only what the pruner may write (model change M9); removing
/// someone else's data in a shared collection is a merge edit instead. Readers
/// that know of it report "pruned", not the data; copies already made are the
/// stated forward-only limit (model invariant 9). Filled by slice 3.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Prune {
    /// The prune record's own id.
    pub id: VersionId,
    /// The prefix pruned.
    pub prefix: Name,
    /// The point up to which versions are dropped.
    pub upto: Frontier,
}
