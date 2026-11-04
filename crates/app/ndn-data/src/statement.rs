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
/// Holder `holder` keeps every version of the collection `prefix` inside
/// [`holds`](Self::holds) that applies — admitted by the collection's
/// members record, not pruned — with its pieces, each until the earlier of
/// [`until`](Self::until) and the version's own [`Keep`](crate::Keep). The
/// lease is a log entry of the holder, so it spreads like data; the newest
/// of one holder supersedes its older ones, and an authorised [`Prune`]
/// ends it for what the prune covers (model change M5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Lease {
    /// The holder's key, which signs the lease.
    pub holder: Writer,
    /// The lease's own name: a log entry of the holder.
    pub name: Name,
    /// The collection held.
    pub prefix: Name,
    /// What the holder held, verified, when it signed: exactly what it
    /// promises and what an audit asks it for.
    pub holds: Frontier,
    /// Until when; never beyond the keep of what it holds.
    pub until: Timestamp,
    /// This device's last audit of the lease.
    pub audit: Audit,
}

/// An owner device's audit of a [`Lease`]: random pieces of what the lease
/// promises, each asked for from the holder with a fresh nonce (spec §13).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Audit {
    /// Not audited by this device yet.
    NotAudited,
    /// Every piece asked for came back, signed by the holder, and was the
    /// piece.
    Kept {
        /// How many pieces were asked for.
        pieces: u32,
    },
    /// The holder signed an answer that is evidence of a broken promise.
    Broken {
        /// The piece it failed.
        piece: Name,
        /// How.
        breach: Breach,
    },
    /// The holder did not answer for some pieces. No verdict: unanswered
    /// pieces are not evidence (they may be the network's), but durability
    /// is unconfirmed, so repair starts as for a broken lease.
    Unanswered {
        /// Pieces asked for.
        asked: u32,
        /// Pieces answered and verified.
        answered: u32,
    },
}

impl Audit {
    /// Whether the last audit confirmed the lease.
    pub fn kept(&self) -> bool {
        matches!(self, Audit::Kept { .. })
    }
}

/// How a holder's signed audit answer breaks its lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Breach {
    /// It signed that it does not hold the piece.
    Missing,
    /// It signed bytes that are not the piece.
    Wrong,
    /// It signed that the piece expired while its writer's signed keep
    /// shows it has not: kept forever, or until a date further past the
    /// auditor's clock than any clock skew it allows.
    Expired,
}

/// The custody of one collection after a [`hold`](crate::DataLayer::hold):
/// the leases that hold it, each audited.
///
/// Durability is the set of live leases audited [`Audit::Kept`]. A lease
/// whose audit finds it broken, or unanswered, counts as not holding, and
/// repair starts: the holder is asked again (it fetches back what it lost),
/// then other holders, until `copies` leases are kept.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Custody {
    /// The collection held.
    pub prefix: Name,
    /// How many holders were asked for.
    pub copies: u32,
    /// Until when, as asked; each lease is capped by the data's keep.
    pub until: Timestamp,
    /// The live leases after repair, each with this device's last audit.
    pub leases: Vec<Lease>,
    /// The leases this call found broken or unanswered, before repair.
    pub broken: Vec<Lease>,
    /// The versions asked for that no kept lease holds after repair and
    /// that this device does not hold whole either: kept nowhere this
    /// device can confirm. They are lost unless a copy turns up; the next
    /// step is to put them again from wherever a copy is left.
    pub unkept: Vec<Name>,
}

/// A signed record dropping the pruner's own versions under a prefix up to a
/// point (model primitive "Prune").
///
/// It covers only what the pruner may write (model change M9): its own
/// versions of the collection `prefix` names (or the one version `prefix`
/// names) whose seq is at most what `upto` lists for its key; removing
/// someone else's data in a shared collection is a merge edit instead. It
/// is a log entry of the pruner, so it spreads like data. Readers that know
/// of it report "pruned", not the data, holders drop it and their leases
/// end for it, and copies already made are the stated forward-only limit
/// (model invariant 9).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Prune {
    /// The prune record's own id.
    pub id: VersionId,
    /// The prune record's own name.
    pub name: Name,
    /// The prefix pruned: a collection, or one version's name.
    pub prefix: Name,
    /// The point up to which versions are dropped.
    pub upto: Frontier,
}
