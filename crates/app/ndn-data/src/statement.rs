//! The version that says something about other versions: [`Snapshot`]. It is
//! itself a signed version and spreads like data.

use ndn_foundation_types::Name;

use crate::version::VersionId;

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
