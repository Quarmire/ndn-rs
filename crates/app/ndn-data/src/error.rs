//! Why a verb did not do what was asked, and what to do about it.
//!
//! Every [`DataError`] says why in its message and what to do in
//! [`DataError::next`], with [`DataError::retry`] telling whether the same
//! call, unchanged, can succeed later. Failures that the model degrades
//! instead ("stale, never wrong", model invariant 5) are not errors: `get`
//! answers older verified data with its [`Age`](crate::Age).

use ndn_foundation_types::Name;

use crate::collection::Cut;
use crate::statement::Prune;
use crate::version::{VersionId, Writer};

/// What the caller can do about an error, by class. A host words the step
/// itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NextStep {
    /// Nothing: the outcome is final and correct.
    None,
    /// Ask again later, unchanged: no path or holder answered.
    RetryLater,
    /// Ask the collection's owner: for membership, a reading key, or the
    /// re-admission of work a cut refused.
    AskOwner,
    /// Do it on a device holding the owner's key.
    UseOwnerDevice,
    /// Remove it with an edit to the collection instead: the data is someone
    /// else's.
    EditInstead,
    /// Fix this device: its storage or its keys.
    FixLocal,
    /// Ask again with a name the layer can use: the error says how such a
    /// name is formed.
    FixName,
    /// Ask holders to keep it first (`hold`), and audit them: nothing
    /// confirms it is kept anywhere else.
    HoldFirst,
    /// Ask again as the error says: the request, as given, asks for
    /// something no device does (a prune past the log, too few holders).
    FixRequest,
}

/// Why a version was refused. A refused version is never served as data.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// Its key was cut and the cut does not list it, whatever date or seq
    /// it claims.
    OutsideCut(Cut),
    /// Its key is not a writer of the collection, by the members record and
    /// the trust schema.
    NotMember,
    /// It does not verify: wrong signature, or bytes that do not match its
    /// name (a poisoned cache).
    BadSignature,
    /// It is a summary or members record older than one already seen from
    /// the same signer.
    Rollback,
    /// It is not sealed, and the collection's members record seals the
    /// collection: its writer wrote it before hearing the record that sealed
    /// it. Versions inside the record's `since` (written before the seal)
    /// are not refused for this.
    Unsealed,
    /// Its payload travels in pieces, and the collection's merge rule needs
    /// every operation inline in its version (spec §4.1).
    NotInline,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::OutsideCut(cut) => {
                let accepted = cut
                    .accept
                    .iter()
                    .map(|(w, ranges)| {
                        let seqs = ranges
                            .iter()
                            .map(|(lo, hi)| match lo == hi {
                                true => lo.to_string(),
                                false => format!("{lo}–{hi}"),
                            })
                            .collect::<Vec<_>>();
                        format!("{} seq {}", w.key(), seqs.join(", "))
                    })
                    .collect::<Vec<_>>();
                write!(
                    f,
                    "its key lies under {}, which the collection's owner removed, and the cut \
                     accepts exactly {}, which this version is not, whatever date or seq it \
                     claims; ask the owner",
                    cut.of,
                    if accepted.is_empty() {
                        "nothing of it".to_owned()
                    } else {
                        accepted.join(", ")
                    }
                )
            }
            Refusal::NotMember => f.write_str(
                "its key is not a writer of the collection by its members record; ask the owner",
            ),
            Refusal::BadSignature => f.write_str(
                "it does not verify (signature, name or sealed payload); it may verify when \
                 fetched from another holder",
            ),
            Refusal::Rollback => {
                f.write_str("it is older than one already verified from the same signer")
            }
            Refusal::Unsealed => f.write_str(
                "it is not sealed, and the collection's members record seals it: its writer \
                 wrote it before hearing the record that sealed the collection; the writer \
                 writes it again, sealed",
            ),
            Refusal::NotInline => f.write_str(
                "its payload travels in pieces, and the collection's merge rule needs every \
                 operation inline; its writer writes it again inline, or puts the large value \
                 into a log collection and refers to it by name",
            ),
        }
    }
}

/// A data-layer error.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DataError {
    /// Nothing by this name is held here and no holder answered.
    #[error("{name} is not held here and no holder answered")]
    Unavailable {
        /// The name asked for.
        name: Name,
    },
    /// A signed summary covering the name shows there is no such version.
    #[error("no version is named {name}")]
    NotFound {
        /// The name asked for.
        name: Name,
    },
    /// The name cannot name what the verb takes: a collection is
    /// `<namespace>/32=data/<path>` (spec §3). Nothing by it can exist.
    #[error("{name} is not a data-layer name: {why}")]
    BadName {
        /// The name given.
        name: Name,
        /// Why not, and how to name it.
        why: String,
    },
    /// The data was pruned by its writer; this reader knows the prune.
    #[error("{name} was pruned by {by:?}")]
    Pruned {
        /// The name asked for.
        name: Name,
        /// The prune record that covers it.
        by: Prune,
    },
    /// The version is refused.
    #[error("version {} of {} is refused: {why}", id.seq.0, id.writer.key())]
    Refused {
        /// The refused version.
        id: VersionId,
        /// Why.
        why: Refusal,
    },
    /// This device's key may not write into the collection.
    #[error("{writer:?} may not write into {collection}")]
    NotAllowed {
        /// The collection.
        collection: Name,
        /// This device's key.
        writer: Writer,
    },
    /// Only the collection's owner signs its members record.
    #[error("only the owner of {collection} may change its members")]
    NotOwner {
        /// The collection.
        collection: Name,
    },
    /// Prune reaches only the pruner's own writes (model change M9).
    #[error("{prefix} holds versions this key did not write; prune covers only its own writes")]
    NotOwnWrites {
        /// The prefix asked for.
        prefix: Name,
    },
    /// This device is not in the data's seal audience.
    #[error("{name} is sealed to an audience this device is not in")]
    Sealed {
        /// The name asked for.
        name: Name,
    },
    /// The payload is too large for the collection's rule: a merge
    /// collection carries every operation inline (spec §4.1); a log
    /// collection, in pieces, up to [`PAYLOAD_MAX`](crate::wire::PAYLOAD_MAX).
    #[error(
        "a payload of {size} octets is larger than the {limit} a version of {collection} carries \
         (inline in a merge collection, in pieces in a log collection); put a large value into a \
         log collection, where it travels in pieces, split one larger than that, and refer to it \
         by name"
    )]
    TooLarge {
        /// The collection.
        collection: Name,
        /// The payload's octets.
        size: u64,
        /// The most a version of the collection carries.
        limit: u64,
    },
    /// Prune does not apply to this collection's rule (spec §14).
    #[error("{name} cannot be pruned: {why}")]
    NotPrunable {
        /// The name given.
        name: Name,
        /// Why, and what to do instead.
        why: String,
    },
    /// Nothing confirms the data is kept anywhere but here, so this device
    /// keeps its copy.
    #[error(
        "{name} is not released: {why}; ask holders that keep it to hold it (hold), then release \
         it again"
    )]
    NotHeld {
        /// The name given.
        name: Name,
        /// Why the evidence did not suffice: which holders proved what.
        why: String,
    },
    /// The request asks for something no device does as given.
    #[error("{name}: {why}")]
    BadRequest {
        /// The name given.
        name: Name,
        /// Why, and what to ask instead.
        why: String,
    },
    /// A local failure: storage or keys.
    #[error("local failure: {reason}")]
    Local {
        /// What failed.
        reason: String,
    },
}

impl DataError {
    /// Whether the same call, unchanged, can succeed later.
    pub fn retry(&self) -> bool {
        match self {
            DataError::Unavailable { .. } => true,
            DataError::Refused { why, .. } => {
                matches!(why, Refusal::BadSignature | Refusal::Rollback)
            }
            _ => false,
        }
    }

    /// What to do about it.
    pub fn next(&self) -> NextStep {
        match self {
            DataError::Unavailable { .. } => NextStep::RetryLater,
            DataError::NotFound { .. } | DataError::Pruned { .. } => NextStep::None,
            DataError::BadName { .. } | DataError::TooLarge { .. } => NextStep::FixName,
            DataError::Refused { why, .. } => match why {
                Refusal::OutsideCut(_) | Refusal::NotMember => NextStep::AskOwner,
                Refusal::BadSignature | Refusal::Rollback => NextStep::RetryLater,
                Refusal::Unsealed | Refusal::NotInline => NextStep::None,
            },
            DataError::NotAllowed { .. } | DataError::Sealed { .. } => NextStep::AskOwner,
            DataError::NotOwner { .. } => NextStep::UseOwnerDevice,
            DataError::NotOwnWrites { .. } | DataError::NotPrunable { .. } => NextStep::EditInstead,
            DataError::NotHeld { .. } => NextStep::HoldFirst,
            DataError::BadRequest { .. } => NextStep::FixRequest,
            DataError::Local { .. } => NextStep::FixLocal,
        }
    }
}
