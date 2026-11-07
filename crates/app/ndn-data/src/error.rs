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
use crate::version::{Keep, Timestamp, VersionId, Writer};

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
    /// Run a program that knows the named merge rule: this one holds the
    /// collection's versions and reads them under no other rule.
    UpdateProgram,
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
    /// It is a summary, members record or one-key head older than one
    /// already seen from the same signer.
    Rollback,
    /// It is not sealed, and the collection's members record seals the
    /// collection: its writer wrote it before hearing the record that sealed
    /// it. Versions inside the record's `since` (written before the seal)
    /// are not refused for this.
    Unsealed,
    /// Its payload is a block, and the collection's merge rule needs one
    /// operation per version (spec §4.1).
    NotInline,
    /// Its key is marked suspected on this device (it may be in a thief's
    /// hands, [`Device::suspect`](crate::Device::suspect)): no new entry of
    /// it is taken while the mark stands; the entries held from before stay.
    Suspected {
        /// The key, `<id>/KEY/<k>`.
        key: Name,
        /// Since when, by this device's clock, as the owner said.
        since: Timestamp,
    },
    /// The durable rule, run again on its packet against the trust contexts
    /// held now, refuses it for a reason no cut can excuse: a key above its
    /// signer (an issuer in its certificate chain) is revoked, or the chain
    /// is no longer authorized. Withdrawn, not re-admitted by name and
    /// digest; taken back only if its key's chain verifies again (a new
    /// certificate of the key from an issuer still trusted).
    Untrusted {
        /// The validator's verdict.
        why: String,
    },
    /// It is under this device's own name at a seq far beyond the last one
    /// this device wrote: a copy of its key signed it.
    BeyondOwnLog {
        /// The last seq this device wrote.
        head: u64,
    },
    /// The collection's merge rule refuses its operation: its check or its
    /// application failed, for good.
    Rule {
        /// The rule's reason.
        why: String,
    },
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
                    "its key lies under {}, which {} cut (a writer the collection's owner \
                     removed, or a key its namespace's trust context revoked), and the cut \
                     accepts exactly {}, which this version is not, whatever date or seq it \
                     claims; ask the owner (who may write the member back in, or re-admit this \
                     exact version of a revoked key)",
                    cut.of,
                    cut.signer.key(),
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
                "its payload is a block of entries, and the collection's merge rule needs one \
                 operation per version; its writer writes each entry as its own version, or puts \
                 the stream into a log collection and refers to it by name",
            ),
            Refusal::Rule { why } => write!(
                f,
                "the collection's merge rule refuses its operation ({why}); its writer writes \
                 an operation the rule takes"
            ),
            Refusal::Suspected { key, since } => write!(
                f,
                "its key {key} is marked suspected on this device since {} (it may be in a \
                 thief's hands), so no new entry of it is taken; finish the key's revocation \
                 (the owner revokes it with a cut bounded by when it was lost), or unsuspect \
                 the key if it is safe",
                since.0
            ),
            Refusal::Untrusted { why } => write!(
                f,
                "the trust context held now no longer lets its signer's certificate chain \
                 sign it ({why}), which no cut excuses; it is taken back only once its key has \
                 a certificate from an issuer still trusted (ask the namespace owner to \
                 certify the writer again)"
            ),
            Refusal::BeyondOwnLog { head } => write!(
                f,
                "it is under this device's own name at a seq far beyond the last one this \
                 device wrote ({head}): a copy of this device's key signed it; mark the key \
                 suspected and have the owner revoke it with a cut"
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
    /// The data's keep passed by this device's clock (spec §14.1): it
    /// dropped it and keeps none of it, whoever else may still hold it.
    #[error("{name} expired: its keep {keep:?} passed by this device's clock")]
    Expired {
        /// The name asked for.
        name: Name,
        /// The keep its writer chose.
        keep: Keep,
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
    #[error(
        "the key {} may not write into {collection}; ask its owner to add it as a writer",
        writer.key()
    )]
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
    /// The payload is too large: a version carries at most
    /// [`PAYLOAD_MAX`](crate::wire::PAYLOAD_MAX) octets, in pieces.
    #[error(
        "a payload of {size} octets is larger than the {limit} a version of {collection} carries; \
         split it into several versions, or put it into a log collection in parts, and refer to \
         them by name"
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
    /// The collection's members record names a merge rule this program
    /// does not know.
    #[error(
        "{collection} merges with {rule}, which this program does not know: it is held here \
         unreadable and never read under another rule; update the program to one that knows \
         {rule}"
    )]
    RuleUnknown {
        /// The collection.
        collection: Name,
        /// The rule its members record names.
        rule: Name,
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
            DataError::NotFound { .. } | DataError::Pruned { .. } | DataError::Expired { .. } => {
                NextStep::None
            }
            DataError::BadName { .. } | DataError::TooLarge { .. } => NextStep::FixName,
            DataError::Refused { why, .. } => match why {
                Refusal::OutsideCut(_)
                | Refusal::NotMember
                | Refusal::Suspected { .. }
                | Refusal::Untrusted { .. }
                | Refusal::BeyondOwnLog { .. } => NextStep::AskOwner,
                Refusal::BadSignature | Refusal::Rollback => NextStep::RetryLater,
                Refusal::Unsealed | Refusal::NotInline | Refusal::Rule { .. } => NextStep::None,
            },
            DataError::NotAllowed { .. } | DataError::Sealed { .. } => NextStep::AskOwner,
            DataError::NotOwner { .. } => NextStep::UseOwnerDevice,
            DataError::NotOwnWrites { .. } | DataError::NotPrunable { .. } => NextStep::EditInstead,
            DataError::NotHeld { .. } => NextStep::HoldFirst,
            DataError::BadRequest { .. } => NextStep::FixRequest,
            DataError::Local { .. } => NextStep::FixLocal,
            DataError::RuleUnknown { .. } => NextStep::UpdateProgram,
        }
    }
}
