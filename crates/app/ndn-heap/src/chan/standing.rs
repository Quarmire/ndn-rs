//! Who may take part in live data over a space: the membership judgement signals made
//! (`signal.rs`) and a channel makes, one function for both.
//!
//! A key **stands** when the person the trust context governing it names is listed by the
//! operation fold of the space the way the question asks ([`Who`]), the key's role is
//! `owner_capable` (a `guest` or a `node` device of a member is no member, as for the owner,
//! heap.md §9.9), the context does not revoke it and this node does not mark it suspected. It is
//! read from what is held at the call, so it flips on the first call after the entry that removes
//! a person, or the context that revokes a key, is held. [`gate`] asks the same of this device
//! itself.
//!
//! Signals keep their own surface (`signal_member`, `signal_scope`, `signal_header`): they call
//! these functions and map the answer to their own refusal.

use ndn_foundation_types::Name;

use crate::error::HeapError;
use crate::log::Log;
use crate::trust::{Judge, owner_capable};
use crate::wire::device_of;

/// Why nothing about a space is decided here yet.
pub(crate) const NO_RECORD: &str = "its creation, the owner's first members entry, is not held \
                                    here yet; follow the space (watch it) so the owner's entries \
                                    arrive, then ask again";

/// Whom a standing question is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Who {
    /// A writer: the owner always is.
    Writer,
    /// A writer or a reader, **everybody reading a public space** (what signals asked
    /// with `reads = true`).
    Reader,
    /// A writer or a reader the fold **lists**: a public space makes no reader of an unlisted
    /// person, because a channel's key is wrapped to a judged key (channel.md).
    Listed,
}

/// Why a key does not stand. [`signal`](crate::signal) maps these to its refusals, a channel to
/// its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Unstanding {
    /// No person of the asked kind owns the key, or its role is no owner-capable one, or it is no
    /// device key at all.
    NotMember,
    /// The trust context governing the key revokes it.
    Revoked,
    /// This node marks the key suspected.
    Suspected,
}

/// The person `key` belongs to, if the fold lists that person as `who` asks, the trust context
/// governing the key does not revoke it and this node does not mark it suspected. The context is
/// the one `judge` judges the key's packets about the space by (heap.md §9): the node's own for a
/// person it holds, else the view adopted for the person while a listing of the space names her
/// as a writer or a reader.
pub(crate) fn standing(log: &Log, judge: &Judge, key: &Name, who: Who) -> Result<Name, Unstanding> {
    if device_of(key).is_none() {
        return Err(Unstanding::NotMember);
    }
    let view = judge.view_for(key, &log.space, true);
    let context = view.keyring().context_for(key);
    let person = context.namespace();
    let fold = &log.fold;
    let listed = match who {
        Who::Writer => fold.is_writer(person),
        Who::Reader => fold.is_writer(person) || fold.is_reader(person),
        Who::Listed => fold.lists(person),
    };
    if person.is_empty() || !listed {
        return Err(Unstanding::NotMember);
    }
    // A person stands only through its `admin` and `member` devices, where its namespace
    // declares the role layout: a `guest` or a `node` relay device of a member is no member.
    if !owner_capable(&context, key) {
        return Err(Unstanding::NotMember);
    }
    if context.is_revoked(key) {
        return Err(Unstanding::Revoked);
    }
    if log.suspected(key) {
        return Err(Unstanding::Suspected);
    }
    Ok(person.clone())
}

/// This device may take part: the creation of the space is held and this device's key stands as
/// `who`. `use_for` names the use in the log line of a refusal.
pub(crate) fn gate(
    log: &Log,
    judge: &Judge,
    who: Who,
    use_for: &'static str,
) -> Result<(), HeapError> {
    if log.fold.create().is_none() {
        return Err(HeapError::NotReady {
            name: log.space.clone(),
            why: NO_RECORD.into(),
        });
    }
    let (why, next) = match standing(log, judge, &log.key, who) {
        Ok(_) => return Ok(()),
        Err(Unstanding::Revoked) => (
            "the trust context governing this device's key revokes it",
            "ask the owner to add this device's person to the space",
        ),
        Err(Unstanding::Suspected) => (
            "this device's key is marked suspected here",
            "unsuspect it if it is safe, or enrol this device with a new key",
        ),
        Err(Unstanding::NotMember) if who == Who::Writer => (
            "this device is no writer of it by the entries held",
            "ask the owner to add this device's person to the space",
        ),
        Err(Unstanding::NotMember) => (
            "this device is neither a writer nor a reader of it by the entries held",
            "ask the owner to add this device's person to the space",
        ),
    };
    tracing::debug!(space = %log.space, key = %log.key, "{use_for} refused: {why}");
    Err(HeapError::NotAllowed {
        space: log.space.clone(),
        why: format!("{why}; {next}"),
    })
}
