//! Who may take part in live data over a space: the membership judgement a channel makes.
//!
//! A key **stands** when the person the trust context governing it names is listed by the
//! operation fold of the space the way the question asks ([`Who`]), the key's role is
//! `owner_capable` (a `guest` or a `node` device of a member is no member, as for the owner,
//! heap.md §9.9), the context does not revoke it and this node does not mark it suspected. It is
//! read from what is held at the call, so it flips on the first call after the entry that removes
//! a person, or the context that revokes a key, is held. [`gate`] asks the same of this device
//! itself.

use std::time::Duration;

use ndn_foundation_types::Name;
use ndn_security::cert_name::key_name_of;
use ndn_security::{SignedTrustContext, Validator};

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
    /// A writer or a reader the fold **lists**: a public space makes no reader of an unlisted
    /// person, because a channel's key is wrapped to a judged key (channel.md).
    Listed,
}

/// Why a key does not stand; a channel maps these to its own refusals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Unstanding {
    /// No person of the asked kind owns the key, or its role is no owner-capable one, or it is no
    /// device key at all.
    NotMember,
    /// The trust context governing the key revokes it.
    Revoked,
    /// This node marks the key suspected.
    Suspected,
    /// The context revokes a key and the certificates held do not show that none of them is on
    /// the chain above this key (a certificate of it is not held, or the chain is not complete).
    Unchained,
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
    match read_chain(&view, &context, key) {
        Chain::Revoked => return Err(Unstanding::Revoked),
        // Nothing to find while the context revokes nothing; once it revokes a key, a chain
        // that cannot be read may hold it, and a standing that cannot be shown is not given.
        Chain::Unknown if !context.revocations().is_empty() => return Err(Unstanding::Unchained),
        Chain::Clear | Chain::Unknown => {}
    }
    if log.suspected(key) {
        return Err(Unstanding::Suspected);
    }
    Ok(person.clone())
}

/// The most issuers above a key [`read_chain`] follows: a chain of certificates is a few
/// hops (a device, its person's issuer, an anchor).
const CHAIN_HOPS: usize = 8;

/// What [`read_chain`] found above a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Chain {
    /// The certificates held lead to an anchor of the context and none of their issuers is
    /// revoked.
    Clear,
    /// An issuer on the way is revoked by the context.
    Revoked,
    /// The certificates held do not lead to an anchor: one is missing, one is no issuer's, or
    /// the chain is longer than [`CHAIN_HOPS`].
    Unknown,
}

/// What `view` holds of the issuers above `key`: whether `context` revokes one of them, as a
/// chain walk of a packet the key signed would find (revoking the key that certified a key
/// revokes what it certified). Offline: it reads only the certificates **vouched for** (a walk
/// reached an anchor through them, or their holder inserted them), the newest of a key, and
/// fetches nothing. An unverified certificate is whatever its server wrote, its `issuer`
/// included, so it neither revokes a key nor hides a revoked issuer. The key's own revocation
/// is [`context`'s](ndn_security::SignedTrustContext::is_revoked) to say.
fn read_chain(view: &Validator, context: &SignedTrustContext, key: &Name) -> Chain {
    let cache = view.cert_cache();
    let mut want = key.clone();
    for _ in 0..CHAIN_HOPS {
        if context.is_anchor(&want) {
            return Chain::Clear;
        }
        let Some(issuer) = cache.get_vouched(&want).and_then(|cert| cert.issuer) else {
            return Chain::Unknown;
        };
        if context.is_revoked(&issuer) {
            return Chain::Revoked;
        }
        if key_name_of(&issuer) == key_name_of(&want) {
            return Chain::Unknown;
        }
        want = (*issuer).clone();
    }
    Chain::Unknown
}

/// How long the certificates above `key` last, by the clock the validator judges them by: the
/// least time left of any certificate on the chain the node holds (the key's own, then each
/// issuer's, up to an anchor), or `None` when none of them has an end. The signed path judges a
/// signed ask or query against each of these at the moment it is made, so a standing that
/// rests on the chain ends with the first of them: [`Duration::ZERO`] when one has lapsed. It
/// reads only certificates vouched for (a walk reached an anchor through them), and fetches
/// nothing.
pub(crate) fn chain_lasts(log: &Log, judge: &Judge, key: &Name) -> Option<Duration> {
    let view = judge.view_for(key, &log.space, true);
    let context = view.keyring().context_for(key);
    let cache = view.cert_cache();
    let now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos() as u64);
    let mut ends: Option<u64> = None;
    let mut want = key.clone();
    for _ in 0..CHAIN_HOPS {
        if context.is_anchor(&want) {
            break;
        }
        let Some(cert) = cache.get_vouched(&want) else {
            break;
        };
        if cert.valid_until != u64::MAX {
            ends = Some(ends.map_or(cert.valid_until, |e| e.min(cert.valid_until)));
        }
        let Some(issuer) = cert.issuer else { break };
        if key_name_of(&issuer) == key_name_of(&want) {
            break;
        }
        want = (*issuer).clone();
    }
    ends.map(|end| Duration::from_nanos(end.saturating_sub(now)))
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
        Err(Unstanding::Unchained) => (
            "the trust context governing this device's key revokes keys and the certificates \
             held here do not show that none of them certified this device's key",
            "renew this device's certificate (or enrol it again) so its whole chain is held, \
             then retry",
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
