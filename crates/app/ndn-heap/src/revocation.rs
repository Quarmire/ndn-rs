//! Revocation cuts and suspicion (spec §9).
//!
//! A key lost to a thief is revoked by the owner of its namespace, and the
//! revocation carries a *cut*: the entries of the key that still count. This
//! node can vouch for one, because it keeps, for every entry it verified, a
//! `verified/` marker with the digest of the public key that verified it and
//! the time it first saw it ([`crate::store::Marker`]).
//!
//! [`propose`] reads that and nothing else: it walks the entries held of the
//! key's device in every space the node holds ([`Log::each_held`]), takes the
//! ones whose packet names the key as its signer, and keeps those that are
//! applied (or held closed), first seen strictly before
//! [`CutBound::held_before`] and at or below [`CutBound::upto`] of their
//! space. The cut names `(<D>/32=log/<S>, seq)` runs and a manifest of the
//! implicit digest of every kept packet; the digest of the key that verified
//! them comes from the markers, never from verifying again. Everything the
//! bound leaves out, and every entry that verified but cannot be read, is
//! listed by its full name, for the owner to re-admit one by one.
//!
//! The log names `<D>/32=log/<S>/seq=<n>` are under `<D>/32=log`, which is all
//! `ndn-cert` asks of a cut's names (`check_cut_names`): `ndn-fwd revoke` and
//! the cut file need no change.
//!
//! Suspicion is the node's mark on a key it fears is in a thief's hands
//! ([`suspect`]): no new entry of it is taken, what is held stays. It lives in
//! every space's log, so these functions work over all of them; the mark ends
//! with [`unsuspect`], or once a revocation of the key is held
//! ([`lift_revoked`]), after which the cut decides.
//!
//! The functions are free and take the node's logs (the node locks one per
//! space and passes the guards) and its judge; they hold no state.

use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_security::cert_name::key_name_of;
use ndn_security::{RevocationCut, cut_manifest, public_key_digest};

use crate::error::{HeapError, Timestamp};
use crate::log::{Log, Standing};
use crate::trust::Judge;
use crate::wire::{device_of, implicit_digest, log_name};

/// What bounds the revocation cut a node vouches for (`propose`): its own
/// observation, never anything the revoked key signed. At least one is given.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CutBound {
    /// Keep only entries this node first verified strictly before this time,
    /// by its own clock: when the device was lost (by default, when its key
    /// was marked suspected).
    pub held_before: Option<Timestamp>,
    /// Keep, per space, only entries at or below this seq. When given, a
    /// space it does not name keeps nothing. The key is by space
    /// (`<owner>/32=data/<name>`), not by log prefix: a key is one device's,
    /// so the space names the log `<D>/32=log/<S>`, and a space is what the
    /// owner knows.
    pub upto: BTreeMap<Name, u64>,
}

/// A revocation cut a node vouches for (`propose`).
#[derive(Clone, Debug)]
pub struct CutProposal {
    /// The cut, with the digest of the public key that verified its entries
    /// and the full name of its manifest's root.
    pub cut: RevocationCut,
    /// The manifest's packets, root first: self-certifying Data listing the
    /// implicit digest of every entry the cut's ranges accept, to be
    /// published beside the trust context. Empty when the cut keeps nothing.
    pub manifest: Vec<Bytes>,
    /// The entries of the key held here that the bound leaves out, and the
    /// ones that verified but cannot be read, each by its full name ending in
    /// its implicit digest (sorted): the owner may re-admit them one by one.
    pub left_out: Vec<Name>,
}

/// What the node's trust contexts say of a key's cut: the namespace its
/// manifest is made under, and the public keys the node holds certificates of
/// for the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CutAuthority {
    /// The namespace of the context that governs the key.
    pub(crate) namespace: Name,
    /// The digests of the public keys the node holds a certificate or an
    /// anchor of for the key: what a cut that keeps nothing binds to, when
    /// there is exactly one.
    pub(crate) certified: BTreeSet<[u8; 32]>,
}

fn bad(why: String) -> HeapError {
    HeapError::BadRequest { why }
}

/// The key `name` names (a certificate name of it, or the key's own), if it
/// is a key `<device>/KEY/<id>`.
fn key_of(name: &Name) -> Result<Name, HeapError> {
    let key = key_name_of(name);
    if device_of(&key).is_none() {
        return Err(bad(format!(
            "{name} is no key name: a key is named <id>/KEY/<k> (or by one of its \
             certificates); give the lost device's key"
        )));
    }
    Ok(key)
}

/// `<D>/32=log/<S>`: what every entry name of the device in the space extends.
fn log_prefix(device: &Name, space: &Name) -> Name {
    let entry = log_name(device, space, 0);
    Name::from_components(entry.components()[..entry.len() - 1].iter().cloned())
}

/// The key a held packet names as its signer; `None` for a packet that does
/// not decode or names none.
fn signer_of(wire: &Bytes) -> Option<Name> {
    let data = Data::decode(wire.clone()).ok()?;
    let locator = data.sig_info()?.key_locator_name()?;
    Some(key_name_of(&locator))
}

/// What the node's contexts say of `key`'s cut. Refused when no context held
/// here governs the key: its namespace's trust context must be adopted first.
pub(crate) fn cut_authority(judge: &Judge, key: &Name) -> Result<CutAuthority, HeapError> {
    let key = key_of(key)?;
    let validator = judge.validator();
    let ctx = validator.keyring().context_for(&key);
    if ctx.namespace().is_empty() {
        return Err(bad(format!(
            "no trust context held here governs the key {key}, so it cannot be revoked in \
             one; adopt its namespace's trust context first"
        )));
    }
    let mut certified: BTreeSet<[u8; 32]> = validator
        .cert_cache()
        .all(&key)
        .iter()
        .map(|c| public_key_digest(&c.public_key))
        .collect();
    certified.extend(
        ctx.anchor_for(&key)
            .map(|a| public_key_digest(&a.public_key)),
    );
    Ok(CutAuthority {
        namespace: ctx.namespace().clone(),
        certified,
    })
}

/// The cut this node can vouch for if `key` (a key name `<id>/KEY/<k>`, or one
/// of its certificate names) is revoked now, over every space in `logs`,
/// bounded by `bound` (see the module docs).
///
/// Refused ([`HeapError::BadRequest`]) when neither bound is given (say when
/// the device was lost: [`suspected`] is when its key was marked suspected),
/// when the entries it would keep were verified under two different public
/// keys, and when no public key of the key can be named.
pub(crate) fn propose(
    logs: &[&Log],
    authority: &CutAuthority,
    key: &Name,
    bound: &CutBound,
) -> Result<CutProposal, HeapError> {
    let key = key_of(key)?;
    if bound.held_before.is_none() && bound.upto.is_empty() {
        let since = suspected(logs, &key);
        return Err(bad(format!(
            "a revocation cut keeps what this node held of the key {key} before it was lost, \
             so say when that was: give held_before (the time the device was lost{}) or upto \
             (the last seq to keep per space); every entry first verified here later, or \
             above upto, is left out and listed, for the owner to re-admit one by one",
            match since {
                Some(t) => format!("; its key is marked suspected here since {}", t.0),
                None => String::new(),
            }
        )));
    }
    let device = device_of(&key).expect("key_of checked the key name");
    let mut entries: Vec<(Name, u64, [u8; 32])> = Vec::new();
    let mut left_out = Vec::new();
    let mut public: BTreeSet<[u8; 32]> = BTreeSet::new();
    for log in logs {
        let space = log.space();
        let prefix = log_prefix(&device, space);
        log.each_held(&device, |held| {
            if !matches!(held.standing, Standing::Live | Standing::Unreadable) {
                return;
            }
            let name = log_name(&device, space, held.seq);
            let Some(wire) = held.wire else {
                tracing::warn!(%name, "held without the packet its marker verified: left out of the cut");
                return;
            };
            // A packet that names no signer may be the key's: it is listed.
            let signer = signer_of(&wire);
            if signer.as_ref().is_some_and(|s| *s != key) {
                return;
            }
            let digest = implicit_digest(&wire);
            let in_time = bound
                .held_before
                .is_none_or(|t| held.marker.is_some_and(|m| m.at < t.0));
            let in_seq = bound.upto.is_empty()
                || bound
                    .upto
                    .get(space)
                    .is_some_and(|upto| held.seq <= *upto);
            match held.marker {
                Some(m)
                    if held.standing == Standing::Live
                        && signer.is_some()
                        && in_time
                        && in_seq =>
                {
                    public.insert(m.key_digest);
                    entries.push((prefix.clone(), held.seq, digest));
                }
                _ => left_out.push(name.append_implicit_digest(digest)),
            }
        });
    }
    if public.len() > 1 {
        return Err(bad(format!(
            "the entries this node would keep of the key {key} were verified under two \
             different public keys certified under the key's name, so a cut cannot say which \
             one wrote the honest work; revoke the key without a cut, and have the CA's \
             operator find which certificate is genuine"
        )));
    }
    let key_digest = match public.into_iter().next() {
        Some(digest) => digest,
        None => match (authority.certified.len(), authority.certified.first()) {
            (1, Some(digest)) => *digest,
            _ => {
                return Err(bad(format!(
                    "no entry of {key} that this node would keep names the public key that \
                     verified it, and the certificates held of the key do not name exactly \
                     one public key; revoke the key without a cut"
                )));
            }
        },
    };
    let mut cut = RevocationCut::new(key.clone());
    for (prefix, seq, _) in &entries {
        cut.add_seq(prefix, *seq);
    }
    cut.set_key_digest(key_digest);
    let manifest = if entries.is_empty() {
        Vec::new()
    } else {
        let built = cut_manifest::build(&authority.namespace, &key, &entries).map_err(|e| {
            HeapError::Local {
                reason: format!("the cut's manifest of {key} is not made: {e}"),
            }
        })?;
        cut.set_manifest(built.root).map_err(|e| HeapError::Local {
            reason: format!("the cut's manifest of {key} is not named: {e}"),
        })?;
        built.packets
    };
    left_out.sort();
    Ok(CutProposal {
        cut,
        manifest,
        left_out,
    })
}

/// [`propose`] under the namespace of the context `judge` holds for the key.
/// The manifest made is handed to the validator, so this node judges its own
/// held entries by the cut once it is adopted, without fetching what it made.
pub(crate) fn revocation_cut(
    logs: &[&Log],
    judge: &Judge,
    key: &Name,
    bound: &CutBound,
) -> Result<CutProposal, HeapError> {
    let authority = cut_authority(judge, key)?;
    let proposal = propose(logs, &authority, key, bound)?;
    for packet in &proposal.manifest {
        if let Ok(data) = Data::decode(packet.clone()) {
            let _ = judge.validator().cut_manifests().insert(&data);
        }
    }
    Ok(proposal)
}

/// The entries `key` (a key or certificate name) signed that this node holds
/// refused because its revocation does not accept them (withdrawn when the
/// revocation came after them), each by its full name ending in its implicit
/// digest, as the owner re-admits it (`ndn-fwd readmit`), sorted. An entry
/// refused as outside the removal cut of a person who no longer writes is not
/// listed: no re-admission of the key brings it back.
pub(crate) fn refused_by_revocation(logs: &[&Log], key: &Name) -> Vec<Name> {
    let Ok(key) = key_of(key) else {
        return Vec::new();
    };
    let Some(device) = device_of(&key) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for log in logs {
        let space = log.space();
        log.each_held(&device, |held| {
            if held.standing != Standing::Revoked {
                return;
            }
            let Some(wire) = held.wire else {
                return;
            };
            if signer_of(&wire).is_some_and(|s| s == key) {
                out.push(
                    log_name(&device, space, held.seq)
                        .append_implicit_digest(implicit_digest(&wire)),
                );
            }
        });
    }
    out.sort();
    out
}

/// Mark `key` (a key name, or one of its certificate names) suspected since
/// `since`, by this node's clock, in every space: from now on no new entry of
/// it is taken, and the entries held before stay. `since` is the default
/// bound of the key's cut ([`CutBound::held_before`]).
pub(crate) fn suspect(
    logs: &mut [&mut Log],
    key: &Name,
    since: Timestamp,
) -> Result<(), HeapError> {
    let key = key_of(key)?;
    for log in logs.iter_mut() {
        log.suspect(&key, since);
    }
    Ok(())
}

/// Lift the mark of `key` in every space: new entries of it are taken again.
/// Whether it was marked in any.
pub(crate) fn unsuspect(logs: &mut [&mut Log], key: &Name) -> bool {
    let Ok(key) = key_of(key) else {
        return false;
    };
    let mut was = false;
    for log in logs.iter_mut() {
        was |= log.unsuspect(&key);
    }
    was
}

/// Since when `key` is marked suspected: the earliest of the spaces' marks.
pub(crate) fn suspected(logs: &[&Log], key: &Name) -> Option<Timestamp> {
    let key = key_name_of(key);
    logs.iter().filter_map(|log| log.suspected(&key)).min()
}

/// End the mark of every suspected key that `revoked` says a revocation held
/// here now covers: its cut decides from then on. Returns the keys lifted,
/// sorted. The node calls it whenever a context is adopted.
pub(crate) fn lift_revoked(logs: &mut [&mut Log], revoked: impl Fn(&Name) -> bool) -> Vec<Name> {
    let marked: BTreeSet<Name> = logs.iter().flat_map(|log| log.suspected_keys()).collect();
    let lifted: Vec<Name> = marked.into_iter().filter(|key| revoked(key)).collect();
    for key in &lifted {
        for log in logs.iter_mut() {
            log.unsuspect(key);
        }
    }
    lifted
}

/// Whether the trust context `judge` holds for a key revokes it.
pub(crate) fn revoked_by(judge: &Judge) -> impl Fn(&Name) -> bool + '_ {
    move |key| judge.validator().keyring().context_for(key).is_revoked(key)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "revocation_tests.rs"]
mod tests;
