//! The newest-wins register (spec §10).
//!
//! Per path, the *heads* are the applied entries no other applied entry's
//! `after` names; the value is the head with the highest signed-region
//! digest (ties: the full digest, then device, then seq, so the order is
//! total); an empty inline payload is a removal. The state is a function of
//! the set of applied entries: it does not depend on the order they arrived
//! in, and withdrawing an entry leaves what never having applied it would.
//!
//! Memory is O(heads): per head a reference, the writer's person, whether it
//! removes, and the payload's size. A value is never held; the log reads it
//! from the store by the head's entry name when `get` or `watch` needs it.
//!
//! The register is sans-IO and reads no store. It is handed an already
//! accepted entry's facts and returns the writes the log makes in the
//! entry's batch (`heads/<S>/<sha256 of the path TLV>` and
//! `supers/<S>/<device>/<seq 8>/<digest>` records) together with the changes
//! of what each path's winner is. What it must ask the store it asks through
//! closures:
//!
//! - `namers(x)`: the entries that name `x` (its signed-region digest
//!   included) in their `after`, read from the `supers/` record of `x`'s
//!   name and digest ([`decode_refs`]). That record lists *applied* namers
//!   only, and lists namers of entries not held yet: an entry whose `after`
//!   names one that arrives later makes it no head. A ref across paths (a
//!   namer and a target at different paths) supersedes nothing: it is not
//!   recorded when the target is known, and ignored when the target arrives.
//! - `load(x)`: what the applied entry `x` wrote ([`Write`]), `None` when
//!   `x` is not held or not applied. Used to tell which path `x` is at, when
//!   a withdrawal gives the entries a refused one superseded their place
//!   back, and by [`restore`].
//!
//! [`restore`]: Register::restore

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_sync::StoreOp;
use ndn_tlv::TlvWriter;

use crate::store::{Corrupt, heads_key, supers_key};
use crate::wire::{
    AFTER_MAX, EntryRef, WireError, fields, once, read_name, read_ref, tlv, write_path, write_ref,
};

#[cfg(test)]
mod tests;

/// Which entry wrote a value: the [`EntryRef`] under the name readers know it
/// by (`Change`, `put`'s result, `Item::id`).
pub use crate::wire::EntryRef as EntryId;

/// A path's value as `get` and `watch` hand it out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// The path, relative to the space.
    pub path: Name,
    /// The value; empty for a removal.
    pub bytes: Bytes,
    /// The writer's person: the namespace of the trust context that validated
    /// the writing device's key.
    pub by: Name,
    /// The device that signed the entry.
    pub writer: Name,
    /// The entry that wrote it.
    pub id: EntryId,
    /// When the value was current, for a read of a past state; `None` for the
    /// present.
    pub as_of: Option<Duration>,
}

/// A head: an applied entry nothing applied supersedes. A reference and
/// what is said of it; never the value (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    /// The entry; the log reads its payload from the store by this name.
    pub entry: EntryRef,
    /// The path it wrote, relative to the space.
    pub path: Name,
    /// The writer's person.
    pub person: Name,
    /// Whether the entry removes the path.
    pub removal: bool,
    /// Octets of the payload.
    pub size: u64,
}

impl Head {
    /// What the order of heads is: the highest signed-region digest, then
    /// device, then seq. Total over distinct entries.
    fn rank(&self) -> (&[u8; 32], &Name, u64) {
        (&self.entry.digest, &self.entry.device, self.entry.seq)
    }

    /// The item this head makes, once the log has read `bytes` (empty for a
    /// removal).
    pub(crate) fn item(&self, bytes: Bytes) -> Item {
        Item {
            path: self.path.clone(),
            bytes,
            by: self.person.clone(),
            writer: self.entry.device.clone(),
            id: self.entry.clone(),
            as_of: None,
        }
    }
}

/// A change of which head decides a path. `was` and `now` are the winning
/// heads, removals included: `now` a removal is a `Removed`, `now` of `None`
/// means the path has no head left, `was` of `None` that it had none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValueChange {
    /// The winner before.
    pub was: Option<Head>,
    /// The winner after.
    pub now: Option<Head>,
}

/// What [`Register::apply`] and [`Register::withdraw`] ask of the log.
#[derive(Debug, Default)]
pub(crate) struct Effects {
    /// Store writes (inserts and removals of `heads/` and `supers/` records):
    /// the log puts them in the entry's batch.
    pub writes: Vec<StoreOp>,
    /// The paths whose winner changed. One entry can change several paths:
    /// an `after` may name an entry of another path.
    pub changes: Vec<ValueChange>,
}

/// A register read back from its persisted `heads/` records.
#[derive(Debug)]
pub(crate) struct Restored {
    /// The register.
    pub register: Register,
    /// Persisted heads whose entry `load` did not answer (not held, or not
    /// applied): the store and the log disagree. They are not in the
    /// register; the log decides how to repair.
    pub missing: Vec<EntryRef>,
}

/// The heads of every path of one space.
#[derive(Debug)]
pub(crate) struct Register {
    space: Name,
    /// Each path's heads, the winner first.
    paths: BTreeMap<Name, Vec<Head>>,
    /// Which path each head is at.
    at: HashMap<EntryRef, Name>,
}

/// The winners a call changes, by path, as they were before it.
type Touched = BTreeMap<Name, Option<Head>>;

/// The entries that name an entry in their `after` (read from the store).
type Namers<'a> = &'a dyn Fn(&EntryRef) -> Vec<EntryRef>;

/// What the log knows of an applied entry: the head it makes, `None` when it
/// is not held or not applied (derived from the entry, a sealed one after
/// opening it, and the validation context of its key).
type Load<'a> = &'a dyn Fn(&EntryRef) -> Option<Head>;

impl Register {
    /// An empty register of `space`.
    pub(crate) fn new(space: Name) -> Register {
        Register {
            space,
            paths: BTreeMap::new(),
            at: HashMap::new(),
        }
    }

    /// Apply an accepted entry, the head `head` makes (at `head.path`), which
    /// supersedes `after`. Idempotent: an entry applied again changes and
    /// writes nothing.
    ///
    /// A ref supersedes only the entry it names by digest and only at the
    /// path `head` is at: one whose target is held at another path is
    /// ignored, and one naming other bytes at a name hides nothing (its
    /// record is keyed by that digest).
    ///
    /// `namers` answers from the store *including this entry's batch so far*.
    pub(crate) fn apply(
        &mut self,
        head: &Head,
        after: &[EntryRef],
        namers: Namers,
        load: Load,
    ) -> Effects {
        let id = &head.entry;
        let mut touched = Touched::new();
        let mut writes = Vec::new();
        for x in distinct(after, id) {
            if self.path_of(&x, load).is_some_and(|path| path != head.path) {
                continue;
            }
            let mut named = namers(&x);
            if !named.contains(id) {
                named.push(id.clone());
                named.sort();
                writes.push(StoreOp::Insert(self.supers_key(&x), encode_refs(&named)));
            }
            self.take_head(&mut touched, &x);
        }
        // An entry some applied entry at its path already names, one that
        // arrived first, is not a head.
        if !self.at.contains_key(id) && !names_at(&namers(id), &head.path, load) {
            self.add_head(&mut touched, head.clone());
        }
        self.finish(touched, writes)
    }

    /// An applied entry `id` (which superseded `after`) is refused and no
    /// longer applied: call this after the log has marked it so. Its place
    /// is taken by the entries of `after` that no other applied entry names
    /// at their path; those the log holds and applied come back as heads
    /// (`load`), those it does not hold come back when they arrive.
    pub(crate) fn withdraw(
        &mut self,
        id: &EntryRef,
        after: &[EntryRef],
        namers: Namers,
        load: Load,
    ) -> Effects {
        let mut touched = Touched::new();
        let mut writes = Vec::new();
        self.take_head(&mut touched, id);
        for x in distinct(after, id) {
            let all = namers(&x);
            let named: Vec<EntryRef> = all.iter().filter(|r| *r != id).cloned().collect();
            // `id` never named `x` here (the ref was across paths): nothing
            // of it to undo.
            if named.len() == all.len() {
                continue;
            }
            writes.push(if named.is_empty() {
                StoreOp::Remove(self.supers_key(&x))
            } else {
                StoreOp::Insert(self.supers_key(&x), encode_refs(&named))
            });
            if !self.at.contains_key(&x)
                && let Some(head) = load(&x)
                && !names_at(&named, &head.path, load)
            {
                self.add_head(&mut touched, head);
            }
        }
        self.finish(touched, writes)
    }

    /// The register as persisted: `records` are the `heads/<S>/…` rows of
    /// the space (`scan_under(Kind::HEADS.listing(S))`), `load` as for
    /// [`withdraw`](Self::withdraw). A record that is not what
    /// [`apply`](Self::apply) writes is [`Corrupt`], never skipped.
    pub(crate) fn restore(
        space: Name,
        records: impl IntoIterator<Item = (Name, Bytes)>,
        load: Load,
    ) -> Result<Restored, Corrupt> {
        let mut register = Register::new(space);
        let mut missing = Vec::new();
        for (key, value) in records {
            let corrupt = || Corrupt {
                key: key.clone(),
                what: "heads record",
            };
            let (path, refs) = decode_heads_record(&value).map_err(|_| corrupt())?;
            if refs.is_empty() || key != heads_key(&register.space, &path_tlv(&path)) {
                return Err(corrupt());
            }
            for entry in refs {
                match load(&entry) {
                    Some(head) if head.path == path && !register.at.contains_key(&entry) => {
                        register.insert(head);
                    }
                    Some(_) => return Err(corrupt()),
                    None => missing.push(entry),
                }
            }
        }
        Ok(Restored { register, missing })
    }

    /// The head that decides `path`, a removal included.
    pub(crate) fn winner(&self, path: &Name) -> Option<&Head> {
        self.paths.get(path)?.first()
    }

    /// The value of `path`: its winner unless that is a removal. What `get`
    /// reads (the log fetches the bytes by the head's entry).
    pub(crate) fn value(&self, path: &Name) -> Option<&Head> {
        self.winner(path).filter(|h| !h.removal)
    }

    /// The heads of `path`, the winner first.
    pub(crate) fn heads_of(&self, path: &Name) -> &[Head] {
        self.paths.get(path).map_or(&[], Vec::as_slice)
    }

    /// Every path that has a value, as its winner, in path order: the first
    /// listing of a `watch`.
    pub(crate) fn values(&self) -> impl Iterator<Item = &Head> {
        let winners = self.paths.values().filter_map(|heads| heads.first());
        winners.filter(|h| !h.removal)
    }

    /// Every path that has heads, with them, the winner first.
    #[cfg(test)]
    pub(crate) fn paths_with_heads(&self) -> impl Iterator<Item = (&Name, &[Head])> {
        self.paths.iter().map(|(p, hs)| (p, hs.as_slice()))
    }

    /// How many heads the register holds in all: what its memory is
    /// proportional to.
    #[cfg(test)]
    pub(crate) fn head_count(&self) -> usize {
        self.at.len()
    }

    /// The `after` of a Put at `path` made now: its current heads, the
    /// [`AFTER_MAX`] with the highest digests when there are more (the rest
    /// remain heads until a later write names them).
    pub(crate) fn after_for_put(&self, path: &Name) -> Vec<EntryRef> {
        self.heads_of(path)
            .iter()
            .take(AFTER_MAX)
            .map(|h| h.entry.clone())
            .collect()
    }

    fn supers_key(&self, x: &EntryRef) -> Name {
        supers_key(&self.space, &x.device, x.seq, &x.digest)
    }

    /// The path the entry `x` is at, if it is a head or the log holds it
    /// applied.
    fn path_of(&self, x: &EntryRef, load: Load) -> Option<Name> {
        self.at.get(x).cloned().or_else(|| load(x).map(|h| h.path))
    }

    /// Put `head` at its path in rank order.
    fn insert(&mut self, head: Head) {
        self.at.insert(head.entry.clone(), head.path.clone());
        let heads = self.paths.entry(head.path.clone()).or_default();
        let at = heads.partition_point(|h| h.rank() > head.rank());
        heads.insert(at, head);
    }

    /// Remember the winner of `path` as it is now, once per call.
    fn note(&self, touched: &mut Touched, path: &Name) {
        touched
            .entry(path.clone())
            .or_insert_with(|| self.winner(path).cloned());
    }

    fn add_head(&mut self, touched: &mut Touched, head: Head) {
        self.note(touched, &head.path);
        self.insert(head);
    }

    /// Remove `entry` from the heads if it is one.
    fn take_head(&mut self, touched: &mut Touched, entry: &EntryRef) {
        let Some(path) = self.at.get(entry).cloned() else {
            return;
        };
        self.note(touched, &path);
        self.at.remove(entry);
        if let Some(heads) = self.paths.get_mut(&path) {
            heads.retain(|h| h.entry != *entry);
            if heads.is_empty() {
                self.paths.remove(&path);
            }
        }
    }

    /// The `heads/` record of every touched path, and the winners that moved.
    fn finish(&self, touched: Touched, mut writes: Vec<StoreOp>) -> Effects {
        let mut changes = Vec::new();
        for (path, was) in touched {
            let path_tlv = path_tlv(&path);
            let key = heads_key(&self.space, &path_tlv);
            let heads = self.heads_of(&path);
            writes.push(if heads.is_empty() {
                StoreOp::Remove(key)
            } else {
                StoreOp::Insert(key, heads_record(&path_tlv, heads))
            });
            let now = self.winner(&path).cloned();
            if was.as_ref().map(|h| &h.entry) != now.as_ref().map(|h| &h.entry) {
                changes.push(ValueChange { was, now });
            }
        }
        Effects { writes, changes }
    }
}

/// Whether any of `named` (applied entries) is at `path`: only those
/// supersede an entry there. An entry `load` cannot answer for counts.
fn names_at(named: &[EntryRef], path: &Name, load: Load) -> bool {
    named
        .iter()
        .any(|n| load(n).is_none_or(|h| h.path == *path))
}

/// `after` without repeats and without `id` itself.
fn distinct(after: &[EntryRef], id: &EntryRef) -> Vec<EntryRef> {
    let mut out: Vec<EntryRef> = after.iter().filter(|r| *r != id).cloned().collect();
    out.sort();
    out.dedup();
    out
}

// -- Records ---------------------------------------------------------------------

/// The `PATH` TLV of `path`: what `heads/<S>/…` keys hash and its records
/// start with.
fn path_tlv(path: &Name) -> Bytes {
    let mut w = TlvWriter::new();
    write_path(&mut w, path);
    w.finish()
}

/// A `heads/` record: the path TLV, then one `ENTRY_REF` per head.
fn heads_record(path_tlv: &[u8], heads: &[Head]) -> Bytes {
    let mut out = path_tlv.to_vec();
    out.extend_from_slice(&encode_refs(heads.iter().map(|h| &h.entry)));
    Bytes::from(out)
}

/// The path and heads a `heads/` record says; `None` when it is not one.
fn decode_heads_record(value: &Bytes) -> Result<(Name, Vec<EntryRef>), WireError> {
    let (mut path, mut refs) = (None, Vec::new());
    fields!(value.clone(), |v| {
        tlv::PATH => once(&mut path, read_name(v)?, "a path")?,
        tlv::ENTRY_REF => refs.push(read_ref(v)?),
    });
    Ok((path.ok_or(WireError::Missing("a path"))?, refs))
}

/// A `supers/` record: one `ENTRY_REF` per applied entry that names the key's
/// entry in its `after`.
pub(crate) fn encode_refs<'a>(refs: impl IntoIterator<Item = &'a EntryRef>) -> Bytes {
    let mut w = TlvWriter::new();
    for r in refs {
        write_ref(&mut w, r);
    }
    w.finish()
}

/// The entries a `supers/` record lists; `None` when it is not one.
pub(crate) fn decode_refs(record: &[u8]) -> Result<Vec<EntryRef>, WireError> {
    let mut refs = Vec::new();
    fields!(Bytes::copy_from_slice(record), |v| { tlv::ENTRY_REF => refs.push(read_ref(v)?) });
    Ok(refs)
}
