//! Collections: the growing side of the model — their [`Rule`], their
//! owner-signed [`Members`], the [`Cut`]s that end a member or a key, the
//! [`Epoch`] their seal is read in, and the signed, nested [`Summary`] of
//! what they hold.

use std::collections::{BTreeMap, BTreeSet};

use ndn_foundation_types::{Hash, Name};
use sha2::{Digest, Sha256};

use crate::error::Refusal;
use crate::version::{Audience, Frontier, Seq, VersionId, Writer};
use crate::wire;

/// What "newest" means in a collection. The collection decides, not the app.
/// A writer is always one key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Rule {
    /// A single key writes — the one key its members record names — and
    /// the newest is that key's signed head, with a freshness bound
    /// (spec §5.3). Sensors, a service's answers.
    OneKey,
    /// Each member key appends; the collection is the union of exactly its
    /// members' logs. Chat, a photo library. Filled by slice 2.
    Log,
    /// Member logs plus a named merge function (a CRDT) every reader runs
    /// alike; `get` returns the merged state at a frontier. Notes across
    /// devices, a shared document. Filled by slice 1.
    Merge {
        /// The merge function's name; readers that do not know it cannot
        /// compute the state.
        function: Name,
    },
}

/// The owner-signed record of who may write into a collection and who may
/// read it (model change M2).
///
/// Writers write under their own prefixes; the collection gathers exactly
/// the keys listed here, so a reader can tell a member from a stranger
/// posting under the same collection name. [`share`](crate::DataLayer::share)
/// edits it; removing a member adds a [`Cut`], removing a reader starts a
/// new [`Epoch`], changing the rule (or sealing a collection that was not)
/// starts the collection again from [`since`](Self::since). Each revision
/// supersedes the previous one and the revision number never goes back
/// (model invariant 3). Each names its [`parent`](Self::parent), the record
/// its signer had in force; records of one revision signed by different
/// devices of the owner merge ([`Members::merge`]) against the parent they
/// share: every addition and every removal is kept, and removals win. A
/// record of the next revision signed from a view without one of them is
/// taken onto their merge first, so a removal wins across revisions too
/// (spec §6).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Members {
    /// The collection this record governs; of a folder record, the folder.
    pub collection: Name,
    /// Whether this is a folder's record (spec §6, wire `Folder`): it
    /// governs the folder named by [`collection`](Self::collection) and
    /// every collection strictly under it, not a collection of that name.
    /// A name's folder records and its collection records are two separate
    /// lines: revisions, parents and merges count records of one kind only.
    pub folder: bool,
    /// The owner's key, which signs this record (of a merge: the highest
    /// signer key among the records merged).
    pub owner: Writer,
    /// This record's revision.
    pub revision: Seq,
    /// What "newest" means.
    pub rule: Rule,
    /// Key-name prefixes whose keys may write (e.g. `/alice`, `/bob`).
    pub writers: Vec<Name>,
    /// Who may read; the collection's seal follows this list. Empty: the
    /// collection is not sealed. The audience is exactly these readers and
    /// the device that signed the record starting the [`epoch`](Self::epoch).
    pub readers: Vec<Audience>,
    /// Removals in force: a writer prefix this or an earlier revision
    /// removed, with exactly the versions of its keys that stay accepted.
    pub cuts: Vec<Cut>,
    /// The epoch the collection is sealed in; `None` when it has no
    /// readers listed (not sealed).
    pub epoch: Option<Epoch>,
    /// The epoch's key check (spec §9): HKDF-SHA256 of the epoch's key, so
    /// a reader takes a granted key only if it is the epoch's. Set exactly
    /// when [`epoch`](Self::epoch) is.
    pub key_check: Option<[u8; 32]>,
    /// Set once the rule changed, or the collection was sealed after being
    /// unsealed: the frontier the owner had applied then. Versions inside
    /// it stay readable by name and listed by `watch`, and stay out of the
    /// new rule's state.
    pub since: Option<Frontier>,
    /// The record in force at its signer when it signed this one; `None`
    /// for revision 1 (and for a record from a signer that named none).
    pub parent: Option<Parent>,
}

impl Members {
    /// Why this record refuses version `id` of its own collection, if it
    /// does ([`Self::refusal_in`]).
    pub fn refusal(&self, id: &VersionId) -> Option<Refusal> {
        self.refusal_in(&self.collection, id)
    }

    /// Why this record refuses version `id` of collection `c` (its own, or
    /// of a folder record one under it), if it does: a key under a writer
    /// prefix is admitted; else a key under a cut's prefix is admitted if
    /// the cut accepts exactly that version in `c` and refused otherwise,
    /// whatever date or seq it claims; else the key is no member.
    pub fn refusal_in(&self, c: &Name, id: &VersionId) -> Option<Refusal> {
        let key = id.writer.key();
        if self.writers.iter().any(|p| key.has_prefix(p)) {
            return None;
        }
        match self.cuts.iter().find(|k| key.has_prefix(&k.of)) {
            Some(cut) if cut.accept.contains(c, id) => None,
            Some(cut) => Some(Refusal::OutsideCut(cut.clone())),
            None => Some(Refusal::NotMember),
        }
    }

    /// The cut that admits version `id` of collection `c` by keeping it,
    /// if one does ([`Self::refusal_in`] admits it, and not as a writer's):
    /// its bytes are then bound by that cut's manifests for `c` and the
    /// key ([`Accepted::manifests`], spec §8).
    pub fn kept_by(&self, c: &Name, id: &VersionId) -> Option<&Cut> {
        let key = id.writer.key();
        if self.writers.iter().any(|p| key.has_prefix(p)) {
            return None;
        }
        self.cuts
            .iter()
            .find(|k| key.has_prefix(&k.of))
            .filter(|cut| cut.accept.contains(c, id))
    }

    /// What this record is as a parent: its revision and the SHA-256 of
    /// its `MembersRecord` TLV (spec §6, §16.2) — the Content of the packet
    /// that carries it. A merge is digested as the record it stands for.
    pub fn as_parent(&self) -> Parent {
        let body = wire::MembersBody::from(self);
        Parent {
            revision: self.revision,
            digest: Sha256::digest(wire::encode_members(&body)).into(),
        }
    }

    /// The one record that `records` — owner-signed records of one
    /// collection and one revision, by distinct signers — stand for (spec
    /// §6), and what it leaves to resolve. `held` finds a record in force
    /// this device held by what it is as a parent.
    ///
    /// When every record names one parent `P` and `held` has it, they merge
    /// three ways against it: writers and readers are `P`'s, plus every one
    /// a record added and minus every one a record removed — a removal
    /// beating another record's addition of a prefix it covers or lies
    /// under; the rule and `since` are `P`'s unless a record changed them,
    /// then those of the highest signer key among the records that did.
    /// Otherwise writers and readers are the intersection of theirs (a key
    /// is a writer only if every record admits it), rule and `since` those
    /// of the highest signer key. Either way cuts are the union by prefix
    /// (the intersection of the accepted sets where two cut one prefix),
    /// and the epoch is that of the record listing the fewest readers the
    /// merge leaves out, then the fewest readers, then the highest signer
    /// key. `None` for no records.
    pub fn merge<'a>(
        records: &[Members],
        held: impl Fn(&Parent) -> Option<&'a Members>,
    ) -> Option<(Members, Resolve)> {
        Self::merge_refs(&records.iter().collect::<Vec<_>>(), held)
    }

    /// [`Self::merge`] of records held by reference.
    fn merge_refs<'a>(
        records: &[&Members],
        held: impl Fn(&Parent) -> Option<&'a Members>,
    ) -> Option<(Members, Resolve)> {
        if let [one] = records {
            return Some(((*one).clone(), Resolve::Nothing));
        }
        let shared = records
            .iter()
            .map(|m| m.parent)
            .reduce(|a, b| a.filter(|p| b == Some(*p)))
            .flatten();
        let base = shared.and_then(|p| held(&p).filter(|m| m.as_parent() == p));
        let (mut merged, resolve) = Self::merge_over(records, base)?;
        merged.parent = shared;
        Some((merged, resolve))
    }

    /// This record, of revision `n + 1`, taken onto `below`, the record
    /// revision `n` stands for at this reader, when its signer signed it
    /// from another view (spec §6): it merges with `below` three ways
    /// against `parent`, the record of revision `n` it names, when that is
    /// held — so what `below` removed (or added) that `parent` still lists
    /// (or lacks) applies, and what this record changed stands, a removal
    /// winning — and is intersected with `below` otherwise. It keeps its
    /// revision and signer; its parent is `below`.
    pub(crate) fn onto(&self, below: &Members, parent: Option<&Members>) -> (Members, Resolve) {
        let (mut m, resolve) = Self::merge_over(&[self, below], parent).expect("two records");
        m.owner = self.owner.clone();
        m.revision = self.revision;
        m.parent = Some(below.as_parent());
        (m, resolve)
    }

    /// The record that `records` — owner-signed records of one subject and
    /// one revision, by distinct signers — stand for at this reader, and
    /// what it leaves to resolve (spec §6). Each comes with its parent, when
    /// the reader holds it (a record of the revision below, or a merge of
    /// some of them); `below` is the record the revision below stands for
    /// here, with what it is as a parent, when a record of it is held. A
    /// record naming `below` is taken as it is, any other onto `below`
    /// ([`Self::onto`]); they then merge against `below`
    /// ([`Self::merge`]). With no record of the revision below held, they
    /// merge as they are, against no parent. So what stands is a function
    /// of the records held alone, whatever order they arrived in. `None`
    /// for no records.
    pub(crate) fn settle(
        records: &[(&Members, Option<&Members>)],
        below: Option<(&Members, Parent)>,
    ) -> Option<(Members, Resolve)> {
        let Some((below, at)) = below else {
            let records: Vec<&Members> = records.iter().map(|(r, _)| *r).collect();
            return Self::merge_refs(&records, |_| None);
        };
        let mut resolve = Resolve::Nothing;
        let taken: Vec<std::borrow::Cow<'_, Members>> = records
            .iter()
            .map(|(r, parent)| match r.parent {
                Some(p) if p == at => std::borrow::Cow::Borrowed(*r),
                _ => {
                    let (m, why) = r.onto(below, *parent);
                    resolve = resolve.max(why);
                    std::borrow::Cow::Owned(m)
                }
            })
            .collect();
        let taken: Vec<&Members> = taken.iter().map(|m| m.as_ref()).collect();
        let (merged, why) = Self::merge_refs(&taken, |p| (*p == at).then_some(below))?;
        Some((merged, resolve.max(why)))
    }

    /// `records` merged against `base`, their shared parent when held
    /// ([`Self::merge`]); the merge names no parent.
    fn merge_over(records: &[&Members], base: Option<&Members>) -> Option<(Members, Resolve)> {
        let top = *records.iter().max_by(|a, b| a.owner.cmp(&b.owner))?;
        let mut writers: Vec<Name> = match base {
            Some(p) => {
                let removed: Vec<(usize, &Name)> = records
                    .iter()
                    .enumerate()
                    .flat_map(|(i, m)| {
                        p.writers
                            .iter()
                            .filter(move |w| !m.writers.contains(w))
                            .map(move |w| (i, w))
                    })
                    .collect();
                let added = records.iter().enumerate().flat_map(|(i, m)| {
                    m.writers
                        .iter()
                        .filter(move |w| !p.writers.contains(w))
                        .map(move |w| (i, w))
                });
                // A removal beats another record's addition of a prefix it
                // covers or lies under.
                let beaten = |i: usize, a: &Name| {
                    removed
                        .iter()
                        .any(|(j, q)| *j != i && (a.has_prefix(q) || q.has_prefix(a)))
                };
                p.writers
                    .iter()
                    .filter(|w| !removed.iter().any(|(_, q)| q == w))
                    .chain(added.filter(|(i, a)| !beaten(*i, a)).map(|(_, a)| a))
                    .cloned()
                    .collect()
            }
            None => {
                let covers = |m: &Members, p: &Name| m.writers.iter().any(|q| p.has_prefix(q));
                records
                    .iter()
                    .flat_map(|m| m.writers.iter())
                    .filter(|p| records.iter().all(|m| covers(m, p)))
                    .cloned()
                    .collect()
            }
        };
        writers.sort();
        writers.dedup();
        let broadest: Vec<Name> = writers
            .iter()
            .filter(|p| !writers.iter().any(|q| q != *p && p.has_prefix(q)))
            .cloned()
            .collect();
        let mut readers: Vec<Audience> = Vec::new();
        match base {
            Some(p) => {
                let removed = |r: &Audience| records.iter().any(|m| !m.readers.contains(r));
                let added = records
                    .iter()
                    .flat_map(|m| m.readers.iter())
                    .filter(|r| !p.readers.contains(r));
                for r in p.readers.iter().filter(|r| !removed(r)).chain(added) {
                    if !readers.contains(r) {
                        readers.push(r.clone());
                    }
                }
            }
            None => readers.extend(
                top.readers
                    .iter()
                    .filter(|r| records.iter().all(|m| m.readers.contains(r)))
                    .cloned(),
            ),
        }
        let mut cuts: BTreeMap<Name, Cut> = BTreeMap::new();
        for cut in records.iter().flat_map(|m| m.cuts.iter()) {
            match cuts.get_mut(&cut.of) {
                Some(held) => held.accept = held.accept.intersection(&cut.accept),
                None => {
                    cuts.insert(cut.of.clone(), cut.clone());
                }
            }
        }
        let ruling = match base {
            Some(p) => records
                .iter()
                .filter(|m| m.rule != p.rule || m.since != p.since)
                .max_by(|a, b| a.owner.cmp(&b.owner))
                .copied()
                .unwrap_or(p),
            None => top,
        };
        let left_out = |r: &Audience| !readers.contains(r);
        let sealing = records
            .iter()
            .min_by(|a, b| {
                let key = |m: &Members| {
                    let out = m.readers.iter().filter(|r| left_out(r)).count();
                    (out, m.readers.len())
                };
                key(a).cmp(&key(b)).then_with(|| b.owner.cmp(&a.owner))
            })
            .expect("at least one record");
        let removed = sealing.readers.iter().any(left_out)
            || base.is_some_and(|p| {
                p.readers
                    .iter()
                    .chain(records.iter().flat_map(|m| m.readers.iter()))
                    .any(left_out)
            });
        // The audience of the epoch kept: every reader a merged record
        // naming it lists.
        let of_epoch = |r: &Audience| {
            records
                .iter()
                .any(|m| m.epoch == sealing.epoch && m.readers.contains(r))
        };
        let resolve = if removed {
            Resolve::Epoch
        } else if !readers.iter().all(of_epoch) {
            Resolve::Readers
        } else {
            Resolve::Nothing
        };
        let merged = Members {
            collection: top.collection.clone(),
            // One line: every record merged is of one kind.
            folder: top.folder,
            owner: top.owner.clone(),
            revision: top.revision,
            rule: ruling.rule.clone(),
            writers: broadest,
            readers,
            cuts: cuts.into_values().collect(),
            epoch: sealing.epoch.clone(),
            key_check: sealing.key_check,
            since: ruling.since.clone(),
            parent: None,
        };
        Some((merged, resolve))
    }
}

/// The record in force over a subject (spec §6, its effective record):
/// `own`, the subject's own record in force (a collection's, or a
/// folder's), narrowed by `folders`, the folder records in force of every
/// proper prefix of `subject`, nearest first. With no folder it is `own`.
/// Otherwise, of the levels `own` (if any) and `folders`:
/// - writers: a key writes iff every level admits it (the intersection of
///   the prefix sets); a level listing no writers takes those of the levels
///   above it;
/// - cuts: every level's prefix, each accepting exactly the versions of its
///   keys in `subject` (of a folder: in the collections under it) that
///   every level admits — so a version is refused iff a level refuses it,
///   as outside a cut wherever a level cuts its key;
/// - readers: those of the nearest level listing readers, in its epoch and
///   with its key check, less any that an outer level listing readers does
///   not admit ([`admitted`]): widening has no effect; no level lists
///   readers: not sealed;
/// - rule, `since`, owner, revision and parent: `own`'s, else the nearest
///   folder's.
pub(crate) fn effective(
    subject: &Name,
    own: Option<&Members>,
    folders: &[&Members],
) -> Option<Members> {
    if folders.is_empty() {
        return own.cloned();
    }
    let levels: Vec<&Members> = own.into_iter().chain(folders.iter().copied()).collect();
    let base = levels[0];
    // Each level's writers, outermost first — a level listing none takes
    // those of the levels above it — and the keys every level admits.
    let mut writers: Vec<Vec<Name>> = Vec::with_capacity(levels.len());
    let mut above: Option<Vec<Name>> = None;
    for m in levels.iter().rev() {
        if m.writers.is_empty() {
            writers.push(above.clone().unwrap_or_default());
            continue;
        }
        writers.push(m.writers.clone());
        above = Some(match above {
            None => m.writers.clone(),
            Some(a) => intersect(&a, &m.writers),
        });
    }
    writers.reverse();
    let admitted_by_all = above.unwrap_or_default();
    // Per key a cut lists, the versions in `subject` every level admits: by
    // its writers, or by the first of its cuts over the key, as
    // `Members::refusal` reads.
    let keys: BTreeSet<&Writer> = levels
        .iter()
        .flat_map(|m| m.cuts.iter())
        .flat_map(|c| c.accept.iter().map(|(_, w, _)| w))
        .collect();
    let mut accepted = Accepted::new();
    for w in keys {
        let mut kept: Option<Accepted> = None;
        for (m, ws) in levels.iter().zip(&writers) {
            if ws.iter().any(|p| w.key().has_prefix(p)) {
                continue;
            }
            let level = m
                .cuts
                .iter()
                .find(|c| w.key().has_prefix(&c.of))
                .map(|c| c.accept.of_key(w).within(subject))
                .unwrap_or_default();
            kept = Some(match kept {
                None => level,
                Some(k) => k.intersection(&level),
            });
        }
        if let Some(k) = kept {
            accepted.add(&k);
        }
    }
    let mut cuts: BTreeMap<Name, Cut> = BTreeMap::new();
    for c in levels.iter().flat_map(|m| m.cuts.iter()) {
        cuts.entry(c.of.clone()).or_insert_with(|| Cut {
            of: c.of.clone(),
            accept: accepted.under(&c.of),
            signer: c.signer.clone(),
        });
    }
    let (readers, epoch, key_check) = match levels.iter().position(|m| !m.readers.is_empty()) {
        None => (Vec::new(), None, None),
        Some(i) => {
            let m = levels[i];
            let outer: Vec<&Members> = levels[i + 1..]
                .iter()
                .copied()
                .filter(|o| !o.readers.is_empty())
                .collect();
            let readers = m
                .readers
                .iter()
                .filter(|r| outer.iter().all(|o| admitted(r, &o.readers)))
                .cloned()
                .collect();
            (readers, m.epoch.clone(), m.key_check)
        }
    };
    Some(Members {
        collection: subject.clone(),
        folder: own.is_some_and(|m| m.folder),
        owner: base.owner.clone(),
        revision: base.revision,
        rule: base.rule.clone(),
        writers: admitted_by_all,
        readers,
        cuts: cuts.into_values().collect(),
        epoch,
        key_check,
        since: base.since.clone(),
        parent: base.parent,
    })
}

/// The prefixes whose keys both `a` and `b` admit, broadest only.
pub(crate) fn intersect(a: &[Name], b: &[Name]) -> Vec<Name> {
    let mut both: Vec<Name> = a
        .iter()
        .filter(|p| b.iter().any(|q| p.has_prefix(q)))
        .chain(b.iter().filter(|q| a.iter().any(|p| q.has_prefix(p))))
        .cloned()
        .collect();
    both.sort();
    both.dedup();
    both.iter()
        .filter(|p| !both.iter().any(|q| q != *p && p.has_prefix(q)))
        .cloned()
        .collect()
}

/// Whether reader `r` is of the audience `by` lists: listed itself, or a
/// device of a person listed.
pub(crate) fn admitted(r: &Audience, by: &[Audience]) -> bool {
    by.contains(r)
        || matches!(r, Audience::Device(d)
            if by.iter().any(|a| matches!(a, Audience::Person(p) if d.has_prefix(p))))
}

/// The record a members record was signed from (spec §6): the record in
/// force at its signer, by revision and by the SHA-256 of its
/// `MembersRecord` TLV ([`Members::as_parent`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Parent {
    /// The parent's revision, one below the record's.
    pub revision: Seq,
    /// SHA-256 of the parent's `MembersRecord` TLV.
    pub digest: [u8; 32],
}

/// What a merge of concurrent members records leaves to do (spec §6): a
/// device of the owner's namespace that is of the merged audience resolves
/// it with a record of the next revision. Ordered by what it asks: a new
/// epoch does all a record listing the readers does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Resolve {
    /// Nothing: the merge stands.
    #[default]
    Nothing,
    /// A record listing the merged readers in the epoch the merge keeps:
    /// a reader one record added is not of that epoch's audience.
    Readers,
    /// A record in a new epoch: the merge leaves out a reader of the epoch
    /// it keeps or — merged against their parent — a reader of the parent
    /// or of a record merged.
    Epoch,
}

/// The epoch a sealed collection is read in (model primitive "Seal").
///
/// It is named by the members record that started it: the device that
/// signed that record and the record's seq in its log. Its content key is
/// 32 random octets that device made when it signed the record; the record
/// carries the key's check, and a device holding the key grants it, sealed
/// to the asker's own key, to readers that this record and the newest one
/// admit. Removing a reader starts a new epoch, so reading moves forward:
/// what a removed reader already holds it keeps (model invariant 9), and
/// nothing written in the new epoch reaches it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch {
    /// The device (not key) that signed the record starting the epoch.
    pub creator: Name,
    /// That record's seq in the device's log.
    pub seq: Seq,
}

/// One key's accepted seqs in a collection, as ascending, disjoint,
/// inclusive ranges.
pub type KeyRuns<'a> = (&'a Writer, &'a [(u64, u64)]);

/// Exactly the versions a [`Cut`] keeps, per collection and key: the seqs
/// of the key's versions in that collection that the cut's signer held
/// verified (spec §8). Every other version of the cut's keys is outside
/// it, whatever its seq or collection: a removed writer cannot fill a gap
/// below what was kept, nor sign an accepted seq again in another
/// collection — a key's log is one sequence across its collections, so a
/// seq is accepted only in the collection it was held in.
///
/// A removal cut also binds what it keeps to its bytes (spec §8): per
/// collection and key, the full names of the cut manifests (each the root
/// packet, ending in its implicit digest) that list the implicit digest of
/// every version kept there. A version is inside such a cut only with the
/// bytes every one of them lists; where several records' cuts meet (a
/// merge, or a folder's levels), each one's manifests bind what both keep.
/// A key's versions kept with no manifest are bound to no bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Accepted(BTreeMap<Name, BTreeMap<Writer, Kept>>);

/// One key's versions kept in one collection: its seqs, and the manifests
/// binding their bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct Kept {
    runs: Vec<(u64, u64)>,
    bytes: BTreeSet<Name>,
}

impl Accepted {
    /// Nothing accepted.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether exactly `id`, in collection `c`, is accepted.
    pub fn contains(&self, c: &Name, id: &VersionId) -> bool {
        self.highest_at_most(c, &id.writer, id.seq.0) == Some(id.seq.0)
    }

    /// Accept `id` in collection `c`.
    pub fn insert(&mut self, c: &Name, id: &VersionId) {
        self.insert_range(c, &id.writer, id.seq.0, id.seq.0);
    }

    /// Accept every seq of `writer` in collection `c` from `lo` to `hi`,
    /// inclusive.
    pub(crate) fn insert_range(&mut self, c: &Name, writer: &Writer, lo: u64, hi: u64) {
        let ranges = &mut self
            .0
            .entry(c.clone())
            .or_default()
            .entry(writer.clone())
            .or_default()
            .runs;
        // The ranges that overlap or touch [lo, hi] fold into it.
        let start = ranges.partition_point(|(_, h)| h.saturating_add(1) < lo);
        let end = ranges.partition_point(|(l, _)| *l <= hi.saturating_add(1));
        let (mut lo, mut hi) = (lo, hi);
        if start < end {
            lo = lo.min(ranges[start].0);
            hi = hi.max(ranges[end - 1].1);
        }
        ranges.splice(start..end, [(lo, hi)]);
    }

    /// Bind everything accepted to the bytes the cut manifest whose root's
    /// full name is `root` lists (spec §8).
    pub fn bind(&mut self, root: &Name) {
        for kept in self.0.values_mut().flat_map(|ws| ws.values_mut()) {
            kept.bytes.insert(root.clone());
        }
    }

    /// The full names of the cut manifests' roots that bind the bytes of
    /// `writer`'s versions accepted in collection `c`: each lists the
    /// implicit digest of every one of them. Empty: bound to no bytes.
    pub fn manifests(&self, c: &Name, writer: &Writer) -> impl Iterator<Item = &Name> {
        self.0
            .get(c)
            .and_then(|ws| ws.get(writer))
            .into_iter()
            .flat_map(|k| k.bytes.iter())
    }

    /// Every cut manifest's root binding anything accepted, in canonical
    /// order, once each.
    pub fn all_manifests(&self) -> BTreeSet<&Name> {
        self.0
            .values()
            .flat_map(|ws| ws.values())
            .flat_map(|k| k.bytes.iter())
            .collect()
    }

    /// The highest accepted seq of `writer` in collection `c` at or below
    /// `seq`.
    pub fn highest_at_most(&self, c: &Name, writer: &Writer, seq: u64) -> Option<u64> {
        let ranges = &self.0.get(c)?.get(writer)?.runs;
        let i = ranges.partition_point(|(lo, _)| *lo <= seq);
        (i > 0).then(|| ranges[i - 1].1.min(seq))
    }

    /// The accepted seqs per collection and key, as ascending, disjoint,
    /// inclusive ranges.
    pub fn iter(&self) -> impl Iterator<Item = (&Name, &Writer, &[(u64, u64)])> {
        self.0
            .iter()
            .flat_map(|(c, ws)| ws.iter().map(move |(w, k)| (c, w, k.runs.as_slice())))
    }

    /// The accepted seqs per collection, then per key in it.
    pub fn collections(&self) -> impl Iterator<Item = (&Name, impl Iterator<Item = KeyRuns<'_>>)> {
        self.0
            .iter()
            .map(|(c, ws)| (c, ws.iter().map(|(w, k)| (w, k.runs.as_slice()))))
    }

    /// Whether nothing is accepted.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// What it accepts of the entries whose collection and key `keep`
    /// keeps, with their bindings.
    fn only(&self, keep: impl Fn(&Name, &Writer) -> bool) -> Accepted {
        Accepted(
            self.0
                .iter()
                .map(|(c, ws)| {
                    let kept: BTreeMap<Writer, Kept> = ws
                        .iter()
                        .filter(|(w, _)| keep(c, w))
                        .map(|(w, k)| (w.clone(), k.clone()))
                        .collect();
                    (c.clone(), kept)
                })
                .filter(|(_, ws)| !ws.is_empty())
                .collect(),
        )
    }

    /// What it accepts of key `w`.
    pub(crate) fn of_key(&self, w: &Writer) -> Accepted {
        self.only(|_, x| x == w)
    }

    /// What it accepts of the keys under `prefix`.
    pub(crate) fn under(&self, prefix: &Name) -> Accepted {
        self.only(|_, w| w.key().has_prefix(prefix))
    }

    /// What it accepts in collection `subject` or, of a folder, in the
    /// collections under it.
    pub(crate) fn within(&self, subject: &Name) -> Accepted {
        self.only(|c, _| c.has_prefix(subject))
    }

    /// Accept also what `other` accepts, bound as it is there too.
    pub(crate) fn add(&mut self, other: &Accepted) {
        for (c, ws) in &other.0 {
            for (w, k) in ws {
                for (lo, hi) in &k.runs {
                    self.insert_range(c, w, *lo, *hi);
                }
                if let Some(mine) = self.0.get_mut(c).and_then(|x| x.get_mut(w)) {
                    mine.bytes.extend(k.bytes.iter().cloned());
                }
            }
        }
    }

    /// What both accept, bound by the manifests of both.
    pub fn intersection(&self, other: &Accepted) -> Accepted {
        let mut out = Accepted::new();
        for (c, ws) in &self.0 {
            for (w, mine) in ws {
                let Some(theirs) = other.0.get(c).and_then(|x| x.get(w)) else {
                    continue;
                };
                let (a, b) = (&mine.runs, &theirs.runs);
                let (mut i, mut j) = (0, 0);
                while i < a.len() && j < b.len() {
                    let lo = a[i].0.max(b[j].0);
                    let hi = a[i].1.min(b[j].1);
                    if lo <= hi {
                        out.insert_range(c, w, lo, hi);
                    }
                    if a[i].1 < b[j].1 {
                        i += 1;
                    } else {
                        j += 1;
                    }
                }
                if let Some(k) = out.0.get_mut(c).and_then(|x| x.get_mut(w)) {
                    k.bytes = mine.bytes.union(&theirs.bytes).cloned().collect();
                }
            }
        }
        out
    }
}

/// A signed "this much and no more" for a key or a member (model change
/// M3).
///
/// Exactly the versions by the keys under [`of`](Self::of) that
/// [`accept`](Self::accept) lists stay valid; anything else by those keys is
/// refused, whatever date or seq it claims. It replaces clock-based
/// arrives"). Two kinds: a writer's removal, in the members record of a
/// collection or of a folder; and a key's revocation, in its namespace's
/// trust context (spec §8), where [`of`](Self::of) is the revoked key,
/// [`accept`](Self::accept) the key's runs for the collection, and
/// [`signer`](Self::signer) the context's anchor key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Cut {
    /// The key, or the prefix of a member's keys, being ended.
    pub of: Name,
    /// What stays valid: exactly the versions the signer held verified,
    /// each in its collection.
    pub accept: Accepted,
    /// The key that signed the cut (the collection owner, or the namespace
    /// authority for a revocation).
    pub signer: Writer,
}

impl Cut {
    /// Whether this cut refuses `id` in collection `c`: its key falls under
    /// [`of`](Self::of) and [`accept`](Self::accept) does not list it there.
    pub fn refuses(&self, c: &Name, id: &VersionId) -> bool {
        id.writer.key().has_prefix(&self.of) && !self.accept.contains(c, id)
    }
}

/// One child of a nested summary: a sub-collection and the digest of its own
/// summary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Child {
    /// The child collection.
    pub name: Name,
    /// The digest of the child's current summary.
    pub digest: Hash,
}

/// A collection's signed state (model primitive "Summary").
///
/// "I have everything" always means "everything in this signed summary"
/// (model invariant 4). A summary is signed by one writer; with many writers
/// each signs its own, and completeness is per writer, gathered by the
/// [`Members`] record (open item "who signs a shared summary"). A reader
/// refuses a summary older than one it has already seen from the same signer
/// (model invariant 3). Summaries nest: a collection of collections lists its
/// children by digest, so [`watch`](crate::DataLayer::watch) descends only
/// into children whose digest changed (model change M8). The summary also
/// maps sequence numbers to names; that mapping is part of its wire form.
/// Filled by slice 1.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Summary {
    /// The summarised collection.
    pub collection: Name,
    /// The key that signed this summary.
    pub signer: Writer,
    /// Everything the summary covers.
    pub frontier: Frontier,
    /// Sub-collections, by digest of their own summaries.
    pub children: Vec<Child>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(key: &str, seq: u64) -> VersionId {
        VersionId {
            writer: Writer::new(key.parse().unwrap()),
            seq: Seq(seq),
        }
    }

    fn plan() -> Name {
        "/alice/32=data/docs/plan".parse().unwrap()
    }

    /// Exactly `ids`, accepted in collection `c`.
    fn accepted(c: &Name, ids: impl IntoIterator<Item = VersionId>) -> Accepted {
        let mut a = Accepted::new();
        for id in ids {
            a.insert(c, &id);
        }
        a
    }

    #[test]
    fn a_cut_keeps_exactly_what_its_signer_held_and_refuses_the_rest() {
        let p = plan();
        let cut = Cut {
            of: "/bob".parse().unwrap(),
            accept: accepted(
                &p,
                [id("/bob/phone/KEY/1", 40), id("/bob/phone/KEY/1", 100)],
            ),
            signer: Writer::new("/alice/laptop/KEY/1".parse().unwrap()),
        };
        assert!(!cut.refuses(&p, &id("/bob/phone/KEY/1", 40)));
        assert!(!cut.refuses(&p, &id("/bob/phone/KEY/1", 100)));
        assert!(cut.refuses(&p, &id("/bob/phone/KEY/1", 101)));
        // A seq the writer used elsewhere, below what was kept: a gap it
        // cannot fill after its removal.
        assert!(cut.refuses(&p, &id("/bob/phone/KEY/1", 57)));
        // A seq kept here, signed again in another collection: outside.
        let other: Name = "/alice/32=data/docs/notes".parse().unwrap();
        assert!(cut.refuses(&other, &id("/bob/phone/KEY/1", 40)));
        assert_eq!(
            cut.accept
                .highest_at_most(&p, &id("/bob/phone/KEY/1", 0).writer, 99),
            Some(40)
        );
        // A key of the member never seen at all is outside the cut too.
        assert!(cut.refuses(&p, &id("/bob/laptop/KEY/1", 1)));
        // Keys outside the member are not touched.
        assert!(!cut.refuses(&p, &id("/carol/phone/KEY/1", 99)));
    }

    #[test]
    fn accepted_sets_fold_ranges_and_intersect() {
        let p = plan();
        let w = |s| id("/bob/phone/KEY/1", s);
        let a = accepted(&p, [1, 2, 3, 7, 5, 6, 9].map(w));
        assert_eq!(
            a.iter().map(|(_, _, r)| r.to_vec()).collect::<Vec<_>>(),
            vec![vec![(1, 3), (5, 7), (9, 9)]]
        );
        let mut b = accepted(&p, [2, 3, 4, 5, 9].map(w));
        // What only another collection accepts is in no intersection here.
        let other: Name = "/alice/32=data/docs/notes".parse().unwrap();
        b.insert(&other, &w(7));
        let both = a.intersection(&b);
        assert_eq!(
            both.iter().map(|(_, _, r)| r.to_vec()).collect::<Vec<_>>(),
            vec![vec![(2, 3), (5, 5), (9, 9)]]
        );
        assert!(!both.contains(&p, &w(4)) && !both.contains(&p, &w(7)));
        assert!(!both.contains(&other, &w(7)));
    }

    #[test]
    fn a_record_admits_its_writers_and_what_its_cuts_accept_whatever_else() {
        let alice = Writer::new("/alice/laptop/KEY/1".parse().unwrap());
        let cut = Cut {
            of: "/bob".parse().unwrap(),
            accept: accepted(&plan(), [id("/bob/phone/KEY/1", 41)]),
            signer: alice.clone(),
        };
        let mut m = Members {
            collection: "/alice/32=data/docs/plan".parse().unwrap(),
            folder: false,
            owner: alice,
            revision: Seq(2),
            rule: Rule::Log,
            writers: vec!["/alice".parse().unwrap()],
            readers: Vec::new(),
            cuts: vec![cut.clone()],
            epoch: None,
            key_check: None,
            since: None,
            parent: None,
        };
        assert_eq!(m.refusal(&id("/alice/phone/KEY/1", 7)), None);
        assert_eq!(m.refusal(&id("/bob/phone/KEY/1", 41)), None);
        assert_eq!(
            m.refusal(&id("/bob/phone/KEY/1", 42)),
            Some(Refusal::OutsideCut(cut))
        );
        assert_eq!(
            m.refusal(&id("/mallory/phone/KEY/1", 1)),
            Some(Refusal::NotMember)
        );
        // Written back in, the prefix's keys are writers again.
        m.writers.push("/bob".parse().unwrap());
        assert_eq!(m.refusal(&id("/bob/phone/KEY/1", 42)), None);
    }

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn person(s: &str) -> Audience {
        Audience::Person(n(s))
    }

    /// A record of revision 2 by `signer`, naming no parent, in the epoch
    /// `signer`'s log entry `seq` started.
    fn record(
        signer: &str,
        seq: u64,
        writers: &[&str],
        readers: &[&str],
        cuts: Vec<Cut>,
    ) -> Members {
        Members {
            collection: n("/alice/32=data/docs/plan"),
            folder: false,
            owner: Writer::new(n(&format!("{signer}/KEY/1"))),
            revision: Seq(2),
            rule: Rule::Log,
            writers: writers.iter().map(|w| n(w)).collect(),
            readers: readers.iter().map(|r| person(r)).collect(),
            cuts,
            epoch: Some(Epoch {
                creator: n(signer),
                seq: Seq(seq),
            }),
            key_check: Some([seq as u8; 32]),
            since: None,
            parent: None,
        }
    }

    fn cut(of: &str, seqs: &[u64]) -> Cut {
        Cut {
            of: n(of),
            accept: accepted(&plan(), seqs.iter().map(|s| id("/bob/phone/KEY/1", *s))),
            signer: Writer::new(n("/alice/laptop/KEY/1")),
        }
    }

    fn none(_: &Parent) -> Option<&'static Members> {
        None
    }

    #[test]
    fn concurrent_records_without_a_held_parent_merge_by_intersection() {
        // The laptop removes Bob (writer and reader); the phone removes Carol.
        let laptop = record(
            "/alice/laptop",
            9,
            &["/alice"],
            &["/alice", "/carol"],
            vec![cut("/bob", &[3, 5])],
        );
        let phone = record(
            "/alice/phone",
            4,
            &["/alice", "/bob"],
            &["/alice", "/bob"],
            vec![cut("/bob", &[3])],
        );
        let (m, resolve) = Members::merge(&[laptop.clone(), phone.clone()], none).unwrap();
        assert_eq!(m.writers, vec![n("/alice")]);
        assert_eq!(m.readers, vec![person("/alice")]);
        assert_eq!(m.cuts.len(), 1);
        assert!(
            m.cuts[0].refuses(&plan(), &id("/bob/phone/KEY/1", 5)),
            "same prefix: intersection"
        );
        assert!(!m.cuts[0].refuses(&plan(), &id("/bob/phone/KEY/1", 3)));
        // Two readers each: the highest signer's epoch, which the reader the
        // other removed holds — so the merge must be resolved.
        let top = laptop.owner.clone().max(phone.owner.clone());
        assert_eq!(m.owner, top);
        assert_eq!(resolve, Resolve::Epoch);
        // One record only removes: its epoch is new to the removed reader and
        // nothing needs resolving.
        let adds = record(
            "/alice/phone",
            4,
            &["/alice"],
            &["/alice", "/carol", "/dave"],
            Vec::new(),
        );
        let (m, resolve) = Members::merge(&[laptop.clone(), adds], none).unwrap();
        assert_eq!(m.readers, vec![person("/alice"), person("/carol")]);
        assert_eq!(m.epoch, laptop.epoch);
        assert_eq!(m.key_check, laptop.key_check);
        assert_eq!(resolve, Resolve::Nothing);
        // A writer prefix is kept where every record admits its keys.
        let narrower = record(
            "/alice/phone",
            4,
            &["/alice/phone"],
            &["/alice"],
            Vec::new(),
        );
        let (m, _) = Members::merge(&[laptop, narrower], none).unwrap();
        assert_eq!(m.writers, vec![n("/alice/phone")]);
    }

    #[test]
    fn concurrent_records_of_one_held_parent_keep_every_addition_and_removal() {
        let parent = Members {
            revision: Seq(1),
            ..record(
                "/alice/laptop",
                1,
                &["/alice", "/bob"],
                &["/alice", "/bob"],
                Vec::new(),
            )
        };
        let from = |m: Members| Members {
            parent: Some(parent.as_parent()),
            ..m
        };
        let held = |p: &Parent| (p.digest == parent.as_parent().digest).then_some(&parent);
        // The laptop adds Carol in the parent's epoch; the phone removes Bob
        // in a new one.
        let laptop = from(Members {
            epoch: parent.epoch.clone(),
            key_check: parent.key_check,
            ..record(
                "/alice/laptop",
                0,
                &["/alice", "/bob", "/carol"],
                &["/alice", "/bob", "/carol"],
                Vec::new(),
            )
        });
        let phone = from(record(
            "/alice/phone",
            4,
            &["/alice"],
            &["/alice"],
            vec![cut("/bob", &[3])],
        ));
        let (m, resolve) = Members::merge(&[laptop.clone(), phone.clone()], held).unwrap();
        assert_eq!(m.writers, vec![n("/alice"), n("/carol")]);
        assert_eq!(m.readers, vec![person("/alice"), person("/carol")]);
        assert_eq!(m.cuts, phone.cuts);
        assert_eq!(m.parent, Some(parent.as_parent()));
        // The epoch Bob is not of, until a record in a new one resolves it:
        // the merge removed a reader of the parent.
        assert_eq!(m.epoch, phone.epoch);
        assert_eq!(resolve, Resolve::Epoch);
        // Without the parent, or with records of different parents, the
        // intersection: the addition is lost.
        let (m, _) = Members::merge(&[laptop.clone(), phone.clone()], none).unwrap();
        assert_eq!(m.readers, vec![person("/alice")]);
        let elsewhere = Members {
            parent: None,
            ..phone.clone()
        };
        let (m, _) = Members::merge(&[laptop.clone(), elsewhere], held).unwrap();
        assert_eq!(m.writers, vec![n("/alice")]);

        // A removal beats another record's addition under the prefix it
        // removed, not its own record's.
        let tablet = from(record(
            "/alice/laptop",
            0,
            &["/alice", "/bob", "/bob/tablet"],
            &["/alice", "/bob"],
            Vec::new(),
        ));
        let own = from(record(
            "/alice/phone",
            4,
            &["/alice", "/bob/laptop"],
            &["/alice", "/bob"],
            vec![cut("/bob", &[3])],
        ));
        let (m, _) = Members::merge(&[tablet, own], held).unwrap();
        // (Names in canonical order: a shorter component first.)
        assert_eq!(m.writers, vec![n("/bob/laptop"), n("/alice")]);

        // A rule one record changed wins over one that kept the parent's;
        // two changes, the highest signer's.
        let merged = Rule::Merge {
            function: n("/merge/yrs"),
        };
        let changed = from(Members {
            rule: merged.clone(),
            ..laptop.clone()
        });
        let (m, _) = Members::merge(&[changed.clone(), phone.clone()], held).unwrap();
        assert_eq!(m.rule, merged);
        let (m, _) = Members::merge(&[phone.clone(), changed.clone()], held).unwrap();
        assert_eq!(m.rule, merged, "whatever order the records come in");
        let other = from(Members {
            rule: Rule::OneKey,
            ..phone.clone()
        });
        let (m, _) = Members::merge(&[changed.clone(), other.clone()], held).unwrap();
        let top = [&changed, &other]
            .into_iter()
            .max_by(|a, b| a.owner.cmp(&b.owner));
        assert_eq!(m.rule, top.unwrap().rule);

        // Only additions, one in another epoch than the parent's (a group
        // rotated): the merge keeps that epoch, and a record listing the
        // reader added in it resolves the merge.
        let rotated = from(record(
            "/alice/phone",
            4,
            &["/alice", "/bob"],
            &["/alice", "/bob"],
            Vec::new(),
        ));
        let (m, resolve) = Members::merge(&[laptop.clone(), rotated.clone()], held).unwrap();
        assert_eq!(
            m.readers,
            vec![person("/alice"), person("/bob"), person("/carol")]
        );
        assert_eq!(m.epoch, rotated.epoch);
        assert_eq!(resolve, Resolve::Readers);
        // Both add in the parent's epoch: its audience lists both readers.
        let dave = from(Members {
            epoch: parent.epoch.clone(),
            key_check: parent.key_check,
            ..record(
                "/alice/phone",
                0,
                &["/alice", "/bob"],
                &["/alice", "/bob", "/dave"],
                Vec::new(),
            )
        });
        let (m, resolve) = Members::merge(&[laptop, dave], held).unwrap();
        assert_eq!(m.readers.len(), 4);
        assert_eq!(resolve, Resolve::Nothing);
    }

    #[test]
    fn frontiers_only_grow_and_compare_per_writer() {
        let mut f: Frontier = [id("/a/KEY/1", 3), id("/b/KEY/1", 1)].into_iter().collect();
        f.include(&id("/a/KEY/1", 2));
        assert_eq!(f.get(&id("/a/KEY/1", 0).writer), Some(Seq(3)));
        let older: Frontier = [id("/a/KEY/1", 2)].into_iter().collect();
        assert!(f.covers(&older));
        assert!(!older.covers(&f));
        assert!(f.contains(&id("/b/KEY/1", 1)));
        assert!(!f.contains(&id("/c/KEY/1", 1)));
    }

    /// A folder record of `/alice/32=data/docs`.
    fn folder(writers: &[&str], readers: &[&str], cuts: Vec<Cut>) -> Members {
        Members {
            collection: n("/alice/32=data/docs"),
            folder: true,
            ..record("/alice/laptop", 3, writers, readers, cuts)
        }
    }

    #[test]
    fn a_collection_under_a_folder_inherits_what_it_leaves_empty_and_is_narrowed_by_every_level() {
        let c = n("/alice/32=data/docs/plan");
        let f = folder(&["/alice", "/bob"], &["/alice", "/bob"], Vec::new());
        let bob = id("/bob/phone/KEY/1", 1);
        let carol = id("/carol/phone/KEY/1", 1);
        // No own record, or one listing no writers and no readers: the
        // folder's writers, readers and epoch.
        let empty = Members {
            epoch: None,
            key_check: None,
            ..record("/alice/phone", 9, &[], &[], Vec::new())
        };
        for own in [None, Some(&empty)] {
            let e = effective(&c, own, &[&f]).unwrap();
            assert_eq!(e.refusal(&bob), None);
            assert_eq!(e.refusal(&carol), Some(Refusal::NotMember));
            assert_eq!((&e.readers, &e.epoch), (&f.readers, &f.epoch));
            assert!(!e.folder);
        }
        // Narrowed: its own writers and readers, in its own epoch.
        let narrow = record("/alice/phone", 9, &["/alice"], &["/alice"], Vec::new());
        let e = effective(&c, Some(&narrow), &[&f]).unwrap();
        assert_eq!(e.refusal(&bob), Some(Refusal::NotMember));
        assert_eq!(e.refusal(&id("/alice/phone/KEY/1", 4)), None);
        assert_eq!((&e.readers, &e.epoch), (&narrow.readers, &narrow.epoch));
        // Widened: what the folder does not admit has no effect.
        let wide = record(
            "/alice/phone",
            9,
            &["/alice", "/carol"],
            &["/alice", "/carol"],
            Vec::new(),
        );
        let e = effective(&c, Some(&wide), &[&f]).unwrap();
        assert!(e.refusal(&carol).is_some());
        assert!(!e.readers.contains(&person("/carol")));
        assert_eq!(e.epoch, wide.epoch);
    }

    #[test]
    fn a_version_is_admitted_under_a_folder_iff_every_level_admits_it() {
        let c = n("/alice/32=data/docs/plan");
        let bob = |s| id("/bob/phone/KEY/1", s);
        // Bob removed at folder level: his versions the cut kept stay, his
        // later ones are refused, whatever the collection's own record lists.
        let removed = folder(&["/alice"], &["/alice"], vec![cut("/bob", &[1, 2])]);
        let listing = record("/alice/phone", 9, &["/alice", "/bob"], &[], Vec::new());
        for own in [None, Some(&listing)] {
            let e = effective(&c, own, &[&removed]).unwrap();
            assert_eq!(e.refusal(&bob(2)), None);
            assert!(matches!(e.refusal(&bob(3)), Some(Refusal::OutsideCut(_))));
        }
        // A version an own cut keeps, of a key the folder does not admit at
        // all, is refused.
        let only_alice = folder(&["/alice"], &[], Vec::new());
        let kept = record("/alice/phone", 9, &["/alice"], &[], vec![cut("/bob", &[1])]);
        let e = effective(&c, Some(&kept), &[&only_alice]).unwrap();
        assert!(e.refusal(&bob(1)).is_some());
        // Cuts of both levels: exactly what both keep.
        let both = folder(&["/alice"], &[], vec![cut("/bob", &[1, 2, 3])]);
        let own = record(
            "/alice/phone",
            9,
            &["/alice"],
            &[],
            vec![cut("/bob/phone", &[2, 3, 4])],
        );
        let e = effective(&c, Some(&own), &[&both]).unwrap();
        for (s, admitted) in [(1, false), (2, true), (3, true), (4, false)] {
            assert_eq!(e.refusal(&bob(s)).is_none(), admitted, "seq {s}");
        }
        // With no folder, the own record stands as it is.
        assert_eq!(effective(&c, Some(&own), &[]), Some(own.clone()));
        // A folder cut keeps each seq in the collection it was held in: a
        // seq it kept in another collection is outside here.
        let notes = n("/alice/32=data/docs/notes");
        let mut elsewhere = cut("/bob", &[1]);
        elsewhere.accept.insert(&notes, &bob(2));
        let removed = folder(&["/alice"], &["/alice"], vec![elsewhere]);
        let e = effective(&c, None, &[&removed]).unwrap();
        assert_eq!(e.refusal(&bob(1)), None);
        assert!(matches!(e.refusal(&bob(2)), Some(Refusal::OutsideCut(_))));
        let e = effective(&notes, None, &[&removed]).unwrap();
        assert_eq!(e.refusal(&bob(2)), None);
        assert!(matches!(e.refusal(&bob(1)), Some(Refusal::OutsideCut(_))));
    }
}
