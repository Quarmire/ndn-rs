//! Collections: the growing side of the model — their [`Rule`], their
//! owner-signed [`Members`], the [`Cut`]s that end a member or a key, the
//! [`Epoch`] their seal is read in, and the signed, nested [`Summary`] of
//! what they hold.

use std::collections::BTreeMap;

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
/// share: every addition and every removal is kept, and removals win.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Members {
    /// The collection this record governs.
    pub collection: Name,
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
    /// Versions outside a cut that the owner signed back in.
    ///
    /// This answers the open item "a cut can drop honest work": a stolen
    /// device's offline edits that nobody had seen fall outside its cut, and
    /// the owner may re-admit specific ones. Filled by slice 5.
    pub readmitted: Vec<VersionId>,
}

impl Members {
    /// Why this record refuses version `id`, if it does: a key under a
    /// writer prefix is admitted; else a key under a cut's prefix is
    /// admitted if the cut accepts exactly that version and refused
    /// otherwise, whatever date or seq it claims; else the key is no member.
    pub fn refusal(&self, id: &VersionId) -> Option<Refusal> {
        let key = id.writer.key();
        if self.writers.iter().any(|p| key.has_prefix(p)) {
            return None;
        }
        match self.cuts.iter().find(|c| key.has_prefix(&c.of)) {
            Some(cut) if cut.accept.contains(id) => None,
            Some(cut) => Some(Refusal::OutsideCut(cut.clone())),
            None => Some(Refusal::NotMember),
        }
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
        let top = records.iter().max_by(|a, b| a.owner.cmp(&b.owner))?;
        if let [one] = records {
            return Some((one.clone(), Resolve::Nothing));
        }
        let shared = records
            .iter()
            .map(|m| m.parent)
            .reduce(|a, b| a.filter(|p| b == Some(*p)))
            .flatten();
        let base = shared.and_then(|p| held(&p).filter(|m| m.as_parent() == p));
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
            owner: top.owner.clone(),
            revision: top.revision,
            rule: ruling.rule.clone(),
            writers: broadest,
            readers,
            cuts: cuts.into_values().collect(),
            epoch: sealing.epoch.clone(),
            key_check: sealing.key_check,
            since: ruling.since.clone(),
            parent: shared,
            readmitted: Vec::new(),
        };
        Some((merged, resolve))
    }
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
/// it with a record of the next revision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

/// Exactly the versions a [`Cut`] keeps, per key: the seqs of the key's
/// versions in the collection that the cut's signer held verified (spec
/// §8). Every other version of the cut's keys is outside it, whatever its
/// seq: a removed writer cannot fill a gap below what was kept.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Accepted(BTreeMap<Writer, Vec<(u64, u64)>>);

impl Accepted {
    /// Nothing accepted.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether exactly `id` is accepted.
    pub fn contains(&self, id: &VersionId) -> bool {
        let Some(ranges) = self.0.get(&id.writer) else {
            return false;
        };
        let s = id.seq.0;
        let i = ranges.partition_point(|(lo, _)| *lo <= s);
        i > 0 && ranges[i - 1].1 >= s
    }

    /// Accept `id`.
    pub fn insert(&mut self, id: &VersionId) {
        self.insert_range(&id.writer, id.seq.0, id.seq.0);
    }

    /// Accept every seq of `writer` from `lo` to `hi`, inclusive.
    pub(crate) fn insert_range(&mut self, writer: &Writer, lo: u64, hi: u64) {
        let ranges = self.0.entry(writer.clone()).or_default();
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

    /// The highest accepted seq of `writer` at or below `seq`.
    pub fn highest_at_most(&self, writer: &Writer, seq: u64) -> Option<u64> {
        let ranges = self.0.get(writer)?;
        let i = ranges.partition_point(|(lo, _)| *lo <= seq);
        (i > 0).then(|| ranges[i - 1].1.min(seq))
    }

    /// The accepted seqs per key, as ascending, disjoint, inclusive ranges.
    pub fn iter(&self) -> impl Iterator<Item = (&Writer, &[(u64, u64)])> {
        self.0.iter().map(|(w, r)| (w, r.as_slice()))
    }

    /// Whether nothing is accepted.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// What both accept.
    pub fn intersection(&self, other: &Accepted) -> Accepted {
        let mut out = Accepted::new();
        for (w, mine) in &self.0 {
            let Some(theirs) = other.0.get(w) else {
                continue;
            };
            let (mut i, mut j) = (0, 0);
            while i < mine.len() && j < theirs.len() {
                let lo = mine[i].0.max(theirs[j].0);
                let hi = mine[i].1.min(theirs[j].1);
                if lo <= hi {
                    out.insert_range(w, lo, hi);
                }
                if mine[i].1 < theirs[j].1 {
                    i += 1;
                } else {
                    j += 1;
                }
            }
        }
        out
    }
}

impl FromIterator<VersionId> for Accepted {
    fn from_iter<I: IntoIterator<Item = VersionId>>(iter: I) -> Self {
        let mut a = Accepted::new();
        for id in iter {
            a.insert(&id);
        }
        a
    }
}

/// A signed "this much and no more" for a key or a member (model change
/// M3).
///
/// Exactly the versions by the keys under [`of`](Self::of) that
/// [`accept`](Self::accept) lists stay valid; anything else by those keys is
/// refused, whatever date or seq it claims. It replaces clock-based
/// signing-time validity. A reader that receives a cut re-checks everything
/// it already accepted from those keys against it (open item "before a cut
/// arrives"). Cuts on removal are filled by slice 2, revocation cuts by
/// slice 5.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Cut {
    /// The key, or the prefix of a member's keys, being ended.
    pub of: Name,
    /// What stays valid: exactly the versions the signer held verified.
    pub accept: Accepted,
    /// The key that signed the cut (the collection owner, or the namespace
    /// authority for a revocation).
    pub signer: Writer,
}

impl Cut {
    /// Whether this cut refuses `id`: its key falls under [`of`](Self::of)
    /// and [`accept`](Self::accept) does not list it.
    pub fn refuses(&self, id: &VersionId) -> bool {
        id.writer.key().has_prefix(&self.of) && !self.accept.contains(id)
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

    #[test]
    fn a_cut_keeps_exactly_what_its_signer_held_and_refuses_the_rest() {
        let cut = Cut {
            of: "/bob".parse().unwrap(),
            accept: [id("/bob/phone/KEY/1", 40), id("/bob/phone/KEY/1", 100)]
                .into_iter()
                .collect(),
            signer: Writer::new("/alice/laptop/KEY/1".parse().unwrap()),
        };
        assert!(!cut.refuses(&id("/bob/phone/KEY/1", 40)));
        assert!(!cut.refuses(&id("/bob/phone/KEY/1", 100)));
        assert!(cut.refuses(&id("/bob/phone/KEY/1", 101)));
        // A seq the writer used elsewhere, below what was kept: a gap it
        // cannot fill after its removal.
        assert!(cut.refuses(&id("/bob/phone/KEY/1", 57)));
        assert_eq!(
            cut.accept
                .highest_at_most(&id("/bob/phone/KEY/1", 0).writer, 99),
            Some(40)
        );
        // A key of the member never seen at all is outside the cut too.
        assert!(cut.refuses(&id("/bob/laptop/KEY/1", 1)));
        // Keys outside the member are not touched.
        assert!(!cut.refuses(&id("/carol/phone/KEY/1", 99)));
    }

    #[test]
    fn accepted_sets_fold_ranges_and_intersect() {
        let w = |s| id("/bob/phone/KEY/1", s);
        let a: Accepted = [1, 2, 3, 7, 5, 6, 9].into_iter().map(w).collect();
        assert_eq!(
            a.iter().map(|(_, r)| r.to_vec()).collect::<Vec<_>>(),
            vec![vec![(1, 3), (5, 7), (9, 9)]]
        );
        let b: Accepted = [2, 3, 4, 5, 9].into_iter().map(w).collect();
        let both = a.intersection(&b);
        assert_eq!(
            both.iter().map(|(_, r)| r.to_vec()).collect::<Vec<_>>(),
            vec![vec![(2, 3), (5, 5), (9, 9)]]
        );
        assert!(!both.contains(&w(4)) && !both.contains(&w(7)));
    }

    #[test]
    fn a_record_admits_its_writers_and_what_its_cuts_accept_whatever_else() {
        let alice = Writer::new("/alice/laptop/KEY/1".parse().unwrap());
        let cut = Cut {
            of: "/bob".parse().unwrap(),
            accept: [id("/bob/phone/KEY/1", 41)].into_iter().collect(),
            signer: alice.clone(),
        };
        let mut m = Members {
            collection: "/alice/32=data/docs/plan".parse().unwrap(),
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
            readmitted: Vec::new(),
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
            readmitted: Vec::new(),
        }
    }

    fn cut(of: &str, seqs: &[u64]) -> Cut {
        Cut {
            of: n(of),
            accept: seqs.iter().map(|s| id("/bob/phone/KEY/1", *s)).collect(),
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
            m.cuts[0].refuses(&id("/bob/phone/KEY/1", 5)),
            "same prefix: intersection"
        );
        assert!(!m.cuts[0].refuses(&id("/bob/phone/KEY/1", 3)));
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
}
