//! What judging a group of versions costs (spec §5.5). A group's verdict,
//! which of its members move, and what its members are told are found
//! from a [`Book`] kept per group: each member's state as last read, and
//! what the folder's collections hold of the group's writer in its span.
//! A book reads again only the collections changed since it last read
//! ([`Colls`], [`Noted`], [`Gen`] note every change), so a group of `n`
//! members costs each change once, not `n` times per member.
//!
//! A book stands in for the judgement read member by member
//! ([`St::full_verdict`], [`St::judge_members`]) only where it proves the
//! answer the same: a malformed group, a member refused, pruned or refused
//! for its group, a seq of the span signed in two collections of the
//! folder, a member the writer pruned, or members sealed apart are judged
//! member by member, as before.

use std::cell::{Cell, RefCell, RefMut};
use std::collections::{HashSet, btree_map};
use std::ops::{Deref, Range};

use super::*;

/// The collections known here ([`St::colls`]), with when each last
/// changed: every access that may change one notes it, so a [`Book`] reads
/// again only what changed since it last read. By name, so what is done
/// collection by collection (fetches, asks) goes out in the same order in
/// every run (data-layer §18.1).
#[derive(Default)]
pub(super) struct Colls {
    map: BTreeMap<Name, Coll>,
    touches: RefCell<Touches>,
}

/// When each collection was last changed ([`Colls`]).
#[derive(Default)]
struct Touches {
    /// The number of the last change.
    stamp: u64,
    /// The highest change a book read up to: a collection changed again
    /// right after its last change, with no book reading in between, is
    /// noted once.
    read: u64,
    /// Each collection's last change.
    last: HashMap<Name, u64>,
    /// The collections by their last change.
    order: BTreeMap<u64, Name>,
}

impl Touches {
    fn touch(&mut self, c: &Name) {
        if self.stamp > self.read && self.order.get(&self.stamp) == Some(c) {
            return;
        }
        self.stamp += 1;
        if let Some(old) = self.last.insert(c.clone(), self.stamp) {
            self.order.remove(&old);
        }
        self.order.insert(self.stamp, c.clone());
    }
}

impl Deref for Colls {
    type Target = BTreeMap<Name, Coll>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl Colls {
    /// Collection `c`, to change.
    pub(super) fn get_mut(&mut self, c: &Name) -> Option<&mut Coll> {
        let coll = self.map.get_mut(c)?;
        self.touches.get_mut().touch(c);
        Some(coll)
    }

    /// Collection `c`'s entry, to change or add.
    pub(super) fn entry(&mut self, c: Name) -> btree_map::Entry<'_, Name, Coll> {
        self.touches.get_mut().touch(&c);
        self.map.entry(c)
    }

    /// Every collection, to change.
    pub(super) fn iter_mut(&mut self) -> btree_map::IterMut<'_, Name, Coll> {
        let touches = self.touches.get_mut();
        for c in self.map.keys() {
            touches.touch(c);
        }
        self.map.iter_mut()
    }

    /// Note the collection of log entry `name`, if it is of one, changed.
    fn touch_entry(&self, name: &Name) {
        if let Some(c) = parse_log_name(name).and_then(|l| l.subject) {
            self.touches.borrow_mut().touch(&c);
        }
    }

    /// The collections changed after change `since`, and the last change.
    fn changed_since(&self, since: u64) -> (Vec<Name>, u64) {
        let mut t = self.touches.borrow_mut();
        t.read = t.stamp;
        let changed = t.order.range(since + 1..).map(|(_, c)| c.clone()).collect();
        (changed, t.stamp)
    }

    /// The last change, every change up to it read now.
    fn mark_read(&self) -> u64 {
        let mut t = self.touches.borrow_mut();
        t.read = t.stamp;
        t.stamp
    }
}

/// The most entry changes a [`Noted`] map keeps noted between two reads;
/// past it, every book is read anew.
const NOTED_MAX: usize = 1 << 16;

/// A map by log entry name whose changes a [`Book`] reads ([`St::held`],
/// [`St::refused`]): each change notes the entry, read as a change of its
/// collection.
pub(super) struct Noted<V> {
    map: HashMap<Name, V>,
    /// The entries changed since last read.
    changed: RefCell<Vec<Name>>,
    /// How many times more entries changed than [`NOTED_MAX`].
    lost: Cell<u64>,
}

impl<V> Default for Noted<V> {
    fn default() -> Self {
        Noted {
            map: HashMap::new(),
            changed: RefCell::new(Vec::new()),
            lost: Cell::new(0),
        }
    }
}

impl<V> Deref for Noted<V> {
    type Target = HashMap<Name, V>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<V> Noted<V> {
    fn note(&mut self, name: &Name) {
        let changed = self.changed.get_mut();
        if changed.len() >= NOTED_MAX {
            changed.clear();
            *self.lost.get_mut() += 1;
        } else {
            changed.push(name.clone());
        }
    }

    pub(super) fn insert(&mut self, name: Name, value: V) -> Option<V> {
        self.note(&name);
        self.map.insert(name, value)
    }

    pub(super) fn remove(&mut self, name: &Name) -> Option<V> {
        let gone = self.map.remove(name);
        if gone.is_some() {
            self.note(name);
        }
        gone
    }

    /// Read the entries changed as changes of their collections.
    fn read_into(&self, colls: &Colls) {
        for name in self.changed.take() {
            colls.touch_entry(&name);
        }
    }
}

/// A value whose every change a [`Book`] sees as a change of all it reads
/// ([`St::keys`], [`St::folders`], [`St::cut_out`]): changed only through
/// [`Gen::edit`].
pub(super) struct Gen<T> {
    inner: T,
    edits: u64,
}

impl<T> Gen<T> {
    pub(super) fn new(inner: T) -> Self {
        Gen { inner, edits: 0 }
    }

    /// The value, to change.
    pub(super) fn edit(&mut self) -> &mut T {
        self.edits += 1;
        &mut self.inner
    }
}

impl<T> Deref for Gen<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

/// The most members the books kept hold together; past it the least
/// recently used are let go (read again when next needed).
const BOOKED_MAX: usize = 4 * GROUP_MAX as usize;

/// The books kept, by group ([`St::books`]).
#[derive(Default)]
pub(super) struct Books {
    map: HashMap<(Writer, u64), Book>,
    tick: u64,
    members: usize,
}

impl Books {
    /// Note member `m` joining group `key` at `seq` (the `at_seq`-th
    /// there) in the group's book, if one is kept ([`St::note_member`]).
    pub(super) fn join(&mut self, key: &(Writer, u64), seq: u64, m: &Member, at_seq: usize) {
        if let Some(book) = self.map.get_mut(key) {
            let before = book.by_coll.len();
            book.join(seq, m, at_seq);
            self.members = self.members - before + book.by_coll.len();
        }
    }
}

/// What a group member's seal reads as for its group's verdict: the seal
/// it declares, the epoch it is sealed in, and that epoch's readers.
#[derive(Clone, PartialEq, Eq, Hash)]
struct SealKey {
    seal: BTreeSet<Audience>,
    epoch: Option<Epoch>,
    readers: Vec<Audience>,
}

/// One member as its book last read it.
struct Facts {
    coll: Name,
    state: MemberState,
    /// Waiting and ready to apply.
    ready: bool,
    seal: Option<Arc<SealKey>>,
    /// Pending, or held sealed, in its collection under a known record that
    /// still judges the group: acted on there.
    here: bool,
    /// Its collection judges the group on its applications ([`Coll::txns`]).
    judged: bool,
    applied: bool,
    not_counted: bool,
    parked: bool,
}

/// How many members are in each state, and more.
#[derive(Default)]
struct Tally {
    counted: usize,
    waiting: usize,
    missing: usize,
    unreadable: usize,
    refused: usize,
    group_refused: usize,
    dropped: usize,
    /// Waiting and not ready.
    unready: usize,
    parked: usize,
}

/// One group's judgement, as last read (module docs).
pub(super) struct Book {
    /// Read up to this change of the collections ([`Colls::changed_since`]).
    stamp: u64,
    /// The changes to keys, folders and revocations it was read under.
    edits: u64,
    used: u64,
    /// Every member well-formed: one per seq, inside the span, agreeing on
    /// the count, one per collection, all of one folder, kept until pruned.
    /// A book not live stays so (members only join) and judges nothing.
    live: bool,
    folder: Name,
    count: u32,
    span: Range<u64>,
    /// Each member's collection, and its seq.
    by_coll: HashMap<Name, u64>,
    facts: BTreeMap<u64, Facts>,
    tally: Tally,
    seals: HashMap<Arc<SealKey>, usize>,
    /// Per collection of the folder, the seqs of the span its writer
    /// signed there ([`St::signed_in`]).
    signed: HashMap<Name, Vec<u64>>,
    /// How many collections of the folder each seq of the span was signed
    /// in, and how many seqs were signed in more than one.
    signers: HashMap<u64, u32>,
    shared: usize,
    /// The collections of the folder holding a prune of the writer.
    pruning: HashSet<Name>,
    /// The seqs of members [`Facts::here`], waiting or unreadable.
    here: BTreeSet<u64>,
    /// The seqs of members waiting and ready.
    ready: BTreeSet<u64>,
    /// The seqs of members applied that their rule does not count.
    applied_nc: BTreeSet<u64>,
    /// The seqs of members whose collection does not judge the group on
    /// its applications ([`Coll::txns`]).
    unjudged: BTreeSet<u64>,
    /// Members read again since [`St::regroup`] last told the group.
    moved: BTreeSet<u64>,
    /// The blocker [`St::regroup`] last told every member by; `None`
    /// before it told them through this book.
    told: Option<Option<String>>,
}

/// Whether collection `c` is directly in folder `f` ([`folder_of`]).
fn in_folder(c: &Name, f: &Name) -> bool {
    c.len().saturating_sub(1) == f.len() && c.has_prefix(f)
}

impl Book {
    fn dead(edits: u64) -> Self {
        Book {
            stamp: 0,
            edits,
            used: 0,
            live: false,
            folder: Name::root(),
            count: 0,
            span: 0..0,
            by_coll: HashMap::new(),
            facts: BTreeMap::new(),
            tally: Tally::default(),
            seals: HashMap::new(),
            signed: HashMap::new(),
            signers: HashMap::new(),
            shared: 0,
            pruning: HashSet::new(),
            here: BTreeSet::new(),
            ready: BTreeSet::new(),
            applied_nc: BTreeSet::new(),
            unjudged: BTreeSet::new(),
            moved: BTreeSet::new(),
            told: None,
        }
    }

    /// Count `f`, the facts of member `seq`, in (`add`) or out.
    fn tally(&mut self, seq: u64, f: &Facts, add: bool) {
        let step = |n: &mut usize| match add {
            true => *n += 1,
            false => *n -= 1,
        };
        let t = &mut self.tally;
        match &f.state {
            MemberState::Counted => step(&mut t.counted),
            MemberState::Waiting => step(&mut t.waiting),
            MemberState::Missing => step(&mut t.missing),
            MemberState::Unreadable => step(&mut t.unreadable),
            MemberState::Refused(_) => step(&mut t.refused),
            MemberState::GroupRefused => step(&mut t.group_refused),
            MemberState::Dropped => step(&mut t.dropped),
        }
        if f.state == MemberState::Waiting && !f.ready {
            step(&mut t.unready);
        }
        if f.parked {
            step(&mut t.parked);
        }
        let mark = |set: &mut BTreeSet<u64>, on: bool| {
            if on {
                match add {
                    true => set.insert(seq),
                    false => set.remove(&seq),
                };
            }
        };
        let waits = matches!(f.state, MemberState::Waiting | MemberState::Unreadable);
        mark(&mut self.here, f.here && waits);
        mark(&mut self.ready, f.state == MemberState::Waiting && f.ready);
        mark(&mut self.applied_nc, f.applied && f.not_counted);
        mark(&mut self.unjudged, !f.judged);
        if let Some(s) = &f.seal {
            match add {
                true => *self.seals.entry(Arc::clone(s)).or_default() += 1,
                false => {
                    let n = self.seals.get_mut(s).expect("counted in");
                    *n -= 1;
                    if *n == 0 {
                        self.seals.remove(s);
                    }
                }
            }
        }
    }

    /// Note what collection `x` of the folder holds of the group's writer
    /// in its span: the seqs signed there, and whether it holds a prune of
    /// the writer.
    fn read_folder_coll(&mut self, st: &St, w: &Writer, x: &Name) {
        if let Some(old) = self.signed.remove(x) {
            for s in old {
                let n = self.signers.get_mut(&s).expect("counted in");
                *n -= 1;
                match *n {
                    0 => {
                        self.signers.remove(&s);
                    }
                    1 => self.shared -= 1,
                    _ => {}
                }
            }
        }
        let now = st.signed_in(x, w, &self.span);
        for s in &now {
            let n = self.signers.entry(*s).or_default();
            *n += 1;
            if *n == 2 {
                self.shared += 1;
            }
        }
        if !now.is_empty() {
            self.signed.insert(x.clone(), now);
        }
        let prunes = st
            .colls
            .get(x)
            .is_some_and(|k| k.prunes.iter().any(|p| p.id.writer == *w));
        match prunes {
            true => self.pruning.insert(x.clone()),
            false => self.pruning.remove(x),
        };
    }

    /// Read member `seq` of `c` again.
    fn read_member(&mut self, st: &St, key: &(Writer, u64), seq: u64, c: &Name) {
        if let Some(old) = self.facts.remove(&seq) {
            self.tally(seq, &old, false);
        }
        let f = st.member_facts(key, seq, c, &self.seals);
        self.tally(seq, &f, true);
        self.facts.insert(seq, f);
        self.moved.insert(seq);
    }

    /// Add member `seq` of `c` to the book, noted after it was built ([`St::note_member`]);
    /// read at the next refresh, as `c` changed. A member that is not
    /// well-formed ends the book's life.
    fn join(&mut self, seq: u64, m: &Member, at_seq: usize) {
        if !self.live {
            return;
        }
        let fits = at_seq == 1
            && self.span.contains(&seq)
            && m.count == self.count
            && m.keep == Keep::Forever
            && in_folder(&m.collection, &self.folder)
            && !self.by_coll.contains_key(&m.collection);
        if fits {
            self.by_coll.insert(m.collection.clone(), seq);
        } else {
            *self = Book::dead(self.edits);
        }
    }

    /// The group's verdict, when the book proves it the full judgement's
    /// ([`St::full_verdict`]).
    fn verdict(&self) -> Option<GroupVerdict> {
        let t = &self.tally;
        if t.refused + t.group_refused + t.dropped > 0
            || self.shared > 0
            || !self.pruning.is_empty()
            || self.seals.len() > 1
        {
            return None;
        }
        // One seal and epoch for every member held, each epoch's readers
        // the same: none is uncovered.
        if t.unreadable > 0 {
            return Some(GroupVerdict::Unreadable);
        }
        let present = (t.counted + t.waiting) as u32;
        if present < self.count {
            return Some(GroupVerdict::Incomplete {
                present,
                count: self.count,
            });
        }
        let next = match t.unready {
            0 => self.ready.first().copied(),
            _ => None,
        };
        Some(GroupVerdict::Complete { next })
    }
}

impl St {
    /// The changes to keys, folders and revocations, and to entries more
    /// than could be noted, so far.
    fn edits(&self) -> u64 {
        self.keys.edits
            + self.folders.edits
            + self.cut_out.edits
            + self.held.lost.get()
            + self.refused.lost.get()
    }

    /// Group `key`'s book, read up to now; `None` when the group is judged
    /// member by member only (no member known, or one not well-formed).
    fn book(&self, key: &(Writer, u64)) -> Option<RefMut<'_, Book>> {
        self.held.read_into(&self.colls);
        self.refused.read_into(&self.colls);
        let edits = self.edits();
        let mut books = self.books.borrow_mut();
        books.tick += 1;
        let tick = books.tick;
        let stale = books
            .map
            .get(key)
            .is_none_or(|b| b.live && b.edits != edits);
        if stale {
            let book = self.build_book(key, edits)?;
            let size = book.by_coll.len();
            if let Some(old) = books.map.insert(key.clone(), book) {
                books.members -= old.by_coll.len();
            }
            books.members += size;
            while books.members > BOOKED_MAX && books.map.len() > 1 {
                let oldest = books
                    .map
                    .iter()
                    .filter(|(k, _)| *k != key)
                    .min_by_key(|(_, b)| b.used)
                    .map(|(k, _)| k.clone())
                    .expect("more than one");
                let gone = books.map.remove(&oldest).expect("listed");
                books.members -= gone.by_coll.len();
            }
        }
        let mut book = RefMut::map(books, |b| b.map.get_mut(key).expect("kept above"));
        book.used = tick;
        if !book.live {
            return None;
        }
        if !stale {
            let (changed, now) = self.colls.changed_since(book.stamp);
            for c in changed {
                if let Some(&seq) = book.by_coll.get(&c) {
                    book.read_member(self, key, seq, &c);
                }
                if in_folder(&c, &book.folder) {
                    book.read_folder_coll(self, &key.0, &c);
                }
            }
            book.stamp = now;
        }
        Some(book)
    }

    /// Read group `key`'s book whole; `None` when no member is known.
    fn build_book(&self, key: &(Writer, u64), edits: u64) -> Option<Book> {
        let members = self.txns.get(key)?;
        let first = members.values().flatten().next()?;
        let (count, folder) = (first.count, folder_of(&first.collection));
        let mut book = Book::dead(edits);
        let span = key.1..key.1.saturating_add(u64::from(count));
        let mut by_coll = HashMap::with_capacity(members.len());
        for (seq, ms) in members {
            let [m] = &ms[..] else {
                return Some(book);
            };
            let fits = span.contains(seq)
                && m.count == count
                && m.keep == Keep::Forever
                && in_folder(&m.collection, &folder);
            if !fits || by_coll.insert(m.collection.clone(), *seq).is_some() {
                return Some(book);
            }
        }
        book.live = true;
        book.folder = folder;
        book.count = count;
        book.span = span;
        book.stamp = self.colls.mark_read();
        for (c, seq) in &by_coll {
            book.read_member(self, key, *seq, c);
        }
        book.by_coll = by_coll;
        let under: Vec<&Name> = self
            .colls
            .keys()
            .filter(|x| in_folder(x, &book.folder))
            .collect();
        for x in under {
            book.read_folder_coll(self, &key.0, x);
        }
        Some(book)
    }

    /// Member `seq` of group `key`, in `c`, as its book reads it (`seals`:
    /// the seals the book holds, shared).
    fn member_facts(
        &self,
        key: &(Writer, u64),
        seq: u64,
        c: &Name,
        seals: &HashMap<Arc<SealKey>, usize>,
    ) -> Facts {
        let id = VersionId {
            writer: key.0.clone(),
            seq: Seq(seq),
        };
        let state = self.member_state(c, &id);
        let coll = self.colls.get(c);
        let ready = state == MemberState::Waiting
            && coll.is_some_and(|k| {
                k.versions
                    .get(&id)
                    .is_some_and(|hv| ready(&k.waits(c), &k.applied, &hv.version))
            });
        let seal = self.sealing(c, &id).map(|(seal, epoch)| {
            let readers = epoch
                .as_ref()
                .map(|e| self.epoch_readers(c, e))
                .unwrap_or_default();
            let s = SealKey {
                seal,
                epoch,
                readers,
            };
            match seals.get_key_value(&s) {
                Some((k, _)) => Arc::clone(k),
                None => Arc::new(s),
            }
        });
        let here = coll.is_some_and(|k| {
            k.members.is_some()
                && k.txns.contains(key)
                && (k.pending.contains(&id)
                    || k.locked
                        .iter()
                        .any(|l| l.writer == id.writer && l.seq == seq))
        });
        Facts {
            coll: c.clone(),
            state,
            ready,
            seal,
            here,
            applied: coll.is_some_and(|k| k.applied_member(&id)),
            not_counted: coll.is_some_and(|k| k.not_counted.contains_key(&id)),
            parked: coll.is_some_and(|k| k.parked.contains_key(&id)),
            judged: coll.is_some_and(|k| k.txns.contains(key)),
        }
    }

    /// The verdict on group `key` (spec §5.5): from its book where that
    /// proves it ([`Book::verdict`]), else read member by member
    /// ([`Self::full_verdict`]).
    pub(super) fn verdict(&self, key: &(Writer, u64)) -> GroupVerdict {
        let quick = self.book(key).and_then(|b| b.verdict());
        #[cfg(all(test, debug_assertions))]
        if let Some(q) = &quick {
            assert_eq!(*q, self.full_verdict(key), "the book's verdict on {key:?}");
        }
        match quick {
            Some(v) => v,
            None => self.full_verdict(key),
        }
    }

    /// What `verdict`, group `key`'s, makes of its members, from its book
    /// ([`Self::judge_members`]): whether the group is settled, and the
    /// collections of the members it moves, in seq order. `None` when a
    /// member is to be read again ([`Self::reread`]): judged member by
    /// member.
    pub(super) fn quick_moves(
        &self,
        key: &(Writer, u64),
        verdict: &GroupVerdict,
    ) -> Option<(bool, Vec<Name>)> {
        if matches!(verdict, GroupVerdict::Refused { .. }) {
            return None;
        }
        let book = self.book(key)?;
        let t = &book.tally;
        if t.group_refused > 0 {
            return None;
        }
        let settled = t.waiting + t.unreadable + t.missing == 0;
        let mut moves = Vec::new();
        match verdict {
            // Only the next member goes; every other waits untold.
            GroupVerdict::Complete { next } => {
                if let Some(f) = next.and_then(|s| book.facts.get(&s))
                    && f.here
                    && f.state == MemberState::Waiting
                {
                    moves.push(f.coll.clone());
                }
            }
            _ => {
                for s in &book.here {
                    let f = &book.facts[s];
                    let id = VersionId {
                        writer: key.0.clone(),
                        seq: Seq(*s),
                    };
                    let told = self.colls.get(&f.coll).and_then(|k| k.group_waits.get(&id));
                    let go = match verdict.gate(*s) {
                        Gate::Go | Gate::Stop(_) => f.state == MemberState::Waiting,
                        Gate::Wait(Some(why)) => told != Some(&why),
                        Gate::Wait(None) => false,
                    };
                    if go {
                        moves.push(f.coll.clone());
                    }
                }
            }
        }
        Some((settled, moves))
    }

    /// Whether group `key`'s book knows none of its members parked.
    pub(super) fn none_parked(&self, key: &(Writer, u64)) -> bool {
        self.book(key).is_some_and(|b| b.tally.parked == 0)
    }

    /// Have group `key` judged again ([`Self::regroup_under`],
    /// [`Self::regroup_seq`]): every member's collection judges it on its
    /// applications ([`Coll::txns`]) — from the book, only those that no
    /// longer do are told — and the first member's collection applies now.
    pub(super) fn rejudge(&mut self, key: &(Writer, u64)) {
        let (untold, first) = match self.book(key) {
            Some(b) => {
                let untold: Vec<Name> =
                    b.unjudged.iter().map(|s| b.facts[s].coll.clone()).collect();
                (untold, b.facts.values().next().map(|f| f.coll.clone()))
            }
            None => {
                let colls: Vec<Name> = self
                    .group_members(key, None)
                    .into_iter()
                    .map(|(_, c)| c)
                    .collect();
                let first = colls.first().cloned();
                (colls, first)
            }
        };
        for c in untold {
            self.colls.entry(c).or_default().txns.insert(key.clone());
        }
        if let Some(c) = first {
            self.apply_ready(&c, &BTreeSet::new());
        }
    }

    /// The members of group `key` [`Self::regroup`] is to bring in line
    /// with `blocker`, by seq — `None`: every member — and the blocker: the
    /// first member, in seq order, applied and not counted by its rule.
    /// From the book: only the members read again since it last told the
    /// group, while the blocker stays the one it told every member by.
    pub(super) fn regroup_plan(&self, key: &(Writer, u64)) -> (Option<String>, Option<Vec<u64>>) {
        let blocker_of = |id: &VersionId, c: &Name| {
            let coll = self.colls.get(c)?;
            let why = coll.not_counted.get(id)?;
            coll.applied_member(id)
                .then(|| format!("group waiting on {}: {why}", coll.versions[id].version.name))
        };
        let Some(mut book) = self.book(key) else {
            let blocker = self.txns.get(key).and_then(|m| {
                m.iter().find_map(|(s, ms)| {
                    let id = VersionId {
                        writer: key.0.clone(),
                        seq: Seq(*s),
                    };
                    ms.iter().find_map(|m| blocker_of(&id, &m.collection))
                })
            });
            return (blocker, None);
        };
        let blocker = book.applied_nc.first().and_then(|s| {
            let id = VersionId {
                writer: key.0.clone(),
                seq: Seq(*s),
            };
            blocker_of(&id, &book.facts[s].coll)
        });
        let only = match &book.told {
            Some(told) if *told == blocker => {
                Some(std::mem::take(&mut book.moved).into_iter().collect())
            }
            _ => None,
        };
        book.moved.clear();
        book.told = Some(blocker.clone());
        (blocker, only)
    }
}
