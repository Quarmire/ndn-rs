//! The receiver's name-id table of one channel (docs/specs/channel.md, The name table at the
//! receiver): id → name, filled by the session's table, by `BIND` control frames on the stream and
//! by `NAMED` messages, emptied by `UNBIND`; and the **hold** of a message whose bare id is not
//! bound yet.
//!
//! **A datagram can overtake the stream.** A bare id the table does not know may be a message that
//! passed its `BIND`. It is held for [`HOLD`] (50 ms) and delivered when the bind arrives inside
//! that time; otherwise it is dropped and counted (`unknown_name`). At most [`HELD_MAX`] (64) are
//! held per channel: a message that finds the hold full is dropped at once, so a flood of unknown
//! ids costs a bounded amount of memory. No timer task runs: the hold is swept by the next frame
//! of the channel, by a poll of an `Items`, and by the node's maintenance pass, and a bind that
//! arrives after the 50 ms drops what it finds held instead of delivering it, so what happens does
//! not depend on when the sweep ran.

use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;

use super::limits::NAMES_PER_CHANNEL;
use crate::rt::Instant;

/// How long a message with an unbound id is held.
pub(crate) const HOLD: Duration = Duration::from_millis(50);

/// The most messages held per channel.
pub(crate) const HELD_MAX: usize = 64;

/// A name bound to an id.
#[derive(Clone, Debug)]
pub(crate) struct Binding {
    /// The name.
    pub(crate) name: Name,
    /// The octets the name was bound from (the Name TLV's value), kept so a `NAMED` message that
    /// repeats them costs a comparison and no decode.
    octets: Bytes,
    /// How many names this id held before this one: tells two bindings of one id apart.
    pub(crate) bound: u32,
}

/// Why a bind was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BindError {
    /// An id outside 1 to 4,096.
    #[error("name id {id} is outside 1 to {NAMES_PER_CHANNEL}")]
    Id { id: u64 },
    /// Octets that are not a Name's components.
    #[error("the octets bound to name id {id} are not a Name")]
    NotAName { id: u64 },
}

#[derive(Default)]
struct Slot {
    binding: Option<Binding>,
    /// Bindings this id has had.
    binds: u32,
}

/// What [`Names::hold`] did with a message.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Held {
    /// Kept for [`HOLD`].
    Kept,
    /// The hold was full: dropped.
    Full,
}

struct Waiting<T> {
    id: u64,
    at: Instant,
    item: T,
}

/// The table and the hold of one channel. `T` is a held message.
pub(crate) struct Names<T> {
    slots: Vec<Slot>,
    held: VecDeque<Waiting<T>>,
}

impl<T> Default for Names<T> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            held: VecDeque::new(),
        }
    }
}

impl<T> Names<T> {
    /// The binding of `id`, if it has one.
    pub(crate) fn get(&self, id: u64) -> Option<&Binding> {
        let at = usize::try_from(id.checked_sub(1)?).ok()?;
        self.slots.get(at)?.binding.as_ref()
    }

    /// Bind `id` to the name whose octets are `octets`. Binding an id to the octets it already
    /// has changes nothing (and decodes nothing); another name replaces the old one and starts
    /// a new binding.
    pub(crate) fn bind(&mut self, id: u64, octets: &Bytes) -> Result<&Binding, BindError> {
        if !(1..=NAMES_PER_CHANNEL).contains(&id) {
            return Err(BindError::Id { id });
        }
        let at = (id - 1) as usize;
        if self.slots.len() <= at {
            self.slots.resize_with(at + 1, Slot::default);
        }
        let slot = &mut self.slots[at];
        let same = slot.binding.as_ref().is_some_and(|b| b.octets == *octets);
        if !same {
            let name = Name::decode(octets.clone()).map_err(|_| BindError::NotAName { id })?;
            slot.binds += 1;
            slot.binding = Some(Binding {
                name,
                octets: octets.clone(),
                bound: slot.binds,
            });
        }
        Ok(slot.binding.as_ref().expect("bound above"))
    }

    /// `id` names nothing now.
    pub(crate) fn unbind(&mut self, id: u64) {
        if let Some(slot) = id
            .checked_sub(1)
            .and_then(|at| usize::try_from(at).ok())
            .and_then(|at| self.slots.get_mut(at))
        {
            slot.binding = None;
        }
    }

    /// How many ids are bound.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.binding.is_some()).count()
    }

    /// Hold `item`, a message whose bare id `id` is not bound, from `now`.
    pub(crate) fn hold(&mut self, id: u64, item: T, now: Instant) -> Held {
        if self.held.len() >= HELD_MAX {
            return Held::Full;
        }
        self.held.push_back(Waiting { id, at: now, item });
        Held::Kept
    }

    /// `id` was just bound at `now`: the messages held for it that are still inside [`HOLD`], in
    /// the order they were held, and how many held for it were too old (dropped).
    pub(crate) fn release(&mut self, id: u64, now: Instant) -> (Vec<T>, usize) {
        if self.held.iter().all(|w| w.id != id) {
            return (Vec::new(), 0);
        }
        let mut ready = Vec::new();
        let mut late = 0;
        let mut keep = VecDeque::with_capacity(self.held.len());
        for w in self.held.drain(..) {
            if w.id != id {
                keep.push_back(w);
            } else if now.saturating_duration_since(w.at) < HOLD {
                ready.push(w.item);
            } else {
                late += 1;
            }
        }
        self.held = keep;
        (ready, late)
    }

    /// Drop the messages held for [`HOLD`] or longer at `now`; returns how many.
    pub(crate) fn sweep(&mut self, now: Instant) -> usize {
        let mut dropped = 0;
        // Held in arrival order, so the oldest is at the front.
        while self
            .held
            .front()
            .is_some_and(|w| now.saturating_duration_since(w.at) >= HOLD)
        {
            self.held.pop_front();
            dropped += 1;
        }
        dropped
    }

    /// Messages held now.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.held.len()
    }
}

/// Ranges of sequences already delivered: what a `Window` replay is checked against, so a
/// `REPLAYED` message whose original was delivered is not delivered twice.
///
/// At most [`SEEN_RANGES_MAX`] disjoint ranges; when a new one would pass the bound the two
/// lowest are joined, which counts the gap between them as delivered: a replay of a message that
/// is that old is dropped rather than risk a duplicate.
#[derive(Clone, Debug, Default)]
pub(crate) struct Seen {
    ranges: Vec<(u64, u64)>,
}

/// The most ranges [`Seen`] keeps.
pub(crate) const SEEN_RANGES_MAX: usize = 64;

impl Seen {
    /// Whether `seq` was delivered.
    pub(crate) fn contains(&self, seq: u64) -> bool {
        let at = self.ranges.partition_point(|&(_, hi)| hi < seq);
        self.ranges.get(at).is_some_and(|&(lo, _)| lo <= seq)
    }

    /// `seq` was delivered.
    pub(crate) fn insert(&mut self, seq: u64) {
        // The common case: the next sequence after the newest range.
        if let Some(last) = self.ranges.last_mut() {
            if last.1.checked_add(1) == Some(seq) {
                last.1 = seq;
                return;
            }
            if seq > last.1 {
                self.push(seq);
                return;
            }
        } else {
            self.ranges.push((seq, seq));
            return;
        }
        let at = self.ranges.partition_point(|&(_, hi)| hi < seq);
        if self.ranges.get(at).is_some_and(|&(lo, _)| lo <= seq) {
            return;
        }
        let joins_next = self
            .ranges
            .get(at)
            .is_some_and(|&(lo, _)| lo.checked_sub(1) == Some(seq));
        let joins_prev = at > 0 && self.ranges[at - 1].1.checked_add(1) == Some(seq);
        match (joins_prev, joins_next) {
            (true, true) => {
                self.ranges[at - 1].1 = self.ranges[at].1;
                self.ranges.remove(at);
            }
            (true, false) => self.ranges[at - 1].1 = seq,
            (false, true) => self.ranges[at].0 = seq,
            (false, false) => {
                self.ranges.insert(at, (seq, seq));
                self.bound();
            }
        }
    }

    fn push(&mut self, seq: u64) {
        self.ranges.push((seq, seq));
        self.bound();
    }

    fn bound(&mut self) {
        while self.ranges.len() > SEEN_RANGES_MAX {
            let second = self.ranges.remove(1);
            self.ranges[0].1 = second.1;
        }
    }

    /// How many ranges are kept.
    #[cfg(test)]
    pub(crate) fn ranges(&self) -> usize {
        self.ranges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn octets(text: &str) -> Bytes {
        // The components of /a/b as the Name TLV's value.
        let mut v = Vec::new();
        for part in text.split('/').filter(|p| !p.is_empty()) {
            v.push(0x08);
            v.push(part.len() as u8);
            v.extend_from_slice(part.as_bytes());
        }
        Bytes::from(v)
    }

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    #[test]
    fn an_id_is_bound_looked_up_unbound_and_rebound_as_another_binding() {
        let mut t: Names<()> = Names::default();
        assert!(t.get(1).is_none());
        let first = t.bind(1, &octets("a/b")).unwrap().clone();
        assert_eq!(first.name.to_string(), "/a/b");
        assert_eq!(first.bound, 1);
        // The same octets again: the same binding, nothing new.
        assert_eq!(t.bind(1, &octets("a/b")).unwrap().bound, 1);
        t.unbind(1);
        assert!(t.get(1).is_none());
        let second = t.bind(1, &octets("c")).unwrap();
        assert_eq!(
            second.bound, 2,
            "a name after an unbind is another binding of the id"
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn an_id_outside_the_table_and_a_bad_name_are_refused() {
        let mut t: Names<()> = Names::default();
        assert_eq!(
            t.bind(0, &octets("a")).unwrap_err(),
            BindError::Id { id: 0 }
        );
        assert_eq!(
            t.bind(4_097, &octets("a")).unwrap_err(),
            BindError::Id { id: 4_097 }
        );
        assert!(t.bind(4_096, &octets("a")).is_ok());
        assert!(matches!(
            t.bind(2, &Bytes::from_static(&[0x08, 0x05, b'x'])),
            Err(BindError::NotAName { id: 2 })
        ));
        assert!(t.get(2).is_none());
    }

    #[test]
    fn an_unknown_bare_id_is_held_50_ms_and_dropped() {
        let t0 = Instant::now();
        let mut t: Names<&str> = Names::default();
        assert_eq!(t.hold(7, "m", t0), Held::Kept);
        // 49 ms later the bind arrives: the message comes out.
        let (ready, late) = t.release(7, at(t0, 49));
        assert_eq!((ready, late), (vec!["m"], 0));
        assert_eq!(t.held(), 0);

        // Held again; the bind comes at 50 ms: too late, dropped and counted.
        t.hold(7, "n", t0);
        let (ready, late) = t.release(7, at(t0, 50));
        assert_eq!((ready.len(), late), (0, 1));
        assert_eq!(t.held(), 0);

        // Held again; nobody binds: the sweep at 50 ms drops it, at 49 ms it stays.
        t.hold(9, "o", t0);
        assert_eq!(t.sweep(at(t0, 49)), 0);
        assert_eq!(t.held(), 1);
        assert_eq!(t.sweep(at(t0, 50)), 1);
        assert_eq!(t.held(), 0);
    }

    #[test]
    fn at_most_64_are_held_and_the_65th_is_dropped_at_once() {
        let t0 = Instant::now();
        let mut t: Names<u32> = Names::default();
        for i in 0..HELD_MAX as u32 {
            assert_eq!(t.hold(1 + u64::from(i), i, t0), Held::Kept);
        }
        assert_eq!(t.hold(100, 100, t0), Held::Full);
        assert_eq!(t.held(), HELD_MAX);
        // A swept hold has room again.
        assert_eq!(t.sweep(at(t0, 60)), HELD_MAX);
        assert_eq!(t.hold(100, 100, at(t0, 60)), Held::Kept);
    }

    #[test]
    fn a_release_returns_only_the_messages_of_that_id_in_order() {
        let t0 = Instant::now();
        let mut t: Names<&str> = Names::default();
        t.hold(1, "a1", t0);
        t.hold(2, "b1", t0);
        t.hold(1, "a2", at(t0, 5));
        let (ready, late) = t.release(1, at(t0, 10));
        assert_eq!((ready, late), (vec!["a1", "a2"], 0));
        assert_eq!(t.held(), 1);
    }

    #[test]
    fn seen_remembers_delivered_sequences_and_joins_neighbours() {
        let mut s = Seen::default();
        for q in [5, 6, 7, 20, 21] {
            s.insert(q);
        }
        assert_eq!(s.ranges(), 2);
        for q in [5, 6, 7, 20, 21] {
            assert!(s.contains(q));
        }
        for q in [4, 8, 19, 22] {
            assert!(!s.contains(q));
        }
        // Filling the hole joins the ranges.
        for q in 8..20 {
            s.insert(q);
        }
        assert_eq!(s.ranges(), 1);
        assert!(s.contains(13));
    }

    #[test]
    fn seen_is_bounded_and_forgetting_counts_the_gap_as_delivered() {
        let mut s = Seen::default();
        for i in 0..(SEEN_RANGES_MAX as u64 * 2) {
            s.insert(i * 10);
        }
        assert!(s.ranges() <= SEEN_RANGES_MAX);
        // The oldest were joined: what lies between them counts as delivered, never the reverse.
        assert!(s.contains(0));
        assert!(
            s.contains(5),
            "a gap in the joined oldest range is counted delivered"
        );
        assert!(s.contains(SEEN_RANGES_MAX as u64 * 20 - 10));
        assert!(!s.contains(SEEN_RANGES_MAX as u64 * 20 - 5));
    }

    proptest! {
        #[test]
        fn seen_agrees_with_a_set_while_it_is_under_its_bound(
            seqs in prop::collection::vec(0u64..60, 0..80)
        ) {
            let mut s = Seen::default();
            let mut model = std::collections::BTreeSet::new();
            for q in seqs {
                s.insert(q);
                model.insert(q);
            }
            for q in 0..62 {
                prop_assert_eq!(s.contains(q), model.contains(&q), "seq {}", q);
            }
        }
    }
}
