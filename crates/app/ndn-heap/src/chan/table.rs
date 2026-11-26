//! The sender's name-id table (docs/specs/channel.md, The name-id table): a channel carries every
//! path its sender emits in the space under the mode, and a message names its path by a small id.
//!
//! * Ids are allocated from 1, in order, at most [`NAMES_PER_CHANNEL`] live per channel.
//! * The sender says an id's name in a `BIND` on the stream, at once. A datagram can overtake the
//!   stream, so the first [`NAMED_FIRST`] messages under an id and every message within
//!   [`BIND_WINDOW`] of the bind carry the name themselves.
//! * At [`SWEEP_PERCENT`] of the table the ids not used for [`UNBIND_IDLE`] are freed (`UNBIND`),
//!   at most once a [`SWEEP_EVERY`]; at the limit a new name is refused.
//! * An id is reused only after every other free id was: the one reused was idle at least
//!   [`UNBIND_IDLE`] before it was freed, so no datagram that names it can still be in flight.
//!
//! The table is pure state: every operation takes the instant it happens at.

use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_tlv::TlvReader;

use super::limits::{NAME_MAX, NAMES_PER_CHANNEL};
use super::wire::TABLE_BINDS_MAX;
use crate::rt::Instant;

/// The first messages under a new id that carry the name inline: three.
pub(crate) const NAMED_FIRST: u8 = 3;

/// Every message this soon after a bind carries the name inline: 200 ms.
pub(crate) const BIND_WINDOW: Duration = Duration::from_millis(200);

/// An id not used for this long is freed when the table is nearly full: 60 s.
pub(crate) const UNBIND_IDLE: Duration = Duration::from_secs(60);

/// The share of the table (percent) at which idle ids are freed: 90.
pub(crate) const SWEEP_PERCENT: usize = 90;

/// The shortest time between two sweeps of a nearly full table: a sender that makes up new names
/// cannot make the sender scan the table for every one.
pub(crate) const SWEEP_EVERY: Duration = Duration::from_secs(1);

/// What the session's table (`S_TABLE`) may take of the octets of the binds, with the encoding of
/// each bind counted at its largest: the session record refuses a table over 4 KiB.
const SESSION_TABLE_OCTETS: usize = 4 * 1024;
const BIND_OVERHEAD: usize = 24;

/// The octets of a name: the Name TLV's value, as a message and a `BIND` carry it.
pub(crate) fn name_octets(name: &Name) -> Bytes {
    let tlv = name.encode_to_tlv();
    let mut reader = TlvReader::new(tlv);
    match reader.read_tlv() {
        Ok((_, value)) => value,
        Err(_) => Bytes::new(),
    }
}

/// The name is over [`NAME_MAX`] octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NameTooLong {
    pub(crate) len: usize,
}

/// The table holds [`NAMES_PER_CHANNEL`] live ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Full {
    /// How many names the channel would have with this one.
    pub(crate) would_be: usize,
}

struct Entry {
    name: Name,
    octets: Bytes,
    bound_at: Instant,
    /// Messages still to be sent with the name inline for being among the first.
    named_left: u8,
    last_used: Instant,
}

/// An id in use.
#[derive(Clone, Debug)]
pub(crate) struct Use {
    /// The id.
    pub(crate) id: u64,
    /// The name's octets.
    pub(crate) octets: Bytes,
    /// Whether this message carries the name inline.
    pub(crate) named: bool,
}

/// What a bind is: an id and its name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Bound {
    pub(crate) id: u64,
    pub(crate) name: Name,
    pub(crate) octets: Bytes,
}

/// The table.
#[derive(Default)]
pub(crate) struct Table {
    by_name: super::FastMap<Name, u64>,
    /// Index = id; slot 0 is never used.
    entries: Vec<Option<Entry>>,
    live: usize,
    /// Ids freed, oldest first.
    free: VecDeque<u64>,
    last_sweep: Option<Instant>,
    /// Hashes of a name made by this table (a test counts them).
    #[cfg(test)]
    lookups: std::sync::atomic::AtomicU64,
}

impl Table {
    /// How many ids are live.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.live
    }

    fn entry_mut(&mut self, id: u64) -> Option<&mut Entry> {
        self.entries.get_mut(id as usize)?.as_mut()
    }

    /// The id `name` is bound to: the table's one hash of a name.
    fn id_of(&self, name: &Name) -> Option<u64> {
        #[cfg(test)]
        self.lookups
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.by_name.get(name).copied()
    }

    /// How many times the table hashed a name (a test asks).
    #[cfg(test)]
    pub(crate) fn lookups(&self) -> u64 {
        self.lookups.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// What [`Self::touch`] would answer for `name` at `now`, changing nothing: the id, whether
    /// the message would carry the name, and the octets of the name.
    pub(crate) fn peek(&self, name: &Name, now: Instant) -> Option<(u64, bool, usize)> {
        let id = self.id_of(name)?;
        let entry = self.entries.get(id as usize)?.as_ref()?;
        let early = now.saturating_duration_since(entry.bound_at) < BIND_WINDOW;
        Some((id, entry.named_left > 0 || early, entry.octets.len()))
    }

    /// The id of `name` if it is bound, marked used at `now`, and whether this message carries the
    /// name.
    pub(crate) fn touch(&mut self, name: &Name, now: Instant) -> Option<Use> {
        let id = self.id_of(name)?;
        self.touch_id(id, now, true)
    }

    /// [`Self::touch`] for an id that was just read from [`Self::peek`] under the same lock.
    /// `keep_octets` false: the answer holds no reference to the name's octets (empty), for a
    /// message that will not read them.
    pub(crate) fn touch_id(&mut self, id: u64, now: Instant, keep_octets: bool) -> Option<Use> {
        let entry = self.entry_mut(id)?;
        entry.last_used = now;
        let early = now.saturating_duration_since(entry.bound_at) < BIND_WINDOW;
        let named = entry.named_left > 0 || early;
        entry.named_left = entry.named_left.saturating_sub(1);
        Some(Use {
            id,
            octets: if keep_octets {
                entry.octets.clone()
            } else {
                Bytes::new()
            },
            named,
        })
    }

    /// Free the ids not used for [`UNBIND_IDLE`], when the table is at [`SWEEP_PERCENT`] of its
    /// size and the last sweep was [`SWEEP_EVERY`] ago. Returns the ids freed, lowest first.
    pub(crate) fn sweep(&mut self, now: Instant) -> Vec<u64> {
        if self.live * 100 < NAMES_PER_CHANNEL as usize * SWEEP_PERCENT {
            return Vec::new();
        }
        if self
            .last_sweep
            .is_some_and(|at| now.saturating_duration_since(at) < SWEEP_EVERY)
        {
            return Vec::new();
        }
        self.last_sweep = Some(now);
        let idle: Vec<u64> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(id, e)| {
                let e = e.as_ref()?;
                (now.saturating_duration_since(e.last_used) >= UNBIND_IDLE).then_some(id as u64)
            })
            .collect();
        for &id in &idle {
            if let Some(entry) = self.entries[id as usize].take() {
                self.by_name.remove(&entry.name);
                self.live -= 1;
                self.free.push_back(id);
            }
        }
        idle
    }

    /// Bind `name` (whose octets are `octets`) to a new id. The first message under it carries the
    /// name. Refused when the name is over [`NAME_MAX`] octets or [`NAMES_PER_CHANNEL`] ids are
    /// live.
    pub(crate) fn bind(
        &mut self,
        name: &Name,
        octets: Bytes,
        now: Instant,
    ) -> Result<Result<Use, Full>, NameTooLong> {
        if octets.len() > NAME_MAX {
            return Err(NameTooLong { len: octets.len() });
        }
        if self.live >= NAMES_PER_CHANNEL as usize {
            return Ok(Err(Full {
                would_be: self.live + 1,
            }));
        }
        if self.entries.is_empty() {
            self.entries.push(None);
        }
        let fresh = self.entries.len() as u64;
        let id = if fresh <= NAMES_PER_CHANNEL {
            self.entries.push(None);
            fresh
        } else {
            self.free
                .pop_front()
                .expect("fewer live ids than the table holds leaves a free one")
        };
        self.entries[id as usize] = Some(Entry {
            name: name.clone(),
            octets: octets.clone(),
            bound_at: now,
            named_left: NAMED_FIRST - 1,
            last_used: now,
        });
        self.by_name.insert(name.clone(), id);
        self.live += 1;
        Ok(Ok(Use {
            id,
            octets,
            named: true,
        }))
    }

    /// The live binds, lowest id first.
    pub(crate) fn binds(&self) -> impl Iterator<Item = Bound> + '_ {
        self.entries.iter().enumerate().filter_map(|(id, e)| {
            let e = e.as_ref()?;
            Some(Bound {
                id: id as u64,
                name: e.name.clone(),
                octets: e.octets.clone(),
            })
        })
    }

    /// The live binds split as a session's table takes them: the first of them, lowest id first,
    /// up to [`TABLE_BINDS_MAX`] binds and 4 KiB; and the rest, which follow as `BIND` frames.
    pub(crate) fn split_for_session(&self) -> (Vec<Bound>, Vec<Bound>) {
        let (mut inside, mut rest) = (Vec::new(), Vec::new());
        let mut octets = 0;
        for bound in self.binds() {
            let cost = BIND_OVERHEAD + bound.octets.len();
            if rest.is_empty()
                && inside.len() < TABLE_BINDS_MAX
                && octets + cost <= SESSION_TABLE_OCTETS
            {
                octets += cost;
                inside.push(bound);
            } else {
                rest.push(bound);
            }
        }
        (inside, rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(i: usize) -> Name {
        Name::root().append(format!("n{i}"))
    }

    fn bound(t: &mut Table, i: usize, now: Instant) -> Use {
        let n = name(i);
        t.bind(&n, name_octets(&n), now).unwrap().unwrap()
    }

    #[test]
    fn touching_an_id_without_its_octets_answers_the_same_and_holds_no_reference_to_them() {
        let (mut t, now) = (Table::default(), Instant::now());
        let first = bound(&mut t, 0, now);
        let later = now + Duration::from_secs(5);
        let (id, _, _) = t.peek(&name(0), later).unwrap();
        let bare = t.touch_id(id, later, false).unwrap();
        assert_eq!(
            (bare.id, bare.named),
            (first.id, true),
            "the second of three named"
        );
        assert!(bare.octets.is_empty());
        let kept = t.touch_id(id, later, true).unwrap();
        assert_eq!(
            (kept.id, kept.named),
            (first.id, true),
            "the third of three named"
        );
        assert_eq!(kept.octets, first.octets);
        let after = t.touch_id(id, later, true).unwrap();
        assert!(
            !after.named,
            "the fourth, late: the flags do not depend on the octets"
        );
    }

    #[test]
    fn ids_are_allocated_from_one_in_order_and_a_name_keeps_its_id() {
        let (mut t, now) = (Table::default(), Instant::now());
        assert_eq!(bound(&mut t, 0, now).id, 1);
        assert_eq!(bound(&mut t, 1, now).id, 2);
        assert_eq!(bound(&mut t, 2, now).id, 3);
        assert_eq!(t.touch(&name(1), now).unwrap().id, 2);
        assert!(t.touch(&name(9), now).is_none());
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn the_first_three_messages_and_every_message_within_200_ms_of_the_bind_carry_the_name() {
        let (mut t, t0) = (Table::default(), Instant::now());
        let first = bound(&mut t, 0, t0);
        assert!(first.named, "the binding message");
        let later = t0 + Duration::from_secs(5);
        // The second and third message are the first three, whenever they come.
        assert!(t.touch(&name(0), later).unwrap().named);
        assert!(t.touch(&name(0), later).unwrap().named);
        assert!(!t.touch(&name(0), later).unwrap().named, "the fourth, late");
        // Within 200 ms of the bind every message is named.
        let (mut u, t0) = (Table::default(), Instant::now());
        bound(&mut u, 0, t0);
        for ms in [1, 50, 199] {
            for _ in 0..4 {
                assert!(
                    u.touch(&name(0), t0 + Duration::from_millis(ms))
                        .unwrap()
                        .named
                );
            }
        }
        assert!(
            !u.touch(&name(0), t0 + Duration::from_millis(200))
                .unwrap()
                .named
        );
    }

    #[test]
    fn a_table_of_4096_refuses_a_new_name_and_at_90_percent_frees_the_idle_ones() {
        let (mut t, t0) = (Table::default(), Instant::now());
        for i in 0..4096 {
            bound(&mut t, i, t0);
        }
        assert_eq!(t.len(), 4096);
        let n = name(5000);
        assert_eq!(
            t.bind(&n, name_octets(&n), t0).unwrap().unwrap_err(),
            Full { would_be: 4097 }
        );
        // Nothing is idle yet: no sweep frees anything, and the next sweep is not for a second.
        assert!(t.sweep(t0 + Duration::from_secs(30)).is_empty());
        // Keep the last 100 in use; after 60 s the rest are idle.
        let later = t0 + Duration::from_secs(61);
        for i in 3996..4096 {
            t.touch(&name(i), later - Duration::from_secs(1)).unwrap();
        }
        let freed = t.sweep(later);
        assert_eq!(freed.len(), 3996);
        assert_eq!(freed[0], 1);
        assert_eq!(t.len(), 100);
        assert!(
            t.touch(&name(0), later).is_none(),
            "an unbound name has no id"
        );
        // A swept table is under 90 %: a second sweep within a second is a no-op either way.
        assert!(t.sweep(later + Duration::from_millis(10)).is_empty());
        // Freed ids are reused only when no fresh id is left, oldest freed first.
        let again = bound(&mut t, 7000, later);
        assert_eq!(again.id, 1);
        assert_eq!(bound(&mut t, 7001, later).id, 2);
    }

    #[test]
    fn the_sweep_does_nothing_below_90_percent_of_the_table() {
        let (mut t, t0) = (Table::default(), Instant::now());
        for i in 0..3686 {
            bound(&mut t, i, t0);
        }
        assert!(t.sweep(t0 + Duration::from_secs(3600)).is_empty());
        bound(&mut t, 3686, t0);
        assert_eq!(
            t.sweep(t0 + Duration::from_secs(3600)).len(),
            3687,
            "90 % of 4096 is 3686.4: the 3687th id is the first sweep"
        );
    }

    #[test]
    fn a_name_over_255_octets_is_refused() {
        let mut t = Table::default();
        let long = Name::root().append(vec![b'x'; 300]);
        let octets = name_octets(&long);
        assert!(octets.len() > NAME_MAX);
        assert_eq!(
            t.bind(&long, octets, Instant::now()).unwrap_err(),
            NameTooLong { len: 304 }
        );
    }

    #[test]
    fn the_session_takes_at_most_64_binds_and_4_kib_and_the_rest_follow() {
        let (mut t, now) = (Table::default(), Instant::now());
        for i in 0..70 {
            bound(&mut t, i, now);
        }
        let (inside, rest) = t.split_for_session();
        assert_eq!(inside.len(), 64);
        assert_eq!(rest.len(), 6);
        assert_eq!(inside[0].id, 1);
        assert_eq!(rest[0].id, 65);
        // Long names fill the 4 KiB first.
        let mut u = Table::default();
        for i in 0..40 {
            let n = Name::root().append(format!("{i:02}{}", "x".repeat(200)));
            u.bind(&n, name_octets(&n), now).unwrap().unwrap();
        }
        let (inside, rest) = u.split_for_session();
        assert!(inside.len() < 40 && inside.len() + rest.len() == 40);
        let used: usize = inside.iter().map(|b| BIND_OVERHEAD + b.octets.len()).sum();
        assert!(used <= SESSION_TABLE_OCTETS);
    }
}
