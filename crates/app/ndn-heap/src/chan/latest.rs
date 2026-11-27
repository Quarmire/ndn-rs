//! The coalescing queue of a `Latest` receiver (docs/specs/channel.md, The receiver's queues):
//! the newest message per (channel, name), a FIFO of the pairs that have one, at most
//! [`PAIRS_MAX`] pairs and [`LATEST_BYTES`] charged octets.
//!
//! * A newer message replaces a queued older one of its pair **in place** (its turn in the FIFO is
//!   the older message's turn): a slow consumer gets the newest value of each name and never a
//!   backlog, and one name that updates fast cannot push the others back.
//! * A message whose sequence is not above the newest sequence **ever offered** for its pair, queued
//!   or already taken, is [`Offer::Stale`]: an older sequence is never delivered after a newer
//!   one, and a repeated one is not delivered twice. The newest sequence of a pair is kept after
//!   the message is taken (a slot with no message); those slots are forgotten when there are twice
//!   [`PAIRS_MAX`] of them, so the memory is bounded and what is forgotten is a pair quiet for
//!   thousands of other pairs' messages.
//! * A new pair when [`PAIRS_MAX`] pairs are queued, or when the message would take the queue past
//!   [`LATEST_BYTES`] (each queued message is charged what it pins, plus a fixed entry cost), evicts the
//!   **oldest queued** pairs until it fits and counts each in [`Coalescing::take_missed`]: that is
//!   local overload, and the consumer is told it was behind (`Lagged`). Replacing a message of a
//!   pair is not counted: coalescing is the mode. A message larger than the byte bound is taken
//!   when the queue is otherwise empty.

#[cfg(test)]
use std::collections::HashMap;
use std::collections::VecDeque;

use super::FastMap;

/// The most pairs queued at once per `Items`.
pub(crate) const PAIRS_MAX: usize = 4_096;

/// The most octets queued at once per `Items`, as charged: 1 MiB, the bound of a `Reliable` or
/// `Window` queue.
pub(crate) const LATEST_BYTES: usize = 1 << 20;

/// What a queued message costs beyond what it pins (the bookkeeping of its pair).
const ENTRY_OVERHEAD: usize = 64;

/// A (channel, name) pair. `bound` tells apart two names that held one id one after the other (an
/// `UNBIND` and a new `BIND` of the id).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Pair {
    /// The channel (one sender's emissions in one mode).
    pub(crate) channel: u64,
    /// The name id.
    pub(crate) id: u32,
    /// How many times the id was bound before this binding.
    pub(crate) bound: u32,
}

/// What [`Coalescing::offer`] did with a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Offer {
    /// Queued as the pair's first message.
    Queued,
    /// Replaced an older queued message of the pair.
    Replaced,
    /// Not newer than what the pair already saw: dropped.
    Stale,
}

struct Queued<T> {
    /// Its sequence.
    seq: u64,
    /// What it is charged: the octets it pins plus [`ENTRY_OVERHEAD`].
    weight: usize,
    item: T,
}

struct Slot<T> {
    /// The newest sequence ever offered for the pair.
    seq: u64,
    /// The queued message, if it was not taken yet.
    item: Option<Queued<T>>,
}

/// The queue.
pub(crate) struct Coalescing<T> {
    slots: FastMap<Pair, Slot<T>>,
    /// The pairs with a queued message, oldest first. Each appears once.
    order: VecDeque<Pair>,
    max: usize,
    max_bytes: usize,
    /// What the queued messages are charged, in all.
    bytes: usize,
    missed: u64,
}

impl<T> Coalescing<T> {
    /// An empty queue of at most `max` pairs and `max_bytes` charged octets.
    pub(crate) fn new(max: usize, max_bytes: usize) -> Self {
        Self {
            slots: FastMap::default(),
            order: VecDeque::new(),
            max: max.max(1),
            max_bytes: max_bytes.max(1),
            bytes: 0,
            missed: 0,
        }
    }

    /// Messages queued (one per pair).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.order.len()
    }

    /// Octets charged for the messages queued.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether nothing is queued.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Offer `item`, the message of sequence `seq` of `pair`, which pins `pinned` octets.
    pub(crate) fn offer(&mut self, pair: Pair, seq: u64, pinned: usize, item: T) -> Offer {
        let weight = pinned.saturating_add(ENTRY_OVERHEAD);
        if let Some(slot) = self.slots.get_mut(&pair) {
            if seq <= slot.seq {
                return Offer::Stale;
            }
            slot.seq = seq;
            // Written where it stays: the newer message replaces the older in place, or fills the
            // empty slot, with no queued message built aside and moved in.
            if let Some(queued) = slot.item.as_mut() {
                let old = queued.weight;
                queued.seq = seq;
                queued.weight = weight;
                queued.item = item;
                self.bytes = self.bytes - old + weight;
                // The pair keeps its turn; what the newer message adds is made room for by
                // evicting others, never the pair itself.
                self.make_room_besides(pair);
                return Offer::Replaced;
            }
            slot.item = Some(Queued { seq, weight, item });
            self.make_room(weight);
            self.bytes += weight;
            self.order.push_back(pair);
            return Offer::Queued;
        }
        if self.slots.len() >= 2 * self.max {
            self.slots.retain(|_, s| s.item.is_some());
        }
        self.make_room(weight);
        self.bytes += weight;
        self.slots.insert(
            pair,
            Slot {
                seq,
                item: Some(Queued { seq, weight, item }),
            },
        );
        self.order.push_back(pair);
        Offer::Queued
    }

    /// Evict the oldest queued pairs while one more of `weight` would pass a bound and something
    /// is queued.
    fn make_room(&mut self, weight: usize) {
        while self.order.len() >= self.max || self.bytes + weight > self.max_bytes {
            if !self.evict_oldest(None) {
                break;
            }
        }
    }

    /// Evict the oldest queued pairs, never `keep`, while the bytes are over their bound.
    fn make_room_besides(&mut self, keep: Pair) {
        while self.bytes > self.max_bytes {
            if !self.evict_oldest(Some(keep)) {
                break;
            }
        }
    }

    /// Evict the oldest queued pair other than `keep`; false when there is none.
    fn evict_oldest(&mut self, keep: Option<Pair>) -> bool {
        let at = match keep {
            None => 0,
            Some(keep) => match self.order.iter().position(|p| *p != keep) {
                Some(at) => at,
                None => return false,
            },
        };
        let Some(oldest) = self.order.remove(at) else {
            return false;
        };
        if let Some(slot) = self.slots.get_mut(&oldest)
            && let Some(gone) = slot.item.take()
        {
            self.bytes -= gone.weight;
        }
        self.missed += 1;
        true
    }

    /// The oldest queued message and its sequence.
    #[inline(always)]
    pub(crate) fn take(&mut self) -> Option<(Pair, u64, T)> {
        let pair = self.order.pop_front()?;
        let queued = self
            .slots
            .get_mut(&pair)
            .and_then(|slot| slot.item.take())
            .expect("a pair in the order has a queued message");
        self.bytes -= queued.weight;
        Some((pair, queued.seq, queued.item))
    }

    /// Forget the newest sequences a channel's pairs saw, for the pairs with nothing queued (the
    /// session ended and its messages that were queued are still to be read).
    pub(crate) fn forget_idle(&mut self, channel: u64) {
        self.slots
            .retain(|pair, slot| pair.channel != channel || slot.item.is_some());
    }

    /// The messages evicted for want of room since the last call.
    pub(crate) fn take_missed(&mut self) -> u64 {
        std::mem::take(&mut self.missed)
    }

    /// The messages evicted since the last [`Self::take_missed`], without taking them.
    pub(crate) fn pending_missed(&self) -> u64 {
        self.missed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn pair(id: u32) -> Pair {
        Pair {
            channel: 1,
            id,
            bound: 0,
        }
    }

    /// A byte bound no test message reaches.
    const ROOMY: usize = 1 << 40;

    #[test]
    fn the_queue_is_bounded_by_charged_bytes_as_well_as_pairs() {
        // 1 KiB bound; each message pins 400 octets and is charged 464.
        let mut q = Coalescing::new(PAIRS_MAX, 1_024);
        assert_eq!(q.offer(pair(1), 1, 400, "a"), Offer::Queued);
        assert_eq!(q.offer(pair(2), 2, 400, "b"), Offer::Queued);
        assert_eq!(q.bytes(), 928);
        // The third would pass the bound: the oldest pair goes, counted.
        assert_eq!(q.offer(pair(3), 3, 400, "c"), Offer::Queued);
        assert_eq!(q.len(), 2);
        assert_eq!(q.bytes(), 928);
        assert_eq!(q.take_missed(), 1);
        assert_eq!(q.take().map(|(p, _, i)| (p.id, i)), Some((2, "b")));
        assert_eq!(q.take().map(|(p, _, i)| (p.id, i)), Some((3, "c")));
        assert_eq!(q.bytes(), 0, "what is taken is no longer charged");
    }

    #[test]
    fn a_message_over_the_byte_bound_is_taken_when_nothing_else_is_queued() {
        let mut q = Coalescing::new(PAIRS_MAX, 1_024);
        assert_eq!(q.offer(pair(1), 1, 100, "small"), Offer::Queued);
        assert_eq!(q.offer(pair(2), 2, 10_000, "big"), Offer::Queued);
        assert_eq!(q.len(), 1, "the small one made room");
        assert_eq!(q.take_missed(), 1);
        assert_eq!(q.take().map(|(_, _, i)| i), Some("big"));
    }

    #[test]
    fn a_replacement_that_grows_evicts_others_and_never_its_own_pair() {
        let mut q = Coalescing::new(PAIRS_MAX, 1_024);
        q.offer(pair(1), 1, 100, "a1");
        q.offer(pair(2), 2, 100, "b2");
        assert_eq!(q.offer(pair(1), 3, 850, "a3"), Offer::Replaced);
        assert_eq!(q.take_missed(), 1, "pair 2 was evicted for the larger a3");
        assert_eq!(q.len(), 1);
        assert_eq!(q.take().map(|(p, s, i)| (p.id, s, i)), Some((1, 3, "a3")));
    }

    #[test]
    fn many_tiny_pairs_with_a_big_weight_each_stay_inside_the_byte_bound() {
        let mut q = Coalescing::new(PAIRS_MAX, 1 << 20);
        for id in 0..10_000u32 {
            q.offer(pair(id), u64::from(id) + 1, 2_048, id);
            assert!(q.bytes() <= 1 << 20, "{} charged", q.bytes());
        }
        assert!(q.len() <= (1 << 20) / (2_048 + ENTRY_OVERHEAD));
    }

    #[test]
    fn a_newer_message_replaces_an_unsent_older_one_in_place() {
        let mut q = Coalescing::new(16, ROOMY);
        assert_eq!(q.offer(pair(1), 10, 0, "a10"), Offer::Queued);
        assert_eq!(q.offer(pair(2), 11, 0, "b11"), Offer::Queued);
        assert_eq!(q.offer(pair(1), 12, 0, "a12"), Offer::Replaced);
        assert_eq!(q.len(), 2);
        assert_eq!(q.take().map(|(p, s, i)| (p.id, s, i)), Some((1, 12, "a12")));
        assert_eq!(q.take().map(|(p, s, i)| (p.id, s, i)), Some((2, 11, "b11")));
        assert!(q.take().is_none());
        assert_eq!(q.take_missed(), 0, "coalescing is not a loss");
    }

    #[test]
    fn an_older_or_repeated_sequence_is_stale_even_after_the_newer_was_taken() {
        let mut q = Coalescing::new(16, ROOMY);
        q.offer(pair(1), 20, 0, "new");
        assert!(q.take().is_some());
        assert_eq!(q.offer(pair(1), 19, 0, "old"), Offer::Stale);
        assert_eq!(q.offer(pair(1), 20, 0, "again"), Offer::Stale);
        assert!(q.is_empty());
        assert_eq!(q.offer(pair(1), 21, 0, "newer"), Offer::Queued);
    }

    #[test]
    fn another_binding_of_the_same_id_is_another_pair() {
        let mut q = Coalescing::new(16, ROOMY);
        let first = pair(5);
        let second = Pair { bound: 1, ..first };
        q.offer(first, 100, 0, "old name");
        assert_eq!(q.offer(second, 3, 0, "new name"), Offer::Queued);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn the_oldest_pair_is_evicted_and_counted_when_the_bound_is_passed() {
        let mut q = Coalescing::new(3, ROOMY);
        for id in 1..=3 {
            q.offer(pair(id), u64::from(id), 0, id);
        }
        assert_eq!(q.offer(pair(4), 4, 0, 4), Offer::Queued);
        assert_eq!(q.len(), 3);
        assert_eq!(q.take_missed(), 1);
        let ids: Vec<u32> = std::iter::from_fn(|| q.take())
            .map(|(p, _, _)| p.id)
            .collect();
        assert_eq!(ids, [2, 3, 4]);
        // The evicted pair's newest sequence is kept: an older message of it stays stale.
        assert_eq!(q.offer(pair(1), 1, 0, 1), Offer::Stale);
        assert_eq!(q.offer(pair(1), 5, 0, 5), Offer::Queued);
    }

    #[test]
    fn at_most_the_bound_is_ever_queued_and_memory_is_bounded() {
        let mut q = Coalescing::new(8, ROOMY);
        for id in 0..10_000u32 {
            q.offer(pair(id), u64::from(id) + 1, 0, id);
            assert!(q.len() <= 8);
            assert!(q.slots.len() <= 2 * 8 + 1, "slots {}", q.slots.len());
        }
        assert_eq!(q.take_missed(), 10_000 - 8);
    }

    #[test]
    fn forgetting_a_channel_keeps_what_is_queued_and_drops_what_is_idle() {
        let mut q = Coalescing::new(8, ROOMY);
        q.offer(pair(1), 1, 0, "first");
        assert_eq!(q.take().map(|(_, _, i)| i), Some("first"));
        q.offer(pair(2), 1, 0, "second");
        q.forget_idle(1);
        assert_eq!(q.len(), 1, "what is queued is still to be read");
        // The idle pair's sequence is forgotten: a message of it is no longer stale.
        assert_eq!(q.offer(pair(1), 1, 0, "again"), Offer::Queued);
        assert_eq!(q.take().map(|(_, _, i)| i), Some("second"));
    }

    proptest! {
        /// Over every arrival order of messages of a few names, what is taken for a name never
        /// goes back in sequence, nothing is taken twice, and the newest message of each name that
        /// arrived is what the last take of that name returns.
        #[test]
        fn the_latest_queue_never_delivers_an_older_sequence_after_a_newer(
            arrivals in prop::collection::vec((1u32..5, 1u64..200, any::<bool>()), 1..300)
        ) {
            let mut q = Coalescing::new(PAIRS_MAX, ROOMY);
            let mut taken: HashMap<u32, Vec<u64>> = HashMap::new();
            let mut newest: HashMap<u32, u64> = HashMap::new();
            for (id, seq, take_now) in arrivals {
                q.offer(pair(id), seq, 0, (id, seq));
                let n = newest.entry(id).or_default();
                *n = (*n).max(seq);
                if take_now && let Some((p, s, (iid, iseq))) = q.take() {
                    prop_assert_eq!((p.id, s), (iid, iseq));
                    taken.entry(p.id).or_default().push(s);
                }
            }
            while let Some((p, s, _)) = q.take() {
                taken.entry(p.id).or_default().push(s);
            }
            for (id, seqs) in &taken {
                for w in seqs.windows(2) {
                    prop_assert!(w[0] < w[1], "name {} delivered {:?}", id, seqs);
                }
                prop_assert_eq!(seqs.last(), newest.get(id), "name {} ended on its newest", id);
            }
            prop_assert_eq!(q.take_missed(), 0);
        }
    }
}
