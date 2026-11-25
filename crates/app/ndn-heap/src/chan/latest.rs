//! The coalescing queue of a `Latest` receiver (docs/specs/channel.md, The receiver's queues):
//! the newest message per (channel, name), a FIFO of the pairs that have one, at most
//! [`PAIRS_MAX`] pairs.
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
//! * A new pair when [`PAIRS_MAX`] pairs are queued evicts the **oldest queued** pair and counts it
//!   in [`Coalescing::take_missed`]: that is local overload, and the consumer is told it was
//!   behind (`Lagged`). Replacing a message of a pair is not counted: coalescing is the mode.

use std::collections::{HashMap, VecDeque};

/// The most pairs queued at once per `Items`.
pub(crate) const PAIRS_MAX: usize = 4_096;

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

struct Slot<T> {
    /// The newest sequence ever offered for the pair.
    seq: u64,
    /// The queued message, if it was not taken yet.
    item: Option<(u64, T)>,
}

/// The queue.
pub(crate) struct Coalescing<T> {
    slots: HashMap<Pair, Slot<T>>,
    /// The pairs with a queued message, oldest first. Each appears once.
    order: VecDeque<Pair>,
    max: usize,
    missed: u64,
}

impl<T> Coalescing<T> {
    /// An empty queue of at most `max` pairs.
    pub(crate) fn new(max: usize) -> Self {
        Self {
            slots: HashMap::new(),
            order: VecDeque::new(),
            max: max.max(1),
            missed: 0,
        }
    }

    /// Messages queued (one per pair).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether nothing is queued.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Offer `item`, the message of sequence `seq` of `pair`.
    pub(crate) fn offer(&mut self, pair: Pair, seq: u64, item: T) -> Offer {
        if let Some(slot) = self.slots.get_mut(&pair) {
            if seq <= slot.seq {
                return Offer::Stale;
            }
            slot.seq = seq;
            let replaced = slot.item.replace((seq, item)).is_some();
            if replaced {
                return Offer::Replaced;
            }
            self.make_room();
            self.order.push_back(pair);
            return Offer::Queued;
        }
        if self.slots.len() >= 2 * self.max {
            self.slots.retain(|_, s| s.item.is_some());
        }
        self.make_room();
        self.slots.insert(
            pair,
            Slot {
                seq,
                item: Some((seq, item)),
            },
        );
        self.order.push_back(pair);
        Offer::Queued
    }

    /// Evict the oldest queued pair when one more would pass the bound.
    fn make_room(&mut self) {
        while self.order.len() >= self.max {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(slot) = self.slots.get_mut(&oldest) {
                slot.item = None;
            }
            self.missed += 1;
        }
    }

    /// The oldest queued message and its sequence.
    pub(crate) fn take(&mut self) -> Option<(Pair, u64, T)> {
        let pair = self.order.pop_front()?;
        let (seq, item) = self
            .slots
            .get_mut(&pair)
            .and_then(|slot| slot.item.take())
            .expect("a pair in the order has a queued message");
        Some((pair, seq, item))
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

    #[test]
    fn a_newer_message_replaces_an_unsent_older_one_in_place() {
        let mut q = Coalescing::new(16);
        assert_eq!(q.offer(pair(1), 10, "a10"), Offer::Queued);
        assert_eq!(q.offer(pair(2), 11, "b11"), Offer::Queued);
        assert_eq!(q.offer(pair(1), 12, "a12"), Offer::Replaced);
        assert_eq!(q.len(), 2);
        assert_eq!(q.take().map(|(p, s, i)| (p.id, s, i)), Some((1, 12, "a12")));
        assert_eq!(q.take().map(|(p, s, i)| (p.id, s, i)), Some((2, 11, "b11")));
        assert!(q.take().is_none());
        assert_eq!(q.take_missed(), 0, "coalescing is not a loss");
    }

    #[test]
    fn an_older_or_repeated_sequence_is_stale_even_after_the_newer_was_taken() {
        let mut q = Coalescing::new(16);
        q.offer(pair(1), 20, "new");
        assert!(q.take().is_some());
        assert_eq!(q.offer(pair(1), 19, "old"), Offer::Stale);
        assert_eq!(q.offer(pair(1), 20, "again"), Offer::Stale);
        assert!(q.is_empty());
        assert_eq!(q.offer(pair(1), 21, "newer"), Offer::Queued);
    }

    #[test]
    fn another_binding_of_the_same_id_is_another_pair() {
        let mut q = Coalescing::new(16);
        let first = pair(5);
        let second = Pair { bound: 1, ..first };
        q.offer(first, 100, "old name");
        assert_eq!(q.offer(second, 3, "new name"), Offer::Queued);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn the_oldest_pair_is_evicted_and_counted_when_the_bound_is_passed() {
        let mut q = Coalescing::new(3);
        for id in 1..=3 {
            q.offer(pair(id), u64::from(id), id);
        }
        assert_eq!(q.offer(pair(4), 4, 4), Offer::Queued);
        assert_eq!(q.len(), 3);
        assert_eq!(q.take_missed(), 1);
        let ids: Vec<u32> = std::iter::from_fn(|| q.take())
            .map(|(p, _, _)| p.id)
            .collect();
        assert_eq!(ids, [2, 3, 4]);
        // The evicted pair's newest sequence is kept: an older message of it stays stale.
        assert_eq!(q.offer(pair(1), 1, 1), Offer::Stale);
        assert_eq!(q.offer(pair(1), 5, 5), Offer::Queued);
    }

    #[test]
    fn at_most_the_bound_is_ever_queued_and_memory_is_bounded() {
        let mut q = Coalescing::new(8);
        for id in 0..10_000u32 {
            q.offer(pair(id), u64::from(id) + 1, id);
            assert!(q.len() <= 8);
            assert!(q.slots.len() <= 2 * 8 + 1, "slots {}", q.slots.len());
        }
        assert_eq!(q.take_missed(), 10_000 - 8);
    }

    #[test]
    fn forgetting_a_channel_keeps_what_is_queued_and_drops_what_is_idle() {
        let mut q = Coalescing::new(8);
        q.offer(pair(1), 1, "first");
        assert_eq!(q.take().map(|(_, _, i)| i), Some("first"));
        q.offer(pair(2), 1, "second");
        q.forget_idle(1);
        assert_eq!(q.len(), 1, "what is queued is still to be read");
        // The idle pair's sequence is forgotten: a message of it is no longer stale.
        assert_eq!(q.offer(pair(1), 1, "again"), Offer::Queued);
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
            let mut q = Coalescing::new(PAIRS_MAX);
            let mut taken: HashMap<u32, Vec<u64>> = HashMap::new();
            let mut newest: HashMap<u32, u64> = HashMap::new();
            for (id, seq, take_now) in arrivals {
                q.offer(pair(id), seq, (id, seq));
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
