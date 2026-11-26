//! The bounded FIFO of a `Reliable` or `Window` receiver (docs/specs/channel.md, The receiver's
//! queues): every message in the channel's order, at most `queue_bytes` queued, and a `Lagged`
//! entry in the place where messages are known to be missing.
//!
//! A queued message weighs what it pins plus [`ENTRY_OVERHEAD`] (the receiver passes the octets of
//! the frame a message shares, or its own payload when it was copied out of a large frame), so a
//! flood of empty messages, or of tiny ones in padded frames, is bounded too. What a full queue
//! does is the caller's policy (`Congestion`): [`Fifo::is_full`]
//! says it is, and the caller either stops taking frames from the stream (back pressure) or calls
//! [`Fifo::push_dropping_oldest`], which discards from the front and leaves a `Lagged` entry in
//! the place of what it discarded.

use std::collections::VecDeque;

/// What a queued message costs beyond its payload.
pub(crate) const ENTRY_OVERHEAD: usize = 64;

/// The default bound: 1 MiB.
pub(crate) const QUEUE_BYTES: usize = 1 << 20;

/// One place in the queue.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Entry<T> {
    /// A message.
    Item(T),
    /// That many messages are missing here.
    Lagged(u64),
}

struct Weighed<T> {
    entry: Entry<T>,
    weight: usize,
}

/// The queue.
pub(crate) struct Fifo<T> {
    queue: VecDeque<Weighed<T>>,
    bytes: usize,
    cap: usize,
}

impl<T> Fifo<T> {
    /// An empty queue holding at most `cap` bytes (see [`ENTRY_OVERHEAD`]).
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            bytes: 0,
            cap: cap.max(1),
        }
    }

    /// The weight of a message of `payload` octets.
    pub(crate) const fn weight(payload: usize) -> usize {
        payload.saturating_add(ENTRY_OVERHEAD)
    }

    /// Queued bytes.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Queued entries.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue is at or over its bound: a caller that applies back pressure takes no
    /// further frame while this holds. The bound can be passed by the one frame in hand when the
    /// last check was made, never by more.
    pub(crate) fn is_full(&self) -> bool {
        self.bytes >= self.cap
    }

    /// Queue a message of `payload` octets at the back, bound or not (the caller applies its
    /// policy first).
    pub(crate) fn push(&mut self, item: T, payload: usize) {
        let weight = Self::weight(payload);
        self.bytes += weight;
        self.queue.push_back(Weighed {
            entry: Entry::Item(item),
            weight,
        });
    }

    /// Queue a message of `payload` octets, first discarding messages from the front while the
    /// bound would be passed and something is queued. Returns how many messages were discarded;
    /// a `Lagged` entry for them stands at the front.
    pub(crate) fn push_dropping_oldest(&mut self, item: T, payload: usize) -> u64 {
        let weight = Self::weight(payload);
        let mut dropped = 0u64;
        while self.bytes + weight > self.cap {
            match self.pop_front_item() {
                Some(()) => dropped += 1,
                None => break,
            }
        }
        if dropped > 0 {
            self.lag_front(dropped);
        }
        self.push(item, payload);
        dropped
    }

    /// Discard the oldest message, skipping `Lagged` entries (they stay).
    fn pop_front_item(&mut self) -> Option<()> {
        let at = self
            .queue
            .iter()
            .position(|w| matches!(w.entry, Entry::Item(_)))?;
        let gone = self.queue.remove(at)?;
        self.bytes -= gone.weight;
        Some(())
    }

    /// `missed` messages are missing at the front: add them to a `Lagged` entry there, or make one.
    fn lag_front(&mut self, missed: u64) {
        if let Some(Weighed {
            entry: Entry::Lagged(n),
            ..
        }) = self.queue.front_mut()
        {
            *n += missed;
        } else {
            self.queue.push_front(Weighed {
                entry: Entry::Lagged(missed),
                weight: 0,
            });
        }
    }

    /// `missed` messages are missing at the back (a gap in the sequence): a `Lagged` entry joins
    /// a `Lagged` entry already at the back.
    pub(crate) fn lagged(&mut self, missed: u64) {
        if missed == 0 {
            return;
        }
        if let Some(Weighed {
            entry: Entry::Lagged(n),
            ..
        }) = self.queue.back_mut()
        {
            *n += missed;
        } else {
            self.queue.push_back(Weighed {
                entry: Entry::Lagged(missed),
                weight: 0,
            });
        }
    }

    /// The oldest entry.
    pub(crate) fn pop(&mut self) -> Option<Entry<T>> {
        let w = self.queue.pop_front()?;
        self.bytes -= w.weight;
        Some(w.entry)
    }

    /// The oldest entry, without taking it.
    pub(crate) fn front(&self) -> Option<&Entry<T>> {
        self.queue.front().map(|w| &w.entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: usize = ENTRY_OVERHEAD;

    #[test]
    fn messages_come_out_in_the_order_they_went_in_and_bytes_are_counted() {
        let mut q = Fifo::new(1_000);
        q.push("a", 10);
        q.push("b", 20);
        assert_eq!(q.bytes(), 30 + 2 * W);
        assert_eq!(q.pop(), Some(Entry::Item("a")));
        assert_eq!(q.bytes(), 20 + W);
        assert_eq!(q.pop(), Some(Entry::Item("b")));
        assert_eq!(q.bytes(), 0);
        assert!(q.pop().is_none());
    }

    #[test]
    fn the_queue_says_it_is_full_at_its_bound_and_not_before() {
        let mut q = Fifo::new(3 * W);
        q.push(1, 0);
        q.push(2, 0);
        assert!(!q.is_full());
        q.push(3, 0);
        assert!(q.is_full(), "back pressure starts at the bound");
        q.pop();
        assert!(!q.is_full());
    }

    #[test]
    fn dropping_the_oldest_keeps_the_bound_and_counts_what_it_dropped_in_place() {
        let mut q = Fifo::new(3 * W);
        q.push(1, 0);
        q.push(2, 0);
        q.push(3, 0);
        assert_eq!(q.push_dropping_oldest(4, 0), 1);
        assert!(q.bytes() <= 3 * W);
        assert_eq!(
            q.pop(),
            Some(Entry::Lagged(1)),
            "the gap stands where the dropped was"
        );
        assert_eq!(q.pop(), Some(Entry::Item(2)));
        assert_eq!(q.pop(), Some(Entry::Item(3)));
        assert_eq!(q.pop(), Some(Entry::Item(4)));
    }

    #[test]
    fn lagged_entries_merge_and_weigh_nothing() {
        let mut q: Fifo<u8> = Fifo::new(100);
        q.lagged(2);
        q.lagged(3);
        q.lagged(0);
        assert_eq!(q.len(), 1);
        assert_eq!(q.bytes(), 0);
        assert_eq!(q.pop(), Some(Entry::Lagged(5)));
    }

    #[test]
    fn one_message_larger_than_the_bound_is_taken_when_the_queue_is_empty() {
        let mut q = Fifo::new(100);
        assert_eq!(q.push_dropping_oldest("big", 10_000), 0);
        assert_eq!(q.pop(), Some(Entry::Item("big")));
    }

    #[test]
    fn drop_oldest_discards_enough_for_a_large_message() {
        let mut q = Fifo::new(10 * W);
        for i in 0..8 {
            q.push(i, 0);
        }
        // 4 * W of payload plus its own overhead needs 5 * W of room: 3 free, so 2 go.
        let dropped = q.push_dropping_oldest(100, 4 * W);
        assert_eq!(dropped, 3);
        assert!(q.bytes() <= 10 * W);
        assert_eq!(q.pop(), Some(Entry::Lagged(3)));
    }
}
