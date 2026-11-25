//! What waits to be written (docs/specs/channel.md, Batching): the coalescing set of `Latest` and
//! the FIFO of `Reliable` and `Window`.
//!
//! Both hold [`Pending`] messages that already took their sequence (the sequence is taken when the
//! message is emitted, so the order of the queue is the order of the sequences and a message that is
//! dropped leaves a gap a receiver can see). Both are only touched under the channel's lock, so
//! neither synchronises. A message **stays** in its queue until the frame that carries it was
//! handed to the carrier (the writer packs from the front without removing, then commits): a
//! frame the carrier refused loses nothing, and a message that was replaced while the frame was
//! sealed is not sent twice.

use std::collections::VecDeque;

use bytes::Bytes;

use super::message::{Origin, OutMessage};
use crate::rt::Instant;

/// A message that took its sequence and waits to be written.
#[derive(Clone, Debug)]
pub(crate) struct Pending {
    /// The sequence the message took when it was emitted (the original one for a replay: a replay
    /// takes a new one, see `origin`).
    pub(crate) seq: u64,
    /// The name id.
    pub(crate) id: u64,
    /// The name's octets (a replay and the window's history need them whether or not this message
    /// carries them).
    pub(crate) name: Bytes,
    /// Whether the message carries the name inline.
    pub(crate) named: bool,
    /// Seconds the emission stands for, as the message says.
    pub(crate) stand: Option<u64>,
    /// Set for a replay: the original sequence.
    pub(crate) origin: Option<Origin>,
    /// The payload.
    pub(crate) payload: Bytes,
    /// Whether the message was already packed once into a frame the path's size fell under.
    pub(crate) repacked: bool,
    /// When the message was emitted (what the window's age counts from).
    pub(crate) at: Instant,
    /// Whether the message is in a frame being written (set by the writer, under the lock).
    pub(crate) inflight: bool,
}

impl Pending {
    /// The message as the writer appends it.
    pub(crate) fn out(&self) -> OutMessage<'_> {
        OutMessage {
            name_id: self.id,
            name: self.named.then_some(&self.name[..]),
            stand_secs: self.stand,
            origin: self.origin,
            payload: &self.payload,
        }
    }
}

/// `Latest`: one slot per name id, in the order of the sequences.
#[derive(Default)]
pub(crate) struct LatestSet {
    /// Index = name id.
    slots: Vec<Option<Pending>>,
    /// `(sequence, id)` in the order of the sequences; an entry whose slot holds another sequence
    /// is a tombstone (the message was replaced, taken or moved).
    order: VecDeque<(u64, u32)>,
    live: usize,
    bytes: usize,
}

impl LatestSet {
    /// How many names have a message waiting.
    pub(crate) fn len(&self) -> usize {
        self.live
    }

    /// Whether nothing waits.
    pub(crate) fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Payload octets waiting.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    fn is_live(&self, seq: u64, id: u32) -> bool {
        self.slots
            .get(id as usize)
            .and_then(|s| s.as_ref())
            .is_some_and(|p| p.seq == seq)
    }

    /// Put `message` in its name's slot. Returns the message it replaced, which is never sent.
    pub(crate) fn put(&mut self, message: Pending) -> Option<Pending> {
        let id = message.id as usize;
        if self.slots.len() <= id {
            self.slots.resize_with(id + 1, || None);
        }
        let entry = (message.seq, message.id as u32);
        match self.order.back() {
            Some(&(tail, _)) if tail > entry.0 => {
                let at = self.order.partition_point(|&(s, _)| s < entry.0);
                self.order.insert(at, entry);
            }
            _ => self.order.push_back(entry),
        }
        self.bytes += message.payload.len();
        let old = self.slots[id].replace(message);
        match &old {
            Some(old) => self.bytes -= old.payload.len(),
            None => self.live += 1,
        }
        if self.order.len() > 2 * self.live + 64 {
            let slots = &self.slots;
            self.order.retain(|&(seq, id)| {
                slots
                    .get(id as usize)
                    .and_then(|s| s.as_ref())
                    .is_some_and(|p| p.seq == seq)
            });
        }
        old
    }

    /// The message of name `id`, taken out.
    pub(crate) fn take(&mut self, id: u64) -> Option<Pending> {
        let old = self.slots.get_mut(id as usize)?.take()?;
        self.live -= 1;
        self.bytes -= old.payload.len();
        Some(old)
    }

    /// The message of name `id` and sequence `seq` was written: take it out, unless a newer one
    /// replaced it meanwhile (that one waits). Returns whether it was taken.
    pub(crate) fn commit(&mut self, id: u64, seq: u64) -> bool {
        if self.is_live(seq, id as u32) {
            self.take(id);
            true
        } else {
            false
        }
    }

    /// The message of name `id` if it holds sequence `seq` (not a newer one), taken out and no
    /// longer in a frame being written.
    pub(crate) fn take_if(&mut self, id: u64, seq: u64) -> Option<Pending> {
        if !self.is_live(seq, id as u32) {
            return None;
        }
        let mut p = self.take(id)?;
        p.inflight = false;
        Some(p)
    }

    /// Give the message of name `id` and sequence `old` the sequence `new` (a re-pack takes new
    /// sequences) and mark it repacked. Returns whether it was still waiting under `old`.
    pub(crate) fn resequence(&mut self, id: u64, old: u64, new: u64) -> bool {
        if !self.is_live(old, id as u32) {
            return false;
        }
        if let Some(p) = self.slots[id as usize].as_mut() {
            p.seq = new;
            p.repacked = true;
            p.inflight = false;
        }
        self.order.push_back((new, id as u32));
        true
    }

    /// The waiting messages, oldest sequence first.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Pending> + '_ {
        self.order.iter().filter_map(|&(seq, id)| {
            self.slots
                .get(id as usize)
                .and_then(|s| s.as_ref())
                .filter(|p| p.seq == seq)
        })
    }

    /// Forget the tombstones at the front.
    pub(crate) fn prune_front(&mut self) {
        while let Some(&(seq, id)) = self.order.front() {
            if self.is_live(seq, id) {
                break;
            }
            self.order.pop_front();
        }
    }

    /// The oldest waiting message that is not in a frame being written, taken out: what a full
    /// queue drops.
    pub(crate) fn pop_oldest(&mut self) -> Option<Pending> {
        self.prune_front();
        let slots = &self.slots;
        let at = self.order.iter().position(|&(seq, id)| {
            slots
                .get(id as usize)
                .and_then(|s| s.as_ref())
                .is_some_and(|p| p.seq == seq && !p.inflight)
        })?;
        let (_, id) = self.order.remove(at)?;
        self.take(u64::from(id))
    }

    /// The messages `(id, sequence)` are in a frame being written: a full queue does not drop
    /// them, and one a newer message replaces is not counted replaced (it is sent).
    pub(crate) fn mark_inflight(&mut self, sent: &[(u64, u64)]) {
        for &(id, seq) in sent {
            if let Some(Some(p)) = self.slots.get_mut(id as usize)
                && p.seq == seq
            {
                p.inflight = true;
            }
        }
    }

    /// The frame was not written: its messages are waiting again. Returns how many of them a
    /// newer message replaced meanwhile (those are not sent, and nothing else will count them).
    pub(crate) fn unmark_inflight(&mut self, sent: &[(u64, u64)]) -> usize {
        let mut replaced = 0;
        for &(id, seq) in sent {
            match self.slots.get_mut(id as usize) {
                Some(Some(p)) if p.seq == seq => p.inflight = false,
                _ => replaced += 1,
            }
        }
        replaced
    }

    /// Every waiting message, taken out, oldest first.
    pub(crate) fn drain_all(&mut self) -> Vec<Pending> {
        let mut out = Vec::with_capacity(self.live);
        loop {
            self.prune_front();
            let Some((_, id)) = self.order.pop_front() else {
                break;
            };
            if let Some(p) = self.take(u64::from(id)) {
                out.push(p);
            }
        }
        out
    }
}

/// What the stream carries: data, and the control frames (which take a sequence each).
#[derive(Clone, Debug)]
pub(crate) enum Item {
    /// A message.
    Data(Pending),
    /// A `CONTROL` frame: its sequence and its record.
    Control {
        /// The frame's sequence.
        seq: u64,
        /// The encoded record.
        body: Bytes,
    },
}

impl Item {
    /// The sequence the item took.
    #[cfg(test)]
    pub(crate) fn seq(&self) -> u64 {
        match self {
            Item::Data(p) => p.seq,
            Item::Control { seq, .. } => *seq,
        }
    }
}

/// The FIFO of the stream: items in the order of their sequences.
#[derive(Default)]
pub(crate) struct Fifo {
    items: VecDeque<Item>,
    data_bytes: usize,
    /// The first this many items are in a frame being written.
    inflight: usize,
}

impl Fifo {
    /// Items waiting, written ones excluded once committed.
    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether nothing waits.
    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Payload octets of the data waiting, those in a frame being written included: what
    /// `queue_bytes` bounds.
    pub(crate) fn data_bytes(&self) -> usize {
        self.data_bytes
    }

    /// Payload octets of the data that a full queue may drop: all but a frame being written.
    pub(crate) fn evictable_bytes(&self) -> usize {
        self.items
            .iter()
            .skip(self.inflight)
            .map(|item| match item {
                Item::Data(p) => p.payload.len(),
                Item::Control { .. } => 0,
            })
            .sum()
    }

    /// Append at the end.
    pub(crate) fn push(&mut self, item: Item) {
        if let Item::Data(p) = &item {
            self.data_bytes += p.payload.len();
        }
        self.items.push_back(item);
    }

    /// The items in order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Item> + '_ {
        self.items.iter()
    }

    /// The first `n` items are in a frame being written: they are not dropped.
    pub(crate) fn mark_inflight(&mut self, n: usize) {
        self.inflight = n.min(self.items.len());
    }

    /// The frame was written: remove its `inflight` items, handing each to `each`.
    pub(crate) fn finish(&mut self, mut each: impl FnMut(Item)) {
        for _ in 0..self.inflight {
            if let Some(item) = self.items.pop_front() {
                if let Item::Data(p) = &item {
                    self.data_bytes -= p.payload.len();
                }
                each(item);
            }
        }
        self.inflight = 0;
    }

    /// The frame being written was not: its items stay.
    pub(crate) fn unmark(&mut self) {
        self.inflight = 0;
    }

    /// Drop the oldest data message that is not in a frame being written (control frames are
    /// never dropped). `None` when there is none.
    pub(crate) fn evict_oldest_data(&mut self) -> Option<Pending> {
        let at = self
            .items
            .iter()
            .enumerate()
            .skip(self.inflight)
            .find_map(|(i, item)| matches!(item, Item::Data(_)).then_some(i))?;
        match self.items.remove(at) {
            Some(Item::Data(p)) => {
                self.data_bytes -= p.payload.len();
                Some(p)
            }
            _ => None,
        }
    }

    /// Everything, taken out (the channel is gone or the carrier closed).
    pub(crate) fn drain_all(&mut self) -> Vec<Item> {
        self.inflight = 0;
        self.data_bytes = 0;
        self.items.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(seq: u64, id: u64, payload: &'static [u8]) -> Pending {
        Pending {
            seq,
            id,
            name: Bytes::new(),
            named: false,
            stand: None,
            origin: None,
            payload: Bytes::from_static(payload),
            repacked: false,
            at: Instant::now(),
            inflight: false,
        }
    }

    fn seqs(set: &LatestSet) -> Vec<u64> {
        set.iter().map(|p| p.seq).collect()
    }

    #[test]
    fn a_newer_message_replaces_an_unsent_older_one_of_its_name_and_moves_to_the_back() {
        let mut set = LatestSet::default();
        assert!(set.put(msg(1, 1, b"a1")).is_none());
        assert!(set.put(msg(2, 2, b"b1")).is_none());
        assert!(set.put(msg(3, 3, b"c1")).is_none());
        let old = set.put(msg(4, 2, b"b2")).expect("b1 was replaced");
        assert_eq!(old.seq, 2);
        assert_eq!(seqs(&set), [1, 3, 4], "the replaced sequence is never sent");
        assert_eq!(set.len(), 3);
        assert_eq!(set.bytes(), 6);
    }

    #[test]
    fn a_commit_takes_what_was_sent_and_leaves_a_message_that_replaced_it_meanwhile() {
        let mut set = LatestSet::default();
        set.put(msg(1, 1, b"a1"));
        set.put(msg(2, 2, b"b1"));
        // The frame carrying a1 and b1 is being sealed; b2 arrives.
        set.put(msg(3, 2, b"b2"));
        assert!(set.commit(1, 1));
        assert!(!set.commit(2, 2), "b1 was replaced: b2 still waits");
        assert_eq!(seqs(&set), [3]);
        assert!(set.commit(2, 3));
        assert!(set.is_empty());
        assert_eq!(set.bytes(), 0);
    }

    #[test]
    fn replacements_do_not_grow_the_order_without_bound() {
        let mut set = LatestSet::default();
        for seq in 1..=10_000u64 {
            set.put(msg(seq, 1 + seq % 3, b"x"));
        }
        assert_eq!(set.len(), 3);
        assert!(set.order.len() <= 2 * 3 + 64 + 1, "{}", set.order.len());
        assert_eq!(seqs(&set), [9_998, 9_999, 10_000]);
    }

    #[test]
    fn a_resequenced_message_goes_to_the_back_under_its_new_sequence() {
        let mut set = LatestSet::default();
        set.put(msg(1, 1, b"a"));
        set.put(msg(2, 2, b"b"));
        assert!(set.resequence(1, 1, 3));
        assert!(!set.resequence(1, 1, 4), "it holds 3 now");
        assert_eq!(seqs(&set), [2, 3]);
        assert!(set.iter().find(|p| p.id == 1).unwrap().repacked);
        // One a newer emission replaced is not resequenced.
        set.put(msg(4, 2, b"b2"));
        assert!(!set.resequence(2, 2, 5));
    }

    #[test]
    fn a_message_moved_in_from_another_set_keeps_the_order_of_the_sequences() {
        let mut set = LatestSet::default();
        set.put(msg(5, 1, b"a"));
        set.put(msg(3, 2, b"b"));
        assert_eq!(seqs(&set), [3, 5]);
    }

    #[test]
    fn the_oldest_is_dropped_first_and_drain_empties_in_order() {
        let mut set = LatestSet::default();
        set.put(msg(1, 1, b"a"));
        set.put(msg(2, 2, b"b"));
        set.put(msg(3, 1, b"a2"));
        assert_eq!(set.pop_oldest().unwrap().seq, 2);
        let rest: Vec<u64> = set.drain_all().iter().map(|p| p.seq).collect();
        assert_eq!(rest, [3]);
        assert!(set.pop_oldest().is_none());
    }

    #[test]
    fn the_fifo_never_drops_a_control_frame_or_a_message_in_a_frame_being_written() {
        let mut fifo = Fifo::default();
        fifo.push(Item::Data(msg(1, 1, b"aa")));
        fifo.push(Item::Control {
            seq: 2,
            body: Bytes::from_static(b"\x04"),
        });
        fifo.push(Item::Data(msg(3, 1, b"bb")));
        fifo.push(Item::Data(msg(4, 1, b"cc")));
        assert_eq!(fifo.data_bytes(), 6);
        fifo.mark_inflight(1);
        assert_eq!(
            fifo.evict_oldest_data().unwrap().seq,
            3,
            "1 is in flight, 2 is control"
        );
        assert_eq!(fifo.data_bytes(), 4);
        let mut done = Vec::new();
        fifo.finish(|item| done.push(item.seq()));
        assert_eq!(done, [1]);
        assert_eq!(fifo.data_bytes(), 2);
        assert_eq!(fifo.evict_oldest_data().unwrap().seq, 4);
        assert!(
            fifo.evict_oldest_data().is_none(),
            "only the control frame is left"
        );
        assert_eq!(fifo.len(), 1);
    }
}
