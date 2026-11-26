//! The receiver's memory of the frames it accepted, and what a verified checkpoint does to it
//! (docs/specs/channel.md, Checkpoints, The receiver).
//!
//! Per channel the receiver keeps a [`Verify`]: one **slot** per `seq0` it accepted a frame at
//! (at most [`SLOTS_MAX`] = 4,096, the replay window's own size), each holding the frame octets as
//! they came (`Bytes`, a copy: the AEAD opened the original in place) until a checkpoint judges
//! it, then only the hash and the signed checkpoint frame that vouched for it. The octets kept
//! are bounded per channel ([`CHANNEL_BYTES`], 2 MiB) and per node ([`NODE_BYTES`], 8 MiB, one
//! [`Budget`] shared by every channel); past either bound the frame with the lowest `seq0` is
//! forgotten and **counted** (`unchecked`): a frame nobody judges is not a mismatch.
//!
//! * **A frame at a seen sequence.** The replay window drops a second frame of one `seq0` before
//!   the AEAD, which would let a key holder's second frame go unnoticed. [`Verify::seen`] answers
//!   for it: byte-identical to an accepted frame (or hashing to a settled one) is a copy and is
//!   dropped for a comparison; one that differs gets **one AEAD attempt** (at most
//!   [`ATTEMPTS_PER_SEQ`] per sequence, so garbage cannot cost more) and, if it opens, is a
//!   **conflict** ([`Verify::conflict`]): the first accepted wins and is the only one delivered, the
//!   second is an event. Both stay in the slot, so the next checkpoint that covers the sequence says
//!   which of them is the sender's. At most [`EXTRA_MAX`] such second frames are kept per channel.
//! * **A verified checkpoint** ([`Verify::judge`]) settles every frame with `lo <= seq0 < hi` that
//!   it lists with the same hash, and returns as a **mismatch** every accepted frame in the range
//!   that it does not list (or lists with another hash). A listed frame this receiver does not hold
//!   is ignored (loss is not forgery). A frame below `lo` that was never judged is forgotten: ranges
//!   only rise, so no checkpoint will cover it.
//! * **Silence.** [`Verify::silence`]: a frame accepted since the last verified checkpoint that is
//!   older than `unchecked_max = max(4 x period, 100 ms)` is [`Silence::Hold`]; older than 3 s,
//!   [`Silence::End`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_transport::SideKind;

use super::checkpoint::Record;
use super::ring::{HASH_LEN, RING_FRAMES, frame_hash};
use crate::rt::Instant;

/// The most sequences a channel holds a slot for: the replay window's size.
pub(crate) const SLOTS_MAX: usize = RING_FRAMES;

/// The octets of accepted frames one channel keeps for checkpoints: 2 MiB.
pub(crate) const CHANNEL_BYTES: usize = 2 << 20;

/// The octets of accepted frames a node keeps for checkpoints across its channels: 8 MiB.
pub(crate) const NODE_BYTES: usize = 8 << 20;

/// The most second frames (frames at an already-accepted sequence) one channel keeps.
pub(crate) const EXTRA_MAX: usize = 64;

/// How many frames differing from the accepted one are opened per sequence: a flood of garbage
/// at a seen sequence costs this many attempts and then comparisons.
pub(crate) const ATTEMPTS_PER_SEQ: u8 = 3;

/// How long a frame may wait for a verified checkpoint before the session ends: 3 s.
pub(crate) const UNVERIFIED_MAX: Duration = Duration::from_secs(3);

/// The age past which an unchecked frame makes the receiver hold what follows: four periods,
/// at least 100 ms.
pub(crate) fn unchecked_max(period: Duration) -> Duration {
    (period * 4).max(Duration::from_millis(100))
}

/// The octets of accepted frames and held messages all the channels of a node keep, against
/// [`NODE_BYTES`].
#[derive(Debug, Default)]
pub(crate) struct Budget {
    used: AtomicUsize,
}

impl Budget {
    /// Charge `n` octets if the node stays within [`NODE_BYTES`].
    pub(crate) fn try_charge(&self, n: usize) -> bool {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(n).filter(|total| *total <= NODE_BYTES)
            })
            .is_ok()
    }

    /// Give `n` octets back.
    pub(crate) fn release(&self, n: usize) {
        self.used.fetch_sub(n, Ordering::AcqRel);
    }

    /// Octets charged now.
    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

/// A frame the receiver accepted: what a checkpoint judges and what evidence keeps.
#[derive(Clone, Debug)]
pub(crate) struct Accepted {
    /// The frame's octets as they came.
    pub(crate) frame: Bytes,
    /// The face it came over.
    pub(crate) ingress: u64,
    /// When it was accepted.
    pub(crate) at: Instant,
    /// The sequences it takes (`count`, or 1 for a `CONTROL` frame).
    pub(crate) sequences: u64,
    /// Its kind.
    pub(crate) kind: SideKind,
    /// The key epoch it was opened under (all 32 bits).
    pub(crate) epoch: u32,
    /// Whether it bound or unbound a name id (a `BIND` or `UNBIND` record, or a message that
    /// carries its own name): a frame a checkpoint contradicts that did is one the name table
    /// must not keep what it wrote.
    pub(crate) rebinds: bool,
}

#[derive(Debug)]
enum State {
    /// Not judged: the octets are kept.
    Pending(Bytes),
    /// A verified checkpoint listed it with this hash; `proof` is that checkpoint's frame.
    Settled { hash: [u8; HASH_LEN], proof: Bytes },
}

#[derive(Debug)]
struct Entry {
    state: State,
    ingress: u64,
    at: Instant,
    sequences: u64,
    kind: SideKind,
    epoch: u32,
    rebinds: bool,
}

impl Entry {
    fn octets(&self) -> usize {
        match &self.state {
            State::Pending(frame) => frame.len(),
            State::Settled { .. } => 0,
        }
    }
}

#[derive(Debug, Default)]
struct Slot {
    /// The frame accepted first, then any second frames that opened under the key.
    entries: Vec<Entry>,
    /// Frames unlike the accepted one that were opened for this sequence.
    attempts: u8,
}

/// What [`Verify::seen`] says of a frame at a sequence the replay window has marked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dup {
    /// The same octets as an accepted frame (or the hash of a settled one), or over the
    /// attempts allowed: a copy. Drop it.
    Same,
    /// Nothing is known of the sequence (it was forgotten): drop it as replayed.
    Unknown,
    /// Different octets than every frame accepted: open it once; if it authenticates it is a
    /// [`Verify::conflict`].
    Different,
}

/// What a second authentic frame at a seen sequence was set against.
#[derive(Clone, Debug)]
pub(crate) struct Conflict {
    /// The frame accepted first, if its octets are still kept (a settled one is only a hash).
    pub(crate) first: Option<Bytes>,
    /// The signed checkpoint frame that listed the frame accepted first, when one did: then the
    /// second frame is provably not the sender's.
    pub(crate) settled_by: Option<Bytes>,
}

/// An accepted frame a verified checkpoint contradicts.
#[derive(Clone, Debug)]
pub(crate) struct Mismatch {
    /// Its first sequence.
    pub(crate) seq0: u64,
    /// Whether it is the frame accepted first at its sequence (the one that was delivered), not a
    /// second frame that opened under the key and was only an event.
    pub(crate) first: bool,
    /// The frame, as it came.
    pub(crate) accepted: Accepted,
}

/// What a verified checkpoint did to the frames held.
#[derive(Debug, Default)]
pub(crate) struct Judged {
    /// The `seq0` of each slot whose **first** accepted frame (the one that was delivered) the
    /// checkpoint listed with the hash held, rising.
    pub(crate) settled: Vec<u64>,
    /// The accepted frames in the range the checkpoint does not list.
    pub(crate) mismatches: Vec<Mismatch>,
    /// Frames below the range that no checkpoint can cover any more (forgotten, counted).
    pub(crate) uncoverable: u64,
}

/// What the age of the oldest unverified frame asks of the receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Silence {
    /// Nothing waits too long.
    Ok,
    /// A frame waited past `unchecked_max`: hold what follows until a checkpoint verifies.
    Hold,
    /// A frame waited past [`UNVERIFIED_MAX`]: end the session.
    End,
}

/// One channel's accepted frames and checkpoint clock.
pub(crate) struct Verify {
    period: Duration,
    slots: BTreeMap<u64, Slot>,
    /// Octets of `Pending` frames held.
    bytes: usize,
    /// Second frames held.
    extra: usize,
    budget: Arc<Budget>,
    /// When the oldest frame accepted since the last verified checkpoint was.
    pending_since: Option<Instant>,
    /// The highest `hi` of a verified checkpoint, if any verified.
    #[cfg(test)]
    verified_hi: Option<u64>,
}

impl Verify {
    /// A verifier of a channel whose sender checkpoints every `period`, charging `budget`.
    pub(crate) fn new(period: Duration, budget: Arc<Budget>) -> Verify {
        Verify {
            period,
            slots: BTreeMap::new(),
            bytes: 0,
            extra: 0,
            budget,
            pending_since: None,
            #[cfg(test)]
            verified_hi: None,
        }
    }

    /// The period the sender announced.
    pub(crate) fn period(&self) -> Duration {
        self.period
    }

    /// Slots held (a test asks).
    #[cfg(test)]
    pub(crate) fn slots(&self) -> usize {
        self.slots.len()
    }

    /// Octets of frames held (a test asks).
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// The highest `hi` a verified checkpoint covered.
    #[cfg(test)]
    pub(crate) fn verified_hi(&self) -> Option<u64> {
        self.verified_hi
    }

    fn forget(&mut self, entries: Vec<Entry>) -> u64 {
        let mut n = 0;
        for entry in entries {
            let octets = entry.octets();
            if octets > 0 {
                self.bytes -= octets;
                self.budget.release(octets);
                n += 1;
            }
        }
        n
    }

    /// Forget the slot with the lowest `seq0`, counting its pending frames.
    fn forget_lowest(&mut self) -> Option<u64> {
        let (&seq0, _) = self.slots.iter().next()?;
        let slot = self.slots.remove(&seq0)?;
        self.extra = self
            .extra
            .saturating_sub(slot.entries.len().saturating_sub(1));
        Some(self.forget(slot.entries))
    }

    /// Make room for `octets` more: forget the lowest sequences until the channel and the node
    /// bounds hold. Returns the frames forgotten, or `None` when `octets` cannot be kept even
    /// with nothing else held.
    fn room(&mut self, octets: usize) -> Option<u64> {
        let mut forgotten = 0;
        while self.bytes + octets > CHANNEL_BYTES || !self.budget.try_charge(octets) {
            if self.bytes + octets <= CHANNEL_BYTES && self.bytes == 0 {
                // The node's budget is spent by other channels: nothing of this one's to give.
                return None;
            }
            forgotten += self.forget_lowest()?;
        }
        Some(forgotten)
    }

    /// Record the first frame accepted at `seq0`. Returns how many frames were forgotten to make
    /// room (counted `unchecked` by the caller), and whether this one was kept: a frame that
    /// cannot be kept (the node's budget is spent) is counted by the caller as unchecked too.
    pub(crate) fn offer(&mut self, seq0: u64, accepted: Accepted) -> (u64, bool) {
        let mut forgotten = 0;
        if !self.slots.contains_key(&seq0) && self.slots.len() >= SLOTS_MAX {
            forgotten += self.forget_lowest().unwrap_or(0);
        }
        let octets = accepted.frame.len();
        let Some(more) = self.room(octets) else {
            return (forgotten, false);
        };
        forgotten += more;
        self.bytes += octets;
        let entry = Entry {
            state: State::Pending(accepted.frame),
            ingress: accepted.ingress,
            at: accepted.at,
            sequences: accepted.sequences,
            kind: accepted.kind,
            epoch: accepted.epoch,
            rebinds: accepted.rebinds,
        };
        self.slots.entry(seq0).or_default().entries.push(entry);
        (forgotten, true)
    }

    /// What the receiver should do with `frame`, which the replay window says it saw at `seq0`.
    pub(crate) fn seen(&mut self, seq0: u64, frame: &Bytes) -> Dup {
        let Some(slot) = self.slots.get_mut(&seq0) else {
            return Dup::Unknown;
        };
        let mut hashed = None;
        for entry in &slot.entries {
            let same = match &entry.state {
                State::Pending(kept) => kept == frame,
                State::Settled { hash, .. } => {
                    *hashed.get_or_insert_with(|| frame_hash(frame)) == *hash
                }
            };
            if same {
                return Dup::Same;
            }
        }
        if slot.attempts >= ATTEMPTS_PER_SEQ {
            return Dup::Same;
        }
        slot.attempts += 1;
        Dup::Different
    }

    /// A frame that opened under the key arrived at `seq0`, which already holds an accepted frame
    /// of other octets. Keeps `second` for the next checkpoint when there is room.
    pub(crate) fn conflict(&mut self, seq0: u64, second: Accepted) -> Conflict {
        let (first, settled_by) = match self
            .slots
            .get(&seq0)
            .and_then(|s| s.entries.first())
            .map(|e| &e.state)
        {
            Some(State::Pending(frame)) => (Some(frame.clone()), None),
            Some(State::Settled { proof, .. }) => (None, Some(proof.clone())),
            None => (None, None),
        };
        if settled_by.is_some() {
            // The frame accepted first was listed by a verified checkpoint: this one is not the
            // sender's, and needs no keeping to be told so.
            return Conflict { first, settled_by };
        }
        let octets = second.frame.len();
        if self.extra < EXTRA_MAX && self.slots.contains_key(&seq0) && self.room(octets).is_some() {
            // Making room may have forgotten this very slot (the lowest): then nothing is kept
            // and what was charged is given back.
            match self.slots.get_mut(&seq0) {
                Some(slot) => {
                    slot.entries.push(Entry {
                        state: State::Pending(second.frame),
                        ingress: second.ingress,
                        at: second.at,
                        sequences: second.sequences,
                        kind: second.kind,
                        epoch: second.epoch,
                        rebinds: second.rebinds,
                    });
                    self.bytes += octets;
                    self.extra += 1;
                }
                None => self.budget.release(octets),
            }
        }
        Conflict { first, settled_by }
    }

    /// A frame was accepted at `now`: the clock of silence starts if it was not running.
    pub(crate) fn note_accepted(&mut self, now: Instant) {
        self.pending_since.get_or_insert(now);
    }

    /// What the age of the oldest frame accepted since the last verified checkpoint asks.
    pub(crate) fn silence(&self, now: Instant) -> Silence {
        let Some(since) = self.pending_since else {
            return Silence::Ok;
        };
        let waited = now.saturating_duration_since(since);
        if waited > UNVERIFIED_MAX {
            Silence::End
        } else if waited > unchecked_max(self.period) {
            Silence::Hold
        } else {
            Silence::Ok
        }
    }

    /// Judge the frames held by `record`, a checkpoint whose signature verified; `frame` is its
    /// octets (kept as the proof of each frame it settles). Settles the frames it lists with the
    /// hash held, hands back those in its range it does not list, forgets the frames below its
    /// range, and sets the silence clock to the oldest frame still waiting (a frame above its range:
    /// a checkpoint does not make a frame it does not cover look verified).
    pub(crate) fn judge(&mut self, record: &Record, frame: &Bytes) -> Judged {
        let mut judged = Judged::default();
        let range_hi = record.hi;
        #[cfg(test)]
        {
            self.verified_hi = Some(self.verified_hi.map_or(record.hi, |hi| hi.max(record.hi)));
        }
        // Below the range: no later checkpoint covers it.
        let below: Vec<u64> = self.slots.range(..record.lo).map(|(s, _)| *s).collect();
        for seq0 in below {
            let Some(slot) = self.slots.get_mut(&seq0) else {
                continue;
            };
            let (pending, settled): (Vec<Entry>, Vec<Entry>) = std::mem::take(&mut slot.entries)
                .into_iter()
                .partition(|e| matches!(e.state, State::Pending(_)));
            slot.entries = settled;
            if slot.entries.is_empty() {
                self.slots.remove(&seq0);
            }
            judged.uncoverable += self.forget(pending);
        }
        let inside: Vec<u64> = self
            .slots
            .range(record.lo..record.hi)
            .map(|(s, _)| *s)
            .collect();
        let mut released = 0usize;
        for seq0 in inside {
            let Some(slot) = self.slots.get_mut(&seq0) else {
                continue;
            };
            let mut keep = Vec::with_capacity(slot.entries.len());
            for (index, entry) in std::mem::take(&mut slot.entries).into_iter().enumerate() {
                let State::Pending(octets) = entry.state else {
                    keep.push(entry);
                    continue;
                };
                released += octets.len();
                let hash = frame_hash(&octets);
                if record.listed(seq0).any(|listed| *listed == hash) {
                    if index == 0 {
                        judged.settled.push(seq0);
                    }
                    keep.push(Entry {
                        state: State::Settled {
                            hash,
                            proof: frame.clone(),
                        },
                        ..entry
                    });
                } else {
                    judged.mismatches.push(Mismatch {
                        seq0,
                        first: index == 0,
                        accepted: Accepted {
                            frame: octets,
                            ingress: entry.ingress,
                            at: entry.at,
                            sequences: entry.sequences,
                            kind: entry.kind,
                            epoch: entry.epoch,
                            rebinds: entry.rebinds,
                        },
                    });
                }
            }
            slot.entries = keep;
            if slot.entries.is_empty() {
                self.slots.remove(&seq0);
            }
        }
        // Every frame judged left the slots: settled ones keep a hash, mismatches went to the
        // caller.
        self.bytes -= released.min(self.bytes);
        self.budget.release(released);
        self.recount_extra();
        // The frames above the range are still unjudged: the clock runs from the oldest of them.
        self.pending_since = self
            .slots
            .range(range_hi..)
            .flat_map(|(_, slot)| slot.entries.iter())
            .filter(|e| matches!(e.state, State::Pending(_)))
            .map(|e| e.at)
            .min();
        judged
    }

    fn recount_extra(&mut self) {
        self.extra = self
            .slots
            .values()
            .map(|s| s.entries.len().saturating_sub(1))
            .sum();
    }

    /// Give back everything held (the channel ended).
    pub(crate) fn release_all(&mut self) {
        self.budget.release(self.bytes);
        self.bytes = 0;
        self.extra = 0;
        self.slots.clear();
    }
}

impl Drop for Verify {
    fn drop(&mut self) {
        self.release_all();
    }
}

#[cfg(test)]
mod tests {
    use ndn_foundation_types::Name;
    use ndn_security::Ed25519Signer;

    use super::*;
    use crate::chan::checkpoint;

    fn at(ms: u64) -> Instant {
        thread_local! {
            static ZERO: Instant = Instant::now();
        }
        ZERO.with(|zero| *zero + Duration::from_millis(ms))
    }

    /// A frame whose octets are `len` long and differ for every `tag`.
    fn frame(tag: u64, len: usize) -> Bytes {
        let mut octets = vec![0xA5u8; len.max(8)];
        octets[..8].copy_from_slice(&tag.to_be_bytes());
        Bytes::from(octets)
    }

    fn accepted(frame: &Bytes, ingress: u64, ms: u64) -> Accepted {
        Accepted {
            frame: frame.clone(),
            ingress,
            at: at(ms),
            sequences: 1,
            kind: SideKind::Data,
            epoch: 1,
            rebinds: false,
        }
    }

    fn verify(budget: &Arc<Budget>) -> Verify {
        Verify::new(Duration::from_millis(20), Arc::clone(budget))
    }

    /// A checkpoint record over `[lo, hi)` listing `frames` (each at its `seq0`), signed.
    fn record(lo: u64, hi: u64, frames: &[(u64, &Bytes)]) -> Record {
        let signer =
            Ed25519Signer::from_seed(&[7; 32], "/bob/phone/KEY/1".parse::<Name>().unwrap());
        let entries: Vec<(u64, [u8; HASH_LEN])> = frames
            .iter()
            .map(|(seq0, frame)| (*seq0, frame_hash(frame)))
            .collect();
        let octets = checkpoint::sign(&signer, 1, 1, lo, hi, &entries).unwrap();
        Record::decode(&octets).unwrap()
    }

    /// The frames a channel holds are bounded at 4,096 (the replay window's size): the lowest
    /// sequence is forgotten and counted, and a frame at a forgotten sequence is no longer
    /// known (the replay window drops it as a copy).
    #[test]
    fn a_channel_keeps_4096_slots_and_forgets_and_counts_the_lowest() {
        let budget = Arc::new(Budget::default());
        let mut v = verify(&budget);
        let mut forgotten = 0;
        for seq0 in 0..(4_096u64 + 3) {
            let f = frame(seq0, 64);
            let (forgot, kept) = v.offer(seq0, accepted(&f, 1, 0));
            assert!(kept);
            forgotten += forgot;
        }
        assert_eq!(forgotten, 3, "three frames over the bound");
        assert_eq!(SLOTS_MAX, 4_096);
        assert_eq!(v.slots(), 4_096);
        assert_eq!(v.bytes(), 4_096 * 64);
        assert_eq!(
            budget.used(),
            v.bytes(),
            "the node's budget is charged what the channel holds"
        );
        assert_eq!(
            v.seen(0, &frame(0, 64)),
            Dup::Unknown,
            "the lowest was forgotten"
        );
        assert_eq!(v.seen(2, &frame(2, 64)), Dup::Unknown);
        assert_eq!(
            v.seen(3, &frame(3, 64)),
            Dup::Same,
            "the next lowest is still held"
        );
    }

    /// A channel keeps at most 2 MiB of frame octets: the oldest sequences go, counted.
    #[test]
    fn a_channel_keeps_2_mib_of_frames_and_forgets_the_oldest_counted() {
        let budget = Arc::new(Budget::default());
        let mut v = verify(&budget);
        let each = 100 * 1024;
        assert_eq!(CHANNEL_BYTES, 2 * 1024 * 1024);
        let fits = 2 * 1024 * 1024 / each;
        assert_eq!(fits, 20);
        let mut forgotten = 0;
        for seq0 in 0..25u64 {
            let (forgot, kept) = v.offer(seq0, accepted(&frame(seq0, each), 1, 0));
            assert!(kept);
            forgotten += forgot;
        }
        assert_eq!(forgotten, 5);
        assert_eq!(v.slots(), fits);
        assert!(v.bytes() <= 2 * 1024 * 1024);
        assert_eq!(v.bytes(), fits * each);
        assert_eq!(budget.used(), v.bytes());
        assert_eq!(
            v.seen(4, &frame(4, each)),
            Dup::Unknown,
            "sequences 0..5 were forgotten"
        );
        assert_eq!(v.seen(5, &frame(5, each)), Dup::Same);
        // A frame that alone is over the channel's bound cannot be kept at all.
        let big = frame(99, 2 * 1024 * 1024 + 1);
        let (_, kept) = v.offer(99, accepted(&big, 1, 0));
        assert!(!kept, "over 2 MiB on its own");
    }

    /// All the channels of a node keep at most 8 MiB of frame octets between them, one budget:
    /// a channel that cannot be given room by forgetting its own oldest frames keeps nothing
    /// (counted unchecked by the caller), and what a channel gives back is another's room.
    #[test]
    fn a_node_keeps_8_mib_of_frames_across_its_channels() {
        let budget = Arc::new(Budget::default());
        let mib = 1024 * 1024;
        let mut channels: Vec<Verify> = (0..3).map(|_| verify(&budget)).collect();
        for v in &mut channels {
            for seq0 in 0..2u64 {
                assert!(v.offer(seq0, accepted(&frame(seq0, mib), 1, 0)).1);
            }
            assert_eq!(v.bytes(), 2 * mib);
        }
        let mut fourth = verify(&budget);
        assert!(fourth.offer(0, accepted(&frame(0, mib), 1, 0)).1);
        assert_eq!(budget.used(), 7 * mib);

        // A fifth channel with nothing held cannot be given a frame past 8 MiB.
        let mut fifth = verify(&budget);
        let (forgot, kept) = fifth.offer(0, accepted(&frame(0, 2 * mib), 1, 0));
        assert_eq!(
            (forgot, kept),
            (0, false),
            "no room and nothing of its own to give"
        );
        assert_eq!(fifth.slots(), 0);
        assert_eq!(budget.used(), 7 * mib, "a refused frame is not charged");

        // A channel that holds something forgets its own oldest to fit the node's bound.
        assert!(fifth.offer(1, accepted(&frame(1, mib / 2), 1, 0)).1);
        assert_eq!(budget.used(), 7 * mib + mib / 2);
        let (forgot, kept) = fifth.offer(2, accepted(&frame(2, mib), 1, 0));
        assert!(kept);
        assert_eq!(
            forgot, 1,
            "its own oldest went so the node stays within 8 MiB"
        );
        assert_eq!(budget.used(), 8 * mib);
        assert!(budget.used() <= 8 * 1024 * 1024);
        assert_eq!(NODE_BYTES, 8 * 1024 * 1024);

        // A channel that ends gives its octets back for the others.
        drop(channels.pop());
        assert_eq!(budget.used(), 6 * mib);
        assert!(fifth.offer(3, accepted(&frame(3, mib), 1, 0)).1);
        assert_eq!(budget.used(), 7 * mib);
    }

    /// A frame at a sequence already accepted costs a comparison; one that differs gets an AEAD
    /// attempt, at most 3 for each sequence, and then is a copy too: garbage at one sequence
    /// cannot cost more than three attempts.
    #[test]
    fn at_most_three_aead_attempts_are_made_for_one_sequence() {
        let budget = Arc::new(Budget::default());
        let mut v = verify(&budget);
        let first = frame(1, 100);
        v.offer(10, accepted(&first, 1, 0));
        assert_eq!(v.seen(10, &first), Dup::Same, "the same octets are a copy");
        for n in 0..3u8 {
            assert_eq!(
                v.seen(10, &frame(100 + u64::from(n), 100)),
                Dup::Different,
                "attempt {n}"
            );
        }
        assert_eq!(
            v.seen(10, &frame(200, 100)),
            Dup::Same,
            "the fourth is not opened"
        );
        assert_eq!(v.seen(10, &frame(201, 100)), Dup::Same);
        assert_eq!(v.seen(10, &first), Dup::Same);
        // Another sequence has its own three.
        v.offer(11, accepted(&frame(2, 100), 1, 0));
        assert_eq!(v.seen(11, &frame(300, 100)), Dup::Different);
        // A sequence nothing is held for was forgotten.
        assert_eq!(v.seen(12, &frame(3, 100)), Dup::Unknown);
        assert_eq!(ATTEMPTS_PER_SEQ, 3);
    }

    /// A second authentic frame at a sequence is kept for the next checkpoint, at most 64 a
    /// channel; the checkpoint then says which of the two is the sender's.
    #[test]
    fn second_frames_are_kept_up_to_64_and_the_checkpoint_says_which_is_the_senders() {
        let budget = Arc::new(Budget::default());
        let mut v = verify(&budget);
        let genuine = frame(1, 100);
        v.offer(10, accepted(&genuine, 1, 0));
        assert_eq!(EXTRA_MAX, 64);
        for n in 0..70u64 {
            let second = frame(1_000 + n, 100);
            let conflict = v.conflict(10, accepted(&second, 9, 0));
            assert_eq!(conflict.first.as_ref(), Some(&genuine));
            assert!(
                conflict.settled_by.is_none(),
                "nothing vouched for the first yet"
            );
        }
        assert_eq!(
            v.bytes(),
            65 * 100,
            "the 65th second frame and later are not kept"
        );
        let proof = Bytes::from_static(b"checkpoint");
        let judged = v.judge(&record(10, 11, &[(10, &genuine)]), &proof);
        assert_eq!(judged.settled, [10]);
        assert_eq!(
            judged.mismatches.len(),
            64,
            "every kept second frame is a mismatch"
        );
        assert!(
            judged
                .mismatches
                .iter()
                .all(|m| !m.first && m.accepted.ingress == 9)
        );
        assert_eq!(v.bytes(), 0);
        assert_eq!(budget.used(), 0);
        // The settled frame is only a hash now; a second frame meets the checkpoint that listed
        // the first, and needs no keeping to be told so.
        let late = v.conflict(10, accepted(&frame(5_000, 100), 9, 0));
        assert_eq!(late.settled_by.as_deref(), Some(&b"checkpoint"[..]));
        assert_eq!(v.bytes(), 0);
    }

    /// What a verified checkpoint does to the frames held: it settles what it lists with the same
    /// hash, hands back what it does not list or lists with another hash, ignores a frame it lists
    /// that was not received (loss is not forgery), leaves a frame above its range for the next,
    /// and forgets, counted, a frame below its range that no checkpoint will cover.
    #[test]
    fn a_verified_checkpoint_settles_exposes_ignores_and_forgets() {
        let budget = Arc::new(Budget::default());
        let mut v = verify(&budget);
        let f: Vec<Bytes> = (0..8).map(|i| frame(i, 100)).collect();
        for (seq0, bytes) in f.iter().enumerate() {
            v.offer(seq0 as u64, accepted(bytes, 4, 0));
        }
        // Below the range [2, 6): 0 and 1. Inside: 2 listed, 3 not listed, 4 listed with another
        // hash, 5 listed. Above: 6 and 7.
        let other = frame(404, 100);
        let first = record(2, 6, &[(2, &f[2]), (4, &other), (5, &f[5])]);
        let proof = Bytes::from_static(b"the checkpoint frame");
        let judged = v.judge(&first, &proof);
        assert_eq!(judged.settled, [2, 5]);
        let mut mismatched: Vec<u64> = judged.mismatches.iter().map(|m| m.seq0).collect();
        mismatched.sort_unstable();
        assert_eq!(mismatched, [3, 4], "unlisted, and listed with another hash");
        assert!(
            judged
                .mismatches
                .iter()
                .all(|m| m.first && m.accepted.ingress == 4)
        );
        assert_eq!(judged.uncoverable, 2, "0 and 1 are below the range");
        // Settled frames are hashes now: the octets held are the two above the range.
        assert_eq!(v.bytes(), 2 * 100);
        assert_eq!(budget.used(), 2 * 100);
        assert_eq!(
            v.seen(2, &f[2]),
            Dup::Same,
            "a settled frame is a copy by its hash"
        );
        assert_eq!(v.seen(6, &f[6]), Dup::Same);
        assert_eq!(v.seen(0, &f[0]), Dup::Unknown);
        assert_eq!(
            v.seen(3, &f[3]),
            Dup::Unknown,
            "a mismatch left the slots for the caller"
        );
        assert_eq!(v.verified_hi(), Some(6));

        // A checkpoint that lists a frame this receiver does not hold (8 never came) settles what
        // it holds and objects to nothing: loss is not forgery.
        let f8 = frame(8, 100);
        let next = record(6, 9, &[(6, &f[6]), (7, &f[7]), (8, &f8)]);
        let judged = v.judge(&next, &proof);
        assert_eq!(judged.settled, [6, 7]);
        assert!(judged.mismatches.is_empty(), "loss is not forgery");
        assert_eq!(judged.uncoverable, 0);
        assert_eq!(v.bytes(), 0);
    }

    /// A frame at a sequence at or above the range's end is not yet covered: neither settled nor
    /// a mismatch.
    #[test]
    fn a_lone_frame_above_the_range_is_neither_settled_nor_a_mismatch() {
        let budget = Arc::new(Budget::default());
        let mut v = verify(&budget);
        let below = frame(1, 80);
        let above = frame(2, 80);
        v.offer(3, accepted(&below, 1, 0));
        v.offer(4, accepted(&above, 1, 0));
        let judged = v.judge(&record(0, 4, &[(3, &below)]), &Bytes::new());
        assert_eq!(judged.settled, [3]);
        assert!(judged.mismatches.is_empty());
        assert_eq!(
            v.bytes(),
            80,
            "the frame above waits for its own checkpoint"
        );
    }

    /// The silence clock: a frame accepted and not yet judged is `Ok` to `max(4 x period, 100 ms)`,
    /// holds what follows past it, and ends the session past 3 s.
    #[test]
    fn silence_holds_past_the_unchecked_maximum_and_ends_past_three_seconds() {
        assert_eq!(
            unchecked_max(Duration::from_millis(20)),
            Duration::from_millis(100)
        );
        assert_eq!(
            unchecked_max(Duration::from_millis(1)),
            Duration::from_millis(100)
        );
        assert_eq!(
            unchecked_max(Duration::from_millis(60)),
            Duration::from_millis(240)
        );
        let budget = Arc::new(Budget::default());
        let mut v = verify(&budget);
        assert_eq!(
            v.silence(at(10_000)),
            Silence::Ok,
            "nothing accepted: nothing waits"
        );
        v.note_accepted(at(0));
        v.note_accepted(at(90));
        assert_eq!(
            v.silence(at(100)),
            Silence::Ok,
            "exactly the maximum is not past it"
        );
        assert_eq!(
            v.silence(at(101)),
            Silence::Hold,
            "the oldest frame counts, not the newest"
        );
        assert_eq!(v.silence(at(3_000)), Silence::Hold);
        assert_eq!(v.silence(at(3_001)), Silence::End);
        let f = frame(1, 50);
        v.offer(1, accepted(&f, 1, 0));
        v.judge(&record(0, 2, &[(1, &f)]), &Bytes::new());
        assert_eq!(
            v.silence(at(9_000)),
            Silence::Ok,
            "a verified checkpoint judged everything held"
        );
    }

    /// A verified checkpoint that covers only the older frames does not restart the clock of the
    /// frames above its range: they have still waited since they were accepted, so a link that
    /// lets one checkpoint through and drops the rest cannot keep them flowing.
    #[test]
    fn a_checkpoint_below_a_frame_does_not_restart_that_frames_silence_clock() {
        let budget = Arc::new(Budget::default());
        let mut v = verify(&budget);
        let old = frame(1, 50);
        let newer = frame(2, 50);
        v.note_accepted(at(0));
        v.offer(1, accepted(&old, 1, 0));
        v.note_accepted(at(10));
        v.offer(5, accepted(&newer, 1, 10));
        v.judge(&record(0, 3, &[(1, &old)]), &Bytes::new());
        assert_eq!(
            v.silence(at(3_000)),
            Silence::Hold,
            "the newer frame was accepted at 10 ms"
        );
        assert_eq!(
            v.silence(at(3_011)),
            Silence::End,
            "3 s after it was accepted, not after the checkpoint"
        );
        // A checkpoint that reaches it settles it and the clock stops.
        v.judge(&record(3, 6, &[(5, &newer)]), &Bytes::new());
        assert_eq!(v.silence(at(9_000)), Silence::Ok);
    }
}
