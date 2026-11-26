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
use super::replay::REPLAY_WINDOW;
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

/// The checkpoints a channel may have verified a second, whatever its period: a channel of a
/// slow sender (2 s period, one checkpoint a second at most) is never starved by a bucket sized
/// to it.
const CHECKPOINTS_FLOOR_PER_SEC: f64 = 4.0;

/// How many checkpoints a channel may have verified in a burst: after congestion on a stream a
/// relay hands over what it held at once.
pub(crate) const CHECKPOINT_BURST: f64 = 64.0;

/// The checkpoints a node verifies a second across all its channels, and the burst: each costs a
/// hash of its list and an Ed25519 verification (about 41 µs), on the one task that reads every
/// channel's frames (channel.md, 13.12 item 15). 4,000 a second is a sixth of a core.
pub(crate) const NODE_CHECKPOINTS_PER_SEC: f64 = 4_000.0;

/// The burst of the node's ceiling.
pub(crate) const NODE_CHECKPOINT_BURST: f64 = 256.0;

/// A token bucket on the node's monotonic clock: `rate` tokens a second, at most `burst`, full
/// when made. It limits cost, never correctness: what it refuses is dropped and counted, and a
/// dropped checkpoint is neither a forgery nor a bad checkpoint.
#[derive(Debug)]
pub(crate) struct Bucket {
    tokens: f64,
    burst: f64,
    rate: f64,
    at: Option<Instant>,
}

impl Bucket {
    /// A full bucket.
    pub(crate) fn new(rate: f64, burst: f64) -> Bucket {
        Bucket {
            tokens: burst,
            burst,
            rate,
            at: None,
        }
    }

    /// The bucket of one channel whose sender checkpoints every `period`: two checkpoints a
    /// period (a genuine sender sends one, and one more at an `END` or after idle), at least
    /// [`CHECKPOINTS_FLOOR_PER_SEC`] a second, with [`CHECKPOINT_BURST`] in hand.
    pub(crate) fn for_period(period: Duration) -> Bucket {
        let per_sec = (2.0 / period.as_secs_f64().max(0.001)).max(CHECKPOINTS_FLOOR_PER_SEC);
        Bucket::new(per_sec, CHECKPOINT_BURST)
    }

    /// Take one token at `now`: false when none is left.
    pub(crate) fn take(&mut self, now: Instant) -> bool {
        if let Some(at) = self.at {
            let elapsed = now.saturating_duration_since(at).as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        }
        self.at = Some(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The node's ceiling on verified checkpoints ([`NODE_CHECKPOINTS_PER_SEC`]).
pub(crate) struct Ceiling(parking_lot::Mutex<Bucket>);

impl Default for Ceiling {
    fn default() -> Self {
        Ceiling(parking_lot::Mutex::new(Bucket::new(
            NODE_CHECKPOINTS_PER_SEC,
            NODE_CHECKPOINT_BURST,
        )))
    }
}

impl Ceiling {
    /// Take one verification of the node's at `now`: false when the node's are spent.
    pub(crate) fn take(&self, now: Instant) -> bool {
        self.0.lock().take(now)
    }
}

/// The least a channel's share of the node's budget may be: a node with more than 128 channels
/// that hold anything is past what the budget can guarantee each of them.
pub(crate) const SHARE_MIN: usize = 64 << 10;

/// The octets of accepted frames and held messages all the channels of a node keep, against
/// [`NODE_BYTES`], divided fairly: every channel that has a [`Share`] may hold up to an equal part
/// of the node's bytes (at most [`CHANNEL_BYTES`], at least [`SHARE_MIN`]), so a peer that holds
/// the key of many channels cannot take what the others need. A channel's part shrinks when a
/// channel is added; a channel over its part gives the excess back ([`Share::over`]) the next
/// time it runs (a frame, or the node's maintenance pass).
#[derive(Debug, Default)]
pub(crate) struct Budget {
    state: parking_lot::Mutex<BudgetState>,
}

#[derive(Debug, Default)]
struct BudgetState {
    /// Octets charged by every share.
    used: usize,
    /// Shares alive.
    shares: usize,
}

impl Budget {
    /// A channel's share of the budget (one per channel, held by everything of it that is
    /// charged).
    pub(crate) fn share(self: &Arc<Self>) -> Arc<Share> {
        self.state.lock().shares += 1;
        Arc::new(Share {
            budget: Arc::clone(self),
            charged: AtomicUsize::new(0),
        })
    }

    /// What each share may hold now.
    fn cap(state: &BudgetState) -> usize {
        (NODE_BYTES / state.shares.max(1)).clamp(SHARE_MIN, CHANNEL_BYTES)
    }

    /// Octets charged now.
    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.state.lock().used
    }
}

/// What a charge to a [`Share`] came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Charge {
    /// Charged.
    Granted,
    /// The channel would hold more than its part: give up something of its own first.
    OverShare,
    /// The channel is within its part and the node's bytes are all taken: channels that hold
    /// more than their part have not given the excess back yet (or there are more channels than
    /// [`SHARE_MIN`] divides the node into).
    Starved,
}

/// One channel's part of a [`Budget`]: what its frames kept for checkpoints and its held frames
/// are charged to. What is charged when it drops is given back.
#[derive(Debug)]
pub(crate) struct Share {
    budget: Arc<Budget>,
    charged: AtomicUsize,
}

impl Share {
    /// Charge `n` octets.
    pub(crate) fn try_charge(&self, n: usize) -> Charge {
        let mut node = self.budget.state.lock();
        let held = self.charged.load(Ordering::Acquire);
        if held.saturating_add(n) > Budget::cap(&node) {
            return Charge::OverShare;
        }
        if node.used.saturating_add(n) > NODE_BYTES {
            return Charge::Starved;
        }
        node.used += n;
        self.charged.store(held + n, Ordering::Release);
        Charge::Granted
    }

    /// Give `n` octets back.
    pub(crate) fn release(&self, n: usize) {
        let mut node = self.budget.state.lock();
        node.used = node.used.saturating_sub(n);
        let held = self.charged.load(Ordering::Acquire);
        self.charged
            .store(held.saturating_sub(n), Ordering::Release);
    }

    /// The octets this channel holds above its part now.
    pub(crate) fn over(&self) -> usize {
        let node = self.budget.state.lock();
        self.charged
            .load(Ordering::Acquire)
            .saturating_sub(Budget::cap(&node))
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        let mut node = self.budget.state.lock();
        node.used = node
            .used
            .saturating_sub(self.charged.load(Ordering::Acquire));
        node.shares = node.shares.saturating_sub(1);
    }
}

/// Why a frame was not kept for a checkpoint to judge (the caller counts it `unchecked`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotKept {
    /// It is over what the channel may hold, alone or with everything of the channel's own given
    /// up.
    TooBig,
    /// The channel is full and the frame is far above everything it holds (more than the replay
    /// window): a frame like that cannot be judged until the sender reaches it, and keeping it
    /// would push out frames that can. A key holder seals such frames.
    Far,
    /// The node's bytes are taken by channels that hold more than their part
    /// ([`Charge::Starved`]).
    Starved,
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
    share: Arc<Share>,
    /// When the oldest frame accepted since the last verified checkpoint was.
    pending_since: Option<Instant>,
    /// The highest `hi` of a verified checkpoint, if any verified.
    #[cfg(test)]
    verified_hi: Option<u64>,
}

impl Verify {
    /// A verifier of a channel whose sender checkpoints every `period`, charging `share`.
    pub(crate) fn new(period: Duration, share: Arc<Share>) -> Verify {
        Verify {
            period,
            slots: BTreeMap::new(),
            bytes: 0,
            extra: 0,
            share,
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
                self.share.release(octets);
                n += 1;
            }
        }
        n
    }

    /// Forget the slot at `seq0`, counting its pending frames.
    fn forget_slot(&mut self, seq0: u64) -> Option<u64> {
        let slot = self.slots.remove(&seq0)?;
        self.extra = self
            .extra
            .saturating_sub(slot.entries.len().saturating_sub(1));
        Some(self.forget(slot.entries))
    }

    /// Forget the slot a checkpoint is least likely to judge soon, when octets are wanted: the
    /// lowest of the **highest run** of sequences (a run is broken by a gap of more than the
    /// replay window). Frames of a sender are one run, and then this is the lowest, the oldest;
    /// a frame a key holder sealed far above them is a run of its own and is the first to go,
    /// not the sender's frames below it.
    fn forget_farthest(&mut self) -> Option<u64> {
        let mut low = *self.slots.keys().next_back()?;
        for &seq0 in self.slots.keys().rev().skip(1) {
            if low - seq0 > REPLAY_WINDOW {
                break;
            }
            low = seq0;
        }
        self.forget_slot(low)
    }

    /// Whether `seq0` is above every slot held by more than the replay window.
    fn far_above(&self, seq0: u64) -> bool {
        self.slots
            .keys()
            .next_back()
            .is_some_and(|&top| seq0 > top.saturating_add(REPLAY_WINDOW))
    }

    /// Make room for `octets` more at `seq0`: forget this channel's own frames, the farthest
    /// first, until the channel's bound and its part of the node's hold. Returns the frames
    /// forgotten; a frame far above what is held is refused rather than pushing frames out.
    fn room(&mut self, octets: usize, seq0: u64) -> Result<u64, NotKept> {
        let mut forgotten = 0;
        loop {
            if self.bytes + octets <= CHANNEL_BYTES {
                match self.share.try_charge(octets) {
                    Charge::Granted => return Ok(forgotten),
                    Charge::Starved => return Err(NotKept::Starved),
                    Charge::OverShare => {}
                }
            }
            if self.far_above(seq0) {
                return Err(NotKept::Far);
            }
            forgotten += self.forget_farthest().ok_or(NotKept::TooBig)?;
        }
    }

    /// Give back what this channel holds above its part of the node's bytes (the part shrinks
    /// when channels are added). Returns the frames forgotten.
    pub(crate) fn shed(&mut self) -> u64 {
        let mut forgotten = 0;
        while self.share.over() > 0 {
            match self.forget_farthest() {
                Some(n) => forgotten += n,
                None => break,
            }
        }
        forgotten
    }

    /// Record the first frame accepted at `seq0`. Returns how many frames were forgotten to make
    /// room (counted `unchecked` by the caller), and whether this one was kept: a frame that
    /// cannot be kept is counted by the caller as unchecked too, and the reason says whether it
    /// was for the node's bytes ([`NotKept::Starved`]).
    pub(crate) fn offer(&mut self, seq0: u64, accepted: Accepted) -> (u64, Result<(), NotKept>) {
        let mut forgotten = 0;
        if !self.slots.contains_key(&seq0) && self.slots.len() >= SLOTS_MAX {
            if self.far_above(seq0) {
                return (0, Err(NotKept::Far));
            }
            forgotten += self.forget_farthest().unwrap_or(0);
        }
        let octets = accepted.frame.len();
        match self.room(octets, seq0) {
            Ok(more) => forgotten += more,
            Err(why) => return (forgotten, Err(why)),
        }
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
        (forgotten, Ok(()))
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
        if self.extra < EXTRA_MAX
            && self.slots.contains_key(&seq0)
            && self.room(octets, seq0).is_ok()
        {
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
                None => self.share.release(octets),
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
        self.share.release(released);
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
        self.share.release(self.bytes);
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
        Verify::new(Duration::from_millis(20), budget.share())
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
            assert!(kept.is_ok());
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
            assert!(kept.is_ok());
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
        assert_eq!(kept, Err(NotKept::TooBig), "over 2 MiB on its own");
    }

    /// All the channels of a node keep at most 8 MiB of frame octets between them, one budget
    /// divided fairly (security review M7): channels that hold more than an equal part give the
    /// excess back, so a channel that came late is not starved by those that came first, and
    /// what a channel gives back is another's room.
    #[test]
    fn a_node_keeps_8_mib_across_its_channels_and_each_has_an_equal_part() {
        let budget = Arc::new(Budget::default());
        let mib = 1024 * 1024;
        let mut early: Vec<Verify> = (0..4).map(|_| verify(&budget)).collect();
        for v in &mut early {
            for seq0 in 0..2u64 {
                assert!(v.offer(seq0, accepted(&frame(seq0, mib), 1, 0)).1.is_ok());
            }
            assert_eq!(v.bytes(), 2 * mib);
        }
        assert_eq!(budget.used(), 8 * mib);
        assert_eq!(NODE_BYTES, 8 * 1024 * 1024);

        // A fifth channel finds the node's bytes taken, and says so: nothing of its own to give.
        let mut fifth = verify(&budget);
        let (forgot, kept) = fifth.offer(0, accepted(&frame(0, mib / 2), 1, 0));
        assert_eq!((forgot, kept), (0, Err(NotKept::Starved)));
        assert_eq!(fifth.slots(), 0);
        assert_eq!(budget.used(), 8 * mib, "a refused frame is not charged");

        // Each channel is now over its fifth of the node (1.6 MiB): it gives the excess back.
        for v in &mut early {
            assert_eq!(v.shed(), 1, "one frame of the two went");
            assert_eq!(v.bytes(), mib);
        }
        assert_eq!(budget.used(), 4 * mib);

        // The late channel now keeps its part, and no more than that.
        assert!(fifth.offer(0, accepted(&frame(0, mib), 1, 0)).1.is_ok());
        let (forgot, kept) = fifth.offer(1, accepted(&frame(1, mib), 1, 0));
        assert!(kept.is_ok());
        assert_eq!(
            forgot, 1,
            "its own oldest went: a fifth of 8 MiB is 1.6 MiB"
        );
        assert_eq!(fifth.bytes(), mib);
        assert!(budget.used() <= NODE_BYTES);

        // A channel that ends gives its octets back for the others.
        drop(early.pop());
        assert_eq!(budget.used(), 4 * mib);
    }

    /// A frame far above everything a channel holds is no way to push the sender's frames out
    /// (security review M7): when the channel is full it is refused, and when it was held already
    /// it is the first to go.
    #[test]
    fn a_frame_far_above_the_rest_never_pushes_out_the_senders_frames() {
        let budget = Arc::new(Budget::default());
        let each = 100 * 1024;
        let mut v = verify(&budget);
        for seq0 in 0..20u64 {
            assert!(v.offer(seq0, accepted(&frame(seq0, each), 1, 0)).1.is_ok());
        }
        // Full at 20 frames: one a holder sealed far ahead is refused, and nothing was forgotten.
        let far = 1u64 << 20;
        let (forgot, kept) = v.offer(far, accepted(&frame(far, each), 9, 0));
        assert_eq!((forgot, kept), (0, Err(NotKept::Far)));
        assert_eq!(
            v.seen(0, &frame(0, each)),
            Dup::Same,
            "the oldest is still held"
        );

        // Held while there was room, it is the first forgotten when the sender's frames need it.
        let mut v = verify(&budget);
        for seq0 in 0..10u64 {
            assert!(v.offer(seq0, accepted(&frame(seq0, each), 1, 0)).1.is_ok());
        }
        assert!(v.offer(far, accepted(&frame(far, each), 9, 0)).1.is_ok());
        let mut forgotten = 0;
        for seq0 in 10..21u64 {
            let (forgot, kept) = v.offer(seq0, accepted(&frame(seq0, each), 1, 0));
            assert!(kept.is_ok(), "seq {seq0}");
            forgotten += forgot;
        }
        assert_eq!(forgotten, 2, "the far frame, then (still full) the oldest");
        assert_eq!(
            v.seen(far, &frame(far, each)),
            Dup::Unknown,
            "the far frame went first"
        );
        assert_eq!(v.seen(0, &frame(0, each)), Dup::Unknown);
        assert_eq!(v.seen(1, &frame(1, each)), Dup::Same);
    }

    /// A frame at a sequence already accepted costs a comparison; one that differs gets an AEAD
    /// attempt, at most 3 for each sequence, and then is a copy too: garbage at one sequence
    /// cannot cost more than three attempts.
    #[test]
    fn at_most_three_aead_attempts_are_made_for_one_sequence() {
        let budget = Arc::new(Budget::default());
        let mut v = verify(&budget);
        let first = frame(1, 100);
        assert!(v.offer(10, accepted(&first, 1, 0)).1.is_ok());
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
        assert!(v.offer(11, accepted(&frame(2, 100), 1, 0)).1.is_ok());
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
        assert!(v.offer(10, accepted(&genuine, 1, 0)).1.is_ok());
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
            assert!(v.offer(seq0 as u64, accepted(bytes, 4, 0)).1.is_ok());
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
        assert!(v.offer(3, accepted(&below, 1, 0)).1.is_ok());
        assert!(v.offer(4, accepted(&above, 1, 0)).1.is_ok());
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
        assert!(v.offer(1, accepted(&f, 1, 0)).1.is_ok());
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
        assert!(v.offer(1, accepted(&old, 1, 0)).1.is_ok());
        v.note_accepted(at(10));
        assert!(v.offer(5, accepted(&newer, 1, 10)).1.is_ok());
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

    /// A channel verifies a burst of checkpoints and then about two a period, whatever is sent
    /// (security review M1): a holder of the key that seals a genuine checkpoint again at fresh
    /// sequences cannot make the node pay a signature check for each.
    #[test]
    fn a_channel_bucket_lets_a_burst_then_two_a_period_through() {
        let mut bucket = Bucket::for_period(Duration::from_millis(20));
        let burst = (0..1_000).filter(|_| bucket.take(at(0))).count();
        assert_eq!(burst, CHECKPOINT_BURST as usize, "the burst, no more");
        // Two a period at 20 ms is 100 a second: 100 ms later, ten.
        let after = (0..1_000).filter(|_| bucket.take(at(100))).count();
        assert_eq!(after, 10);
        // Never more than the burst, however long it was idle.
        let idle = (0..1_000).filter(|_| bucket.take(at(600_000))).count();
        assert_eq!(idle, CHECKPOINT_BURST as usize);
    }

    /// A genuine sender never meets the bucket: a checkpoint each period, and one more at an
    /// `END` or after a quiet spell, for any period a session announces, the slowest included
    /// (where the floor serves it).
    #[test]
    fn a_genuine_sender_is_never_refused_by_its_bucket() {
        for period_ms in [1u64, 20, 100, 500, 2_000] {
            let mut bucket = Bucket::for_period(Duration::from_millis(period_ms));
            let mut now = 0;
            for n in 0..2_000u64 {
                assert!(
                    bucket.take(at(now)),
                    "period {period_ms} ms, checkpoint {n}"
                );
                if n % 7 == 0 {
                    // The extra one, a moment after.
                    assert!(
                        bucket.take(at(now + period_ms / 2)),
                        "period {period_ms} ms, extra {n}"
                    );
                }
                now += period_ms;
            }
        }
    }

    /// The node's ceiling is one bucket for every channel: it spends its burst, then
    /// [`NODE_CHECKPOINTS_PER_SEC`] a second.
    #[test]
    fn the_node_ceiling_bounds_every_channel_together() {
        let ceiling = Ceiling::default();
        let burst = (0..10_000).filter(|_| ceiling.take(at(0))).count();
        assert_eq!(burst, NODE_CHECKPOINT_BURST as usize);
        // Ten milliseconds later, a hundredth of the rate: 40.
        let later = (0..100_000).filter(|_| ceiling.take(at(10))).count();
        assert_eq!(later, (NODE_CHECKPOINTS_PER_SEC / 100.0) as usize);
    }
}
