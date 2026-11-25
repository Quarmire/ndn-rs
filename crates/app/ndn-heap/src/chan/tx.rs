//! The sender's frame layer: one [`TxChannel`] per channel, and the combining writer that turns
//! emissions into frames (docs/specs/channel.md, Batching).
//!
//! **No timer decides when a frame leaves.** A channel has two lanes, the datagram lane and the
//! stream lane, each with a pending set and a `writing` flag.
//!
//! 1. An emission takes the next sequence **under the channel's lock** (so the order of a queue is
//!    the order of the sequences, and a message that is dropped leaves a gap a receiver sees) and
//!    joins the pending set. `Latest`: one slot per name id; a newer message replaces an unsent older
//!    one, whose sequence is simply never sent. `Reliable`, `Window`: a FIFO bounded by
//!    [`QUEUE_BYTES`].
//! 2. If the datagram lane's `writing` flag is clear the caller sets it and **is the writer**: it
//!    packs messages of consecutive sequences into a frame up to the carrier's room or 255
//!    messages, seals it **once**, hands it to the carrier, and goes on for up to [`COMBINE_MAX`]
//!    frames; it then re-checks the pending set under the lock that clears the flag. What is left
//!    is given to the carrier's writer task ([`Carrier::on_ready`]), which drains with no bound.
//!    A message that arrives while the flag is set waits for the writer, which looks again before it
//!    clears the flag. So an idle link sees one message leave at once, inline, as a one-message
//!    frame, and a batch forms only while the writer is busy or the carrier refused with `Full`.
//! 3. The stream lane is drained by a task of the node (a `Reliable` frame may wait on flow
//!    control, which an emitter that must not be cancelled cannot do): `emit` with
//!    [`Congestion::Block`] waits for **queue room**, with [`Congestion::Drop`] it drops the oldest
//!    queued message at [`QUEUE_BYTES`] and counts it.
//!
//! A message stays in its queue until the frame that carries it was handed to the carrier: a frame
//! the carrier refused loses nothing, and a message replaced while its frame was sealed is not
//! sent twice. Every frame sent is recorded in the ring of sent-frame hashes.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_transport::{SideClass, SideKind};
use parking_lot::Mutex;
use tokio::sync::Notify;

use super::aead::{Aead, FrameCipher};
use super::carrier::{Carrier, CarrierRefused, CarrierSlot};
use super::channels::{Live, SendKey};
use super::control::Control;
use super::frame::{self, Header};
use super::history::{Held, History, StandFull, Standing};
use super::hub::Counter;
use super::limits::{self, FRAME_OVERHEAD, MESSAGE_DEFAULT, MIN_FRAME_LEN, NAME_MAX};
use super::message::{MessageWriter, Origin, OutMessage, WriteError};
use super::queues::{Fifo, Item, LatestSet, Pending};
use super::ring::SentFrames;
use super::table::{self, Full, NameTooLong, Table, Use};
use super::varint;
use super::verbs::{Congestion, EmitError, EmitOptions, Mode, STAND_MAX, Window};
use super::wire::{self, ChannelMode};
use crate::rt::{Instant, Tasks};

/// Frames one emitter writes before it hands what is left to the carrier's writer task.
pub(crate) const COMBINE_MAX: usize = 4;

/// Payload octets a queue holds: 1 MiB.
pub(crate) const QUEUE_BYTES: usize = 1 << 20;

/// The largest datagram frame a session names (`S_FRAME_MAX`): what the default `path_mtu_max` of
/// the link (9,000) carries.
pub(crate) const FRAME_CAP: usize = 9_000;

/// When a `Drop` emission that found the queue full of what cannot be dropped may try again.
pub(crate) const CONGESTED_RETRY: Duration = Duration::from_millis(100);

/// Sequences are below this: 2^62 − 1, the largest value of the varint in which `HELLO` and a
/// replayed message carry a sequence (and so below the frame's own limit of 2^63).
pub(crate) const SEQ_END: u64 = varint::MAX;

/// The room a channel's own bookkeeping needs in the sequences before it refuses (a bind, an unbind
/// and the message).
const SEQ_HEADROOM: u64 = 4;

/// Where a channel's key comes from, and whom to tell when the sequence ran out.
pub(crate) trait KeySource: Send + Sync {
    /// The channel's id, key epoch and frame key now; `None` when the channel is gone.
    fn current(&self) -> Option<SendKey>;
    /// The channel used its last sequence: end it (a new one begins with the next emission).
    fn exhausted(&self);
}

/// What the frame layer counted.
#[derive(Default)]
pub(crate) struct TxStats {
    /// Emissions accepted for sending.
    pub(crate) emitted: Counter,
    /// Frames handed to the carrier as datagrams.
    pub(crate) datagram_frames: Counter,
    /// Frames handed to the carrier on the stream.
    pub(crate) stream_frames: Counter,
    /// Messages in the frames handed over (control frames not counted).
    pub(crate) messages: Counter,
    /// Messages a newer one of the same name replaced before they were sent (`Latest`).
    pub(crate) replaced: Counter,
    /// Messages dropped because the queue was at [`QUEUE_BYTES`].
    pub(crate) dropped: Counter,
    /// Times the carrier refused a datagram with `Full`.
    pub(crate) full: Counter,
    /// Messages re-packed or moved to the stream because the path's size fell.
    pub(crate) resized: Counter,
    /// Messages dropped because the carrier or the channel was gone.
    pub(crate) lost_closed: Counter,
    /// Emissions that had no receiver or no carrier to go to (nothing was sent).
    pub(crate) unrouted: Counter,
    /// Binds sent.
    pub(crate) binds: Counter,
    /// Unbinds sent.
    pub(crate) unbinds: Counter,
    /// Frames the sender could not seal (never expected).
    pub(crate) seal_failed: Counter,
    /// Replayed messages (standing and window) queued for a new session.
    pub(crate) replayed: Counter,
    /// Frames by the messages they carry: 1, 2, 3-4, 5-8, 9-16, 17-32, 33-64, 65-128, 129-255.
    pub(crate) by_count: [Counter; 9],
}

impl TxStats {
    fn note_frame(&self, class: SideClass, count: usize) {
        match class {
            SideClass::Datagram => self.datagram_frames.bump(),
            SideClass::Stream => self.stream_frames.bump(),
        }
        for _ in 0..count {
            self.messages.bump();
        }
        let bucket = match count {
            0 | 1 => 0,
            2 => 1,
            3..=4 => 2,
            5..=8 => 3,
            9..=16 => 4,
            17..=32 => 5,
            33..=64 => 6,
            65..=128 => 7,
            _ => 8,
        };
        if count > 0 {
            self.by_count[bucket].bump();
        }
    }
}

/// Why a [`TxChannel`] did not take an emission.
#[derive(Debug)]
pub(crate) enum Refused {
    /// The channel ended (closed, expired or re-judged away): the caller finds or makes another.
    Gone,
    /// The emission itself is refused.
    Error(EmitError),
}

impl From<EmitError> for Refused {
    fn from(e: EmitError) -> Self {
        Refused::Error(e)
    }
}

/// What a new receiver's session is given by the sender.
#[derive(Clone, Debug)]
pub(crate) struct Terms {
    /// The name table bound so far: at most 64 binds and 4 KiB; the rest follow as `BIND` frames.
    pub(crate) table: Vec<wire::Bind>,
    /// `Window` mode: what is replayed.
    pub(crate) window: Option<wire::Window>,
    /// The largest datagram frame the sender sends.
    pub(crate) frame_max: u64,
    /// The next sequence the sender will use.
    pub(crate) seq: u64,
}

/// What an emission asks the caller to do once the lock is released.
#[derive(Default)]
struct Kick {
    /// The caller is the datagram lane's writer.
    datagram: bool,
    /// The stream lane's `writing` flag was set for a task the caller must spawn.
    stream: bool,
}

struct State {
    cipher: Arc<FrameCipher>,
    key_epoch: u32,
    next_seq: u64,
    table: Table,
    latest: LatestSet,
    /// `Latest` messages that fit no datagram: they go on the stream.
    big: LatestSet,
    fifo: Fifo,
    datagram_writing: bool,
    stream_writing: bool,
    history: History,
    window: Window,
    standing: Standing,
    sent: SentFrames,
    scratch: Vec<(u64, u64)>,
    ended: bool,
    /// The channel's `END` is queued on the stream: the lane sends what waits, then it, under the
    /// key in force when the channel ended, and goes idle. (`ended` alone means nothing more is
    /// sent.)
    ending: bool,
    /// `ending` was set where the stream's writer could not be spawned (the state's lock is held
    /// by the emission): the emission spawns it once the lock is released.
    end_kick: bool,
}

impl State {
    fn take_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    /// A control frame takes the next sequence and joins the stream's FIFO. A record that cannot
    /// be written (never: its fields are checked) takes none.
    fn control(&mut self, control: &Control) {
        if let Ok(body) = control.encode() {
            let seq = self.take_seq();
            self.fifo.push(Item::Control { seq, body });
        }
    }

    /// Bind a new name: free the idle ids if the table is nearly full, take an id, say it on the
    /// stream (when the carrier has one: without a stream every message names itself).
    fn bind(
        &mut self,
        stats: &TxStats,
        path: &Name,
        octets: Bytes,
        now: Instant,
        stream: bool,
    ) -> Result<Use, EmitError> {
        for id in self.table.sweep(now) {
            stats.unbinds.bump();
            if stream {
                self.control(&Control::Unbind { id });
            }
        }
        match self.table.bind(path, octets, now) {
            Err(NameTooLong { len }) => Err(EmitError::TooLarge {
                what: "name",
                size: len,
                max: NAME_MAX,
            }),
            Ok(Err(Full { would_be })) => Err(EmitError::TooLarge {
                what: "names in one channel",
                size: would_be,
                max: limits::NAMES_PER_CHANNEL as usize,
            }),
            Ok(Ok(used)) => {
                stats.binds.bump();
                if stream {
                    self.control(&Control::Bind {
                        id: used.id,
                        name: used.octets.clone(),
                    });
                }
                Ok(used)
            }
        }
    }

    /// The datagram lane's waiting messages are lost, counted: the channel ended and sends no
    /// more of them. The stream's `END` still goes.
    fn lose_latest(&mut self, stats: &TxStats) {
        for _ in self.latest.drain_all() {
            stats.lost_closed.bump();
        }
    }

    /// The stream lane's `big` messages are lost, counted, as [`Self::lose_latest`].
    fn lose_big(&mut self, stats: &TxStats) {
        for _ in self.big.drain_all() {
            stats.lost_closed.bump();
        }
    }

    /// Drop everything waiting, counted: the carrier or the channel is gone.
    fn lose_pending(&mut self, stats: &TxStats) {
        let lost = self.latest.drain_all().len()
            + self.big.drain_all().len()
            + self
                .fifo
                .drain_all()
                .iter()
                .filter(|i| matches!(i, Item::Data(_)))
                .count();
        for _ in 0..lost {
            stats.lost_closed.bump();
        }
    }
}

/// One channel's sender.
pub(crate) struct TxChannel {
    id: u64,
    mode: ChannelMode,
    keys: Arc<dyn KeySource>,
    live: Arc<Live>,
    tasks: Arc<Tasks>,
    slot: Arc<CarrierSlot>,
    stats: Arc<TxStats>,
    aead: Aead,
    state: Mutex<State>,
    /// Woken when the stream's queue made room.
    room: Notify,
    /// A callback is registered with the carrier ([`Carrier::on_ready`]).
    drain_requested: AtomicU64,
    queue_bytes: usize,
    message_limit: usize,
    /// The space's fold version, to tell when the writer gate must be passed again.
    fold_version: Arc<AtomicU64>,
    gated_generation: AtomicU64,
    gated_version: AtomicU64,
    gate_set: AtomicBool,
}

/// What `pack_datagram` found.
enum Pack {
    Frame(Packed),
    Idle,
    Gone,
}

struct Packed {
    writer: MessageWriter,
    cipher: Arc<FrameCipher>,
    seq0: u64,
    scratch: Vec<(u64, u64)>,
}

/// What a frame of the stream lane took out of the queues.
enum Done {
    /// The control frame at the head of the FIFO.
    Control,
    /// The first items of the FIFO.
    Fifo,
    /// Messages of `big`, as `(id, sequence)`.
    Big(Vec<(u64, u64)>),
}

/// What `pack_stream` found.
enum StreamPack {
    Control {
        seq: u64,
        body: Bytes,
        cipher: Arc<FrameCipher>,
        epoch: u8,
    },
    Data {
        packed: Packed,
        /// `true`: the frame is the first items of the FIFO; `false`: messages of `big`.
        from_fifo: bool,
    },
    Idle,
    Gone,
}

impl TxChannel {
    /// The sender of the channel `key` names.
    pub(crate) fn new(
        mode: ChannelMode,
        key: &SendKey,
        keys: Arc<dyn KeySource>,
        tasks: Arc<Tasks>,
        slot: Arc<CarrierSlot>,
        stats: Arc<TxStats>,
        fold_version: Arc<AtomicU64>,
    ) -> Arc<TxChannel> {
        let aead = Aead::preferred();
        Arc::new(TxChannel {
            id: key.id,
            mode,
            keys,
            live: Arc::clone(&key.live),
            tasks,
            slot,
            stats,
            aead,
            state: Mutex::new(State {
                cipher: Arc::new(FrameCipher::new(&key.frame_key, aead)),
                key_epoch: key.key_epoch,
                next_seq: 1,
                table: Table::default(),
                latest: LatestSet::default(),
                big: LatestSet::default(),
                fifo: Fifo::default(),
                datagram_writing: false,
                stream_writing: false,
                history: History::default(),
                window: Window::DEFAULT,
                standing: Standing::default(),
                sent: SentFrames::new(),
                scratch: Vec::new(),
                ended: false,
                ending: false,
                end_kick: false,
            }),
            room: Notify::new(),
            drain_requested: AtomicU64::new(0),
            queue_bytes: QUEUE_BYTES,
            message_limit: MESSAGE_DEFAULT,
            fold_version,
            gated_generation: AtomicU64::new(0),
            gated_version: AtomicU64::new(0),
            gate_set: AtomicBool::new(false),
        })
    }

    /// Whether the writer gate was passed under the judges' state as it is now: the trust
    /// generation `generation` and the space's fold version, read without a lock.
    pub(crate) fn gate_valid(&self, generation: u64) -> bool {
        self.gate_set.load(Ordering::Acquire)
            && self.gated_generation.load(Ordering::Relaxed) == generation
            && self.gated_version.load(Ordering::Relaxed)
                == self.fold_version.load(Ordering::SeqCst)
    }

    /// The writer gate was passed under `(generation, version)`.
    pub(crate) fn set_gate(&self, generation: u64, version: u64) {
        self.gated_generation.store(generation, Ordering::Relaxed);
        self.gated_version.store(version, Ordering::Relaxed);
        self.gate_set.store(true, Ordering::Release);
    }

    /// What the channel reads without a lock.
    pub(crate) fn live(&self) -> &Arc<Live> {
        &self.live
    }

    /// The next sequence the channel will use.
    #[cfg(test)]
    pub(crate) fn next_seq(&self) -> u64 {
        self.state.lock().next_seq
    }

    /// Start the sequence at `seq` (a test seeds a channel near its limit).
    #[cfg(test)]
    pub(crate) fn set_next_seq(&self, seq: u64) {
        self.state.lock().next_seq = seq;
    }

    /// Refuse what no mode accepts. `Latest` never blocks.
    pub(crate) fn validate(opts: &EmitOptions) -> Result<(), EmitError> {
        if opts.mode == Mode::Latest && opts.congestion == Congestion::Block {
            return Err(EmitError::latest_blocks());
        }
        if let Some(stand) = opts.stand
            && stand > STAND_MAX
        {
            return Err(EmitError::TooLarge {
                what: "stand lifetime in seconds",
                size: stand.as_secs() as usize,
                max: STAND_MAX.as_secs() as usize,
            });
        }
        Ok(())
    }

    fn refresh_key(&self, st: &mut State) {
        if st.ended {
            return;
        }
        if self.live.closed.load(Ordering::Acquire) {
            st.ended = true;
            return;
        }
        let epoch = self.live.key_epoch.load(Ordering::Acquire);
        if epoch != st.key_epoch {
            match self.keys.current() {
                Some(key) if key.id == self.id => {
                    st.cipher = Arc::new(FrameCipher::new(&key.frame_key, self.aead));
                    st.key_epoch = key.key_epoch;
                }
                _ => st.ended = true,
            }
        }
    }

    /// The channel ended with `key` in force (a close, its space's end, its sequence limit):
    /// what waits on the stream is written, then one `CONTROL END` frame sealed under `key`, and
    /// the channel sends nothing more. Best effort, and it never waits: the frame goes out from
    /// the stream's writer task, and is not sent when the carrier has no stream, when no receiver
    /// holds the channel, or when `key` is not this channel's.
    pub(crate) fn end(self: &Arc<Self>, key: &SendKey) {
        // What waits for the carrier's call back goes now: a close is told after the messages
        // that were emitted before it.
        if let Some(carrier) = self.slot.get() {
            self.drain_from_carrier(&carrier);
        }
        let stream = self.slot.get().is_some_and(|c| c.has_stream());
        let spawn = {
            let mut st = self.state.lock();
            self.queue_end(&mut st, key, stream);
            std::mem::take(&mut st.end_kick)
        };
        if spawn {
            self.spawn_stream();
        }
    }

    /// Wait until the stream lane's writer has nothing left to write (after an [`Self::end`],
    /// the `END` is out or could not be): the caller bounds the wait.
    pub(crate) async fn flushed(&self) {
        loop {
            let notified = {
                let st = self.state.lock();
                if !st.stream_writing {
                    return;
                }
                self.room.notified()
            };
            notified.await;
        }
    }

    /// Mark the channel ended and queue its `END` (see [`Self::end`]), under the lock. When the
    /// stream's writer must be spawned, `end_kick` says so: the caller spawns it once the lock
    /// is released.
    fn queue_end(&self, st: &mut State, key: &SendKey, stream: bool) {
        if st.ending {
            return;
        }
        st.ended = true;
        let heard = self.live.receivers.load(Ordering::Acquire) > 0;
        if !stream || !heard || key.id != self.id || st.next_seq >= SEQ_END {
            return;
        }
        // The key in force when the channel ended, not the one this sender last refreshed to.
        st.cipher = Arc::new(FrameCipher::new(&key.frame_key, self.aead));
        st.key_epoch = key.key_epoch;
        st.ending = true;
        st.control(&Control::End);
        if !st.stream_writing {
            st.stream_writing = true;
            st.end_kick = true;
        }
    }

    /// Emit `payload` at `path` (relative to the space).
    ///
    /// Returns when the message is queued: at once for `Latest` and for `Drop`; for `Block`, when
    /// the queue has room. A channel with no receiver, or no carrier attached, sends nothing and
    /// returns at once; its standing values and, in `Window` mode, its window are still kept for
    /// a receiver that joins later.
    pub(crate) async fn emit(
        self: &Arc<Self>,
        path: &Name,
        payload: &Bytes,
        opts: &EmitOptions,
        now: Instant,
    ) -> Result<(), Refused> {
        Self::validate(opts)?;
        let carrier = self.slot.get();
        loop {
            let (kick, waiting) = {
                let mut st = self.state.lock();
                let step = self.enqueue(&mut st, path, payload, opts, now, carrier.as_ref());
                let end = std::mem::take(&mut st.end_kick);
                // Created under the lock: a wake-up between the lock and the wait is not lost.
                let waiting = matches!(step, Ok(Step::Wait)).then(|| self.room.notified());
                drop(st);
                if end {
                    self.spawn_stream();
                }
                match step? {
                    Step::Done(kick) => (kick, None),
                    Step::Wait => (Kick::default(), waiting),
                }
            };
            match waiting {
                None => {
                    self.run(kick, carrier.as_ref());
                    return Ok(());
                }
                Some(notified) => notified.await,
            }
        }
    }

    /// Do what the kick says: spawn the stream's writer, or be the datagram lane's.
    fn run(self: &Arc<Self>, kick: Kick, carrier: Option<&Arc<dyn Carrier>>) {
        if kick.stream {
            self.spawn_stream();
        }
        if kick.datagram
            && let Some(carrier) = carrier
        {
            self.write_datagrams(carrier, true);
        }
    }

    fn kicks(&self, st: &mut State) -> Kick {
        let mut kick = Kick::default();
        let blocked = self.drain_requested.load(Ordering::Acquire) == self.slot.generation();
        if !st.latest.is_empty() && !st.datagram_writing && !blocked {
            st.datagram_writing = true;
            kick.datagram = true;
        }
        if (!st.fifo.is_empty() || !st.big.is_empty()) && !st.stream_writing {
            st.stream_writing = true;
            kick.stream = true;
        }
        kick
    }

    /// Put the emission in its queue, under the lock. Nothing changes when it is refused or must
    /// wait.
    fn enqueue(
        &self,
        st: &mut State,
        path: &Name,
        payload: &Bytes,
        opts: &EmitOptions,
        now: Instant,
        carrier: Option<&Arc<dyn Carrier>>,
    ) -> Result<Step, Refused> {
        self.refresh_key(st);
        if st.ended {
            return Err(Refused::Gone);
        }
        if let Mode::Window(window) = opts.mode {
            st.window = window.clamped();
        }
        let routed = carrier.filter(|_| self.live.receivers.load(Ordering::Acquire) > 0);
        let stand_secs = opts.stand.map(|d| d.as_secs().max(1));
        if st.next_seq + SEQ_HEADROOM >= SEQ_END {
            // The last sequences are kept for this: the channel ends, and says so on the stream.
            if let Some(key) = self.keys.current() {
                self.queue_end(st, &key, carrier.is_some_and(|c| c.has_stream()));
            }
            st.ended = true;
            self.keys.exhausted();
            return Err(EmitError::SequenceExhausted.into());
        }
        if let Some(c) = carrier {
            if self.mode != ChannelMode::Latest && !c.has_stream() {
                return Err(EmitError::NoStream {
                    what: if self.mode == ChannelMode::Reliable {
                        "Reliable"
                    } else {
                        "Window"
                    },
                }
                .into());
            }
            if opts.stand.is_some() && !c.has_stream() {
                return Err(EmitError::NoStream {
                    what: "a standing value",
                }
                .into());
            }
        }
        if payload.len() > self.message_limit {
            return Err(EmitError::TooLarge {
                what: "message",
                size: payload.len(),
                max: self.message_limit,
            }
            .into());
        }
        let Some(carrier) = routed else {
            return self.quiet(st, path, payload, opts, stand_secs, now);
        };
        let stream = carrier.has_stream();

        // What the message would be, without changing anything.
        let peeked = st.table.peek(path, now);
        let fresh_octets = match peeked {
            Some(_) => None,
            None => Some(table::name_octets(path)),
        };
        let (name_len, named_wanted) = match (&peeked, &fresh_octets) {
            (Some((_, named, len)), _) => (*len, *named),
            (None, Some(octets)) => (octets.len(), true),
            (None, None) => (0, true),
        };
        if name_len > NAME_MAX {
            return Err(EmitError::TooLarge {
                what: "name",
                size: name_len,
                max: NAME_MAX,
            }
            .into());
        }
        let named = named_wanted || !stream;
        let zeros = [0u8; NAME_MAX];
        let probe = OutMessage {
            name_id: peeked.map_or(limits::NAMES_PER_CHANNEL, |(id, _, _)| id),
            name: named.then_some(&zeros[..name_len]),
            stand_secs,
            origin: None,
            payload,
        };
        let need = FRAME_OVERHEAD
            + probe
                .encoded_len(self.message_limit)
                .map_err(|e| EmitError::TooLarge {
                    what: "message",
                    size: payload.len(),
                    max: match e {
                        super::message::MessageError::TooLarge { max, .. } => max,
                        _ => self.message_limit,
                    },
                })?;
        let big = self.mode == ChannelMode::Latest
            && need > limits::datagram_limit(carrier.datagram_max(), FRAME_CAP);
        if big && !stream {
            return Err(EmitError::TooLarge {
                what: "message that fits no datagram on a path with no stream",
                size: need,
                max: limits::datagram_limit(carrier.datagram_max(), FRAME_CAP),
            }
            .into());
        }
        let name_for_standing = fresh_octets.clone();
        if opts.stand.is_some() {
            let octets = match &name_for_standing {
                Some(o) => o.clone(),
                None => table::name_octets(path),
            };
            if let Err(full) = st.standing.check(&octets, payload.len(), now) {
                return Err(stand_refused(full).into());
            }
        }
        // Room, for the FIFO modes.
        if self.mode != ChannelMode::Latest {
            let over = st.fifo.data_bytes() + payload.len() > self.queue_bytes;
            if over {
                match opts.congestion {
                    Congestion::Block => return Ok(Step::Wait),
                    Congestion::Drop => {
                        if st.fifo.data_bytes() + payload.len()
                            > self.queue_bytes + st.fifo.evictable_bytes()
                        {
                            return Err(EmitError::Congested {
                                retry_after: CONGESTED_RETRY,
                            }
                            .into());
                        }
                        while st.fifo.data_bytes() + payload.len() > self.queue_bytes {
                            if st.fifo.evict_oldest_data().is_none() {
                                break;
                            }
                            self.stats.dropped.bump();
                        }
                    }
                }
            }
        }

        // Nothing can refuse the emission now.
        // The id `peek` read under this same lock: the path is not hashed again.
        let used = match peeked.and_then(|(id, _, _)| st.table.touch_id(id, now)) {
            Some(used) => used,
            None => {
                let octets = fresh_octets.unwrap_or_else(|| table::name_octets(path));
                st.bind(&self.stats, path, octets, now, stream)
                    .map_err(Refused::Error)?
            }
        };
        let seq = st.take_seq();
        if let Some(stand) = opts.stand {
            let _ = st
                .standing
                .set(used.octets.clone(), seq, payload.clone(), stand, now);
        } else {
            st.standing.clear(&used.octets);
        }
        let message = Pending {
            seq,
            id: used.id,
            name: used.octets,
            named: used.named || !stream,
            stand: stand_secs,
            origin: None,
            payload: payload.clone(),
            repacked: false,
            at: now,
            inflight: false,
        };
        self.stats.emitted.bump();
        if self.mode == ChannelMode::Latest {
            // A message that is in a frame being written is sent whatever replaces it: only one
            // that was never going to be sent counts as replaced.
            let id = message.id;
            let (older, other) = if big {
                (st.big.put(message), st.latest.take(id))
            } else {
                (st.latest.put(message), st.big.take(id))
            };
            let lost = |old: Option<Pending>| old.is_some_and(|o| !o.inflight);
            if lost(older) | lost(other) {
                self.stats.replaced.bump();
            }
            while st.latest.bytes() + st.big.bytes() > self.queue_bytes {
                let dropped = st.latest.pop_oldest().or_else(|| st.big.pop_oldest());
                if dropped.is_none() {
                    break;
                }
                self.stats.dropped.bump();
            }
        } else {
            st.fifo.push(Item::Data(message));
        }
        Ok(Step::Done(self.kicks(st)))
    }

    /// An emission nobody receives: nothing is sent. A standing value is still held, and a
    /// `Window` message goes into the window, for a receiver that joins later.
    fn quiet(
        &self,
        st: &mut State,
        path: &Name,
        payload: &Bytes,
        opts: &EmitOptions,
        stand_secs: Option<u64>,
        now: Instant,
    ) -> Result<Step, Refused> {
        self.stats.unrouted.bump();
        let window = matches!(opts.mode, Mode::Window(_));
        if !window && opts.stand.is_none() {
            return Ok(Step::Done(Kick::default()));
        }
        let octets = table::name_octets(path);
        if octets.len() > NAME_MAX {
            return Err(EmitError::TooLarge {
                what: "name",
                size: octets.len(),
                max: NAME_MAX,
            }
            .into());
        }
        if opts.stand.is_some()
            && let Err(full) = st.standing.check(&octets, payload.len(), now)
        {
            return Err(stand_refused(full).into());
        }
        let seq = st.take_seq();
        match opts.stand {
            Some(stand) => {
                let _ = st
                    .standing
                    .set(octets.clone(), seq, payload.clone(), stand, now);
            }
            None => st.standing.clear(&octets),
        }
        if window {
            let held = Held {
                seq,
                name: octets,
                payload: payload.clone(),
                at: now,
            };
            let w = st.window;
            st.history.record(held, &w, now);
        }
        let _ = stand_secs;
        Ok(Step::Done(Kick::default()))
    }

    // ---- the datagram lane ----------------------------------------------------------------

    /// Write what waits on the datagram lane. The caller set `datagram_writing`.
    ///
    /// `inline`: the writer is an emitter, which stops after [`COMBINE_MAX`] frames and gives the
    /// rest to the carrier's writer task; the carrier's own task (`inline` false) writes until
    /// nothing waits or the carrier refuses.
    fn write_datagrams(self: &Arc<Self>, carrier: &Arc<dyn Carrier>, inline: bool) {
        let mut frames = 0usize;
        let mut shrunk: Option<usize> = None;
        loop {
            if inline && frames >= COMBINE_MAX {
                let more = {
                    let mut st = self.state.lock();
                    st.latest.prune_front();
                    st.datagram_writing = false;
                    !st.latest.is_empty()
                };
                if more {
                    self.request_drain(carrier);
                }
                return;
            }
            let mut packed = match self.pack_datagram(carrier, shrunk) {
                Pack::Frame(p) => p,
                Pack::Gone => return,
                Pack::Idle => {
                    // An emitter wrote and nothing else waits: the emissions that follow without
                    // the emitter stopping (a loop) must not each be a frame of one. They queue
                    // behind a call back the carrier makes from its own writer task, and leave
                    // together. The first of a burst keeps the idle link's latency.
                    if inline && frames > 0 {
                        self.request_drain(carrier);
                    }
                    return;
                }
            };
            let count = packed.writer.len();
            let seq0 = packed.seq0;
            let cipher = Arc::clone(&packed.cipher);
            let scratch = std::mem::take(&mut packed.scratch);
            let frame = match packed.writer.seal(&cipher) {
                Ok(frame) => frame,
                Err(_) => {
                    self.stats.seal_failed.bump();
                    self.finish_datagram(scratch, seq0, None, 0);
                    continue;
                }
            };
            match carrier.try_send_datagram(frame.clone()) {
                Ok(()) => {
                    shrunk = None;
                    self.finish_datagram(scratch, seq0, Some(&frame), count);
                    frames += 1;
                }
                Err(CarrierRefused::Full) => {
                    self.stats.full.bump();
                    {
                        let mut st = self.state.lock();
                        for _ in 0..st.latest.unmark_inflight(&scratch) {
                            self.stats.replaced.bump();
                        }
                        st.scratch = scratch;
                        st.datagram_writing = false;
                    }
                    self.request_drain(carrier);
                    return;
                }
                Err(CarrierRefused::TooLarge { max }) => {
                    let repacked_before = shrunk.is_some();
                    shrunk = Some(max);
                    self.resize(scratch, repacked_before);
                }
                Err(CarrierRefused::Closed) => {
                    let mut st = self.state.lock();
                    st.scratch = scratch;
                    st.lose_pending(&self.stats);
                    st.datagram_writing = false;
                    drop(st);
                    self.room.notify_waiters();
                    return;
                }
            }
        }
    }

    /// The frame was handed over (`frame` is `Some`) or could not be sealed: the messages in it
    /// leave the queue.
    fn finish_datagram(
        &self,
        scratch: Vec<(u64, u64)>,
        seq0: u64,
        frame: Option<&Bytes>,
        count: usize,
    ) {
        let mut st = self.state.lock();
        for &(id, seq) in &scratch {
            st.latest.commit(id, seq);
        }
        if let Some(frame) = frame {
            st.sent.record(seq0, frame);
            self.stats.note_frame(SideClass::Datagram, count);
        }
        st.scratch = scratch;
    }

    /// The path's size fell under a frame: its messages take **new** sequences and are packed
    /// once more at the new size; messages of a frame that fell a second time go to the stream.
    fn resize(self: &Arc<Self>, scratch: Vec<(u64, u64)>, second: bool) {
        let mut st = self.state.lock();
        let stream = self.slot.get().is_some_and(|c| c.has_stream());
        for &(id, seq) in &scratch {
            self.stats.resized.bump();
            if second {
                match st.latest.take_if(id, seq) {
                    Some(p) if stream => {
                        let _ = st.big.put(p);
                    }
                    Some(_) => self.stats.lost_closed.bump(),
                    None => self.stats.replaced.bump(),
                }
            } else {
                let new = st.next_seq;
                if st.latest.resequence(id, seq, new) {
                    st.next_seq += 1;
                } else {
                    // A newer message replaced it while the frame was written: it is not sent.
                    self.stats.replaced.bump();
                }
            }
        }
        st.scratch = scratch;
        if second && !st.big.is_empty() && !st.stream_writing {
            st.stream_writing = true;
            drop(st);
            self.spawn_stream();
        }
    }

    /// Pack the oldest run of consecutive sequences of the datagram lane into one frame, under
    /// the lock; nothing leaves the queue yet.
    fn pack_datagram(self: &Arc<Self>, carrier: &Arc<dyn Carrier>, cap: Option<usize>) -> Pack {
        let mut st = self.state.lock();
        self.refresh_key(&mut st);
        if st.ended {
            if st.ending {
                st.lose_latest(&self.stats);
            } else {
                st.lose_pending(&self.stats);
            }
            st.datagram_writing = false;
            drop(st);
            self.room.notify_waiters();
            return Pack::Gone;
        }
        let stream = carrier.has_stream();
        loop {
            st.latest.prune_front();
            let Some(head) = st.latest.iter().next().map(|p| p.seq) else {
                st.datagram_writing = false;
                return Pack::Idle;
            };
            let mut room = limits::datagram_limit(carrier.datagram_max(), FRAME_CAP);
            if let Some(cap) = cap {
                room = room.min(cap.max(MIN_FRAME_LEN));
            }
            let capacity = room.min(FRAME_OVERHEAD + st.latest.bytes() + 16 * st.latest.len());
            let mut writer = match MessageWriter::new(
                SideClass::Datagram,
                self.id,
                st.key_epoch as u8,
                head,
                room,
                capacity,
                self.message_limit,
            ) {
                Ok(w) => w,
                Err(_) => {
                    // The room is no frame's: nothing fits. Drop the head message.
                    if let Some(p) = st.latest.pop_oldest() {
                        let _ = p;
                        self.stats.dropped.bump();
                    }
                    continue;
                }
            };
            let mut scratch = std::mem::take(&mut st.scratch);
            scratch.clear();
            let mut expect = head;
            let mut unfit: Option<(u64, bool)> = None;
            for p in st.latest.iter() {
                if p.seq != expect {
                    break;
                }
                match writer.push(&p.out()) {
                    Ok(()) => {
                        scratch.push((p.id, p.seq));
                        expect += 1;
                    }
                    Err(WriteError::Full { .. }) if writer.is_empty() => {
                        unfit = Some((p.id, true));
                        break;
                    }
                    Err(WriteError::Full { .. } | WriteError::CountFull) => break,
                    Err(WriteError::Invalid(_)) => {
                        unfit = Some((p.id, false));
                        break;
                    }
                }
            }
            if let Some((id, to_stream)) = unfit {
                // The message fits no datagram now (the path's size fell, or it never did).
                if let Some(p) = st.latest.take(id) {
                    if to_stream && stream {
                        self.stats.resized.bump();
                        let _ = st.big.put(p);
                    } else if to_stream {
                        self.stats.lost_closed.bump();
                    } else {
                        self.stats.dropped.bump();
                    }
                }
                st.scratch = scratch;
                if !st.big.is_empty() && !st.stream_writing {
                    st.stream_writing = true;
                    self.spawn_stream();
                }
                continue;
            }
            if writer.is_empty() {
                st.scratch = scratch;
                continue;
            }
            st.latest.mark_inflight(&scratch);
            return Pack::Frame(Packed {
                writer,
                cipher: Arc::clone(&st.cipher),
                seq0: head,
                scratch,
            });
        }
    }

    /// Ask the carrier to call the datagram drain once it takes datagrams again.
    fn request_drain(self: &Arc<Self>, carrier: &Arc<dyn Carrier>) {
        let generation = self.slot.generation();
        if self.drain_requested.swap(generation, Ordering::AcqRel) == generation {
            return;
        }
        let (me, c) = (Arc::clone(self), Arc::clone(carrier));
        carrier.on_ready(Box::new(move || {
            let _ = me.drain_requested.compare_exchange(
                generation,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            me.drain_from_carrier(&c);
        }));
    }

    fn drain_from_carrier(self: &Arc<Self>, carrier: &Arc<dyn Carrier>) {
        {
            let mut st = self.state.lock();
            st.latest.prune_front();
            if st.datagram_writing || st.latest.is_empty() {
                return;
            }
            st.datagram_writing = true;
        }
        self.write_datagrams(carrier, false);
    }

    // ---- the stream lane ------------------------------------------------------------------

    fn spawn_stream(self: &Arc<Self>) {
        let me = Arc::clone(self);
        self.tasks.spawn(async move { me.write_stream().await });
    }

    /// The stream lane's writer: one frame at a time, in the order of the sequences, until
    /// nothing waits. The caller set `stream_writing`.
    async fn write_stream(self: Arc<Self>) {
        let Some(carrier) = self.slot.get() else {
            let mut st = self.state.lock();
            st.lose_pending(&self.stats);
            st.stream_writing = false;
            drop(st);
            self.room.notify_waiters();
            return;
        };
        loop {
            let (frame, done, seq0, count) = match self.pack_stream(&carrier) {
                StreamPack::Idle | StreamPack::Gone => return,
                StreamPack::Control {
                    seq,
                    body,
                    cipher,
                    epoch,
                } => {
                    let sealed =
                        Header::new(SideClass::Stream, SideKind::Control, self.id, epoch, seq, 0)
                            .and_then(|h| frame::seal(&cipher, &h, &body));
                    match sealed {
                        Ok(frame) => (frame, Done::Control, seq, 0),
                        Err(_) => {
                            self.stats.seal_failed.bump();
                            self.finish_stream(Done::Control, None);
                            continue;
                        }
                    }
                }
                StreamPack::Data {
                    mut packed,
                    from_fifo,
                } => {
                    let (count, seq0) = (packed.writer.len(), packed.seq0);
                    let scratch = std::mem::take(&mut packed.scratch);
                    let done = if from_fifo {
                        Done::Fifo
                    } else {
                        Done::Big(scratch)
                    };
                    match packed.writer.seal(&packed.cipher) {
                        Ok(frame) => (frame, done, seq0, count),
                        Err(_) => {
                            self.stats.seal_failed.bump();
                            self.finish_stream(done, None);
                            continue;
                        }
                    }
                }
            };
            match carrier.send_stream(frame.clone()).await {
                Ok(()) => self.finish_stream(done, Some((seq0, &frame, count))),
                Err(_) => {
                    let mut st = self.state.lock();
                    st.fifo.unmark();
                    st.lose_pending(&self.stats);
                    st.stream_writing = false;
                    drop(st);
                    self.room.notify_waiters();
                    return;
                }
            }
        }
    }

    /// A frame left (`sent` says which, and how many messages it carried) or could not be sealed
    /// (`sent` is `None`): take its items out of the queues, record the frame, hold its messages
    /// in the window, and wake the emitters that wait for room.
    fn finish_stream(&self, done: Done, sent: Option<(u64, &Bytes, usize)>) {
        let mut st = self.state.lock();
        let window_mode = self.mode == ChannelMode::Window && sent.is_some();
        match done {
            Done::Control => st.fifo.finish(|_| {}),
            Done::Fifo => {
                let window = st.window;
                let mut held = Vec::new();
                st.fifo.finish(|item| {
                    if let Item::Data(p) = item
                        && window_mode
                        && p.origin.is_none()
                    {
                        held.push(Held {
                            seq: p.seq,
                            name: p.name,
                            payload: p.payload,
                            at: p.at,
                        });
                    }
                });
                for h in held {
                    let at = h.at;
                    st.history.record(h, &window, at);
                }
            }
            Done::Big(scratch) => {
                for &(id, seq) in &scratch {
                    st.big.commit(id, seq);
                }
                st.scratch = scratch;
            }
        }
        if let Some((seq0, frame, count)) = sent {
            st.sent.record(seq0, frame);
            self.stats.note_frame(SideClass::Stream, count);
        }
        drop(st);
        self.room.notify_waiters();
    }

    /// Pack the next frame of the stream lane, under the lock.
    fn pack_stream(self: &Arc<Self>, carrier: &Arc<dyn Carrier>) -> StreamPack {
        let _ = carrier;
        let mut st = self.state.lock();
        self.refresh_key(&mut st);
        if st.ended && !st.ending {
            st.lose_pending(&self.stats);
            st.stream_writing = false;
            drop(st);
            self.room.notify_waiters();
            return StreamPack::Gone;
        }
        let epoch = st.key_epoch as u8;
        let limit = limits::STREAM_FRAME_DEFAULT;
        enum Head {
            Control(u64, Bytes),
            Data(u64),
            Nothing,
        }
        let head = match st.fifo.iter().next() {
            Some(Item::Control { seq, body }) => Head::Control(*seq, body.clone()),
            Some(Item::Data(p)) => Head::Data(p.seq),
            None => Head::Nothing,
        };
        match head {
            Head::Control(seq, body) => {
                st.fifo.mark_inflight(1);
                StreamPack::Control {
                    seq,
                    body,
                    cipher: Arc::clone(&st.cipher),
                    epoch,
                }
            }
            Head::Data(seq0) => {
                let capacity =
                    limit.min(FRAME_OVERHEAD + st.fifo.data_bytes() + 32 * st.fifo.len());
                let Ok(mut writer) = MessageWriter::new(
                    SideClass::Stream,
                    self.id,
                    epoch,
                    seq0,
                    limit,
                    capacity,
                    self.message_limit,
                ) else {
                    st.stream_writing = false;
                    return StreamPack::Gone;
                };
                let (mut items, mut expect) = (0usize, seq0);
                let mut bad = false;
                for item in st.fifo.iter() {
                    let Item::Data(p) = item else { break };
                    if p.seq != expect {
                        break;
                    }
                    match writer.push(&p.out()) {
                        Ok(()) => {
                            items += 1;
                            expect += 1;
                        }
                        Err(WriteError::Invalid(_)) => {
                            bad = items == 0;
                            break;
                        }
                        Err(_) => break,
                    }
                }
                if bad || items == 0 {
                    // A message no frame can carry (never expected: the limits are checked at
                    // emit): drop it so the lane goes on.
                    st.fifo.mark_inflight(1);
                    st.fifo.finish(|_| {});
                    self.stats.dropped.bump();
                    drop(st);
                    return self.pack_stream(carrier);
                }
                st.fifo.mark_inflight(items);
                StreamPack::Data {
                    packed: Packed {
                        writer,
                        cipher: Arc::clone(&st.cipher),
                        seq0,
                        scratch: Vec::new(),
                    },
                    from_fifo: true,
                }
            }
            Head::Nothing => {
                if st.ending {
                    // The FIFO and the `END` after it are written; what only `big` held is lost.
                    st.lose_big(&self.stats);
                    st.stream_writing = false;
                    drop(st);
                    self.room.notify_waiters();
                    return StreamPack::Idle;
                }
                st.big.prune_front();
                let Some(head) = st.big.iter().next().map(|p| p.seq) else {
                    st.stream_writing = false;
                    return StreamPack::Idle;
                };
                let capacity = limit.min(FRAME_OVERHEAD + st.big.bytes() + 32 * st.big.len());
                let Ok(mut writer) = MessageWriter::new(
                    SideClass::Stream,
                    self.id,
                    epoch,
                    head,
                    limit,
                    capacity,
                    self.message_limit,
                ) else {
                    st.stream_writing = false;
                    return StreamPack::Gone;
                };
                let mut scratch = std::mem::take(&mut st.scratch);
                scratch.clear();
                for (expect, p) in (head..).zip(st.big.iter()) {
                    if p.seq != expect || writer.push(&p.out()).is_err() {
                        break;
                    }
                    scratch.push((p.id, p.seq));
                }
                if scratch.is_empty() {
                    // Nothing in the head fits (never expected): drop it.
                    st.scratch = scratch;
                    if let Some(p) = st.big.pop_oldest() {
                        let _ = p;
                        self.stats.dropped.bump();
                    }
                    drop(st);
                    return self.pack_stream(carrier);
                }
                st.big.mark_inflight(&scratch);
                StreamPack::Data {
                    packed: Packed {
                        writer,
                        cipher: Arc::clone(&st.cipher),
                        seq0: head,
                        scratch,
                    },
                    from_fifo: false,
                }
            }
        }
    }

    // ---- a new receiver ---------------------------------------------------------------------

    /// A receiver was judged in: what its session says of this sender, and, when the stream
    /// exists, the frames that follow the session on it, in this order: `HELLO` (the sequence the
    /// next message takes), the binds the session's table did not take, the standing values
    /// between `STANDING_BEGIN` and `STANDING_END`, and, in `Window` mode, the replay of the
    /// window from `since` (all of it when the receiver names none).
    ///
    /// `fresh`: the device was not a receiver before; others (a renewal, a re-ask) are given
    /// nothing but the replay of a window they name a start for.
    pub(crate) fn welcome(
        self: &Arc<Self>,
        fresh: bool,
        since: Option<u64>,
        now: Instant,
    ) -> Terms {
        let carrier = self.slot.get();
        let stream = carrier.as_ref().is_some_and(|c| c.has_stream());
        let mut st = self.state.lock();
        self.refresh_key(&mut st);
        let (inside, rest) = st.table.split_for_session();
        let terms = Terms {
            table: inside
                .into_iter()
                .map(|b| wire::Bind {
                    id: b.id,
                    name: b.name,
                })
                .collect(),
            window: (self.mode == ChannelMode::Window).then(|| wire::Window {
                messages: st.window.messages as u64,
                bytes: st.window.bytes as u64,
                ms: st.window.age.as_millis() as u64,
            }),
            frame_max: FRAME_CAP as u64,
            seq: st.next_seq,
        };
        let replay_window = self.mode == ChannelMode::Window && (fresh || since.is_some());
        if !stream || st.ended || !(fresh || replay_window) {
            return terms;
        }
        let room = |st: &State, n: u64| st.next_seq + n + SEQ_HEADROOM < SEQ_END;
        if fresh && room(&st, 1) {
            let next = st.next_seq + 1;
            st.control(&Control::Hello { seq: next });
            for bound in rest {
                if room(&st, 1) {
                    st.control(&Control::Bind {
                        id: bound.id,
                        name: bound.octets,
                    });
                }
            }
        }
        // What is replayed names itself, but its names are bound first, so the brackets of the
        // standing values hold messages and nothing else.
        let mut standing = Vec::new();
        if fresh {
            for (stood, left) in st.standing.replay(now) {
                if let Some(used) = self.replay_binding(&mut st, &stood.name, now) {
                    standing.push((stood, left, used));
                }
            }
        }
        let mut replay = Vec::new();
        if replay_window {
            let window = st.window;
            for held in st.history.since(since, &window, now) {
                if let Some(used) = self.replay_binding(&mut st, &held.name, now) {
                    replay.push((held, used));
                }
            }
        }
        if !standing.is_empty() && room(&st, 2 + standing.len() as u64) {
            st.control(&Control::StandingBegin);
            for (stood, left, used) in standing {
                let seq = st.take_seq();
                self.stats.replayed.bump();
                st.fifo.push(Item::Data(Pending {
                    seq,
                    id: used.id,
                    name: used.octets,
                    named: true,
                    stand: Some(left),
                    origin: Some(Origin::Standing(stood.seq)),
                    payload: stood.payload,
                    repacked: false,
                    at: now,
                    inflight: false,
                }));
            }
            st.control(&Control::StandingEnd);
        }
        if room(&st, replay.len() as u64 + 1) {
            for (held, used) in replay {
                let seq = st.take_seq();
                self.stats.replayed.bump();
                st.fifo.push(Item::Data(Pending {
                    seq,
                    id: used.id,
                    name: used.octets,
                    named: true,
                    stand: None,
                    origin: Some(Origin::Replayed(held.seq)),
                    payload: held.payload,
                    repacked: false,
                    at: now,
                    inflight: false,
                }));
            }
        }
        let kick = self.kicks(&mut st);
        drop(st);
        if kick.stream {
            self.spawn_stream();
        }
        terms
    }

    /// The id a replayed message of the name with these octets carries (it names itself, so the
    /// id only has to be unique): the bound one, or a new bind.
    fn replay_binding(&self, st: &mut State, octets: &Bytes, now: Instant) -> Option<Use> {
        let name = Name::decode(octets.clone()).ok()?;
        if let Some(used) = st.table.touch(&name, now) {
            return Some(used);
        }
        st.bind(&self.stats, &name, octets.clone(), now, true).ok()
    }

    /// Everything that waits is on its way or counted: no frame is pending and no writer is
    /// active (a test asks).
    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        let st = self.state.lock();
        st.latest.is_empty()
            && st.big.is_empty()
            && st.fifo.is_empty()
            && !st.datagram_writing
            && !st.stream_writing
    }

    /// The carrier calls back, as its writer task does (a test stands in for that task).
    #[cfg(test)]
    pub(crate) fn call_back(self: &Arc<Self>) {
        if let Some(carrier) = self.slot.get() {
            let generation = self.slot.generation();
            let _ = self.drain_requested.compare_exchange(
                generation,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            self.drain_from_carrier(&carrier);
        }
    }

    /// Messages waiting in the queues (a test asks).
    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        let st = self.state.lock();
        st.latest.len() + st.big.len() + st.fifo.len()
    }

    /// Hashes in the ring of sent frames (a test asks).
    #[cfg(test)]
    pub(crate) fn sent_frames(&self) -> usize {
        self.state.lock().sent.len()
    }

    /// Names bound (a test asks).
    #[cfg(test)]
    pub(crate) fn names(&self) -> usize {
        self.state.lock().table.len()
    }

    /// How many times the name table hashed a name (a test asks).
    #[cfg(test)]
    pub(crate) fn table_lookups(&self) -> u64 {
        self.state.lock().table.lookups()
    }
}

/// What `enqueue` decided.
enum Step {
    Done(Kick),
    Wait,
}

fn stand_refused(full: StandFull) -> EmitError {
    match full {
        StandFull::Names { would_be } => EmitError::TooLarge {
            what: "standing names in one channel",
            size: would_be,
            max: super::verbs::STANDING_NAMES_MAX,
        },
        StandFull::Bytes { would_be } => EmitError::TooLarge {
            what: "standing octets in one channel",
            size: would_be,
            max: super::verbs::STANDING_BYTES_MAX,
        },
    }
}

/// The channels a node sends on and what they share: the fixed route, the counters.
#[derive(Default)]
pub(crate) struct Tx {
    /// The carrier every frame goes to (the node's fixed route, stage 3).
    pub(crate) carrier: Arc<CarrierSlot>,
    /// What the frame layer counted.
    pub(crate) stats: Arc<TxStats>,
    channels: parking_lot::RwLock<super::FastMap<Name, [Option<Arc<TxChannel>>; 3]>>,
}

fn index(mode: ChannelMode) -> usize {
    match mode {
        ChannelMode::Latest => 0,
        ChannelMode::Reliable => 1,
        ChannelMode::Window => 2,
    }
}

impl Tx {
    /// The sender of `(space, mode)`, if there is one.
    pub(crate) fn get(&self, space: &Name, mode: ChannelMode) -> Option<Arc<TxChannel>> {
        self.channels.read().get(space)?[index(mode)].clone()
    }

    /// The sender of `(space, mode)` for the channel `id`: the one held if it is of that channel
    /// and the channel did not end, else the one `make` builds (under the lock, so two callers
    /// never make two senders of one channel: they would share a sequence counter's nonces).
    pub(crate) fn get_or_make(
        &self,
        space: &Name,
        mode: ChannelMode,
        id: u64,
        make: impl FnOnce() -> Arc<TxChannel>,
    ) -> Arc<TxChannel> {
        let mut channels = self.channels.write();
        let slot = &mut channels.entry(space.clone()).or_default()[index(mode)];
        if let Some(held) = slot
            && held.id == id
            && !held.live.closed.load(Ordering::Acquire)
        {
            return Arc::clone(held);
        }
        let made = make();
        *slot = Some(Arc::clone(&made));
        made
    }
}
