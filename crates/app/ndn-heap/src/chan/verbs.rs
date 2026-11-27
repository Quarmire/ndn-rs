//! The public types of the verbs: what `Heap::emit` takes and refuses, and what a receiver's
//! `Items` yields (docs/specs/channel.md, Modes and The verbs: put, emit, get).
//!
//! One place declares them so the sender (`emit`) and the receiver (`get`) agree: the options, the
//! modes, the error with its [`NextStep`], and the item a receiver gets.

use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;

use super::sessions::EndReason;
use super::wire::ChannelMode;
use crate::error::{NextStep, Refusal};
use crate::query::{Answered, Ask, QueryError};
use crate::register::EntryId;

/// The longest stand lifetime: one hour.
pub const STAND_MAX: Duration = Duration::from_secs(3600);

/// The most standing names one channel holds.
pub const STANDING_NAMES_MAX: usize = 256;

/// The most octets of standing payloads one channel holds.
pub const STANDING_BYTES_MAX: usize = 64 * 1024;

/// What a receiver of `get` wants: one path or everything under a prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Select {
    /// This path exactly.
    Path(Name),
    /// This path and everything below it (the empty name: everything).
    Prefix(Name),
}

impl Select {
    /// Whether a kept value or an emission at `path` is wanted.
    pub fn matches(&self, path: &Name) -> bool {
        match self {
            Select::Path(want) => path == want,
            Select::Prefix(prefix) => path.has_prefix(prefix),
        }
    }
}

/// What a `Window` channel's sender keeps and replays to a joiner: the least of the three limits
/// holds. Clamped to [`Window::MAX`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// The most messages kept.
    pub messages: usize,
    /// The most payload octets kept.
    pub bytes: usize,
    /// How long a message stays in the window.
    pub age: Duration,
}

impl Window {
    /// The default: the last 256 messages, 1 MiB, 10 s, whichever is least.
    pub const DEFAULT: Window = Window {
        messages: 256,
        bytes: 1 << 20,
        age: Duration::from_secs(10),
    };

    /// The most a window may be asked to keep: 4,096 messages, 16 MiB, 5 minutes.
    pub const MAX: Window = Window {
        messages: 4_096,
        bytes: 16 << 20,
        age: Duration::from_secs(300),
    };

    /// This window with each limit at most [`Window::MAX`]'s (a larger one is clamped, not refused)
    /// and at least one message and one octet.
    pub fn clamped(self) -> Window {
        Window {
            messages: self.messages.clamp(1, Self::MAX.messages),
            bytes: self.bytes.clamp(1, Self::MAX.bytes),
            age: self.age.min(Self::MAX.age).max(Duration::from_millis(1)),
        }
    }
}

impl Default for Window {
    fn default() -> Self {
        Window::DEFAULT
    }
}

/// How an emission travels and what it guarantees.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Mode {
    /// The newest per name; an older message is never delivered after a newer; loss is allowed;
    /// never blocks. The default.
    #[default]
    Latest,
    /// Every message, in the channel's order, or a visible gap; on the stream.
    Reliable,
    /// [`Mode::Reliable`] plus a replayable history a joiner asks for.
    Window(Window),
}

impl Mode {
    /// The channel mode a message of this mode goes to.
    pub(crate) fn channel(&self) -> ChannelMode {
        match self {
            Mode::Latest => ChannelMode::Latest,
            Mode::Reliable => ChannelMode::Reliable,
            Mode::Window(_) => ChannelMode::Window,
        }
    }
}

/// What a sender does when the local queue is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Congestion {
    /// Drop the oldest queued message and count it. For [`Mode::Latest`] the only choice: a newer
    /// emission replaces an unsent older one of its name.
    #[default]
    Drop,
    /// Wait for queue room (`emit().await` is pending until there is). Not for [`Mode::Latest`].
    Block,
}

/// What `Heap::emit` is given besides the path and the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct EmitOptions {
    /// How it travels; [`Mode::Latest`] by default.
    pub mode: Mode,
    /// Let this emission stand for a receiver that joins later, for this long (at most
    /// [`STAND_MAX`]): the sender holds the last emission of the path and replays it to a new
    /// session as the first frames after it starts. At most [`STANDING_NAMES_MAX`] names and
    /// [`STANDING_BYTES_MAX`] octets per channel. `None`: nothing stands, and an earlier standing
    /// value of the path is dropped (the last emission of a path is the one that stands).
    pub stand: Option<Duration>,
    /// What to do when the queue is full. The default [`Congestion::Drop`] is the default of
    /// `Latest` only: [`EmitOptions::reliable`] and [`EmitOptions::window`] say
    /// [`Congestion::Block`].
    pub congestion: Congestion,
}

impl EmitOptions {
    /// `Latest`, never blocking: the default.
    pub fn latest() -> Self {
        Self::default()
    }

    /// `Reliable`, blocking when the queue is full.
    pub fn reliable() -> Self {
        Self {
            mode: Mode::Reliable,
            stand: None,
            congestion: Congestion::Block,
        }
    }

    /// `Window` keeping `window`, blocking when the queue is full.
    pub fn window(window: Window) -> Self {
        Self {
            mode: Mode::Window(window),
            stand: None,
            congestion: Congestion::Block,
        }
    }

    /// The same, standing for `lifetime` (see [`EmitOptions::stand`]).
    pub fn standing(mut self, lifetime: Duration) -> Self {
        self.stand = Some(lifetime);
        self
    }

    /// The same with `congestion`.
    pub fn on_congestion(mut self, congestion: Congestion) -> Self {
        self.congestion = congestion;
        self
    }
}

/// Why `Heap::emit` refused. [`EmitError::next`] says what to do. A sender with no receiver is
/// **not** an error: it sends nothing and returns at once.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EmitError {
    /// This device is no writer of the space: only a writer's device emits.
    #[error("this device may not emit in {space}: {why}")]
    NotWriter {
        /// The space.
        space: Name,
        /// Why, and what to do.
        why: String,
    },
    /// The space is not open here as a member, or its record is not held yet.
    #[error("{space} is not ready for live data: {why}; try again later, unchanged")]
    NotReady {
        /// The space.
        space: Name,
        /// Why.
        why: String,
    },
    /// Something is over a limit.
    #[error(
        "{what}: {size} is over the limit of {max}; send less (split the message, emit fewer \
         names, or stand fewer values)"
    )]
    TooLarge {
        /// What is over its limit.
        what: &'static str,
        /// How much was asked.
        size: usize,
        /// The limit.
        max: usize,
    },
    /// The local queue is full of what cannot be dropped, and the emission asked not to wait.
    #[error(
        "the send queue is full and nothing in it can be dropped; try again in {retry_after:?}"
    )]
    Congested {
        /// When to try again.
        retry_after: Duration,
    },
    /// The mode needs an ordered stream and this path has none.
    #[error(
        "this path has no ordered stream, which {what} needs; emit with Mode::Latest, or put the \
         value instead"
    )]
    NoStream {
        /// What needs the stream (a mode, a stand, a message that fits no datagram).
        what: &'static str,
    },
    /// The request, as given, asks for something no sender does.
    #[error("{why}")]
    FixRequest {
        /// What is wrong and what to ask for instead.
        why: String,
    },
    /// The channel used its last sequence (2^63); it ends, and the next emission begins a new one.
    #[error(
        "the channel's sequence reached its limit and the channel ended: emit again to begin a \
         new channel (receivers ask again)"
    )]
    SequenceExhausted,
    /// This device's own failure.
    #[error("local failure: {reason}; fix this device")]
    Local {
        /// What failed.
        reason: String,
    },
}

impl EmitError {
    /// What to do about it, in the heap's vocabulary.
    pub fn next(&self) -> NextStep {
        match self {
            EmitError::NotWriter { .. } => NextStep::AskOwner,
            EmitError::NotReady { .. }
            | EmitError::Congested { .. }
            | EmitError::SequenceExhausted => NextStep::RetryLater,
            EmitError::TooLarge { .. }
            | EmitError::NoStream { .. }
            | EmitError::FixRequest { .. } => NextStep::FixRequest,
            EmitError::Local { .. } => NextStep::FixLocal,
        }
    }

    /// The refusal of `Latest` with [`Congestion::Block`].
    pub(crate) fn latest_blocks() -> Self {
        EmitError::FixRequest {
            why: "Latest never blocks; a newer emission replaces an older one. Use Reliable".into(),
        }
    }
}

/// Which channel modes a receiver joins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modes {
    /// Join the `Latest` channels.
    pub latest: bool,
    /// Join the `Reliable` channels.
    pub reliable: bool,
    /// Join the `Window` channels.
    pub window: bool,
}

impl Modes {
    /// Every mode a sender offers.
    pub const ALL: Modes = Modes {
        latest: true,
        reliable: true,
        window: true,
    };

    /// Only `mode`.
    pub fn only(mode: ChannelMode) -> Modes {
        Modes {
            latest: mode == ChannelMode::Latest,
            reliable: mode == ChannelMode::Reliable,
            window: mode == ChannelMode::Window,
        }
    }

    /// Whether `mode` is joined.
    pub fn contains(&self, mode: ChannelMode) -> bool {
        match mode {
            ChannelMode::Latest => self.latest,
            ChannelMode::Reliable => self.reliable,
            ChannelMode::Window => self.window,
        }
    }
}

impl Default for Modes {
    fn default() -> Self {
        Modes::ALL
    }
}

/// Whether `get` also receives emissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Live {
    /// Receive emissions (the default).
    #[default]
    Emitted,
    /// Kept values only (a follower may read these; it takes no part in channels).
    Off,
}

/// How far a receiver trusts frames before a signed checkpoint covers them (docs/specs/channel.md,
/// Checkpoints).
///
/// **Checkpoints detect; they do not prevent.** Between two checkpoints a holder of the channel
/// key (any receiver the sender admitted, or a member relaying) can alter or invent frames under
/// the sender's key, and a [`Trust::Prompt`] receiver delivers them: authenticated as "a holder of
/// the key's" inside the window [`ChannelConfig::checkpoint`](super::config::ChannelConfig)
/// states, as the sender's after a checkpoint that lists the frame verified. Silence is not trust
/// either way: frames older than `max(4 x period, 100 ms)` that no verified checkpoint has been
/// received for make a `Prompt` receiver hold what follows, and none within 3 s ends the session
/// ([`EndReason::Unverifiable`](super::sessions::EndReason)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Trust {
    /// Deliver a frame as soon as its AEAD opens (the default): lowest latency, forgeries by a
    /// key holder are delivered for at most the stated window and then exposed
    /// ([`GetNotice::Retracted`], [`crate::Alert::ChannelForgery`], evidence).
    #[default]
    Prompt,
    /// Deliver a frame only after a signed checkpoint that lists it (with the same hash)
    /// verified: it **prevents** delivery of a holder's forgeries, at up to one checkpoint period
    /// of latency (so it cannot meet the latency target). A frame the checkpoint does not list is
    /// dropped and is evidence. A checkpoint that was lost leaves its frames unlisted for good (a
    /// checkpoint covers only its own range): they are **dropped**, counted and told as
    /// [`GetNotice::Lagged`], never delivered unverified, as soon as a later checkpoint shows the
    /// range passed and after 3 s at the latest. A channel whose sender sends no checkpoints (its
    /// path has no stream) is never delivered to a `Verified` receiver: the `Items` are told
    /// [`EndReason::Unverifiable`](super::sessions::EndReason).
    Verified,
}

/// Which heads of a path `get` tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Heads {
    /// The winner of each path: the value `kept` reads. The default; what `get` always did.
    #[default]
    Winner,
    /// Every head, each as its own [`Kind::Kept`] with [`Kept::winner`] and
    /// [`Kept::supersedes`], at most [`HEADS_MAX`] per path (more is [`GetNotice::HeadsCapped`]),
    /// and [`GetNotice::HeadsEnded`] for a head that leaves with no successor. For a library that
    /// merges concurrent writes itself and puts the merge with `Heap::put_merged`. It tells
    /// heads, not history: a superseded entry is never told.
    All,
}

/// The most heads of one path an [`Heads::All`] stream tells.
pub const HEADS_MAX: usize = 64;

/// What a receiver of `get` asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetOptions {
    /// Deliver the kept values first, then the changes of kept values as they arrive (default
    /// `true`). With `false` the stream carries emissions only.
    pub kept: bool,
    /// Which heads of a path the kept values are: [`Heads::Winner`] (the default) or every head
    /// ([`Heads::All`]). Emissions are unaffected.
    pub heads: Heads,
    /// Whether to receive emissions (default [`Live::Emitted`]).
    pub live: Live,
    /// Which channel modes to join (default: all the senders offer).
    pub modes: Modes,
    /// Whether to wait for a signed checkpoint (default [`Trust::Prompt`]).
    pub trust: Trust,
    /// What a `Reliable` or `Window` receiver does when its queue is full: [`Congestion::Block`]
    /// stalls the stream (back pressure to the sender), [`Congestion::Drop`] discards the oldest and
    /// says [`GetNotice::Lagged`]. `Latest` ignores it. Default `Block`.
    pub congestion: Congestion,
    /// Ask the servers of the space a question: each answer is a [`Kind::Answered`] item and the
    /// stream says [`GetNotice::AnswersDone`] when every server asked has resolved. `None` (the
    /// default) asks nothing and `get` is what it always was. With `kept: false` and
    /// `live: Live::Off` the stream is a query alone: it ends after `AnswersDone`. See
    /// `docs/specs/query.md`.
    pub ask: Option<Ask>,
}

impl Default for GetOptions {
    fn default() -> Self {
        GetOptions {
            kept: true,
            heads: Heads::Winner,
            live: Live::Emitted,
            modes: Modes::ALL,
            trust: Trust::Prompt,
            congestion: Congestion::Block,
            ask: None,
        }
    }
}

/// A kept value: what `watch` and `kept` call an `Item`, as `get` yields it.
///
/// The struct grows: build one with [`Kept::new`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Kept {
    /// The entry.
    pub id: EntryId,
    /// How long ago it was written, when known.
    pub as_of: Option<Duration>,
    /// The path has no value now: the item's bytes are empty and `id` is the entry that removed
    /// it (the entry this stream delivered last for the path when the register holds no head of
    /// it any more). With [`Heads::All`] a removal that is itself a head is told the same way:
    /// it is a head concurrent with the others.
    pub removed: bool,
    /// Whether this entry was the winner of its path (the head of highest rank) when it was
    /// told. [`Heads::Winner`]: always `true`. [`Heads::All`]: a snapshot, as another head can
    /// outrank it later; a reader that needs the winner now reads `Heap::kept`.
    pub winner: bool,
    /// The heads this stream had told at the path that are no longer heads once this item
    /// applies (at most [`HEADS_MAX`]), so a reader that keeps a value per head deletes them and
    /// inserts this one, and never holds a head the register has dropped. A head superseded
    /// through entries the stream never saw is listed too: it is the stream's heads that count,
    /// not the entries' `after`. [`Heads::Winner`]: always empty.
    pub supersedes: Vec<EntryId>,
}

impl Kept {
    /// A kept value written by the entry `id`: the winner, no value superseded, not a removal,
    /// of no stated age. The other fields are public: set them.
    pub fn new(id: EntryId) -> Kept {
        Kept {
            id,
            as_of: None,
            removed: false,
            winner: true,
            supersedes: Vec::new(),
        }
    }
}

/// An emission as received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Emitted {
    /// The channel's sequence of the message (the original one for a replay).
    pub seq: u64,
    /// What is left of a stated lifetime, for a standing value; `None` for a live emission.
    pub stands: Option<Duration>,
    /// Whether a signed checkpoint of the sender had listed this frame **before it was given**
    /// (an `Items` with [`Trust::Verified`] is given nothing else): the frame is then the
    /// sender's, not a key holder's. `false` for a [`Trust::Prompt`] `Items`: it is given the
    /// frame as soon as it opens under the channel's key, which every reader of the space holds,
    /// and the checkpoint that covers it comes later (a [`GetNotice::Retracted`] follows a frame
    /// it contradicts, and none follows a frame of a channel that sends no checkpoints). A
    /// `Prompt` item is therefore never marked verified afterwards.
    pub verified: bool,
}

/// What an item is.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    /// A kept value: durable and signed by `Got::writer`'s device, the register's head of its
    /// path.
    Kept(Kept),
    /// A live emission: not durable, never the current value of the path.
    Emitted(Emitted),
    /// A server's answer to this query (`GetOptions::ask`): not durable, not an entry, never
    /// the current value of a path and never told again.
    Answered(Answered),
}

/// One item `get` yields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Got {
    /// The path, relative to the space.
    pub path: Name,
    /// The payload.
    pub bytes: Bytes,
    /// The writer's person. For a kept value, the person of the trust context that validated the
    /// signing key of the entry. For an emission, the person of the sender's device as judged
    /// when the session was set up: the channel's, not proof that this frame is the sender's
    /// (see [`Emitted::verified`]).
    pub by: Name,
    /// The writer's device.
    pub writer: Name,
    /// What it is.
    pub kind: Kind,
}

/// Why the live part of an `Items` ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiveEnd {
    /// A sender's session ended.
    Ended {
        /// The sender's device.
        writer: Name,
        /// Why.
        reason: EndReason,
    },
    /// No path to any sender.
    NoPath {
        /// Why, and what to do.
        why: String,
    },
}

/// What an `Items` says besides items. The enum grows: match it with a wildcard arm.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GetNotice {
    /// The consumer fell behind, or the mode dropped messages: this many were missed. Told for
    /// emissions (the mode dropped them: `Latest` past its bound, `Reliable` and `Window`
    /// with [`Congestion::Drop`], or a gap in the sequence) and for answers of a query (the
    /// answer queue holds 64 answers and 1 MiB: past it the oldest are dropped, in their place
    /// in the stream, and the server is never made to wait). A slow reader of kept values is
    /// never told this: it is given the current values again from the store.
    Lagged {
        /// How many.
        missed: u64,
    },
    /// An entry this stream delivered was refused after the fact (a signed removal of its writer
    /// reached this device, a cut left it out): the value that stands is the one that follows,
    /// or none (a removal item) when the path has no head left. Told for an entry that was the
    /// current value this stream had delivered at its path (with [`Heads::All`]: a head this
    /// stream had told and still holds; what its withdrawal gives back, or [`GetNotice::HeadsEnded`]
    /// when it gives nothing back, follows).
    Withdrawn {
        /// The entry.
        id: EntryId,
        /// Why.
        why: Refusal,
    },
    /// The live part ended; kept data goes on.
    LiveEnded(LiveEnd),
    /// The kept part ended and gives nothing more, while the live part goes on: this device's
    /// person is no reader of the sealed space any more (a removal reached this node), or the
    /// feed had to read the heads again and could not trust the register (an entry of a sealed
    /// space is held closed, its path unknown, so a head may not be the current value of its
    /// path). `why` says which and what to do; a new `get` after that either goes on or is
    /// refused with the same reason.
    KeptEnded {
        /// Why, and what to do.
        why: String,
    },
    /// A signed checkpoint contradicted these emissions: a frame this `Items` was given for the
    /// writer's channel is not one the writer's checkpoint lists. Discard what was delivered with
    /// a `seq` from `from` to `to` (inclusive); delivered items stay delivered, nothing is taken
    /// back by the stream itself. When a frame that is not data (a `BIND`, a `HELLO`, a standing
    /// bracket) was contradicted, `to` is the highest sequence accepted at that time: what
    /// followed was read under a table or a state a key holder wrote.
    Retracted {
        /// The writer's device.
        writer: Name,
        /// The first retracted sequence.
        from: u64,
        /// The last retracted sequence.
        to: u64,
    },
    /// Heads this stream told left the head set of `path` and no new head came with them
    /// (`Heads::All` only): a withdrawn entry with nothing to restore, or an entry that arrived
    /// already superseded and that superseded a head. A reader that keeps one value per head
    /// drops `ids`. Heads that a new item replaces are in that item's [`Kept::supersedes`]
    /// instead, and the entries of this notice are never told again, unless they return as
    /// items.
    HeadsEnded {
        /// The path.
        path: Name,
        /// The told heads that are no longer heads.
        ids: Vec<EntryId>,
    },
    /// `path` has more than [`HEADS_MAX`] heads and this stream tells the [`HEADS_MAX`] of
    /// highest rank (`Heads::All` only): `hidden` heads of lower rank are not told. Told when
    /// the number changes, never silently: merge the heads told (`Heap::put_merged`) and the
    /// others follow as the register's heads change, or read all of them with
    /// [`Heap::kept_all`](crate::Heap::kept_all).
    HeadsCapped {
        /// The path.
        path: Name,
        /// How many heads of lower rank are not told.
        hidden: u32,
    },
    /// A query to one server failed (`GetOptions::ask`): `why` says what and, by
    /// [`QueryError::next`], what to do. Counted `failed` in [`GetNotice::AnswersDone`].
    QueryFailed {
        /// The server's device, or the space's name when no server is known.
        server: Name,
        /// Why.
        why: QueryError,
    },
    /// Every server a query asked has resolved, or its deadline passed (`GetOptions::ask`): told
    /// **once** per `get`, after the answers and failures that came before it. Each server
    /// asked is in exactly one bucket, so `asked == answered + refused + failed + silent`.
    /// `not_asked` counts the servers known beyond the 16 a query asks. The deadline is
    /// liveness, never correctness: an answer that came later was dropped and cannot be told
    /// from silence.
    AnswersDone {
        /// Servers the query addressed: each is in exactly one of the buckets below. A device
        /// named in `Targets::Devices` that is no writer is counted `failed` (a
        /// [`QueryError::NotWriter`] is told) and nothing is sent to it; a device that
        /// `Targets::Serving` or `Targets::Person` finds is no writer is not addressed and not
        /// counted.
        asked: u32,
        /// Servers that gave bytes.
        answered: u32,
        /// Servers whose handler refused (an [`Answered`] with a refusal).
        refused: u32,
        /// Servers a [`GetNotice::QueryFailed`] was told for.
        failed: u32,
        /// Servers that said nothing by the deadline (a `Pass`, a dropped query, a slow handler,
        /// a server that is down).
        silent: u32,
        /// Servers known and not asked, past the limit of 16.
        not_asked: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_is_clamped_to_its_maximum_and_never_empty() {
        let big = Window {
            messages: 1 << 30,
            bytes: 1 << 40,
            age: Duration::from_secs(86_400),
        }
        .clamped();
        assert_eq!(big, Window::MAX);
        let none = Window {
            messages: 0,
            bytes: 0,
            age: Duration::ZERO,
        }
        .clamped();
        assert!(none.messages == 1 && none.bytes == 1 && none.age > Duration::ZERO);
        assert_eq!(Window::default(), Window::DEFAULT);
    }

    #[test]
    fn every_refusal_says_what_to_do() {
        use EmitError as E;
        let n = Name::root();
        let cases = [
            (
                E::NotWriter {
                    space: n.clone(),
                    why: "x".into(),
                },
                NextStep::AskOwner,
            ),
            (
                E::NotReady {
                    space: n,
                    why: "x".into(),
                },
                NextStep::RetryLater,
            ),
            (
                E::TooLarge {
                    what: "names in one channel",
                    size: 4097,
                    max: 4096,
                },
                NextStep::FixRequest,
            ),
            (
                E::Congested {
                    retry_after: Duration::from_millis(5),
                },
                NextStep::RetryLater,
            ),
            (E::NoStream { what: "Reliable" }, NextStep::FixRequest),
            (E::latest_blocks(), NextStep::FixRequest),
            (E::SequenceExhausted, NextStep::RetryLater),
            (E::Local { reason: "x".into() }, NextStep::FixLocal),
        ];
        for (error, next) in cases {
            assert_eq!(error.next(), next, "{error}");
            assert!(!error.to_string().is_empty());
        }
        assert!(E::latest_blocks().to_string().contains("Use Reliable"));
    }

    #[test]
    fn select_matches_a_path_exactly_and_a_prefix_below() {
        let n = |s: &str| s.parse::<Name>().unwrap();
        assert!(Select::Path(n("/a/b")).matches(&n("/a/b")));
        assert!(!Select::Path(n("/a/b")).matches(&n("/a/b/c")));
        assert!(Select::Prefix(n("/a")).matches(&n("/a/b/c")));
        assert!(Select::Prefix(Name::root()).matches(&n("/x")));
        assert!(!Select::Prefix(n("/a")).matches(&n("/b")));
    }
}
