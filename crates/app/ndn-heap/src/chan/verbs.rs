//! The public types of the live verbs: what `Heap::emit` takes and refuses, and what a receiver's
//! `Items` yields (docs/specs/channel.md, Modes and The verbs).
//!
//! One place declares them so the sender (`emit`) and the receiver (`live`) agree: the options, the
//! modes, the error with its [`NextStep`], and the item a receiver gets.

use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;

use super::sessions::EndReason;
use super::wire::ChannelMode;
use crate::error::NextStep;
use crate::register::EntryId;

/// The longest stand lifetime: one hour.
pub const STAND_MAX: Duration = Duration::from_secs(3600);

/// The most standing names one channel holds.
pub const STANDING_NAMES_MAX: usize = 256;

/// The most octets of standing payloads one channel holds.
pub const STANDING_BYTES_MAX: usize = 64 * 1024;

/// What a receiver of `live` wants: one path or everything under a prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Select {
    /// This path exactly.
    Path(Name),
    /// This path and everything below it (the empty name: everything).
    Prefix(Name),
}

impl Select {
    /// Whether an emission at `path` is wanted.
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

/// Whether `live` also receives emissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Live {
    /// Receive emissions (the default).
    #[default]
    Emitted,
    /// Kept values only.
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

/// What a receiver of `live` asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetOptions {
    /// Deliver kept values first (default `true`). Kept values: stage 6; `live` ignores it.
    pub kept: bool,
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
}

impl Default for GetOptions {
    fn default() -> Self {
        GetOptions {
            kept: true,
            live: Live::Emitted,
            modes: Modes::ALL,
            trust: Trust::Prompt,
            congestion: Congestion::Block,
        }
    }
}

/// A kept value (what today's `Item` carries). Produced by `get` at stage 6; `live` yields none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept {
    /// The entry.
    pub id: EntryId,
    /// How long ago it was written, when known.
    pub as_of: Option<Duration>,
}

/// An emission as received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Emitted {
    /// The channel's sequence of the message (the original one for a replay).
    pub seq: u64,
    /// What is left of a stated lifetime, for a standing value; `None` for a live emission.
    pub stands: Option<Duration>,
}

/// What an item is.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    /// A kept value (stage 6).
    Kept(Kept),
    /// A live emission.
    Emitted(Emitted),
}

/// One item `live` yields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Got {
    /// The path, relative to the space.
    pub path: Name,
    /// The payload.
    pub bytes: Bytes,
    /// The writer's person.
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

/// What an `Items` says besides items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GetNotice {
    /// The consumer fell behind, or the mode dropped messages: this many were missed. For kept data
    /// watch again; for emissions the mode dropped them.
    Lagged {
        /// How many.
        missed: u64,
    },
    /// The live part ended; kept data goes on.
    LiveEnded(LiveEnd),
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
