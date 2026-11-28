//! The public types of `serve` and of a query on `get` (docs/specs/query.md, The API): what a
//! handler is given and answers, what an asker asks, what it is told, and why a query failed.
//!
//! **An answer is not an entry.** Nothing here is stored: a [`Query`] lives while its handler
//! runs, an [`Answered`] is an item of one `Items` and is never replayed, and the asker's
//! pending set and the server's in-flight set are memory bounded by outstanding queries.

use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;

use crate::chan::error::ChanError;
use crate::error::{NextStep, Timestamp};
use crate::rt::Instant;

/// The id an asker gives a query: eight random octets, echoed by the server in its answer, the
/// same to every server of one `get`. A handler with side effects keys them on it and on the
/// asker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QueryId(pub u64);

impl std::fmt::Display for QueryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Which path a query came by. The enum grows with the paths: match it with a wildcard arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Via {
    /// A signed Interest and a signed Data: the answer is the server device's own statement. With
    /// [`Ask::proof`] the asker keeps the signed query with it ([`Answered::proof`]), and anyone
    /// who holds the space's record can check what was asked and answered, and when by the
    /// asker's clock. In a sealed space the octets are sealed to the pair of devices as well; the
    /// signature covers the sealed octets, so a proof there shows the exchange and not its words.
    Signed,
    /// A `QUERY` and an `ANSWER` frame of an `Ask` channel, each sealed under one of the two keys
    /// of the pair the asker and the server share (docs/specs/query.md, the channel path). The
    /// frame that opens under the asker's key is the asker's and the one that opens under the
    /// server's key is the server's: origin authentication between those two devices and **no
    /// proof** for a third party (either could have made any frame), which is why
    /// [`Ask::proof`] is signed-path only. The pair seals every query, in a public space as well
    /// as a sealed one.
    Sealed,
}

/// Which path a query takes ([`Ask::via`]), per server asked.
///
/// * [`QueryPath::Auto`] takes the channel only for a server whose `Ask` session this device
///   already holds with a pair (an earlier `Channel` query or [`ask_channel_in`] with
///   `ChannelMode::Ask` made it, and it has not been idle for 60 s), a forwarder is attached, the
///   query fits one channel frame ([`CHANNEL_QUERY_MAX`] octets of query, a frame of at most
///   1,150 octets) and [`Ask::proof`] is not set. Otherwise it is the signed path. It never
///   creates a session.
/// * [`QueryPath::Channel`] creates the `Ask` session if none is held (one signed ask, inside the
///   deadline) and never falls back to signed: a refused setup is
///   [`QueryError::NoSession`] with the setup's reason, and a node without a forwarder is
///   [`QueryError::NotReady`].
///
/// [`ask_channel_in`]: crate::NodeHandle::ask_channel_in
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum QueryPath {
    /// The channel for a server whose session this device holds, else signed. The default.
    #[default]
    Auto,
    /// Always the signed Interest.
    Signed,
    /// Always the channel, opening its session if none is held.
    Channel,
}

/// Who is asked.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Targets {
    /// The devices whose announce lists a prefix of the asked path (a hint: the server's own
    /// judgement of the query is the authority), judged offline as writers of the space; the 16
    /// heard last. The default.
    #[default]
    Serving,
    /// Exactly these devices (at most 16).
    Devices(Vec<Name>),
    /// The known devices of this person that are writers (at most 16).
    Person(Name),
}

/// The most servers one query asks.
pub const TARGETS_MAX: usize = 16;

/// The most octets of a query on the signed path (and on `Auto`, which may fall to it).
pub const QUERY_MAX: usize = crate::wire::QUERY_BYTES_MAX;

/// The most octets of a query on the channel path: one datagram on the smallest floor
/// ([`QueryPath::Channel`] refuses more; [`QueryPath::Auto`] goes signed for it).
pub const CHANNEL_QUERY_MAX: usize = crate::chan::qframe::QUERY_BYTES_MAX;

/// The most octets of an answer the channel path carries, and the most `answer_max` it allows:
/// 64 KiB (a datagram when the sealed frame fits, else a stream frame).
pub const ANSWER_MAX_CHANNEL: usize = 65_536;

/// The longest deadline of a query: ten seconds.
pub const DEADLINE_MAX: Duration = Duration::from_secs(10);

/// What a receiver of `get` asks the servers of the space (`GetOptions::ask`).
///
/// Build one with [`Ask::new`]: the fields are public and the defaults are the ones listed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ask {
    /// The query octets: at most [`QUERY_MAX`] (2,048) on the signed path, at most
    /// [`CHANNEL_QUERY_MAX`] (1,024) on [`QueryPath::Channel`].
    pub query: Bytes,
    /// Who is asked (default [`Targets::Serving`]).
    pub targets: Targets,
    /// Which path (default [`QueryPath::Auto`]).
    pub via: QueryPath,
    /// How long the query lives, setup and handler together: 1 ms to [`DEADLINE_MAX`] (default 3
    /// s). **Liveness only**: a late answer is dropped and counted as silence; nothing the
    /// application decides should depend on the deadline.
    pub deadline: Duration,
    /// The largest answer told (default [`ANSWER_MAX_DEFAULT`], 4,096): at most
    /// [`ANSWER_MAX_DEFAULT`] on [`QueryPath::Signed`], at most [`ANSWER_MAX_CHANNEL`] (65,536)
    /// on `Channel` and `Auto`. A larger answer is a [`QueryError::AnswerTooLarge`] failure.
    pub answer_max: usize,
    /// Keep the proof of each answer ([`Answered::proof`]: the signed query and the signed
    /// answer, which a third party verifies from the space's record with
    /// [`Heap::verify_answer_proof`](crate::Heap::verify_answer_proof)); default `false`.
    pub proof: bool,
}

/// The largest answer [`Ask::answer_max`] allows by default, and the most the signed path
/// carries: 4 KiB.
pub const ANSWER_MAX_DEFAULT: usize = crate::wire::ANSWER_BYTES_MAX;

impl Ask {
    /// A query of `query` to the devices that serve the path, by the path that suits, within 3 s.
    pub fn new(query: impl Into<Bytes>) -> Ask {
        Ask {
            query: query.into(),
            targets: Targets::Serving,
            via: QueryPath::Auto,
            deadline: Duration::from_secs(3),
            answer_max: ANSWER_MAX_DEFAULT,
            proof: false,
        }
    }
}

/// The asker, as the server's space judged it when the query arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asker {
    /// The asker's person: the one the trust context vouched for the signing key as.
    pub person: Name,
    /// The asker's device.
    pub device: Name,
}

/// A query, as a handler is given it.
#[derive(Clone, Debug)]
pub struct Query {
    /// The asker's id of the query; the same to every server of one `get`.
    pub id: QueryId,
    /// The asked name, relative to the space; a served prefix is a prefix of it.
    pub path: Name,
    /// The query octets.
    pub bytes: Bytes,
    /// Who asked, as judged when the query arrived: a handler that does something for the asker
    /// still judges her itself, since a removal after that moves nothing it already began.
    pub asker: Asker,
    /// Which path it came by.
    pub via: Via,
    pub(crate) deadline: Instant,
}

impl Query {
    /// How long the asker still waits: the handler's future is dropped at that moment and its
    /// answer, if it made one, is not sent.
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

/// The application's own refusal: a code it defines and a text for the asker, at most 256
/// octets (a longer text is cut at a character boundary). Not a system failure: the asker is
/// told it as an answer ([`Answered::refusal`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRefusal {
    /// The application's code.
    pub code: u16,
    /// The application's words.
    pub text: String,
}

/// The most octets of a refusal's text.
pub const REFUSAL_TEXT_MAX: usize = 256;

impl AppRefusal {
    /// A refusal with `code` and `text`; `text` is cut to [`REFUSAL_TEXT_MAX`] octets.
    pub fn new(code: u16, text: impl Into<String>) -> AppRefusal {
        let mut text = text.into();
        if text.len() > REFUSAL_TEXT_MAX {
            let mut cut = REFUSAL_TEXT_MAX;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
        }
        AppRefusal { code, text }
    }
}

/// What a handler answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The answer: at most 4,096 octets on the signed path. A larger result is the handler's
    /// `put` and an answer that names the path.
    Answer(Bytes),
    /// The application's refusal, told to the asker as an answer.
    Refuse(AppRefusal),
    /// Nothing for this query: nothing is sent, and the asker counts this server silent at its
    /// deadline. A handler that wants the asker to know says [`Reply::Refuse`].
    Pass,
}

impl Reply {
    /// [`Reply::Refuse`] with `code` and `text`.
    pub fn refuse(code: u16, text: impl Into<String>) -> Reply {
        Reply::Refuse(AppRefusal::new(code, text))
    }
}

/// The future of a [`Handler::answer`].
#[cfg(not(target_arch = "wasm32"))]
pub type HandlerFuture = futures::future::BoxFuture<'static, Reply>;
/// The future of a [`Handler::answer`].
#[cfg(target_arch = "wasm32")]
pub type HandlerFuture = futures::future::LocalBoxFuture<'static, Reply>;

/// What answers the queries of a served prefix: it runs once per query that reaches it and its
/// result goes to that asker once. Any `Fn(Query) -> impl Future<Output = Reply>` is one.
///
/// **No answers family.** A handler's result is never stored, cached, recomputed, sealed by a
/// reader or made an entry: the handler is a producer callback and nothing else
/// (docs/specs/query.md, the invariant).
pub trait Handler: Send + Sync + 'static {
    /// Answer `query`.
    fn answer(&self, query: Query) -> HandlerFuture;
}

#[cfg(not(target_arch = "wasm32"))]
impl<F, Fut> Handler for F
where
    F: Fn(Query) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Reply> + Send + 'static,
{
    fn answer(&self, query: Query) -> HandlerFuture {
        Box::pin(self(query))
    }
}

#[cfg(target_arch = "wasm32")]
impl<F, Fut> Handler for F
where
    F: Fn(Query) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Reply> + 'static,
{
    fn answer(&self, query: Query) -> HandlerFuture {
        Box::pin(self(query))
    }
}

/// What a query's answer item is (`Kind::Answered`): the server's word, never an entry and
/// never the current value of a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answered {
    /// The query this answers.
    pub query: QueryId,
    /// Which path it came by.
    pub via: Via,
    /// The handler's own refusal; the item's bytes are then empty. Not a failure: the
    /// application's word, counted `refused`.
    pub refusal: Option<AppRefusal>,
    /// The proof of this answer, when [`Ask::proof`] was set: the asker's **signed query** (the
    /// Interest, whose parameters carry the space, the path and the query octets in a public
    /// space, and the `SignatureTime`) **and** the server's signed answer (the Data), as one
    /// bundle. Check it, with the record of the space and nothing else, by
    /// [`Heap::verify_answer_proof`](crate::Heap::verify_answer_proof); keep the octets whole.
    ///
    /// In a sealed space the question and the answer inside the bundle are ciphertext that only
    /// the asker and the server open: the proof then shows that this server, a writer, signed
    /// an answer sealed to this asker's signed query, at the asker's time, and
    /// [`ProvenAnswer::Sealed`] says so. It does not show what was asked or answered.
    pub proof: Option<Bytes>,
}

/// What [`Heap::verify_answer_proof`](crate::Heap::verify_answer_proof) found in a proof that
/// verified.
///
/// **The time** is [`VerifiedAnswer::signed_at`], the `SignatureTime` of the asker's query, on
/// the asker's clock: the answer's Data carries no time of its own (it has a KeyLocator only).
/// The answer was made after that moment (its name is the digest of the signed Interest) and no
/// more is signed about when. **Standing** is judged by the record the verifier holds when it
/// verifies: a person removed from the space, or a key revoked, after the exchange fails the
/// proof closed; keep the verdict from the day the proof was received.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedAnswer {
    /// The space the query was asked in.
    pub space: Name,
    /// The query's id, echoed by the answer.
    pub query: QueryId,
    /// The asker's person.
    pub asker: Name,
    /// The asker's device, whose key signed the query.
    pub asker_device: Name,
    /// The server's person.
    pub server_person: Name,
    /// The server's device, a writer's, whose key signed the answer.
    pub server: Name,
    /// The asked path, relative to the space; `None` in a sealed space, where it is ciphertext.
    pub path: Option<Name>,
    /// The query octets; `None` in a sealed space, where they are ciphertext.
    pub query_bytes: Option<Bytes>,
    /// Milliseconds since the Unix epoch on the asker's clock when it signed the query.
    pub signed_at: Timestamp,
    /// What the server answered.
    pub answer: ProvenAnswer,
}

/// What a verified proof shows the server answered.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvenAnswer {
    /// The handler answered with these octets.
    Answered(Bytes),
    /// The handler refused, in the application's words.
    Refused(AppRefusal),
    /// The server serves no prefix of the path.
    NotServed,
    /// The answer did not fit the server's limit of `max` octets.
    TooLarge {
        /// The limit.
        max: u64,
    },
    /// The space is sealed: the server signed `ciphertext`, which only the asker and the server
    /// can open. The proof shows the exchange took place and whose it was, not what was said.
    Sealed {
        /// The ciphertext of the status the server signed.
        ciphertext: Bytes,
    },
}

/// Why [`Heap::verify_answer_proof`](crate::Heap::verify_answer_proof) did not accept a proof.
/// [`ProofError::next`] says what to do. The enum grows: match it with a wildcard arm.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofError {
    /// The octets are no proof: not the bundle [`Answered::proof`] holds, or changed.
    #[error(
        "these octets are no proof of a query's answer ({why}): give the octets \
         Answered::proof held, whole and unchanged"
    )]
    Malformed {
        /// Why.
        why: String,
    },
    /// The proof is about another space than this one.
    #[error(
        "the proof is of a query in {proof}, and this is {held}: verify it with the Heap of {proof}"
    )]
    OtherSpace {
        /// The space the proof names.
        proof: Name,
        /// The space of this Heap.
        held: Name,
    },
    /// The record of the space is not held here, so nobody's standing can be judged.
    #[error(
        "the space's record is not held here yet, so no standing can be judged: follow the \
         space (watch it) until its owner's entries arrive, then verify again"
    )]
    NoRecord,
    /// The signed query does not verify as its asker's.
    #[error(
        "the query in the proof does not verify as its asker's ({why}): this is no proof of a \
         query by a member of the space"
    )]
    Question {
        /// Why.
        why: String,
    },
    /// The asker is no listed member by the record held here.
    #[error(
        "the asker {asker} is neither a writer nor a reader of the space by the record held \
         here ({why}): the proof is no proof of a member's query; ask the owner, or hold a \
         newer record if the asker was listed when it asked"
    )]
    AskerNotListed {
        /// The asker's device key.
        asker: Name,
        /// Why.
        why: String,
    },
    /// The answer is not the answer to this query.
    #[error(
        "the answer in the proof is not the answer to the query in it ({why}): a proof is the \
         query and its own answer, as Answered::proof keeps them"
    )]
    Unrelated {
        /// Why.
        why: String,
    },
    /// The answer does not verify as its server's.
    #[error(
        "the answer in the proof does not verify as the server's ({why}): it is not the \
         statement of that device"
    )]
    Answer {
        /// Why.
        why: String,
    },
    /// The server's key is no writer's by the record held here.
    #[error(
        "the server {server} is no writer of the space by the record held here ({why}): its \
         word is no word of the space's writers; ask the owner, or hold a newer record if it \
         was a writer when it answered"
    )]
    ServerNotWriter {
        /// The server's device key.
        server: Name,
        /// Why.
        why: String,
    },
    /// A signature cannot be judged from what is held and carried.
    #[error(
        "the proof cannot be verified yet ({why}): nothing is fetched to verify a proof; hold \
         the signers' certificates (open the space and let its members' contexts arrive) and \
         verify again"
    )]
    NotJudged {
        /// What waits.
        why: String,
    },
}

impl ProofError {
    /// What to do about it, in the heap's vocabulary.
    pub fn next(&self) -> NextStep {
        match self {
            ProofError::Malformed { .. }
            | ProofError::OtherSpace { .. }
            | ProofError::Unrelated { .. } => NextStep::FixRequest,
            ProofError::NoRecord | ProofError::NotJudged { .. } => NextStep::RetryLater,
            ProofError::AskerNotListed { .. } | ProofError::ServerNotWriter { .. } => {
                NextStep::AskOwner
            }
            ProofError::Question { .. } | ProofError::Answer { .. } => NextStep::None,
        }
    }
}

/// Why a query to one server failed: told as [`GetNotice::QueryFailed`](crate::GetNotice) and
/// counted `failed`. [`QueryError::next`] says what to do. The enum grows (the channel path adds
/// its setup refusals): match it with a wildcard arm.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum QueryError {
    /// No device is known to serve the path.
    #[error(
        "no device is known to serve {path}: name the servers with Targets::Devices, or ask the \
         space's owner which device serves it"
    )]
    NoServer {
        /// The asked path.
        path: Name,
    },
    /// The server refused to answer this device, or nothing routes to it.
    #[error(
        "the server did not answer: it does not list this device's person (or this device has \
         no standing in the space, or the person is outside a sealed space's audience), the \
         query was signed more than 120 s from the server's clock, the server began serving less \
         than 120 s ago (a server that has just started refuses signed queries for that long), \
         or no route reaches it; ask the owner to list the person, correct the clock, check that \
         the server's device is reachable, and ask again in a couple of minutes"
    )]
    NotListed,
    /// The server serves no prefix of the path.
    #[error(
        "the device serves no prefix of {path}: ask a device that serves it (Targets::Serving), \
         or name the path it serves"
    )]
    NotServed {
        /// The asked path.
        path: Name,
    },
    /// The server could not take the query now.
    #[error(
        "the server could not take the query now (over a limit of its own, or it had seen a \
         copy of this query already); try again later with a new get"
    )]
    Busy,
    /// The server does not hold the asker's certificate chain yet, or the sealed space's epoch.
    #[error(
        "the server cannot judge this device yet (it does not hold its certificate chain or the \
         space's epoch); try again in a moment"
    )]
    NotYet,
    /// Nothing answered or routed the query.
    #[error(
        "no route to the server, or its forwarder dropped the query; try again later (the \
         server may be down)"
    )]
    Unreachable,
    /// A query or an answer is over its limit.
    #[error("over the limit of {max} octets: {what}; send less, or put the data and name its path")]
    TooLarge {
        /// What is over.
        what: &'static str,
        /// The limit.
        max: u64,
    },
    /// An answer is larger than [`Ask::answer_max`].
    #[error(
        "the answer is {size} octets, over answer_max {max}: raise answer_max, or have the \
         handler put the data and answer its path"
    )]
    AnswerTooLarge {
        /// Its size.
        size: usize,
        /// The limit asked for.
        max: usize,
    },
    /// The answer failed to verify as the server's.
    #[error("the answer did not verify as the server's ({why}); try again later")]
    BadAnswer {
        /// Why.
        why: String,
    },
    /// This device has as many queries outstanding as it may.
    #[error(
        "this device has as many queries outstanding as it may (64 in all, 16 to one server); \
         try again when some have finished"
    )]
    TooManyOutstanding,
    /// The named device is no writer of the space, as this device judges it now.
    #[error(
        "{device} is no writer of the space by the record held here, so it serves nothing and \
         was not asked: name a writer's device, or ask the owner whether it may write"
    )]
    NotWriter {
        /// The device named.
        device: Name,
    },
    /// The space or this device's standing does not allow the query yet.
    #[error("the query cannot be sent: {why}")]
    NotReady {
        /// Why, and what to do.
        why: String,
    },
    /// [`QueryPath::Channel`] could not set up the `Ask` session the query goes over: the
    /// setup's own refusal, which says why and what to do ([`ChanError::next`]). The query was
    /// not sent signed instead.
    #[error("the channel session for the query cannot be set up: {why}")]
    NoSession {
        /// The setup's refusal.
        why: ChanError,
    },
    /// This device's queue to its forwarder is full: the query was not sent.
    #[error(
        "this device's queue to its forwarder is full, so the query was not sent; try again in a \
         moment, with fewer queries at once"
    )]
    Congested,
}

impl QueryError {
    /// What to do about it, in the heap's vocabulary.
    pub fn next(&self) -> NextStep {
        match self {
            QueryError::NoServer { .. } | QueryError::NotServed { .. } => NextStep::FixRequest,
            QueryError::NotListed => NextStep::AskOwner,
            QueryError::NotWriter { .. } => NextStep::FixRequest,
            QueryError::Busy
            | QueryError::NotYet
            | QueryError::Unreachable
            | QueryError::BadAnswer { .. }
            | QueryError::TooManyOutstanding
            | QueryError::Congested
            | QueryError::NotReady { .. } => NextStep::RetryLater,
            QueryError::TooLarge { .. } | QueryError::AnswerTooLarge { .. } => NextStep::FixRequest,
            QueryError::NoSession { why } => why.next(),
        }
    }
}

/// Why `Heap::serve` refused. [`ServeError::next`] says what to do.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// This device is no writer of the space: only a writer's device serves.
    #[error(
        "this device may not serve in {space}: {why}; a reader asks, a writer's device serves \
         (ask the owner to make this person a writer, or serve from a writer's device)"
    )]
    NotWriter {
        /// The space.
        space: Name,
        /// Why.
        why: String,
    },
    /// The space is not ready here: its record is not held yet.
    #[error("{space} is not ready to serve: {why}; try again later")]
    NotReady {
        /// The space.
        space: Name,
        /// Why.
        why: String,
    },
    /// The prefix is already served by this heap.
    #[error(
        "{existing} is already served by this heap: drop that Serving first, or serve a nested \
         prefix (nested prefixes are allowed; the longest one answers)"
    )]
    Overlap {
        /// The prefix served.
        existing: Name,
    },
    /// This heap serves as many prefixes as it may.
    #[error("this heap serves as many prefixes as it may ({max}); drop a Serving first")]
    TooMany {
        /// The limit.
        max: usize,
    },
    /// The prefix is over 255 octets.
    #[error("the prefix is {size} octets, over the limit of {max}: serve a shorter prefix")]
    BadPrefix {
        /// Its size.
        size: usize,
        /// The limit.
        max: usize,
    },
}

impl ServeError {
    /// What to do about it, in the heap's vocabulary.
    pub fn next(&self) -> NextStep {
        match self {
            ServeError::NotWriter { .. } => NextStep::AskOwner,
            ServeError::NotReady { .. } => NextStep::RetryLater,
            ServeError::Overlap { .. }
            | ServeError::TooMany { .. }
            | ServeError::BadPrefix { .. } => NextStep::FixRequest,
        }
    }
}

/// The most prefixes one heap serves.
pub const SERVE_PREFIXES_MAX: usize = 64;

/// The longest served prefix, in octets of its name.
pub const SERVE_PREFIX_MAX: usize = 255;
