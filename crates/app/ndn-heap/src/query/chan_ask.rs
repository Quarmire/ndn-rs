//! The asker's half of the channel path (docs/specs/query.md, the channel path): a query as a
//! sealed `QUERY` frame up an `Ask` channel's route and its `ANSWER` back, with no signature
//! after the one that made the session.
//!
//! **Which path.** [`NodeInner::query_channel_for`] decides per server: `Signed` never takes the
//! channel; `Channel` takes the session this device holds with the server and, with none, makes
//! one (a signed ask, inside the query's deadline; a refusal is [`QueryError::NoSession`], never
//! a fall back to signed); `Auto` takes the channel only for a session already held with its
//! pair, a forwarder attached, a query that fits one frame, and no proof asked, and is signed
//! otherwise. `Auto` never creates a session.
//!
//! **One query.** [`NodeInner::ask_server_channel`] takes the next number of the pair's counter
//! (taken once, whatever becomes of the send: a retry is a new query), a random 64-bit token,
//! seals the plaintext under `Kq` with the 36 header octets as additional data, registers the
//! pending entry `(route, token)` **before** the frame leaves, sends it through the connection to
//! the forwarder (a full queue is [`QueryError::Congested`]) and waits for the answer or the
//! deadline. The entry is removed by whatever ends the wait ([`Wait`]): an answer, the deadline,
//! or the `Items` being dropped.
//!
//! **One answer.** [`NodeInner::query_answer_frame`] runs in the receive loop and is
//! synchronous: the pending entry is **taken** (so a second frame for the token finds none and is
//! counted `unmatched`), the frame is opened under `Ka` with the entry's pair, key epoch and the
//! query's number (AAD = the 19 header octets), and the entry is resolved once. A frame that does
//! not open or decode resolves it as a bad answer: the token travelled in the clear past the
//! relays, so a frame that carries it and no valid seal is the one outcome of that query and the
//! true answer after it is dropped.
//!
//! **Silence.** A query nothing answered by its deadline is one silent query of its pair; three
//! in a row ([`AskPair::silence`]) mean the server has forgotten the pair (a restart, an
//! eviction), and the session is let go: the next `Channel` query asks again. Cancelling a query
//! (dropping its `Items`) is not silence.
//!
//! **No answers family.** Nothing here keeps an answer: the pending entry holds a one-shot
//! sender and is gone with the answer; the pair holds counters and keys.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::channel::oneshot;
use ndn_foundation_types::Name;
use ndn_transport::{SideClass, SideRefused};
use parking_lot::Mutex;

use super::ask::{Outcome, Run, Stop, bad_answer, deadline_ms, not_ready};
use super::types::{Answered, AppRefusal, CHANNEL_QUERY_MAX, QueryError, QueryPath, Via};
use crate::chan::hub::Counter;
use crate::chan::limits::TAG_LEN;
use crate::chan::pair::AskPair;
use crate::chan::qframe::{
    ANSWER_HEADER_LEN, AnswerHeader, ChanStatus, QUERY_HEADER_LEN, QUERY_OVERHEAD, QueryHeader,
    QueryPlain, path_value,
};
use crate::chan::route::SINK_LIMIT_FLOOR;
use crate::chan::sessions::RecvSession;
use crate::chan::standing::{Who, standing};
use crate::chan::verbs::{Author, Got, Kind};
use crate::chan::wire::ChannelMode;
use crate::node::NodeInner;
use crate::rt::Instant;

/// The most octets of a `QUERY` frame: what a datagram carries on the smallest floor of any path.
pub(super) const FRAME_MAX: usize = SINK_LIMIT_FLOOR;

/// The octets of the `QUERY` frame of a query of `query` octets for `path`: the header and tag,
/// the query id (8 octets), the deadline (at most 10,000 ms, two octets), the path's length and
/// value, and the query.
pub(super) fn frame_len(path: &Name, query: usize) -> usize {
    let path = path_value(path).len();
    let path_len = crate::chan::varint::len(path as u64).unwrap_or(8);
    QUERY_OVERHEAD + 8 + 2 + path_len + path + query
}

/// What the asker counted of the frames of the channel path.
#[derive(Default)]
pub(crate) struct ChanAskStats {
    /// `QUERY` frames sent.
    pub(crate) sent: Counter,
    /// An `ANSWER` for a (route, token) nothing waits for: a copy, a late one, a stranger's.
    pub(crate) unmatched: Counter,
    /// A frame that is no `ANSWER`.
    pub(crate) bad_frame: Counter,
    /// An answer that did not open or decode: the query's one outcome.
    pub(crate) bad_answers: Counter,
    /// Answers that opened and resolved their query.
    pub(crate) answers: Counter,
    /// Queries nothing answered by their deadline.
    pub(crate) silent: Counter,
    /// Queries not sent because the queue to the forwarder was full.
    pub(crate) congested: Counter,
}

/// The word of a pending entry: the server's status, or why the frame was no answer.
type Resolved = Result<ChanStatus, String>;

/// One query waiting for its answer.
struct Waiting {
    reply: oneshot::Sender<Resolved>,
    /// The pair the query was sealed under (a renewal may have replaced the session's).
    pair: Arc<AskPair>,
    /// The query's number: the nonce of its answer.
    qseq: u64,
}

/// What the asker keeps of the channel path: the queries waiting, by (route, token).
#[derive(Default)]
pub(crate) struct ChanAskState {
    waiting: Mutex<HashMap<(u64, u64), Waiting>>,
    pub(crate) stats: ChanAskStats,
}

impl ChanAskState {
    /// Register the query `(route, token)`; `None` when a query of that key waits already.
    fn register(
        &self,
        key: (u64, u64),
        pair: &Arc<AskPair>,
        qseq: u64,
    ) -> Option<oneshot::Receiver<Resolved>> {
        let mut waiting = self.waiting.lock();
        if waiting.contains_key(&key) {
            return None;
        }
        let (reply, receiver) = oneshot::channel();
        waiting.insert(
            key,
            Waiting {
                reply,
                pair: Arc::clone(pair),
                qseq,
            },
        );
        Some(receiver)
    }

    /// The queries waiting for an answer.
    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        self.waiting.lock().len()
    }
}

/// A registered query, removed when dropped: answered (the entry is gone already), past its
/// deadline (one silent query of its pair) or cancelled (nothing is said of the server).
struct Wait<'a> {
    node: &'a NodeInner,
    key: (u64, u64),
    pair: Arc<AskPair>,
    deadline: Instant,
}

impl Drop for Wait<'_> {
    fn drop(&mut self) {
        let state = &self.node.query.ask.chan;
        let unanswered = state.waiting.lock().remove(&self.key).is_some();
        if unanswered && Instant::now() >= self.deadline {
            state.stats.silent.bump();
            if self.pair.silence() {
                self.node.query_release_pair(&self.pair);
            }
        }
    }
}

impl NodeInner {
    /// The `Ask` session this device holds with `server` over `space`, while it may be used, and
    /// its pair.
    fn query_held(&self, space: &Name, server: &Name) -> Option<(Arc<RecvSession>, Arc<AskPair>)> {
        let session = self.chan.sessions.find(space, server, ChannelMode::Ask)?;
        if !session.usable(Instant::now()) {
            return None;
        }
        // The trust or the members moved since the sender was judged: judge it again, offline.
        if !session.is_current() && session.recheck(self).is_err() {
            return None;
        }
        let pair = self.chan.ask_pairs.get(session.id())?;
        Some((session, pair))
    }

    /// Let the session of `pair` go, with the pair, if `pair` is still the session's (a renewal
    /// may have replaced it, and the new one is not the silent one).
    fn query_release_pair(&self, pair: &Arc<AskPair>) {
        let current = self
            .chan
            .ask_pairs
            .get(pair.channel)
            .is_some_and(|held| Arc::ptr_eq(&held, pair));
        if !current {
            return;
        }
        if let Some(session) = self.chan.sessions.get(pair.channel) {
            self.chan_let_go(&session);
        }
        self.chan.ask_pairs.remove(pair.channel);
        self.chan_route_tick(Instant::now());
    }

    /// The session and pair a query of `run` to `server` goes over, or `None` for the signed path
    /// (the module docs say which).
    pub(super) async fn query_channel_for(
        &self,
        run: &Run,
        server: &Name,
    ) -> Result<Option<(Arc<RecvSession>, Arc<AskPair>)>, Stop> {
        let space = &run.held.name;
        match run.ask.via {
            QueryPath::Signed => Ok(None),
            QueryPath::Auto => {
                let fits = run.ask.query.len() <= CHANNEL_QUERY_MAX
                    && frame_len(&run.path, run.ask.query.len()) <= FRAME_MAX;
                if run.ask.proof || !fits || self.chan.route.conn().is_none() {
                    return Ok(None);
                }
                Ok(self.query_held(space, server))
            }
            QueryPath::Channel => {
                if self.chan.route.conn().is_none() {
                    return Err(no_forwarder());
                }
                if let Some(held) = self.query_held(space, server) {
                    return Ok(Some(held));
                }
                let remaining = run.deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(Stop::Silent);
                }
                let session = match crate::rt::timeout(
                    remaining,
                    self.chan_ask(space, server, ChannelMode::Ask),
                )
                .await
                {
                    Err(_) => return Err(Stop::Silent),
                    Ok(Err(why)) => return Err(QueryError::NoSession { why }.into()),
                    Ok(Ok(session)) => session,
                };
                let pair = self.chan.ask_pairs.get(session.id()).ok_or_else(|| {
                    not_ready(
                        "the session was let go as soon as it was made (its last holder left, or \
                         the server no longer stands); ask again",
                    )
                })?;
                Ok(Some((session, pair)))
            }
        }
    }

    /// Ask `server` once over the channel and judge what comes back.
    pub(super) async fn ask_server_channel(
        &self,
        run: &Run,
        server: &Name,
        session: &RecvSession,
        pair: Arc<AskPair>,
    ) -> Result<Outcome, Stop> {
        let Some(conn) = self.chan.route.conn() else {
            return Err(no_forwarder());
        };
        let remaining = run.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Stop::Silent);
        }
        let Some(qseq) = pair.next_qseq() else {
            self.query_release_pair(&pair);
            return Err(not_ready(
                "the pair of this session is used up (its counter reached its limit): the session \
                 was let go; ask again",
            ));
        };
        // Registered before the frame leaves: an answer can come back at once.
        let state = &self.query.ask.chan;
        let (token, reply) = {
            let mut found = None;
            for _ in 0..4 {
                let mut octets = [0u8; 8];
                getrandom::getrandom(&mut octets)
                    .expect("the operating system provides randomness");
                let token = u64::from_be_bytes(octets);
                if let Some(reply) = state.register((pair.channel, token), &pair, qseq) {
                    found = Some((token, reply));
                    break;
                }
            }
            found
                .ok_or_else(|| not_ready("no free token could be drawn for the query: ask again"))?
        };
        let key = (pair.channel, token);
        let _wait = Wait {
            node: self,
            key,
            pair: Arc::clone(&pair),
            deadline: run.deadline,
        };
        let header = QueryHeader {
            route: pair.channel,
            token,
            ttl_ticks: ttl_ticks(remaining),
            pair: pair.id(),
            qseq,
            epoch: pair.epoch(),
        };
        let octets = header.encode();
        let plain = QueryPlain {
            id: run.id.0,
            deadline_ms: deadline_ms(remaining),
            path: run.path.clone(),
            bytes: run.ask.query.clone(),
        }
        .encode()
        .map_err(|e| not_ready(format!("the query cannot be written ({e})")))?;
        let sealed = pair
            .ciphers()
            .seal_query(header.epoch, qseq, &octets, &plain);
        let mut frame = Vec::with_capacity(QUERY_HEADER_LEN + sealed.len());
        frame.extend_from_slice(&octets);
        frame.extend_from_slice(&sealed);
        match conn.try_send_side(Bytes::from(frame), SideClass::Datagram) {
            Ok(()) => {
                state.stats.sent.bump();
                pair.touch(Instant::now());
            }
            Err(SideRefused::Full) => {
                state.stats.congested.bump();
                return Err(QueryError::Congested.into());
            }
            Err(SideRefused::TooLarge { max, .. }) => {
                return Err(QueryError::TooLarge {
                    what: "the query frame is over what the connection to the forwarder carries; \
                           ask a shorter path or send less",
                    max: max as u64,
                }
                .into());
            }
            Err(SideRefused::Closed) => return Err(QueryError::Unreachable.into()),
            Err(other) => {
                return Err(not_ready(format!(
                    "the forwarder took no query frame ({other}): attach a forwarder that routes \
                     channel frames (NodeHandle::attach_forwarder), or ask QueryPath::Signed"
                )));
            }
        }
        let resolved = match crate::rt::timeout(remaining, reply).await {
            Err(_) => return Err(Stop::Silent),
            Ok(Err(_)) => return Err(QueryError::Unreachable.into()),
            Ok(Ok(resolved)) => resolved,
        };
        let status = resolved.map_err(bad_answer)?;
        self.query_channel_outcome(run, server, session, status)
    }

    /// The outcome of `server` for its sealed `status`: judged as the signed path judges one, and
    /// by the standing **now** of the key that signed the session.
    fn query_channel_outcome(
        &self,
        run: &Run,
        server: &Name,
        session: &RecvSession,
        status: ChanStatus,
    ) -> Result<Outcome, Stop> {
        let space = &run.held.name;
        let person = {
            let log = run.held.log.lock();
            standing(&log, &self.judge, &session.sender_key(), Who::Writer)
        }
        .map_err(|why| {
            bad_answer(format!(
                "the signer of the session is no writer of the space now ({why:?}): it is not \
                 the server"
            ))
        })?;
        if matches!(status, ChanStatus::Answered(_) | ChanStatus::Refused { .. }) {
            self.query.hints.proven(space, server, Instant::now());
        }
        let author = Author::shared(person, server.clone());
        let got = |bytes: Bytes, refusal: Option<AppRefusal>| Got {
            path: run.path.clone(),
            bytes,
            author: Arc::clone(&author),
            kind: Kind::Answered(Answered {
                query: run.id,
                via: Via::Sealed,
                refusal,
                proof: None,
            }),
        };
        match status {
            ChanStatus::Answered(bytes) => {
                if bytes.len() > run.ask.answer_max {
                    return Err(QueryError::AnswerTooLarge {
                        size: bytes.len(),
                        max: run.ask.answer_max,
                    }
                    .into());
                }
                Ok(Outcome::Answered(got(bytes, None)))
            }
            ChanStatus::Refused { code, text } => Ok(Outcome::Refused(got(
                Bytes::new(),
                Some(AppRefusal::new(code, text)),
            ))),
            ChanStatus::Busy { .. } => Err(QueryError::Busy.into()),
            ChanStatus::NotServed => Err(QueryError::NotServed {
                path: run.path.clone(),
            }
            .into()),
            ChanStatus::TooLarge { max } => Err(QueryError::TooLarge {
                what: "the server's answer does not fit what the channel path carries",
                max,
            }
            .into()),
        }
    }

    /// One `ANSWER` frame the forwarder routed to this node: the module docs say what becomes of
    /// it. Synchronous: the receive loop does not wait.
    pub(crate) fn query_answer_frame(&self, frame: Bytes) {
        let state = &self.query.ask.chan;
        let Ok((header, sealed)) = AnswerHeader::parse(&frame) else {
            state.stats.bad_frame.bump();
            return;
        };
        let taken = state.waiting.lock().remove(&(header.route, header.token));
        let Some(waiting) = taken else {
            state.stats.unmatched.bump();
            return;
        };
        let resolved = open_status(&waiting, &header, &frame[..ANSWER_HEADER_LEN], sealed);
        match &resolved {
            Ok(_) => {
                waiting.pair.answered();
                state.stats.answers.bump();
            }
            Err(why) => {
                tracing::debug!(route = header.route, "an answer is refused: {why}");
                state.stats.bad_answers.bump();
            }
        }
        // The waiter may be gone already (its deadline passed in the same instant): the answer
        // is dropped with the entry.
        let _ = waiting.reply.send(resolved);
    }
}

/// The status `sealed` holds, opened under the answer key of the pair the query was sealed under,
/// with the query's number as the nonce and `head` (the 19 octets) as the additional data.
fn open_status(waiting: &Waiting, header: &AnswerHeader, head: &[u8], sealed: &[u8]) -> Resolved {
    if header.epoch != waiting.pair.epoch() {
        return Err("its key epoch octet is not the pair's: it answers another exchange".into());
    }
    if sealed.len() < TAG_LEN {
        return Err("it is shorter than its seal's tag".into());
    }
    let plain = waiting
        .pair
        .ciphers()
        .open_answer(waiting.pair.epoch(), waiting.qseq, head, sealed)
        .ok_or_else(|| {
            "it does not open under the pair's answer key: the server did not seal it for this \
             query"
                .to_string()
        })?;
    ChanStatus::decode(&plain).map_err(|e| format!("what it holds is no answer ({e})"))
}

/// The ttl of a query's breadcrumb at the relays: its remaining time in 100 ms, 1 to 100.
fn ttl_ticks(remaining: Duration) -> u8 {
    let ticks = remaining.as_millis().div_ceil(100).clamp(1, 100);
    u8::try_from(ticks).expect("clamped to 100")
}

fn no_forwarder() -> Stop {
    not_ready(
        "the channel path needs a forwarder attached to this node: call \
         NodeHandle::attach_forwarder (an embedded engine's app_face carries channel frames), or \
         ask QueryPath::Signed",
    )
}
