//! The server's half of the channel path: a `QUERY` frame the forwarder routed to this node's
//! app face, judged cheapest first, and answered once under the pair's key or dropped with a
//! counter (docs/specs/query.md, the channel path).
//!
//! [`NodeInner::query_frame`] is synchronous up to the handler (the receive loop never waits on
//! this layer), and each step costs more than the one before it, so a stranger costs a lookup and
//! a forgery one AEAD:
//!
//! 1. the header parses and the frame is 52 to 2,048 octets: else `malformed`;
//! 2. the pair id names a live pair of this node on this route: else `unknown_pair`, **no AEAD**;
//! 3. the key epoch octet is the pair's, and the counter is fresh in the pair's window: else
//!    `unknown_pair` / `replayed`, no AEAD (nothing is marked);
//! 4. the asker was judged by what this node holds now: two atomic loads (the trust generation,
//!    which a revocation **and a suspicion mark or lift** move, and the space's fold version)
//!    against what she was judged by; if either moved the pair's space is judged again offline
//!    ([`NodeInner::chan_rejudge`]) and a pair whose asker no longer stands is gone:
//!    `rejudged_out`, **before any AEAD**. (What the clock alone ends is the pair's lease, which
//!    step 2 reads: the pair lives its session's lifetime, at most an hour, and not past the
//!    earliest end of the certificates of her chain, as the signed path would refuse her from
//!    then on);
//! 5. one AEAD open under `Kq` with the 36 header octets as the additional data: `bad_seal`
//!    (nothing is marked: a forged frame burns no counter);
//! 6. the counter is marked in the pair's window. **A counter is marked after the AEAD opened and
//!    before anything is answered**, so a copy, a concurrent copy and a retransmission are
//!    dropped (`replayed`) and every answer (the handler's, `Busy`, `NotServed`, `TooLarge`) is
//!    made for a query that authenticated and was marked: one answer per counter, so a nonce is
//!    used once under `Ka` (the pair module states the argument);
//! 7. the plaintext decodes and its query is at most 1,024 octets: else `bad_plain`;
//! 8. the asker person's rate on this path (256 a second): over it, a sealed `Busy`;
//! 9. the longest served prefix of the path, else a sealed `NotServed`;
//! 10. a place for the handler (64 on the node, 8 for the person, her answer octets, all shared
//!     with the signed path): none, a sealed `Busy`;
//! 11. the handler runs in a task under the asker's deadline; its reply is sealed under `Ka`
//!     with the query's counter and the `ANSWER` header as the additional data, and sent.
//!
//! A refusal that is a `Busy` is itself limited to one a second per pair, so a flood of queries
//! costs one seal a second, not one each. `Reply::Pass` and a handler past the asker's deadline
//! send nothing (the asker counts the server silent).
//!
//! **Not the deleted answers family.** Nothing a handler answers is stored, cached, recomputed
//! or made an entry: the pair keeps a window of counters and never an answer, and a copy of a
//! query that was answered is dropped, not answered again.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_transport::{FaceId, SideClass};

use super::serve::{OwnedSlot, ServerState, run_handler};
use super::types::{ANSWER_MAX_CHANNEL, Asker, Handler, Query, QueryId, Reply, Via};
use crate::chan::pair::ServerPair;
use crate::chan::qframe::{
    ANSWER_OVERHEAD, AnswerHeader, ChanStatus, QUERY_BYTES_MAX, QUERY_HEADER_LEN, QUERY_OVERHEAD,
    QueryHeader, QueryPlain,
};
use crate::chan::varint;
use crate::node::NodeInner;
use crate::rt::{self, Instant};

/// The most octets of a `QUERY` frame: a query of 1,024 octets, a path of 255 and the header,
/// with room to spare. A frame over it is no query of this layer.
pub(crate) const QUERY_FRAME_MAX: usize = 2_048;

/// What a sealed `Busy` tells the asker to wait, in milliseconds: the refusal itself is sent at
/// most once a second per pair, so asking again sooner could not be told anything new.
const BUSY_RETRY_MS: u64 = 1_000;

/// The status a handler's `reply` says, if it says one: `Pass` says none. An answer over what the
/// channel path carries is `TooLarge`; a refusal's text is cut.
fn status_of(reply: Reply) -> Option<ChanStatus> {
    match reply {
        Reply::Answer(bytes) if bytes.len() > ANSWER_MAX_CHANNEL => Some(ChanStatus::TooLarge {
            max: ANSWER_MAX_CHANNEL as u64,
        }),
        Reply::Answer(bytes) => Some(ChanStatus::Answered(bytes)),
        Reply::Refuse(refusal) => Some(ChanStatus::refused(refusal.code, &refusal.text)),
        Reply::Pass => None,
    }
}

/// The longest answer whose sealed frame is at most `cap` octets: the status octet, the length
/// and the answer, under [`ANSWER_OVERHEAD`].
fn answer_room(cap: usize) -> usize {
    let base = cap.saturating_sub(ANSWER_OVERHEAD + 1);
    let fits = |n: usize| n + varint::len(n as u64).unwrap_or(8) <= base;
    let mut n = base.saturating_sub(1);
    while n > 0 && !fits(n) {
        n -= 1;
    }
    n
}

impl NodeInner {
    /// One `QUERY` frame the forwarder routed to this node. The answer goes back through this
    /// node's own carrier (the forwarder's breadcrumb of the token routes it to the asker), so
    /// the ingress face is not needed.
    pub(crate) fn query_frame(&self, frame: Bytes, _ingress: FaceId) {
        let pairs = &self.chan.pairs;
        let stats = &pairs.stats;
        stats.queries.bump();
        let now = Instant::now();

        // 1. The header and the size.
        if frame.len() < QUERY_OVERHEAD || frame.len() > QUERY_FRAME_MAX {
            stats.malformed.bump();
            return;
        }
        let Ok((head, sealed)) = QueryHeader::parse(&frame) else {
            stats.malformed.bump();
            return;
        };

        // 2. The pair, by id, on the route it names. A pair nobody holds costs a lookup.
        let Some(mut pair) = pairs.get(&head.pair, head.route, now) else {
            stats.unknown_pair.bump();
            return;
        };

        // 3. The epoch the pair was made at, and a counter not used: no AEAD for either.
        if head.epoch != pair.owner.key_epoch as u8 {
            stats.unknown_pair.bump();
            return;
        }
        if !pair.fresh(head.qseq) {
            stats.replayed.bump();
            return;
        }

        // 4. Has anything the asker was judged by moved? Two loads say no; if so, judge the space's
        // pairs again (offline, restamping those that stand) and look the pair up again.
        if pair.moved(self.judge.generation()) {
            self.chan_rejudge(&pair.owner.space, now);
            let Some(again) = pairs.get(&head.pair, head.route, now) else {
                stats.rejudged_out.bump();
                return;
            };
            pair = again;
        }

        // 5. The one AEAD: under `Kq`, the header as the additional data. A forgery marks nothing.
        stats.opens.bump();
        let Some(plain) =
            pair.ciphers()
                .open_query(head.epoch, head.qseq, &frame[..QUERY_HEADER_LEN], sealed)
        else {
            stats.bad_seal.bump();
            return;
        };

        // 6. Marked: from here on this counter is answered for, once, whatever happens.
        if !pair.mark(head.qseq) {
            stats.replayed.bump();
            return;
        }

        // 7. The plaintext.
        let plain = match QueryPlain::decode(&plain) {
            Ok(plain) if plain.bytes.len() <= QUERY_BYTES_MAX => plain,
            Ok(plain) => {
                tracing::debug!(
                    pair = ?head.pair,
                    "a channel query of {} octets, over {QUERY_BYTES_MAX}, dropped",
                    plain.bytes.len()
                );
                stats.bad_plain.bump();
                return;
            }
            Err(e) => {
                tracing::debug!(pair = ?head.pair, "a channel query that opened is no query: {e}");
                stats.bad_plain.bump();
                return;
            }
        };

        // 8. The asker person's rate on this path.
        let server = &self.query.server;
        if !server.admit_channel(&pair.owner.person, now) {
            self.query_busy(&pair, &head, now);
            return;
        }

        // 9. The longest served prefix of the path.
        let Some((_, handler)) = self.query.table.lookup(&pair.owner.space, &plain.path) else {
            if self.query_say(&pair, &head, &ChanStatus::NotServed) {
                stats.not_served.bump();
            }
            return;
        };

        // 10. A place for the handler.
        let node = self.arc();
        let Some(slot) = ServerState::slot_owned(&node, &pair.owner.person, now) else {
            self.query_busy(&pair, &head, now);
            return;
        };

        // 11. The handler, under the asker's deadline, in a task of its own.
        stats.handlers.bump();
        let deadline = now + Duration::from_millis(u64::from(plain.deadline_ms));
        let query = Query {
            id: QueryId(plain.id),
            path: plain.path,
            bytes: plain.bytes,
            asker: Asker {
                person: pair.owner.person.clone(),
                device: pair.owner.device.clone(),
            },
            via: Via::Sealed,
            deadline,
        };
        self.tasks.spawn(async move {
            node.query_chan_run(&pair, &head, &handler, query, slot)
                .await;
        });
    }

    /// Run the handler and send what it answers.
    async fn query_chan_run(
        &self,
        pair: &ServerPair,
        head: &QueryHeader,
        handler: &Arc<dyn Handler>,
        query: Query,
        slot: OwnedSlot,
    ) {
        let stats = &self.chan.pairs.stats;
        let deadline = query.deadline;
        let Some(reply) = run_handler(handler, query).await else {
            stats.silent.bump();
            return;
        };
        let Some(status) = status_of(reply) else {
            stats.silent.bump();
            return;
        };
        if self
            .query_answer_sealed(pair, head, status, deadline, &slot)
            .await
        {
            stats.answers.bump();
        }
    }

    /// Seal `status` as the answer to `head`'s query and send it on the class that carries it: a
    /// datagram if it fits the carrier's datagram limit for the route, else a stream frame when
    /// the asker's path and the carrier both have a stream, else a `TooLarge` that says what fits.
    /// Returns whether the carrier took a frame; the `slot` is charged the octets sent.
    async fn query_answer_sealed(
        &self,
        pair: &ServerPair,
        head: &QueryHeader,
        status: ChanStatus,
        deadline: Instant,
        slot: &OwnedSlot,
    ) -> bool {
        let stats = &self.chan.pairs.stats;
        let Some(carrier) = self.chan.tx.carrier.get() else {
            tracing::warn!(
                "a channel query was answered but no carrier is attached: attach the forwarder \
                 (`attach_forwarder`) so answers can leave"
            );
            stats.not_sent.bump();
            return false;
        };
        let datagram = carrier.datagram_max_for(head.route);
        let stream = pair.owner.stream && carrier.has_stream();
        let plain = status.encode();
        let (class, status) = if ANSWER_OVERHEAD + plain.len() <= datagram {
            (SideClass::Datagram, status)
        } else if stream && ANSWER_OVERHEAD + plain.len() <= carrier.stream_frame_max() {
            (SideClass::Stream, status)
        } else {
            let cap = if stream {
                carrier.stream_frame_max()
            } else {
                datagram
            };
            let max = answer_room(cap).min(ANSWER_MAX_CHANNEL) as u64;
            (SideClass::Datagram, ChanStatus::TooLarge { max })
        };
        let frame = seal_status(pair, head, class, &status);
        let sent = match class {
            SideClass::Stream => {
                let wait = deadline.saturating_duration_since(Instant::now());
                // A stream that does not take it by the asker's deadline: the answer is no use.
                matches!(
                    rt::timeout(wait, carrier.send_stream(frame.clone())).await,
                    Ok(Ok(()))
                )
            }
            _ => carrier.try_send_datagram(frame.clone()).is_ok(),
        };
        if sent {
            slot.charge(frame.len(), Instant::now());
        } else {
            stats.not_sent.bump();
        }
        sent
    }

    /// A sealed `Busy` for a query that was opened and marked, at most once a second to its
    /// pair: the others are dropped and counted.
    fn query_busy(&self, pair: &ServerPair, head: &QueryHeader, now: Instant) {
        let stats = &self.chan.pairs.stats;
        if !pair.busy_due(now) {
            stats.busy_dropped.bump();
            return;
        }
        let busy = ChanStatus::Busy {
            retry_ms: BUSY_RETRY_MS,
        };
        if self.query_say(pair, head, &busy) {
            stats.busy.bump();
        }
    }

    /// Seal the small `status` (a `Busy` or a `NotServed`) as a datagram answer to `head`'s
    /// query, with no handler and no place. Returns whether the carrier took it.
    fn query_say(&self, pair: &ServerPair, head: &QueryHeader, status: &ChanStatus) -> bool {
        let stats = &self.chan.pairs.stats;
        let Some(carrier) = self.chan.tx.carrier.get() else {
            stats.not_sent.bump();
            return false;
        };
        let frame = seal_status(pair, head, SideClass::Datagram, status);
        let sent = carrier.try_send_datagram(frame).is_ok();
        if !sent {
            stats.not_sent.bump();
        }
        sent
    }
}

/// The `ANSWER` frame of `status` to the query `head` names, on `class`: the 19 header octets,
/// then the status sealed under `Ka` with the **query's** counter and the header as the
/// additional data (the class is in the header, so a frame moved to the other class opens
/// nowhere).
fn seal_status(
    pair: &ServerPair,
    head: &QueryHeader,
    class: SideClass,
    status: &ChanStatus,
) -> Bytes {
    let header = AnswerHeader {
        class,
        route: head.route,
        token: head.token,
        epoch: head.epoch,
    }
    .encode();
    let sealed = pair
        .ciphers()
        .seal_answer(head.epoch, head.qseq, &header, &status.encode());
    let mut frame = Vec::with_capacity(header.len() + sealed.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&sealed);
    Bytes::from(frame)
}
