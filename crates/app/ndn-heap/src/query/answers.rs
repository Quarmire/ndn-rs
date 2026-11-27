//! The answers of one `get`: the queue a query's items and notices wait in until `Items` is
//! polled (docs/specs/query.md, Order, and when the stream ends).
//!
//! **An answer is not an entry.** The queue belongs to one `Items` and is memory only: it holds
//! at most [`ANSWER_QUEUE_ITEMS`] answers and [`ANSWER_QUEUE_BYTES`] octets charged, and when a
//! slow reader fills it the **oldest** answers are dropped and a [`GetNotice::Lagged`] is told in
//! their place. Answers never block the server: its work ended when it sent. The notices
//! (`QueryFailed`, `AnswersDone`) are queued behind the answers that came before them and are never
//! dropped; there are at most one per server and the one `AnswersDone`.

use std::collections::VecDeque;
use std::task::{Context, Poll};

use futures::task::AtomicWaker;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::chan::verbs::{GetNotice, Got, Kind};

/// The most answers one `Items` queues.
pub(crate) const ANSWER_QUEUE_ITEMS: usize = 64;

/// The most octets of answers one `Items` queues (their bytes, proofs and paths, and a small
/// overhead each).
pub(crate) const ANSWER_QUEUE_BYTES: usize = 1 << 20;

/// What an answer is charged besides its octets.
const ITEM_OVERHEAD: usize = 64;

enum Entry {
    /// An answer and the octets it is charged.
    Item(Got, usize),
    /// This many answers were dropped here.
    Lagged(u64),
    Notice(GetNotice),
}

#[derive(Default)]
struct State {
    queue: VecDeque<Entry>,
    items: usize,
    bytes: usize,
    closed: bool,
    /// `AnswersDone` is queued: nothing follows it.
    done_queued: bool,
    /// `AnswersDone` was taken: the stream of a query alone ends here.
    done_taken: bool,
}

/// One `Items`' answers.
#[derive(Default)]
pub(crate) struct AnswerSink {
    state: Mutex<State>,
    waker: AtomicWaker,
    /// Cancelled when `Items` is dropped: the query run stops, its Interests are dropped and its
    /// pending entries released.
    cancel: CancellationToken,
}

/// The octets an answer is charged.
fn weight(got: &Got) -> usize {
    let proof = match &got.kind {
        Kind::Answered(a) => a.proof.as_ref().map_or(0, |p| p.len()),
        _ => 0,
    };
    got.bytes.len() + proof + got.path.encode_to_tlv().len() + ITEM_OVERHEAD
}

impl AnswerSink {
    /// Queue an answer. A full queue drops the oldest answers first and tells how many.
    pub(crate) fn push(&self, got: Got) {
        let weight = weight(&got);
        {
            let mut st = self.state.lock();
            if st.closed || st.done_queued {
                return;
            }
            while st.items > 0
                && (st.items >= ANSWER_QUEUE_ITEMS || st.bytes + weight > ANSWER_QUEUE_BYTES)
            {
                st.drop_oldest();
            }
            st.items += 1;
            st.bytes += weight;
            st.queue.push_back(Entry::Item(got, weight));
        }
        self.waker.wake();
    }

    /// Queue a notice behind what is queued. `AnswersDone` is the last thing queued: nothing is
    /// accepted after it.
    pub(crate) fn notice(&self, notice: GetNotice) {
        {
            let mut st = self.state.lock();
            if st.closed || st.done_queued {
                return;
            }
            st.done_queued = matches!(notice, GetNotice::AnswersDone { .. });
            st.queue.push_back(Entry::Notice(notice));
        }
        self.waker.wake();
    }

    /// The next answer or notice; `Ready(None)` once `AnswersDone` was taken (the source is
    /// over), `Pending` with the waker registered otherwise.
    pub(crate) fn poll_next(&self, cx: &mut Context<'_>) -> Poll<Option<Result<Got, GetNotice>>> {
        match self.take() {
            Taken::Next(next) => return Poll::Ready(next),
            Taken::Nothing => {}
        }
        self.waker.register(cx.waker());
        match self.take() {
            Taken::Next(next) => Poll::Ready(next),
            Taken::Nothing => Poll::Pending,
        }
    }

    fn take(&self) -> Taken {
        let mut st = self.state.lock();
        match st.queue.pop_front() {
            Some(Entry::Item(got, weight)) => {
                st.items -= 1;
                st.bytes -= weight;
                Taken::Next(Some(Ok(got)))
            }
            Some(Entry::Lagged(missed)) => Taken::Next(Some(Err(GetNotice::Lagged { missed }))),
            Some(Entry::Notice(notice)) => {
                st.done_taken |= matches!(notice, GetNotice::AnswersDone { .. });
                Taken::Next(Some(Err(notice)))
            }
            None if st.done_taken => Taken::Next(None),
            None => Taken::Nothing,
        }
    }

    /// Move the answers queued **before the next notice** into `buf`; returns how many. A
    /// notice, or a `Lagged`, stops it: `Items::next` yields that.
    pub(crate) fn take_items(&self, buf: &mut Vec<Got>) -> usize {
        let mut st = self.state.lock();
        let before = buf.len();
        while let Some(Entry::Item(..)) = st.queue.front() {
            if let Some(Entry::Item(got, weight)) = st.queue.pop_front() {
                st.items -= 1;
                st.bytes -= weight;
                buf.push(got);
            }
        }
        buf.len() - before
    }

    /// Stop: nothing more is queued, and the query run is cancelled.
    pub(crate) fn close(&self) {
        self.state.lock().closed = true;
        self.cancel.cancel();
        self.waker.wake();
    }

    /// The token a query run stops at when [`Self::close`] is called.
    pub(crate) fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Queued items and the octets they are charged: what the bounds count.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> (usize, usize) {
        let st = self.state.lock();
        (st.items, st.bytes)
    }
}

enum Taken {
    Next(Option<Result<Got, GetNotice>>),
    Nothing,
}

impl State {
    /// Drop the oldest answer and tell it in its place, joined to a `Lagged` next to it.
    fn drop_oldest(&mut self) {
        let Some(at) = self.queue.iter().position(|e| matches!(e, Entry::Item(..))) else {
            return;
        };
        if let Entry::Item(_, weight) = &self.queue[at] {
            self.items -= 1;
            self.bytes -= weight;
        }
        self.queue[at] = Entry::Lagged(1);
        if at + 1 < self.queue.len()
            && let Entry::Lagged(next) = self.queue[at + 1]
        {
            self.queue[at] = Entry::Lagged(1 + next);
            self.queue.remove(at + 1);
        }
        if at > 0
            && let Entry::Lagged(prev) = self.queue[at - 1]
            && let Entry::Lagged(this) = self.queue[at]
        {
            self.queue[at - 1] = Entry::Lagged(prev + this);
            self.queue.remove(at);
        }
    }
}
