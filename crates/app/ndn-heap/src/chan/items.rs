//! `Items`, what `Heap::get` returns (docs/specs/channel.md, The verbs: put, emit, get): the one
//! stream of a space's kept values and of what its channels deliver to this device, and the sink
//! the receiver pushes emissions into.
//!
//! A [`Sink`] is one `Items`' queues. A `Latest` channel's messages go to a coalescing queue (the
//! newest per sender and name, at most 4,096 pairs); a `Reliable` or `Window` channel's go to a
//! FIFO of at most `queue_bytes` (1 MiB). A full FIFO either stalls the stream (the receiver waits
//! before it takes the next stream frame: back pressure to the sender) or discards the oldest and
//! says [`GetNotice::Lagged`], as [`Congestion`] says.
//!
//! The consumer is the limit worth watching (one `poll_next` per message costs about 100 ns), so
//! [`Items::next_batch`] hands over everything queued in one call under one lock, with no wake per
//! item.

use std::collections::VecDeque;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use futures::Stream;
use futures::task::AtomicWaker;
use ndn_foundation_types::Name;
use parking_lot::Mutex;
use tokio::sync::Notify;

use super::fifo::{Entry, Fifo, QUEUE_BYTES};
use super::hub::Listen;
use super::latest::{Coalescing, LATEST_BYTES, PAIRS_MAX, Pair};
use super::verbs::{Congestion, GetNotice, GetOptions, Got, Live, LiveEnd, Modes, Select, Trust};
use super::wire::ChannelMode;
use crate::error::HeapError;
use crate::node::NodeInner;
use crate::space::{Heap, KeptFeed, KeptStep};

/// A message on its way to the sinks: the key of its pair, its sequence, the octets it is
/// charged for (what it pins, [`super::message::Message::pinned`]) and the item.
#[derive(Clone, Debug)]
pub(crate) struct Out {
    pub(crate) pair: Pair,
    pub(crate) seq: u64,
    pub(crate) weight: usize,
    pub(crate) got: Got,
}

/// The queues of one `Items`.
pub(crate) struct SinkState {
    latest: Coalescing<Got>,
    fifo: Fifo<Got>,
    /// Sessions that ended, told after what is queued.
    ends: VecDeque<LiveEnd>,
    /// Notices that say something about items already given (a retraction), told after what is
    /// queued and before a session's end.
    notices: VecDeque<GetNotice>,
    closed: bool,
}

impl SinkState {
    fn take_notice_first(&mut self) -> Option<Result<Got, GetNotice>> {
        let missed = self.latest.take_missed();
        if missed > 0 {
            return Some(Err(GetNotice::Lagged { missed }));
        }
        match self.fifo.pop() {
            Some(Entry::Item(got)) => return Some(Ok(got)),
            Some(Entry::Lagged(missed)) => return Some(Err(GetNotice::Lagged { missed })),
            None => {}
        }
        if let Some((_, _, got)) = self.latest.take() {
            return Some(Ok(got));
        }
        if let Some(notice) = self.notices.pop_front() {
            return Some(Err(notice));
        }
        self.ends
            .pop_front()
            .map(|end| Err(GetNotice::LiveEnded(end)))
    }

    /// The next item if the next thing queued is an item, never a notice.
    fn take_item(&mut self) -> Option<Got> {
        if self.latest.pending_missed() > 0 {
            return None;
        }
        match self.fifo.front() {
            Some(Entry::Lagged(_)) => return None,
            Some(Entry::Item(_)) => {
                return match self.fifo.pop() {
                    Some(Entry::Item(got)) => Some(got),
                    _ => unreachable!("the front was an item"),
                };
            }
            None => {}
        }
        self.latest.take().map(|(_, _, got)| got)
    }
}

/// One `Items`' side of the receiver.
pub(crate) struct Sink {
    pub(crate) space: Name,
    select: Select,
    modes: Modes,
    overflow: Congestion,
    /// Whether this sink waits for a signed checkpoint to cover a frame before it is given it.
    pub(crate) trust: Trust,
    /// A `HELLO` came on a channel this sink takes: the path to a sender works.
    hello: AtomicBool,
    state: Mutex<SinkState>,
    waker: AtomicWaker,
    /// Woken when the FIFO has room again, or the sink is closed.
    room: Notify,
}

impl Sink {
    pub(crate) fn new(
        space: Name,
        select: Select,
        modes: Modes,
        overflow: Congestion,
        trust: Trust,
    ) -> Sink {
        Sink {
            space,
            select,
            modes,
            overflow,
            trust,
            hello: AtomicBool::new(false),
            state: Mutex::new(SinkState {
                latest: Coalescing::new(PAIRS_MAX, LATEST_BYTES),
                fifo: Fifo::new(QUEUE_BYTES),
                ends: VecDeque::new(),
                notices: VecDeque::new(),
                closed: false,
            }),
            waker: AtomicWaker::new(),
            room: Notify::new(),
        }
    }

    /// Whether this sink takes the channels of `space` in `mode`.
    pub(crate) fn takes(&self, space: &Name, mode: ChannelMode) -> bool {
        self.space == *space && self.modes.contains(mode)
    }

    /// Push `outs` of a channel of `mode` that this sink's path filter keeps. `last` says no other
    /// sink follows, so the messages are moved instead of cloned. Wakes the consumer once.
    pub(crate) fn deliver(&self, mode: ChannelMode, outs: &mut Vec<Out>, last: bool) {
        let mut pushed = false;
        {
            let mut st = self.state.lock();
            if st.closed {
                return;
            }
            let mut push = |st: &mut SinkState, out: Out| {
                pushed = true;
                match mode {
                    ChannelMode::Latest => {
                        st.latest.offer(out.pair, out.seq, out.weight, out.got);
                    }
                    ChannelMode::Reliable | ChannelMode::Window => match self.overflow {
                        Congestion::Block => st.fifo.push(out.got, out.weight),
                        Congestion::Drop => {
                            st.fifo.push_dropping_oldest(out.got, out.weight);
                        }
                    },
                }
            };
            if last {
                for out in outs.drain(..) {
                    if self.select.matches(&out.got.path) {
                        push(&mut st, out);
                    }
                }
            } else {
                for out in outs.iter() {
                    if self.select.matches(&out.got.path) {
                        push(&mut st, out.clone());
                    }
                }
            }
        }
        if pushed {
            self.waker.wake();
        }
    }

    /// `missed` sequences of a `Reliable` or `Window` channel never came: a notice, in its place
    /// in the queue.
    pub(crate) fn gap(&self, missed: u64) {
        {
            let mut st = self.state.lock();
            if st.closed {
                return;
            }
            st.fifo.lagged(missed);
        }
        self.waker.wake();
    }

    /// A session of this sink's space ended: told after what is queued.
    pub(crate) fn end(&self, channel: u64, end: LiveEnd) {
        {
            let mut st = self.state.lock();
            if st.closed {
                return;
            }
            st.latest.forget_idle(channel);
            st.ends.push_back(end);
        }
        self.waker.wake();
    }

    /// A signed checkpoint contradicted the frames of `writer`'s channel with sequences `from` to
    /// `to`: told after what is queued, so a consumer that read the items reads the retraction
    /// next.
    pub(crate) fn retract(&self, writer: &Name, from: u64, to: u64) {
        {
            let mut st = self.state.lock();
            if st.closed {
                return;
            }
            st.notices.push_back(GetNotice::Retracted {
                writer: writer.clone(),
                from,
                to,
            });
        }
        self.waker.wake();
    }

    /// A `HELLO` came.
    pub(crate) fn hello_seen(&self) {
        self.hello.store(true, Ordering::Release);
    }

    /// Stop taking messages: the stream ends when what is queued has been read.
    pub(crate) fn close(&self) {
        self.state.lock().closed = true;
        self.waker.wake();
        self.room.notify_waiters();
    }

    /// Whether a `Reliable` or `Window` message cannot be taken now without discarding or
    /// passing the bound: the receiver does not take the next stream frame while this holds.
    fn blocks(&self) -> bool {
        let st = self.state.lock();
        !st.closed && self.overflow == Congestion::Block && st.fifo.is_full()
    }

    /// Wait until the FIFO has room (or the sink is closed). Returns at once when it has.
    pub(crate) async fn wait_room(&self) {
        loop {
            let mut notified = pin!(self.room.notified());
            notified.as_mut().enable();
            if !self.blocks() {
                return;
            }
            notified.await;
        }
    }

    fn freed(&self, was_full: bool, st: &SinkState) -> bool {
        was_full && !st.fifo.is_full()
    }
}

/// What `Heap::get` returns: the kept values of one space whose path matches, then the changes of
/// kept values, and every message the channels of the space deliver to this device whose path
/// matches, and notices, as a [`Stream`] of `Result<Got, GetNotice>`. `Got::kind` says which an
/// item is: [`Kind::Kept`](super::verbs::Kind::Kept) is the register's head of its path (durable,
/// signed), [`Kind::Emitted`](super::verbs::Kind::Emitted) is not (and is never the current
/// value of a path).
///
/// * **Creating it does no I/O.** It registers its kept watcher and its emission sink at
///   creation, so nothing between creation and the first poll is lost. It receives the messages
///   of every session of the space this device holds, in the modes it asked for. Which senders to
///   ask for a session is the caller's (`NodeHandle::ask_channel_in`) in this stage.
/// * **Order.** The kept listing first, always: every path with a value under the selector, in
///   path order, whatever was emitted meanwhile (that is held until the listing was yielded).
///   Then the changes of kept values and the emissions, taken in turn so that neither starves the
///   other, with no order promised between the two. Within the kept source: the register's apply
///   order, never an older value of a path after a newer. Within the emissions: the mode's
///   (below). A notice is told after what is queued before it, as it always was.
/// * **A slow reader never loses a kept value.** The kept queue is bounded as `watch`'s is
///   (`Config::watch_queue`); when it overflowed the stream is not told a loss, it reads the
///   current value of each path it was not given from the store and goes on. A path that
///   changed several times meanwhile is given its latest value, never an older one after a newer;
///   a path removed meanwhile is told as a removal. `watch` and the log have the history.
/// * **A path put and emitted** gives two items, one `Kept` and one `Emitted`, never merged and
///   never one for the other.
/// * **Order of the emissions.** Within one channel: `Reliable` and `Window` in sequence order,
///   with a [`GetNotice::Lagged`] where messages are missing; `Latest`: the newest message per
///   sender and name, never an older after a newer. Across channels: arrival order.
/// * **A gap is never silent** in `Reliable` and `Window`: a frame that does not continue the
///   last one is a `Lagged { missed }` in its place in the stream (`missed` counts sequences,
///   and a control record takes one like a message does). `Latest` expects gaps and notices none;
///   its `Lagged` says only that this consumer was too slow for the bound of 4,096 names.
/// * **A full queue** of a `Reliable` or `Window` channel stalls the stream (the default,
///   [`Congestion::Block`]) or discards the oldest and says `Lagged` ([`Congestion::Drop`]).
/// * **The end of a session** is told once what was queued before it has been read:
///   `LiveEnded`. A removed sender is told the first frame after this device holds the removing
///   record.
/// * **Dropping it** cancels the sink: nothing more is queued for it, and a stalled stream is
///   freed.
/// * **What a delivery is worth** (docs/specs/channel.md, Checkpoints). With
///   [`Trust::Prompt`] (the default) an item is delivered as soon as its AEAD opens: it is
///   authenticated as "a holder of the channel key's", never as the sender's: [`Got::by`] and
///   [`Got::writer`] name the channel's sender, and [`Emitted::verified`](super::verbs::Emitted)
///   is `false`. A signed checkpoint of the sender then
///   covers it, at most `W = P + d + epsilon` later (the checkpoint period `P`, 20 ms by default,
///   the stream's one-way delay `d` and 1 ms of verification: about **22 ms** on a 1 ms path;
///   [`crate::ChannelInfo::detection_window`] computes it, and
///   [`crate::ChannelConfig::checkpoint`] sets `P`), and the item is the sender's. A frame a key
///   holder forged is exposed by the next checkpoint instead: a
///   [`GetNotice::Retracted`] for its sequences follows what was delivered, evidence is kept
///   ([`crate::host::NodeHandle::channel_evidence`]), the face it came over is asked to be barred
///   from channel frames ([`crate::IngressBar`]; with none attached nothing is barred) and
///   [`crate::Alert::ChannelForgery`] is raised. With
///   [`Trust::Verified`] nothing is delivered before its checkpoint verified: no forgery of a
///   holder is ever delivered, at up to one period of latency. **Checkpoints detect; `Prompt` does
///   not prevent.**
/// * **Silence is not trust.** A `Prompt` receiver that holds frames no verified checkpoint
///   covers for `max(4 x period, 100 ms)` holds what follows until one verifies, and ends the
///   session when none does within 3 s ([`crate::EndReason::Unverifiable`]).
///
/// The stream ends when the node stops. Poll it with [`futures::StreamExt::next`], or take
/// everything queued at once with [`Items::next_batch`].
pub struct Items {
    space: Name,
    node: Arc<NodeInner>,
    /// The emissions, when asked for.
    live: Option<Emission>,
    /// The kept values, when asked for.
    kept: Option<KeptFeed>,
    /// The kept listing that [`Items::caught_up`] read before it was asked for.
    ready: VecDeque<Got>,
    /// Whether the kept changes are polled before the emissions on the next poll.
    kept_turn: bool,
}

/// The emission side of an `Items`.
struct Emission {
    sink: Arc<Sink>,
    /// While held, announces of senders over the space make this device ask them.
    _listen: Listen,
}

impl Items {
    /// The next item or notice; `None` once the node has stopped and the queues are read.
    pub async fn next(&mut self) -> Option<Result<Got, GetNotice>> {
        futures::StreamExt::next(self).await
    }

    /// Move everything queued **that is an item** into `buf` in one call, under one lock per
    /// source and with no wake per item, and return how many: the kept listing first, then the
    /// kept changes, then the emissions. It stops, in each source, before a notice: when it
    /// returns `0` with something queued, the next thing is a notice, which [`Items::next`]
    /// yields. Returns `0` with nothing queued too; it never waits.
    pub fn next_batch(&mut self, buf: &mut Vec<Got>) -> usize {
        let before = buf.len();
        buf.extend(self.ready.drain(..));
        if let Some(feed) = &mut self.kept {
            while let Some(got) = feed.listing_next() {
                buf.push(got);
            }
            while let Some(got) = feed.next_item() {
                buf.push(got);
            }
        }
        if let Some(live) = &self.live {
            let node = &self.node;
            node.chan.rx.sweep_held_if_any(&node.chan.stats.rx);
            let mut st = live.sink.state.lock();
            let was_full = st.fifo.is_full();
            while let Some(got) = st.take_item() {
                buf.push(got);
            }
            let freed = live.sink.freed(was_full, &st);
            drop(st);
            if freed {
                live.sink.room.notify_waiters();
            }
        }
        buf.len() - before
    }

    /// Whether a `HELLO` has come on a channel this `Items` takes: the sender says the path
    /// works. `false` says only that none has come yet (and always for an `Items` with
    /// [`Live::Off`]).
    pub fn hello_seen(&self) -> bool {
        self.live
            .as_ref()
            .is_some_and(|live| live.sink.hello.load(Ordering::Acquire))
    }

    /// Resolves once the kept listing was yielded: every path that had a value under the selector
    /// when this `Items` was made has been given by [`Items::next`] or [`Items::next_batch`].
    /// Called before the listing was read, it reads the rest of it into this `Items`' own buffer
    /// first (the next call of `next` gives it, before anything else), so it does not wait for
    /// the caller to read it. At once for an `Items` with `kept: false`.
    pub async fn caught_up(&mut self) {
        if let Some(feed) = &mut self.kept {
            while let Some(got) = feed.listing_next() {
                self.ready.push_back(got);
            }
        }
    }

    /// The emissions side: the next item or notice, as the sink holds it.
    fn poll_live(
        node: &NodeInner,
        sink: &Sink,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Got, GetNotice>>> {
        sink.waker.register(cx.waker());
        node.chan.rx.sweep_held_if_any(&node.chan.stats.rx);
        let mut st = sink.state.lock();
        let was_full = st.fifo.is_full();
        let next = st.take_notice_first();
        let closed = st.closed;
        let freed = sink.freed(was_full, &st);
        drop(st);
        if freed {
            sink.room.notify_waiters();
        }
        match next {
            Some(item) => Poll::Ready(Some(item)),
            None if closed => Poll::Ready(None),
            None => Poll::Pending,
        }
    }

    /// The kept side: the next change as an item or a notice.
    fn poll_kept(
        feed: &mut KeptFeed,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Got, GetNotice>>> {
        feed.watch(cx.waker());
        match feed.step() {
            KeptStep::Got(got) => Poll::Ready(Some(Ok(got))),
            KeptStep::Notice(notice) => Poll::Ready(Some(Err(notice))),
            KeptStep::Pending => Poll::Pending,
            KeptStep::Ended => Poll::Ready(None),
        }
    }
}

impl Stream for Items {
    type Item = Result<Got, GetNotice>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        // The kept listing first, whatever the emissions hold.
        if let Some(got) = this.ready.pop_front() {
            return Poll::Ready(Some(Ok(got)));
        }
        if let Some(feed) = &mut this.kept
            && let Some(got) = feed.listing_next()
        {
            return Poll::Ready(Some(Ok(got)));
        }
        // Then the two sources in turn: the one that gave last goes second.
        let (mut kept_ended, mut live_ended) = (this.kept.is_none(), this.live.is_none());
        for pass in 0..2 {
            if (pass == 0) == this.kept_turn {
                if let Some(feed) = &mut this.kept {
                    match Self::poll_kept(feed, cx) {
                        Poll::Ready(Some(next)) => {
                            this.kept_turn = false;
                            return Poll::Ready(Some(next));
                        }
                        Poll::Ready(None) => kept_ended = true,
                        Poll::Pending => {}
                    }
                }
            } else if let Some(live) = &this.live {
                match Self::poll_live(&this.node, &live.sink, cx) {
                    Poll::Ready(Some(next)) => {
                        this.kept_turn = true;
                        return Poll::Ready(Some(next));
                    }
                    Poll::Ready(None) => live_ended = true,
                    Poll::Pending => {}
                }
            }
        }
        if kept_ended && live_ended {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for Items {
    fn drop(&mut self) {
        // The kept feed closes its watcher as it is dropped.
        if let Some(live) = &self.live {
            live.sink.close();
            self.node.chan.rx.remove_sink(&live.sink);
            // A session no other `Items` takes lapses, and its route is given up.
            self.node.chan_route_release(&live.sink);
        }
    }
}

impl std::fmt::Debug for Items {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Items")
            .field("space", &self.space)
            .finish_non_exhaustive()
    }
}

impl Heap {
    /// What this space holds and what its channels deliver, as one stream: the kept values of
    /// the paths under `what` (a path, or everything under a prefix) in path order, then the
    /// changes of kept values as they arrive, and, with [`GetOptions::live`] of
    /// [`Live::Emitted`] (the default), the emissions of the sessions this device holds
    /// ([`crate::host::NodeHandle::ask_channel_in`] asks a sender for one) in the modes
    /// `opts.modes` joins. Creating it does no network I/O and registers both feeds, so nothing
    /// that comes after this call is lost. See [`Items`] for the order, what a slow reader
    /// keeps and loses, and what `by` is.
    ///
    /// # Errors
    ///
    /// [`HeapError::BadRequest`] for `kept: false` with [`Live::Off`] (it asks for nothing: ask
    /// for kept values, emissions, or both); [`HeapError::NotAllowed`] for emissions of a space
    /// this device only follows (a follower takes no part in channels: open the space as a
    /// member; it may read kept values with [`Live::Off`]); [`HeapError::Sealed`] when the
    /// space is sealed and this device's person is no reader of it (kept values only: with
    /// `kept: false` a non-member gets no session, so no emission).
    pub fn get(&self, what: Select, opts: GetOptions) -> Result<Items, HeapError> {
        let live = opts.live == Live::Emitted;
        if !opts.kept && !live {
            return Err(HeapError::BadRequest {
                why: "`kept: false` with `Live::Off` asks for nothing: ask for kept values \
                      (`kept: true`), for emissions (`live: Live::Emitted`), or both"
                    .into(),
            });
        }
        if live && self.inner.follower {
            return Err(HeapError::NotAllowed {
                space: self.inner.name.clone(),
                why: "this device only follows the space and takes no part in its channels: \
                      open it as a member, or read the kept values with `Live::Off`"
                    .into(),
            });
        }
        let kept = if opts.kept {
            Some(self.inner.kept_feed(&self.node, what.clone())?)
        } else {
            None
        };
        let live = live.then(|| {
            let sink = Arc::new(Sink::new(
                self.inner.name.clone(),
                what,
                opts.modes,
                opts.congestion,
                opts.trust,
            ));
            let listen = self.node.chan_listen(&self.inner.name);
            self.node.chan.rx.add_sink(Arc::clone(&sink));
            Emission {
                sink,
                _listen: listen,
            }
        });
        Ok(Items {
            space: self.inner.name.clone(),
            node: Arc::clone(&self.node),
            live,
            kept,
            ready: VecDeque::new(),
            kept_turn: false,
        })
    }
}
