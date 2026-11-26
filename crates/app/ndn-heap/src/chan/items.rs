//! `Items`, what `Heap::live` returns (docs/specs/channel.md, `Items`): the stream of what the
//! channels of a space deliver to this device, and the sink the receiver pushes into.
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
use super::latest::{Coalescing, PAIRS_MAX, Pair};
use super::verbs::{Congestion, GetNotice, GetOptions, Got, Live, LiveEnd, Modes, Select, Trust};
use super::wire::ChannelMode;
use crate::error::HeapError;
use crate::node::NodeInner;
use crate::space::Heap;

/// A message on its way to the sinks: the key of its pair, its sequence, its payload length and
/// the item.
#[derive(Clone, Debug)]
pub(crate) struct Out {
    pub(crate) pair: Pair,
    pub(crate) seq: u64,
    pub(crate) len: usize,
    pub(crate) got: Got,
}

/// The queues of one `Items`.
pub(crate) struct SinkState {
    latest: Coalescing<Got>,
    fifo: Fifo<Got>,
    /// Sessions that ended, told after what is queued.
    ends: VecDeque<LiveEnd>,
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
    /// A `HELLO` came on a channel this sink takes: the path to a sender works.
    hello: AtomicBool,
    state: Mutex<SinkState>,
    waker: AtomicWaker,
    /// Woken when the FIFO has room again, or the sink is closed.
    room: Notify,
}

impl Sink {
    pub(crate) fn new(space: Name, select: Select, modes: Modes, overflow: Congestion) -> Sink {
        Sink {
            space,
            select,
            modes,
            overflow,
            hello: AtomicBool::new(false),
            state: Mutex::new(SinkState {
                latest: Coalescing::new(PAIRS_MAX),
                fifo: Fifo::new(QUEUE_BYTES),
                ends: VecDeque::new(),
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
                        st.latest.offer(out.pair, out.seq, out.got);
                    }
                    ChannelMode::Reliable | ChannelMode::Window => match self.overflow {
                        Congestion::Block => st.fifo.push(out.got, out.len),
                        Congestion::Drop => {
                            st.fifo.push_dropping_oldest(out.got, out.len);
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

/// What `Heap::live` returns: every message the channels of one space deliver to this device whose
/// path matches, and notices, as a [`Stream`] of `Result<Got, GetNotice>`.
///
/// * **Creating it does no I/O.** It receives the messages of every session of the space this
///   device holds, in the modes it asked for. Which senders to ask for a session is the caller's
///   (`NodeHandle::ask_channel_in`) in this stage.
/// * **Order.** Within one channel: `Reliable` and `Window` in sequence order, with a
///   [`GetNotice::Lagged`] where messages are missing; `Latest`: the newest message per sender and
///   name, never an older after a newer. Across channels: arrival order.
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
///
/// The stream ends when the node stops. Poll it with [`futures::StreamExt::next`], or take
/// everything queued at once with [`Items::next_batch`].
pub struct Items {
    sink: Arc<Sink>,
    node: Arc<NodeInner>,
    /// While held, announces of senders over the space make this device ask them.
    _listen: Listen,
}

impl Items {
    /// The next item or notice; `None` once the node has stopped and the queues are read.
    pub async fn next(&mut self) -> Option<Result<Got, GetNotice>> {
        futures::StreamExt::next(self).await
    }

    /// Move everything queued **that is an item** into `buf` in one call, under one lock and with
    /// no wake per item, and return how many. It stops before a notice: when it returns `0` with
    /// something queued, the next thing is a notice, which [`Items::next`] yields. Returns `0`
    /// with nothing queued too; it never waits.
    pub fn next_batch(&mut self, buf: &mut Vec<Got>) -> usize {
        let node = &self.node;
        node.chan.rx.sweep_held_if_any(&node.chan.stats.rx);
        let mut st = self.sink.state.lock();
        let was_full = st.fifo.is_full();
        let before = buf.len();
        while let Some(got) = st.take_item() {
            buf.push(got);
        }
        let freed = self.sink.freed(was_full, &st);
        drop(st);
        if freed {
            self.sink.room.notify_waiters();
        }
        buf.len() - before
    }

    /// Whether a `HELLO` has come on a channel this `Items` takes: the sender says the path
    /// works. `false` says only that none has come yet.
    pub fn hello_seen(&self) -> bool {
        self.sink.hello.load(Ordering::Acquire)
    }
}

impl Stream for Items {
    type Item = Result<Got, GetNotice>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.sink.waker.register(cx.waker());
        let node = &self.node;
        node.chan.rx.sweep_held_if_any(&node.chan.stats.rx);
        let mut st = self.sink.state.lock();
        let was_full = st.fifo.is_full();
        let next = st.take_notice_first();
        let closed = st.closed;
        let freed = self.sink.freed(was_full, &st);
        drop(st);
        if freed {
            self.sink.room.notify_waiters();
        }
        match next {
            Some(item) => Poll::Ready(Some(item)),
            None if closed => Poll::Ready(None),
            None => Poll::Pending,
        }
    }
}

impl Drop for Items {
    fn drop(&mut self) {
        self.sink.close();
        self.node.chan.rx.remove_sink(&self.sink);
    }
}

impl std::fmt::Debug for Items {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Items")
            .field("space", &self.sink.space)
            .finish_non_exhaustive()
    }
}

impl Heap {
    /// The emissions of this space as they arrive: a stream of what the channels of the space's
    /// writers deliver to this device whose path is `what` (a path, or everything under a
    /// prefix). Creating it does no I/O; it receives the messages of the sessions this device
    /// holds ([`crate::host::NodeHandle::ask_channel_in`] asks a sender for one) in the modes
    /// `opts.modes` joins. See [`Items`].
    ///
    /// # Errors
    ///
    /// [`HeapError::NotAllowed`] for a space this device only follows (a follower takes no part in
    /// channels: open the space as a member); [`HeapError::BadRequest`] for `opts.live` of
    /// [`Live::Off`] (it asks for no emissions: read the kept value) and for `opts.trust` of
    /// [`Trust::Verified`] (it holds delivery until a signed checkpoint covers a frame, which
    /// this version does not have: ask for `Trust::Prompt`, or wait for checkpoints).
    pub fn live(&self, what: Select, opts: GetOptions) -> Result<Items, HeapError> {
        if self.inner.follower {
            return Err(HeapError::NotAllowed {
                space: self.inner.name.clone(),
                why: "this device only follows the space and takes no part in its channels: \
                      open it as a member"
                    .into(),
            });
        }
        if opts.live == Live::Off {
            return Err(HeapError::BadRequest {
                why: "`Live::Off` asks for no emissions, so there is nothing to stream: read the \
                      kept value, or ask for `Live::Emitted`"
                    .into(),
            });
        }
        if opts.trust == Trust::Verified {
            return Err(HeapError::BadRequest {
                why:
                    "`Trust::Verified` holds delivery until a signed checkpoint covers the frame, \
                      and this version has no checkpoints to check: ask for `Trust::Prompt`"
                        .into(),
            });
        }
        let sink = Arc::new(Sink::new(
            self.inner.name.clone(),
            what,
            opts.modes,
            opts.congestion,
        ));
        let listen = self.node.chan_listen(&self.inner.name);
        self.node.chan.rx.add_sink(Arc::clone(&sink));
        Ok(Items {
            sink,
            node: Arc::clone(&self.node),
            _listen: listen,
        })
    }
}
