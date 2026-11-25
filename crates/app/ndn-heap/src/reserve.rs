//! Sequence reservation, the flusher and the in-order publisher (spec §4).
//!
//! A node signs entries before they are durable: `put` returns once the
//! entry is stored, and the disk catches up in the background. What keeps a
//! crash from making a device sign a different entry at a seq a peer already
//! saw is the **reservation**: per (device, space) the device keeps `R`
//! durable, and never signs a seq above `R_durable`, the `R` that a returned
//! flush covered. A restart that finds an unclean record resumes above `R`
//! and says so in a signed gap statement.
//!
//! * [`Flusher`]: one task per node. While anything written is not yet
//!   synced it calls [`DataStore::sync`], and every write that returned
//!   before the call is covered by it; writes arriving meanwhile share the
//!   next. A write is named by the [`Ticket`] taken after it returned, and a
//!   flush that covers the ticket is the proof it is durable. A failure is
//!   sticky.
//! * [`Reservation`]: the arithmetic of one (device, space): `R`,
//!   `R_durable`, whether a seq may be signed ([`Reservation::sign_gate`]),
//!   the extension at half a block, open and clean close.
//! * [`Publisher`]: releases each entry to the sync layer once, in seq order,
//!   holding a structural entry (and what follows it) until the flush that
//!   covers it returned.

use std::collections::VecDeque;
use std::sync::{Arc, Weak};

use ndn_foundation_types::Name;
use ndn_sync::DataStore;
use parking_lot::Mutex;
use tokio::sync::{Notify, mpsc};

use crate::error::HeapError;
use crate::rt::Tasks;
use crate::store::{Corrupt, Kind, ReserveRecord, read_head, read_reserve};

#[cfg(test)]
mod tests;

// -- The flusher --------------------------------------------------------------

/// A position in the flusher's count of writes: durable once a flush that
/// covers it returned. Taken ([`Flusher::note_write`]) after the write it
/// stands for returned from the store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Ticket(pub(crate) u64);

/// Why a wait for a flush ended without the flush.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FlushError {
    /// The store failed to sync (sticky): the disk's own reason, with what to
    /// do. Kept by the flusher for good: nothing it holds can be promised
    /// durable any more.
    Disk(Arc<str>),
    /// The node is closing or stopped: nothing more is flushed.
    Stopped,
}

impl std::fmt::Display for FlushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlushError::Disk(why) => f.write_str(why),
            FlushError::Stopped => f.write_str(
                "the node is closing or stopped, so nothing more is made durable; open the \
                 space again on a new node",
            ),
        }
    }
}

impl From<FlushError> for HeapError {
    fn from(why: FlushError) -> HeapError {
        HeapError::local(why)
    }
}

#[derive(Default)]
struct FlushState {
    /// Tickets issued.
    issued: u64,
    /// Every ticket up to this is covered by a returned flush.
    durable: u64,
    failure: Option<Arc<str>>,
    stopped: bool,
}

/// The node's one flusher.
pub(crate) struct Flusher {
    store: Arc<dyn DataStore>,
    st: Mutex<FlushState>,
    /// To the task: a ticket was issued, or the flusher stopped or dropped.
    wake: Arc<Notify>,
    /// To waiters: a flush returned, failed, or the flusher stopped.
    done: Notify,
    /// The flush task, and the end of it: [`Self::ended`].
    tasks: Arc<Tasks>,
}

impl Flusher {
    /// Start the flusher over `store`. The task ends when the flusher is
    /// stopped or dropped.
    pub(crate) fn spawn(store: Arc<dyn DataStore>) -> Arc<Flusher> {
        let wake = Arc::new(Notify::new());
        let tasks = Tasks::new();
        let flusher = Arc::new(Flusher {
            store,
            st: Mutex::new(FlushState::default()),
            wake: Arc::clone(&wake),
            done: Notify::new(),
            tasks: Arc::clone(&tasks),
        });
        tasks.spawn(Self::run(Arc::downgrade(&flusher), wake));
        flusher
    }

    /// Flush until nothing written is unsynced, the store fails or the
    /// flusher stops (then the task ends).
    async fn run(flusher: Weak<Flusher>, wake: Arc<Notify>) {
        loop {
            wake.notified().await;
            let Some(flusher) = flusher.upgrade() else {
                return;
            };
            loop {
                let target = {
                    let st = flusher.st.lock();
                    if st.stopped {
                        return;
                    }
                    if st.failure.is_some() || st.durable >= st.issued {
                        break;
                    }
                    st.issued
                };
                tracing::trace!(target: "ndn_heap::timeline", target, "flush_begin");
                let flushed = flusher.sync().await;
                tracing::trace!(target: "ndn_heap::timeline", ok = flushed.is_ok(), "flush_end");
                let mut st = flusher.st.lock();
                match flushed {
                    Ok(()) => st.durable = st.durable.max(target),
                    Err(why) => {
                        let why: Arc<str> = format!(
                            "the store could not make this node's writes durable: {why}. \
                             Nothing signed is lost and reads continue, but no seq past what \
                             was made durable can be signed, and no Members or Epoch change \
                             is published; free space or fix the disk, then restart the node"
                        )
                        .into();
                        tracing::warn!("{why}");
                        st.failure = Some(why);
                    }
                }
                drop(st);
                flusher.done.notify_waiters();
            }
        }
    }

    /// The store's barrier, on a thread of its own: a flush takes as long as
    /// the disk does. A store whose flush returns at once is flushed inline,
    /// and so is a browser store, which commits each write durably.
    ///
    /// The thread is not one of the runtime's blocking pool: a paused tokio
    /// clock (a simulation) advances only while no pool task runs, so a flush
    /// held on the pool would stop every timer around it.
    async fn sync(&self) -> std::io::Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        if !self.store.sync_is_immediate() {
            let store = Arc::clone(&self.store);
            let (done, flushed) = tokio::sync::oneshot::channel();
            std::thread::Builder::new()
                .name("ndn-heap-flush".into())
                .spawn(move || {
                    let synced = store.sync();
                    // The thread lets go of the store before it says it is done: whoever
                    // waited for the flush may release the store the moment it returns.
                    drop(store);
                    let _ = done.send(synced);
                })?;
            return flushed.await.unwrap_or_else(|e| {
                Err(std::io::Error::other(format!(
                    "the flush did not finish ({e})"
                )))
            });
        }
        self.store.sync()
    }

    /// Say that a write returned from the store, and ask for a flush: the
    /// ticket is durable once [`Self::wait_durable`] says so. Call it after
    /// the write returned (after the batch applied, for one made in a
    /// batch), never before: a flush that began between would cover the
    /// ticket without the write.
    pub(crate) fn note_write(&self) -> Ticket {
        let ticket = {
            let mut st = self.st.lock();
            st.issued += 1;
            Ticket(st.issued)
        };
        self.wake.notify_one();
        ticket
    }

    /// The newest ticket a returned flush covers.
    pub(crate) fn durable(&self) -> Ticket {
        Ticket(self.st.lock().durable)
    }

    /// The ticket that covers every write made so far, when a returned flush
    /// does not cover them all yet; `None` when everything written is durable.
    pub(crate) fn unflushed(&self) -> Option<Ticket> {
        let st = self.st.lock();
        (st.issued > st.durable).then_some(Ticket(st.issued))
    }

    /// The store's failure, once it failed.
    pub(crate) fn failure(&self) -> Option<Arc<str>> {
        self.st.lock().failure.clone()
    }

    /// Wait until `ready` answers from the state; every flush, failure and
    /// stop wakes it.
    async fn until<T>(&self, ready: impl Fn(&FlushState) -> Option<T>) -> T {
        loop {
            let notified = self.done.notified();
            if let Some(answer) = ready(&self.st.lock()) {
                return answer;
            }
            notified.await;
        }
    }

    /// Wait until a flush covering `ticket` returned. A ticket a flush
    /// covered before the store failed is durable whatever happened since.
    pub(crate) async fn wait_durable(&self, ticket: Ticket) -> Result<(), FlushError> {
        self.until(|st| {
            if st.durable >= ticket.0 {
                Some(Ok(()))
            } else if let Some(why) = &st.failure {
                Some(Err(FlushError::Disk(why.clone())))
            } else {
                st.stopped.then_some(Err(FlushError::Stopped))
            }
        })
        .await
    }

    /// Wait for a flush covering everything written so far.
    pub(crate) async fn flush(&self) -> Result<(), FlushError> {
        let ticket = self.note_write();
        self.wait_durable(ticket).await
    }

    /// Wait until the store fails; `None` if the flusher stops first. The
    /// node raises its store-failed alert on it.
    pub(crate) async fn failed(&self) -> Option<Arc<str>> {
        self.until(|st| {
            st.failure
                .clone()
                .map(Some)
                .or_else(|| st.stopped.then_some(None))
        })
        .await
    }

    /// Stop at once: waiters are woken with [`FlushError::Stopped`] and no
    /// flush is begun again. A flush under way finishes on its thread, and
    /// [`Self::ended`] waits for it.
    pub(crate) fn stop(&self) {
        self.st.lock().stopped = true;
        self.wake.notify_one();
        self.done.notify_waiters();
    }

    /// Wait until the flusher's task has ended, a flush it had under way included, and has let
    /// go of the flusher and so of the store. Call it after [`Self::stop`].
    pub(crate) async fn ended(&self) {
        self.tasks.ended().await;
    }
}

impl Drop for Flusher {
    fn drop(&mut self) {
        self.wake.notify_one();
    }
}

// -- Reservation --------------------------------------------------------------

struct ReserveState {
    /// The `R` written, durable or not.
    r: u64,
    /// The `R` a returned flush covered.
    durable_r: u64,
    /// The writes of `R` not yet known durable, oldest first (`R` and the
    /// tickets both ascend).
    pending: VecDeque<(Ticket, u64)>,
    closed: bool,
}

/// The reservation of one (device, space): `R` is the seq up to which the
/// device may sign once `R` is durable.
pub(crate) struct Reservation {
    space: Name,
    block: u64,
    /// The store itself, never a log's [`crate::store::Batch`]: the flush
    /// ticket of a write is taken after it returned, and a write kept in a
    /// batch has not.
    store: Arc<dyn DataStore>,
    flusher: Arc<Flusher>,
    st: Mutex<ReserveState>,
    /// The seq of the first entry to sign: above the head and above `R`.
    pub(crate) first_seq: u64,
    /// The `R` the previous run left, read before this run's extension: the
    /// highest seq an earlier run could have signed.
    pub(crate) floor_r: u64,
    /// Whether the last run closed cleanly with `R` at the head (a clean
    /// start has no hole and says nothing).
    pub(crate) clean: bool,
}

impl Reservation {
    /// Open the reservation of `space`. `adopted_head` is the own head the
    /// caller found (the newest own entry the store holds, then recovery
    /// from peers), 0 when it holds none.
    ///
    /// The start is clean iff the record says so, `R` is the head record's
    /// seq, and the names show no own entry above it. The first seq is
    /// `max(adopted_head, R) + 1` either way: above everything a peer can
    /// have seen. Before anything is signed the next reservation, `R` plus a
    /// block above that point, is written and a flush requested; the first
    /// put waits for it only if it arrives before it completes.
    ///
    /// The `R` the store answers with is durable only if every write made
    /// before it was read is: in a process that left the space and opens it
    /// again, the store lists the first run's `R` before any flush covered it.
    /// Such an `R` becomes durable when the flush covering the writes so far
    /// returns, and till then nothing is signed under it.
    ///
    /// An unreadable record is an error: with `R` unknown a seq a peer saw
    /// could be signed again.
    pub(crate) fn open(
        store: Arc<dyn DataStore>,
        flusher: Arc<Flusher>,
        space: &Name,
        block: u64,
        adopted_head: u64,
    ) -> Result<Reservation, Corrupt> {
        let reserve = read_reserve(&*store, space)?;
        let head = read_head(&*store, space)?.map_or(0, |h| h.seq);
        let recorded = reserve.map_or(0, |r| r.r);
        let uncovered = flusher.unflushed();
        let above = adopted_head.max(recorded);
        let reservation = Reservation {
            space: space.clone(),
            block,
            store,
            flusher,
            st: Mutex::new(ReserveState {
                r: recorded,
                durable_r: if uncovered.is_some() { 0 } else { recorded },
                pending: uncovered
                    .map(|ticket| (ticket, recorded))
                    .into_iter()
                    .collect(),
                closed: false,
            }),
            first_seq: above.saturating_add(1),
            floor_r: recorded,
            clean: reserve.is_some_and(|r| r.clean && r.r == head) && adopted_head == head,
        };
        reservation.extend(&mut reservation.st.lock(), above.saturating_add(block));
        Ok(reservation)
    }

    /// Write `reserve/<S> = (r, clean)` and ask for its flush.
    fn put(&self, r: u64, clean: bool) -> Ticket {
        let record = ReserveRecord { r, clean };
        self.store
            .insert(Kind::RESERVE.of(&self.space), record.encode());
        self.flusher.note_write()
    }

    /// Reserve up to `r`, not durable until the flush of its write returns.
    fn extend(&self, st: &mut ReserveState, r: u64) {
        let ticket = self.put(r, false);
        st.r = r;
        st.pending.push_back((ticket, r));
    }

    /// Move to `durable_r` what a returned flush covered.
    fn promote(&self, st: &mut ReserveState) {
        let durable = self.flusher.durable();
        while let Some(&(ticket, r)) = st.pending.front() {
            if ticket > durable {
                break;
            }
            st.durable_r = st.durable_r.max(r);
            st.pending.pop_front();
        }
    }

    /// The `R` written, durable or not.
    #[cfg(test)]
    pub(crate) fn reserved(&self) -> u64 {
        self.st.lock().r
    }

    /// The `R` a returned flush covered: no seq above it is signed.
    #[cfg(test)]
    pub(crate) fn durable_r(&self) -> u64 {
        let mut st = self.st.lock();
        self.promote(&mut st);
        st.durable_r
    }

    /// Whether `seq`, the next to sign, may be signed now: `Ok(None)` sign,
    /// `Ok(Some(ticket))` wait for the ticket ([`Flusher::wait_durable`]) and
    /// ask again, `Err` refused (the store failed, with the disk's reason, or
    /// the reservation was closed or the flusher stopped). Call it before
    /// signing. When `seq` is above `R - block/2` it writes
    /// `reserve/<S> = (R + block, clean 0)` (straight to the store) and asks
    /// the flusher; so the answer for a `seq` that only just came into reach
    /// is usually `Ok(None)` and the extension is flushed ahead of need.
    /// Once the store failed nothing is written: what `R_durable` covers is
    /// still signed, nothing above it.
    pub(crate) fn sign_gate(&self, seq: u64) -> Result<Option<Ticket>, FlushError> {
        let mut st = self.st.lock();
        if st.closed {
            return Err(FlushError::Stopped);
        }
        self.promote(&mut st);
        let failure = self.flusher.failure();
        if failure.is_none() && seq > st.r.saturating_sub(self.block / 2) {
            let r = st.r.max(seq).saturating_add(self.block);
            self.extend(&mut st, r);
        }
        if seq <= st.durable_r {
            return Ok(None);
        }
        if let Some(why) = failure {
            return Err(FlushError::Disk(why));
        }
        match st.pending.iter().find(|(_, r)| *r >= seq) {
            Some(&(ticket, _)) => Ok(Some(ticket)),
            // Nothing can be written to reach `seq`: the flusher stopped.
            None => Err(FlushError::Stopped),
        }
    }

    /// Wait until `seq` may be signed. The error is the disk's reason (the
    /// store failed) or that the node stopped.
    #[cfg(test)]
    pub(crate) async fn clear_to_sign(&self, seq: u64) -> Result<(), FlushError> {
        while let Some(ticket) = self.sign_gate(seq)? {
            self.flusher.wait_durable(ticket).await?;
        }
        Ok(())
    }

    /// Close cleanly after the node's publications were drained and flushed:
    /// refuse further signing, write `reserve/<S> = (head, clean 1)` and wait
    /// for the flush that makes it durable. The next open resumes at
    /// `head + 1` with no hole. `head` is the own head seq, the one in
    /// `head/<S>`.
    pub(crate) async fn close_clean(&self, head: u64) -> Result<(), FlushError> {
        self.st.lock().closed = true;
        self.flusher.wait_durable(self.put(head, true)).await
    }
}

// -- The in-order publisher -----------------------------------------------------

/// The sync side of publication: what the node plugs `SyncHandle::publish`
/// into. Called once per seq, in seq order, one call at a time.
#[async_trait::async_trait]
pub(crate) trait FlushSink: Send + Sync {
    /// Announce that the own entry at `seq` exists.
    async fn publish(&self, seq: u64);
}

#[derive(Default)]
struct PublisherState {
    /// Submitted and not yet handed to the sink.
    outstanding: usize,
    /// Why the front can never be released.
    blocked: Option<FlushError>,
    /// The own structural entries a returned flush has not covered, with the
    /// ticket each waits for.
    held: Vec<(u64, Ticket)>,
}

struct PublisherShared {
    st: Mutex<PublisherState>,
    /// To [`Publisher::drain`]: a publication went out, or the driver
    /// stopped.
    progress: Notify,
}

/// Publishes every submitted entry once, in seq order, holding an entry that
/// waits for a flush (and every one after it) until the flush covering it
/// returned (spec §4, rule 5): the driver takes the entries from a queue one
/// at a time, and waits for a held one's flush before it takes the next.
pub(crate) struct Publisher {
    flusher: Arc<Flusher>,
    shared: Arc<PublisherShared>,
    queue: mpsc::UnboundedSender<(u64, Option<Ticket>)>,
}

impl Publisher {
    /// Start the publisher. Its task ends when the publisher is dropped, or
    /// when the flusher can no longer cover a held entry.
    pub(crate) fn spawn(
        tasks: &Arc<Tasks>,
        flusher: Arc<Flusher>,
        sink: Arc<dyn FlushSink>,
    ) -> Publisher {
        let (queue, entries) = mpsc::unbounded_channel();
        let shared = Arc::new(PublisherShared {
            st: Mutex::new(PublisherState::default()),
            progress: Notify::new(),
        });
        tasks.spawn(Self::drive(
            entries,
            Arc::clone(&flusher),
            Arc::downgrade(&shared),
            sink,
        ));
        Publisher {
            flusher,
            shared,
            queue,
        }
    }

    /// Queue the publication of the own entry at `seq`: at once when `gate`
    /// is `None`, else once a flush covering the ticket returned. Call it in
    /// seq order, after the entry is stored.
    pub(crate) fn submit(&self, seq: u64, gate: Option<Ticket>) {
        {
            let mut st = self.shared.st.lock();
            st.outstanding += 1;
            st.held.extend(gate.map(|ticket| (seq, ticket)));
        }
        // A driver that ended (a flush failed) leaves it unpublished: `drain`
        // says why.
        let _ = self.queue.send((seq, gate));
    }

    /// Whether the own entry at `seq` may be served: a structural entry only
    /// once a flush covering it returned (spec §4, rule 3).
    pub(crate) fn servable(&self, seq: u64) -> bool {
        let durable = self.flusher.durable();
        let mut st = self.shared.st.lock();
        st.held.retain(|(_, ticket)| *ticket > durable);
        !st.held.iter().any(|(held, _)| *held == seq)
    }

    /// Wait until everything submitted so far was handed to the sink. The
    /// error is why a held entry can never be released (the disk failed, or
    /// the node stopped); what was submitted behind it stays unpublished.
    pub(crate) async fn drain(&self) -> Result<(), FlushError> {
        loop {
            let progress = self.shared.progress.notified();
            {
                let st = self.shared.st.lock();
                if st.outstanding == 0 {
                    return Ok(());
                }
                if let Some(why) = &st.blocked {
                    return Err(why.clone());
                }
            }
            progress.await;
        }
    }

    async fn drive(
        mut entries: mpsc::UnboundedReceiver<(u64, Option<Ticket>)>,
        flusher: Arc<Flusher>,
        shared: Weak<PublisherShared>,
        sink: Arc<dyn FlushSink>,
    ) {
        while let Some((seq, gate)) = entries.recv().await {
            let flushed = match gate {
                Some(ticket) => flusher.wait_durable(ticket).await,
                None => Ok(()),
            };
            let Some(shared) = shared.upgrade() else {
                return;
            };
            if let Err(why) = flushed {
                shared.st.lock().blocked = Some(why);
                shared.progress.notify_waiters();
                return;
            }
            sink.publish(seq).await;
            shared.st.lock().outstanding -= 1;
            shared.progress.notify_waiters();
        }
    }
}
