//! One space: put, get, watch, change (spec §10).
//!
//! A [`Heap`] is a handle on one space of a [`Node`](crate::node::Node). The
//! space's state is a [`Log`] behind one `parking_lot::Mutex`, never held
//! across an `.await`: a call signs or admits under the lock, routes what
//! came of it ([`SpaceInner::route`], the one place effects are acted on) and
//! lets go before it waits for anything.
//!
//! **Effects routing.** After every `Log` call that wrote, a flush ticket is
//! taken (`Flusher::note_write`, after the log's batch reached the store);
//! the own entry it made is submitted to the in-order publisher, held for the
//! ticket when it is a Members or Epoch entry; changes and alerts go to the
//! watchers in the order the log made them; a change of members is told to
//! the judge so it adopts the persons the space lists.
//!
//! **Watchers.** A watcher is a queue: first every head the space holds at the
//! moment it registered (never lagged), then live changes up to
//! `Config.watch_queue`. A change that does not fit is dropped and counted;
//! the watcher reads what was queued and is then told
//! [`Change::Lagged`], and the changes after the drop are dropped until it
//! has been told.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use futures::Stream;
use ndn_foundation_types::Name;
use ndn_security::confidentiality::ContentKey;
use ndn_sync::DataStore;
use parking_lot::Mutex;

use crate::error::{HeapError, Refusal};
use crate::fold::Readers;
use crate::log::{Alert, Blob, Change, Effects, Frontier, Log, Members, Signed, Step};
use crate::node::NodeInner;
use crate::pieces;
use crate::register::{EntryId, Item};
use crate::reserve::{FlushError, Publisher, Ticket};
use crate::rt;
use crate::seal;
use crate::sync::{Group, TIMELINE};
use crate::trust::Listing;
use crate::wire::{
    AUDIENCE_MAX, ChunksBody, INLINE_MAX, MembersBody, Op, PAYLOAD_MAX, Payload, Role, log_name,
    owns, parse_log_name, signed_digest_of,
};

#[cfg(test)]
#[path = "space_tests.rs"]
mod tests;

// -- Values the host passes --------------------------------------------------------

/// Who a new space is shared with. The owner is an implicit writer and,
/// unless the space is public, an implicit reader.
#[derive(Clone, Debug, PartialEq)]
pub struct Share {
    /// Who may read.
    pub readers: Readers,
    /// The persons that may write besides the owner.
    pub writers: Vec<Name>,
}

/// A change of who a space lists. A removal takes the person from both roles.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MembersChange {
    /// Persons to admit as writers.
    pub add_writers: Vec<Name>,
    /// Persons to admit as readers.
    pub add_readers: Vec<Name>,
    /// Persons to remove from both roles.
    pub remove: Vec<Name>,
}

/// How a put returns.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PutOptions {
    /// Whether `put` returns only after a flush covering the entry. `None`:
    /// yes when no peer is known in the space (nobody else holds the entry
    /// yet), no otherwise.
    pub durable: Option<bool>,
}

// -- Watching ----------------------------------------------------------------------

struct QueueState {
    /// What the watch listed as it began.
    listed: VecDeque<Change>,
    /// Live changes, at most the queue's capacity.
    live: VecDeque<Change>,
    /// Changes dropped since the watcher last read.
    missed: u64,
    closed: bool,
    waker: Option<Waker>,
}

/// One watcher's changes.
pub(crate) struct Queue {
    st: Mutex<QueueState>,
    cap: usize,
}

impl Queue {
    fn new(listed: VecDeque<Change>, cap: usize) -> Arc<Queue> {
        Arc::new(Queue {
            st: Mutex::new(QueueState {
                listed,
                live: VecDeque::new(),
                missed: 0,
                closed: false,
                waker: None,
            }),
            cap: cap.max(1),
        })
    }

    pub(crate) fn push(&self, change: Change) {
        let waker = {
            let mut st = self.st.lock();
            if st.closed {
                return;
            }
            if st.missed > 0 || st.live.len() >= self.cap {
                st.missed += 1;
            } else {
                st.live.push_back(change);
            }
            st.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub(crate) fn close(&self) {
        let waker = {
            let mut st = self.st.lock();
            st.closed = true;
            st.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn is_closed(&self) -> bool {
        self.st.lock().closed
    }

    fn poll(&self, cx: &mut Context<'_>) -> Poll<Option<Change>> {
        let mut st = self.st.lock();
        if let Some(change) = st.listed.pop_front().or_else(|| st.live.pop_front()) {
            return Poll::Ready(Some(change));
        }
        if st.missed > 0 {
            let missed = std::mem::take(&mut st.missed);
            return Poll::Ready(Some(Change::Lagged { missed }));
        }
        if st.closed {
            return Poll::Ready(None);
        }
        st.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// What a watch yields: every head the space held when it began, then the
/// changes as they happen. Ends when the node stops.
pub struct Changes {
    queue: Arc<Queue>,
}

impl Changes {
    /// The next change; `None` once the node has stopped and the queue is
    /// read.
    pub async fn next(&mut self) -> Option<Result<Change, HeapError>> {
        futures::future::poll_fn(|cx| self.queue.poll(cx))
            .await
            .map(Ok)
    }
}

impl Stream for Changes {
    type Item = Result<Change, HeapError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.queue.poll(cx).map(|change| change.map(Ok))
    }
}

impl Drop for Changes {
    fn drop(&mut self) {
        self.queue.close();
    }
}

// -- The space ---------------------------------------------------------------------

/// What one `Log` call asks of the node once the lock is let go.
pub(crate) struct Routed {
    /// The flush ticket taken after the call's writes; `None` when it wrote
    /// nothing.
    pub ticket: Option<Ticket>,
    blobs: Vec<Blob>,
    suspect: Vec<Name>,
    repair: bool,
    nudge: bool,
}

/// One space on one node: the log, its publication and its watchers.
pub(crate) struct SpaceInner {
    pub(crate) name: Name,
    pub(crate) log: Mutex<Log>,
    pub(crate) publisher: Publisher,
    pub(crate) group: Arc<Group>,
    watchers: Mutex<Vec<Arc<Queue>>>,
    /// A carrier signs nothing and keeps no read key.
    pub(crate) follower: bool,
    pub(crate) closing: AtomicBool,
    /// Own structural entries not yet covered by a flush: not served.
    held_back: Mutex<Vec<(u64, Ticket)>>,
    /// Entries of this space whose value is in hand here: inline, or in
    /// pieces that are whole. What [`Self::unassembled`] need not read again.
    whole: Mutex<HashSet<EntryId>>,
    /// Held for the length of one [`Self::unassembled`] scan.
    scan: Mutex<()>,
    /// Alerts that stay true (evidence of rollback, of equivocation): a
    /// watcher that begins later is told them after the heads.
    standing: Mutex<Vec<Alert>>,
    /// The entries whose refusal was told, last [`REFUSED_MAX`], with the
    /// alert: a watcher that begins later is told them after the heads.
    refused: Mutex<VecDeque<(Name, Alert)>>,
}

/// The most standing alerts a space keeps for watchers that begin later.
const STANDING_MAX: usize = 32;

/// How many heads' entries one scan for values in pieces reads while it holds
/// the space's lock; the lock is let go between batches.
const HEADS_PER_READ: usize = 256;

/// The most refused entries a space remembers having told.
const REFUSED_MAX: usize = 256;

/// A signing step run under the lock: `None` when there is nothing to sign.
type Sign<'a> = &'a mut (dyn FnMut(&mut Log) -> Result<Option<Step<Signed>>, HeapError> + Send);

/// A sealed space lists at most [`AUDIENCE_MAX`] readers, the owner among
/// them: an epoch names them all. Checked before anything is signed.
pub(crate) fn check_audience(readers: usize) -> Result<(), HeapError> {
    if readers > AUDIENCE_MAX {
        return Err(HeapError::BadRequest {
            why: format!(
                "a sealed space lists at most {AUDIENCE_MAX} readers, the owner included, and \
                 this asks for {readers}: list fewer readers, or make the space public"
            ),
        });
    }
    Ok(())
}

fn flush_error(e: FlushError) -> HeapError {
    HeapError::Local {
        reason: e.to_string(),
    }
}

/// A path is the codec's: 1 to 8 generic components within its octet limit
/// (`wire::check_path`, the one definition).
fn check_path(path: &Name) -> Result<(), HeapError> {
    crate::wire::check_path(path).map_err(|e| HeapError::BadName {
        name: path.clone(),
        why: e.to_string(),
    })
}

impl SpaceInner {
    pub(crate) fn new(
        name: Name,
        log: Log,
        publisher: Publisher,
        group: Arc<Group>,
        follower: bool,
    ) -> SpaceInner {
        SpaceInner {
            name,
            log: Mutex::new(log),
            publisher,
            group,
            watchers: Mutex::new(Vec::new()),
            follower,
            closing: AtomicBool::new(false),
            held_back: Mutex::new(Vec::new()),
            whole: Mutex::new(HashSet::new()),
            scan: Mutex::new(()),
            standing: Mutex::new(Vec::new()),
            refused: Mutex::new(VecDeque::new()),
        }
    }

    /// Tell every watcher.
    pub(crate) fn tell(&self, change: Change) {
        let mut watchers = self.watchers.lock();
        watchers.retain(|q| !q.is_closed());
        for q in watchers.iter() {
            tracing::trace!(target: TIMELINE, "watch_send");
            q.push(change.clone());
        }
    }

    pub(crate) fn close_watchers(&self) {
        for q in self.watchers.lock().drain(..) {
            q.close();
        }
    }

    /// Whether the own entry at `seq` may be served now: a Members or Epoch
    /// entry only once a flush covering it returned (spec §4).
    pub(crate) fn servable(&self, node: &NodeInner, seq: u64) -> bool {
        let durable = node.flusher.durable();
        let mut held = self.held_back.lock();
        held.retain(|(_, t)| *t > durable);
        !held.iter().any(|(s, _)| *s == seq)
    }

    /// The persons the space lists, as the judge adopts them.
    pub(crate) fn listing(log: &Log) -> Listing {
        let fold = log.fold();
        Listing {
            writers: fold.writers(),
            readers: match fold.readers() {
                Readers::Anyone => Vec::new(),
                Readers::Persons(p) => p,
            },
            cut: fold
                .removed_writers()
                .into_iter()
                .map(|(person, _)| person)
                .collect(),
        }
    }

    /// Act on what a `Log` call returned, under the space's lock: the one
    /// place effects are routed. `wrote`: the call stored something.
    pub(crate) fn route(&self, node: &NodeInner, log: &Log, fx: Effects, wrote: bool) -> Routed {
        let ticket = wrote.then(|| node.flusher.note_write());
        if let Some(p) = fx.publish {
            node.signatures.fetch_add(1, Ordering::Relaxed);
            let gate = if p.structural { ticket } else { None };
            if let Some(t) = gate {
                self.held_back.lock().push((p.seq, t));
            }
            self.publisher.submit(p.seq, gate);
        }
        for change in fx.changes {
            self.tell(change);
        }
        for alert in fx.alerts {
            tracing::warn!(space = %self.name, ?alert, "alert");
            if matches!(alert, Alert::RolledBack { .. } | Alert::Equivocation { .. }) {
                let mut standing = self.standing.lock();
                if !standing.contains(&alert) && standing.len() < STANDING_MAX {
                    standing.push(alert.clone());
                }
            }
            self.tell(Change::Alert(alert));
        }
        let mut repair = false;
        if fx.membership {
            node.judge.note(&self.name, &Self::listing(log));
            repair = !self.follower
                && log.sealed()
                && !log.fold().complete()
                && owns(&self.name, log.key());
        }
        Routed {
            ticket,
            blobs: fx.blobs,
            suspect: fx.suspect,
            repair,
            nudge: !fx.wants.is_empty() || fx.membership,
        }
    }

    /// What follows a routed call once the lock is let go: blobs to read and
    /// tell, keys to suspect everywhere, the epoch to repair, the fetch to
    /// wake.
    pub(crate) fn finish(self: &Arc<Self>, node: &Arc<NodeInner>, routed: Routed) {
        for blob in routed.blobs {
            let (space, node) = (Arc::clone(self), Arc::clone(node));
            rt::spawn(async move { space.emit_blob(&node, blob, None) });
        }
        for key in routed.suspect {
            node.suspect_everywhere(&key);
        }
        if routed.repair {
            let (space, node) = (Arc::clone(self), Arc::clone(node));
            rt::spawn(async move {
                if let Err(e) = space.repair_epoch(&node).await {
                    tracing::warn!(space = %space.name, "the epoch is not repaired: {e}");
                }
            });
        }
        if routed.nudge {
            node.nudge(&self.name);
        }
    }

    /// Run `step` under the lock until it signs, waiting outside the lock
    /// whenever the reservation covering the seq is not yet durable. `step`
    /// answers `None` when there is nothing to sign. The entry's id and the
    /// ticket after its writes.
    async fn attempt(
        self: &Arc<Self>,
        node: &Arc<NodeInner>,
        step: Sign<'_>,
    ) -> Result<Option<(EntryId, Ticket)>, HeapError> {
        loop {
            if self.closing.load(Ordering::Relaxed) {
                return Err(HeapError::Local {
                    reason: "the node is closing, so no more entries are signed".into(),
                });
            }
            let wait = {
                let mut log = self.log.lock();
                self.own_key_refusal(node, &log)?;
                match step(&mut log)? {
                    None => return Ok(None),
                    Some(Step::Done(signed)) => {
                        let id = signed.id.clone();
                        let routed = self.route(node, &log, signed.effects, true);
                        drop(log);
                        let ticket = routed.ticket.expect("a signed entry was written");
                        self.finish(node, routed);
                        return Ok(Some((id, ticket)));
                    }
                    Some(Step::Wait(ticket)) => ticket,
                }
            };
            node.flusher.wait_durable(wait).await.map_err(flush_error)?;
        }
    }

    /// [`Self::attempt`] for a step that always has something to sign.
    pub(crate) async fn sign_with(
        self: &Arc<Self>,
        node: &Arc<NodeInner>,
        mut step: impl FnMut(&mut Log) -> Result<Step<Signed>, HeapError> + Send,
    ) -> Result<(EntryId, Ticket), HeapError> {
        let signed = self
            .attempt(node, &mut |log| step(log).map(Some))
            .await?
            .expect("a step that signs always yields");
        Ok(signed)
    }

    /// Sign a new Epoch for exactly the readers when the space is sealed and
    /// the epoch in force is not for them (spec §3.3, rule 7): an owner
    /// device owes it after every change of members, whoever signed it.
    pub(crate) async fn repair_epoch(
        self: &Arc<Self>,
        node: &Arc<NodeInner>,
    ) -> Result<Option<(EntryId, Ticket)>, HeapError> {
        let now = node.now();
        self.attempt(node, &mut |log| {
            let fold = log.fold();
            if fold.create() != Some(false) || fold.complete() || !owns(&self.name, log.key()) {
                return Ok(None);
            }
            let Readers::Persons(audience) = fold.readers() else {
                return Ok(None);
            };
            log.sign_epoch(audience, now).map(Some)
        })
        .await
    }

    /// Before a removal binds what this device holds of the removed persons'
    /// devices, give entries it has heard of and not yet fetched
    /// `Config.first_look` to arrive: what it never held is left outside the
    /// cut. Devices it has not heard of are not waited for.
    pub(crate) async fn look_for_removed(&self, node: &Arc<NodeInner>, removed: &[Name]) {
        if removed.is_empty() {
            return;
        }
        let deadline = rt::Instant::now() + node.config.first_look;
        loop {
            let owed = self.log.lock().missing().into_iter().any(|want| {
                want.digest.is_none() && removed.contains(&node.person_of(&want.device))
            });
            if !owed || rt::Instant::now() >= deadline {
                return;
            }
            node.nudge(&self.name);
            rt::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// A device whose own key is revoked by a context held here, or marked
    /// suspected, signs nothing: peers would refuse it, and the host should
    /// hear why now.
    fn own_key_refusal(&self, node: &NodeInner, log: &Log) -> Result<(), HeapError> {
        let key = log.key();
        let ctx = node.judge.validator().keyring().context_for(key);
        let why = if ctx.is_revoked(key) {
            Refusal::Untrusted {
                why: format!(
                    "the trust context of {} revokes this device's key {key}: it signs nothing \
                     until the namespace's owner enrolls the device with a new key",
                    ctx.namespace()
                ),
            }
        } else if let Some(since) = log.suspected(key) {
            Refusal::Suspected {
                key: key.clone(),
                since,
            }
        } else {
            return Ok(());
        };
        Err(HeapError::Refused {
            name: log_name(log.device(), &self.name, log.next_seq()),
            why,
        })
    }

    /// A writer that is no reader of a sealed space cannot seal in it: told
    /// as it is, not as a wait that never ends.
    fn may_seal(&self, log: &Log) -> Result<(), HeapError> {
        let (fold, person) = (log.fold(), log.person());
        if log.sealed() && fold.is_writer(person) && !fold.is_reader(person) {
            return Err(HeapError::NotAllowed {
                space: self.name.clone(),
                why: "the space is sealed and this device's person may write but is not in its \
                      audience, so nothing it writes could be sealed for the readers; ask the \
                      owner to add this person as a reader"
                    .into(),
            });
        }
        Ok(())
    }

    /// What a read of a sealed space with an entry held closed answers: a
    /// wait when this device's person reads the space and is in the audience
    /// of every epoch whose key it lacks (the key comes by the grant pull),
    /// else [`HeapError::Sealed`].
    fn sealed_error(&self, log: &Log) -> HeapError {
        let (fold, person) = (log.fold(), log.person());
        let waits = fold.is_reader(person)
            && fold
                .epochs()
                .iter()
                .filter(|e| log.keys().key(&self.name, e).is_none())
                .all(|e| fold.audience(e).contains(person));
        if waits {
            HeapError::NotReady {
                name: self.name.clone(),
                why: "an entry of it is sealed in an epoch whose key this device is entitled to \
                      and is being fetched from the devices that hold it (the grant pull)"
                    .into(),
            }
        } else {
            HeapError::Sealed {
                space: self.name.clone(),
            }
        }
    }

    /// Tell the watchers, once per entry, that `why` refused it: the judge's
    /// refusals and the mark on its key, which the log alerts nothing of. A
    /// transient bad signature, a cut (the log alerts it) and the rest are
    /// not told here.
    pub(crate) fn alert_refusal(&self, name: &Name, id: EntryId, why: &Refusal) {
        if !matches!(
            why,
            Refusal::Lapsed { .. } | Refusal::Untrusted { .. } | Refusal::Suspected { .. }
        ) {
            return;
        }
        let alert = Alert::Refused {
            id,
            why: why.clone(),
            next: why.next(),
        };
        {
            let mut told = self.refused.lock();
            if told.iter().any(|(n, _)| n == name) {
                return;
            }
            if told.len() >= REFUSED_MAX {
                told.pop_front();
            }
            told.push_back((name.clone(), alert.clone()));
        }
        tracing::warn!(space = %self.name, entry = %name, ?why, "an entry is refused");
        self.tell(Change::Alert(alert));
    }

    /// [`Self::alert_refusal`] for a packet and what refused it.
    pub(crate) fn alert_refused_packet(&self, data: &ndn_packet::Data, why: &Refusal) {
        if let Some(entry) = parse_log_name(&data.name) {
            let id = EntryId {
                device: entry.device,
                seq: entry.seq,
                digest: signed_digest_of(data),
            };
            self.alert_refusal(&data.name, id, why);
        }
    }

    /// The reader check of `get` and `watch`: a sealed space shows nothing
    /// to a person outside its audience.
    fn check_reader(&self, log: &Log) -> Result<(), HeapError> {
        if log.sealed() && !log.fold().is_reader(log.person()) {
            return Err(HeapError::Sealed {
                space: self.name.clone(),
            });
        }
        Ok(())
    }

    /// The epoch key `blob`'s entry was sealed under (`None`: a plain value),
    /// or `Unavailable` while the entry is not applied and held.
    fn blob_key(&self, blob: &Blob) -> Result<Option<ContentKey>, HeapError> {
        self.log
            .lock()
            .entry_key(&blob.id)
            .ok_or_else(|| HeapError::Unavailable {
                name: log_name(&blob.id.device, &self.name, blob.id.seq),
            })
    }

    /// The value in pieces of `blob`, assembled from the store and opened:
    /// outside the lock.
    fn read_blob(&self, node: &NodeInner, blob: &Blob) -> Result<Bytes, HeapError> {
        let name = log_name(&blob.id.device, &self.name, blob.id.seq);
        let key = self.blob_key(blob)?;
        let body = ChunksBody {
            size: blob.size,
            root: blob.root,
        };
        let stored = pieces::read(&*node.stage, &name, &body).map_err(|e| match e {
            pieces::PieceError::Incomplete { .. } => HeapError::Unavailable { name: name.clone() },
            other => HeapError::Local {
                reason: other.to_string(),
            },
        })?;
        self.open_blob(blob, key, stored)
    }

    /// The value of `blob` from `stored`, the payload its proven pieces
    /// carry (sealed, under `key`, when the space is private).
    fn open_blob(
        &self,
        blob: &Blob,
        key: Option<ContentKey>,
        stored: Vec<u8>,
    ) -> Result<Bytes, HeapError> {
        self.whole.lock().insert(blob.id.clone());
        match key {
            None => Ok(Bytes::from(stored)),
            Some(key) => {
                let name = log_name(&blob.id.device, &self.name, blob.id.seq);
                seal::open_payload(&key, &name, &stored)
                    .map(Bytes::from)
                    .ok_or_else(|| HeapError::Local {
                        reason: format!(
                            "the sealed value of {name} does not open under its epoch key"
                        ),
                    })
            }
        }
    }

    /// Tell watchers (or `only`) a blob head that is whole: when its pieces
    /// are not all held it waits for [`Self::assembled`]. Nothing is told for
    /// a head that something newer superseded.
    pub(crate) fn emit_blob(&self, node: &NodeInner, blob: Blob, only: Option<Arc<Queue>>) {
        let Ok(bytes) = self.read_blob(node, &blob) else {
            return;
        };
        self.tell_blob(&blob, bytes, only);
    }

    /// [`Self::emit_blob`] for the value `bytes` of `blob` already in hand.
    fn tell_blob(&self, blob: &Blob, bytes: Bytes, only: Option<Arc<Queue>>) {
        let change = {
            let log = self.log.lock();
            let Some((path, head)) = log.register().values().find(|(_, h)| {
                h.entry.seq == blob.id.seq
                    && h.entry.digest == blob.id.digest
                    && h.entry.device == blob.id.device
            }) else {
                return;
            };
            Change::Put(head.item(path, bytes))
        };
        match only {
            Some(queue) => queue.push(change),
            None => self.tell(change),
        }
    }

    /// The pieces of `blob` arrived whole: write them as one batch and tell,
    /// with `payload` (what the proven chunks carry): nothing is read back.
    pub(crate) fn assembled(
        self: &Arc<Self>,
        node: &Arc<NodeInner>,
        blob: &Blob,
        ops: Vec<ndn_sync::StoreOp>,
        payload: Vec<u8>,
    ) {
        node.stage.apply(ops);
        node.flusher.note_write();
        if let Ok(key) = self.blob_key(blob)
            && let Ok(bytes) = self.open_blob(blob, key, payload)
        {
            self.tell_blob(blob, bytes, None);
        }
    }

    /// The blob heads whose pieces are not all held here. A head found
    /// inline or whole is remembered ([`Self::whole`]), so a later scan reads
    /// the entries of the heads it has not seen and no others: the scan runs
    /// after every entry taken, and one that read every head's entry from
    /// the store would hold the space's lock for as long as the space is
    /// large. The reads are made in batches, the lock let go between them,
    /// and one scan runs at a time: a second begun meanwhile would read the
    /// heads the first is about to settle.
    pub(crate) fn unassembled(&self, node: &NodeInner) -> Vec<Blob> {
        let _scan = self.scan.lock();
        let pending = {
            let log = self.log.lock();
            let mut seen = self.whole.lock();
            // Superseded heads leave the set only when it outgrows the heads.
            if seen.len() > 2 * log.register().head_count() + HEADS_PER_READ {
                seen.clear();
            }
            log.unsettled_heads(&seen)
        };
        let mut owed = Vec::new();
        for batch in pending.chunks(HEADS_PER_READ) {
            let kinds = self.log.lock().payload_kinds(batch);
            let mut inline = Vec::new();
            for (id, kind) in batch.iter().zip(kinds) {
                match kind {
                    Some(None) => inline.push(id.clone()),
                    Some(Some(blob)) if self.read_blob(node, &blob).is_err() => owed.push(blob),
                    Some(Some(_)) | None => {}
                }
            }
            self.whole.lock().extend(inline);
        }
        owed
    }

    /// Say a blob this node wrote is whole (its pieces went in its batch).
    fn mark_whole(&self, id: &EntryId) {
        self.whole.lock().insert(id.clone());
    }
}

// -- The handle --------------------------------------------------------------------

/// A space of a node: what a host reads, writes and watches.
#[derive(Clone)]
pub struct Heap {
    pub(crate) inner: Arc<SpaceInner>,
    pub(crate) node: Arc<NodeInner>,
}

impl std::fmt::Debug for Heap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Heap")
            .field("name", &self.inner.name)
            .finish()
    }
}

impl Heap {
    pub(crate) fn new(inner: Arc<SpaceInner>, node: Arc<NodeInner>) -> Heap {
        Heap { inner, node }
    }

    /// The space's name, `<owner>/32=data/…`.
    pub fn name(&self) -> &Name {
        &self.inner.name
    }

    /// Write `bytes` at `path` (relative to the space); empty bytes remove
    /// the path. Returns when the entry is signed, stored and applied, and
    /// served and announced at once (a Members or Epoch entry excepted); with
    /// `opts.durable` after the flush that covers it. Never waits for a peer.
    ///
    /// A value over the inline limit goes in pieces under the entry, written
    /// in the entry's own batch, and is sealed whole first in a private space.
    pub async fn put(
        &self,
        path: &Name,
        bytes: Bytes,
        opts: PutOptions,
    ) -> Result<EntryId, HeapError> {
        check_path(path)?;
        if bytes.len() as u64 > PAYLOAD_MAX {
            return Err(HeapError::TooLarge {
                name: path.clone(),
                limit: PAYLOAD_MAX,
            });
        }
        let (id, ticket) = if bytes.len() <= INLINE_MAX {
            self.put_inline(path, bytes).await?
        } else {
            self.put_blob(path, bytes).await?
        };
        let durable = opts.durable.unwrap_or_else(|| self.inner.group.no_peers());
        if durable {
            self.node
                .flusher
                .wait_durable(ticket)
                .await
                .map_err(flush_error)?;
        }
        tracing::trace!(target: TIMELINE, seq = id.seq, durable, "put_returns");
        Ok(id)
    }

    async fn put_inline(&self, path: &Name, bytes: Bytes) -> Result<(EntryId, Ticket), HeapError> {
        let now = self.node.now();
        self.inner
            .sign_with(&self.node, |log| {
                self.inner.may_seal(log)?;
                log.put(path, Payload::Inline(bytes.clone()), vec![], now)
            })
            .await
    }

    /// A value in pieces: sealed whole, cut, and written with its entry. The
    /// work is done outside the lock for the seq and epoch the lock showed;
    /// if either moved before the entry is signed it is done again.
    async fn put_blob(&self, path: &Name, bytes: Bytes) -> Result<(EntryId, Ticket), HeapError> {
        let inner = &self.inner;
        loop {
            let (seq, epoch, key) = {
                let log = inner.log.lock();
                inner.may_seal(&log)?;
                let epoch = log.judge_own()?;
                let key = epoch
                    .as_ref()
                    .and_then(|e| log.keys().key(&inner.name, e).cloned());
                (log.next_seq(), epoch, key)
            };
            let name = log_name(self.node.device(), &inner.name, seq);
            let carried = match &key {
                None => bytes.clone(),
                Some(key) => seal::seal_payload(key, &name, &bytes),
            };
            let cut = pieces::split(&name, &carried).map_err(|e| HeapError::Local {
                reason: e.to_string(),
            })?;
            let (blob, now) = (
                Payload::Blob {
                    size: cut.size,
                    root: cut.root,
                },
                self.node.now(),
            );
            let signed = inner
                .attempt(&self.node, &mut |log| {
                    inner.may_seal(log)?;
                    if log.next_seq() != seq || log.judge_own()? != epoch {
                        return Ok(None);
                    }
                    log.put(path, blob.clone(), cut.ops(), now).map(Some)
                })
                .await?;
            if let Some((id, ticket)) = signed {
                inner.mark_whole(&id);
                return Ok((id, ticket));
            }
        }
    }

    /// The value at `path`, from what this node holds: it never waits for
    /// the network. `None` when the path has no value (or was removed).
    /// [`HeapError::Sealed`] when the space is sealed and this node's person
    /// is outside its audience, or when an entry is held closed (its path is
    /// unknown); [`HeapError::Unavailable`] for a value in pieces not yet
    /// whole here.
    pub async fn get(&self, path: &Name) -> Result<Option<Item>, HeapError> {
        let inner = &self.inner;
        let blob = {
            let log = inner.log.lock();
            inner.check_reader(&log)?;
            match log.get(path) {
                Err(HeapError::Sealed { .. }) => return Err(inner.sealed_error(&log)),
                Err(e @ HeapError::Unavailable { .. }) => match log.blob_head(path) {
                    Some(blob) => blob,
                    None => return Err(e),
                },
                other => return other,
            }
        };
        let bytes = inner.read_blob(&self.node, &blob)?;
        let log = inner.log.lock();
        match log.register().value(path) {
            Some(head) if EntryId::from(&head.entry) == blob.id => Ok(Some(head.item(path, bytes))),
            _ => log.get(path),
        }
    }

    /// Watch the space: first every head held now that `since` does not
    /// already cover, then the changes as they happen.
    pub async fn watch(&self, since: &Frontier) -> Result<Changes, HeapError> {
        let inner = &self.inner;
        let (queue, blobs) = {
            let log = inner.log.lock();
            inner.check_reader(&log)?;
            let (items, blobs) = log.items();
            let mut listed: VecDeque<Change> = items
                .into_iter()
                .filter(|item| item.id.seq > since.get(&item.id.device))
                .map(Change::Put)
                .collect();
            listed.extend(inner.standing.lock().iter().cloned().map(Change::Alert));
            listed.extend(
                inner
                    .refused
                    .lock()
                    .iter()
                    .map(|(_, a)| Change::Alert(a.clone())),
            );
            let queue = Queue::new(listed, self.node.config.watch_queue);
            inner.watchers.lock().push(Arc::clone(&queue));
            (queue, blobs)
        };
        if let Some(why) = self.node.failure() {
            queue.push(Change::Alert(Alert::StoreFailed { why }));
        }
        for blob in blobs {
            if blob.id.seq <= since.get(&blob.id.device) {
                continue;
            }
            let (space, node, queue) = (
                Arc::clone(&self.inner),
                Arc::clone(&self.node),
                Arc::clone(&queue),
            );
            rt::spawn(async move { space.emit_blob(&node, blob, Some(queue)) });
        }
        Ok(Changes { queue })
    }

    /// Who the space lists, the owner first.
    pub fn members(&self) -> Members {
        self.inner.log.lock().members()
    }

    /// Whether the first catch-up is done: the space's creation is seen and
    /// everything heard of is held.
    pub fn ready(&self) -> bool {
        let log = self.inner.log.lock();
        log.fold().create().is_some() && log.missing().is_empty()
    }

    /// Change who the space lists. Only an owner device signs members
    /// ([`HeapError::NotOwner`], next step `UseOwnerDevice`, otherwise). A
    /// removal binds what this device holds of the person's devices; when the
    /// change leaves a sealed space without an epoch for exactly its readers,
    /// a new one is signed. Returns after the flush covering every entry
    /// signed: members and epochs are not served before it.
    pub async fn change(&self, c: MembersChange) -> Result<EntryId, HeapError> {
        let (inner, node) = (&self.inner, &self.node);
        if !owns(&inner.name, node.writer.key()) {
            return Err(HeapError::NotOwner {
                space: inner.name.clone(),
            });
        }
        inner.look_for_removed(node, &c.remove).await;
        let batches = {
            let log = inner.log.lock();
            let fold = log.fold();
            let in_force = fold.in_force();
            if let Readers::Persons(current) = fold.readers() {
                let mut after: BTreeSet<Name> = current.into_iter().collect();
                for person in &c.remove {
                    after.remove(person);
                }
                after.extend(c.add_readers.iter().cloned());
                after.insert(fold.owner().clone());
                check_audience(after.len())?;
            }
            let mut ops: Vec<Op> = c.remove.iter().flat_map(|p| log.remove_ops(p)).collect();
            let mut added = BTreeSet::new();
            for (who, role, standing) in c
                .add_writers
                .iter()
                .map(|w| (w, Role::Writer, fold.is_writer(w)))
                .chain(
                    c.add_readers
                        .iter()
                        .map(|r| (r, Role::Reader, fold.is_reader(r))),
                )
            {
                if !standing && added.insert((who.clone(), role as u8)) {
                    ops.push(Op::Add {
                        id: new_id(),
                        who: who.clone(),
                        role,
                        // A reader reads the history of the epoch in force
                        // (spec §6.6): the Add names it.
                        epoch: if role == Role::Reader {
                            in_force.clone()
                        } else {
                            None
                        },
                    });
                }
            }
            ops.chunks(crate::wire::OPS_MAX)
                .map(<[Op]>::to_vec)
                .collect::<Vec<_>>()
        };
        let mut last = None;
        for ops in batches {
            let now = node.now();
            last = Some(
                inner
                    .sign_with(node, |log| {
                        log.sign_members(
                            MembersBody {
                                create: None,
                                ops: ops.clone(),
                            },
                            now,
                        )
                    })
                    .await?,
            );
        }
        if let Some(epoch) = inner.repair_epoch(node).await? {
            last = Some(epoch);
        }
        let Some((id, ticket)) = last else {
            return Err(HeapError::BadRequest {
                why: "the change lists nobody to add or remove and the epoch is whole: nothing to \
                      sign"
                    .into(),
            });
        };
        node.flusher
            .wait_durable(ticket)
            .await
            .map_err(flush_error)?;
        Ok(id)
    }
}

/// A fresh id for an Add.
pub(crate) fn new_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).expect("the operating system provides randomness");
    id
}

// -- The carrier -------------------------------------------------------------------

/// A carrier of a space: it joins, verifies, stores and serves, publishes no
/// vector entry and needs no read key.
pub struct Follower {
    pub(crate) node: Arc<NodeInner>,
    pub(crate) space: Arc<SpaceInner>,
}

impl std::fmt::Debug for Follower {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Follower")
            .field("space", &self.space.name)
            .finish()
    }
}

impl Follower {
    /// Entries of the space held here (copies).
    pub fn held(&self) -> u64 {
        self.node.held_in(&self.space.name)
    }

    /// Stop carrying the space: it is left, and not carried after a restart.
    /// What was stored stays in the store.
    pub async fn close(self) {
        self.node.leave(&self.space.name).await;
    }
}
