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

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use futures::Stream;
use ndn_foundation_types::Name;
use ndn_security::confidentiality::ContentKey;
use ndn_sync::StoreOp;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::error::{HeapError, Refusal};
use crate::fold::Readers;
use crate::log::{Alert, Blob, Change, Effects, Frontier, Log, Members, Step};
use crate::node::NodeInner;
use crate::pieces;
use crate::register::{EntryId, Item};
use crate::reserve::{FlushError, Publisher, Ticket};
use crate::rt;
use crate::seal;
use crate::store::Kind;
use crate::sync::{Group, TIMELINE};
use crate::trust::Listing;
use crate::wire::{
    AUDIENCE_MAX, ChunksBody, EpochId, INLINE_MAX, MembersBody, Op, PAYLOAD_MAX, Payload, Role,
    log_name, parse_log_name, signed_digest_of,
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

/// One place in a watcher's queue: a change, or a value in pieces that is
/// read from the store when the watcher reaches it. The queue holds the
/// reference (an entry's id, a size, a digest), never the value: a space of
/// many 64 MiB values costs a watcher that reads slowly a few hundred octets
/// each, not the values.
enum Slot {
    Change(Change),
    Blob(Blob),
}

struct QueueState {
    /// What the watch listed as it began.
    listed: VecDeque<Slot>,
    /// Live changes, at most the queue's capacity.
    live: VecDeque<Slot>,
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
    fn new(listed: VecDeque<Slot>, cap: usize) -> Arc<Queue> {
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
        self.put(Slot::Change(change));
    }

    /// Queue a value in pieces that is whole in the store: it is read when
    /// the watcher gets to it.
    fn push_blob(&self, blob: Blob) {
        self.put(Slot::Blob(blob));
    }

    fn put(&self, slot: Slot) {
        let waker = {
            let mut st = self.st.lock();
            if st.closed {
                return;
            }
            if st.missed > 0 || st.live.len() >= self.cap {
                st.missed += 1;
            } else {
                st.live.push_back(slot);
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

    fn poll(&self, cx: &mut Context<'_>) -> Poll<Option<Slot>> {
        let mut st = self.st.lock();
        if let Some(slot) = st.listed.pop_front().or_else(|| st.live.pop_front()) {
            return Poll::Ready(Some(slot));
        }
        if st.missed > 0 {
            let missed = std::mem::take(&mut st.missed);
            return Poll::Ready(Some(Slot::Change(Change::Lagged { missed })));
        }
        if st.closed {
            return Poll::Ready(None);
        }
        st.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// What a watch yields: every head the space held when it began, then the
/// changes as they happen. Ends when the node stops. A value in pieces is
/// read from the store as the watch reaches it, one at a time.
pub struct Changes {
    queue: Arc<Queue>,
    space: Arc<SpaceInner>,
    node: Arc<NodeInner>,
}

impl Changes {
    /// The next change; `None` once the node has stopped and the queue is
    /// read.
    pub async fn next(&mut self) -> Option<Result<Change, HeapError>> {
        loop {
            let slot = futures::future::poll_fn(|cx| self.queue.poll(cx)).await?;
            if let Some(change) = self.resolve(slot) {
                return Some(Ok(change));
            }
        }
    }

    /// The change a slot says: a value in pieces is read now, and told only
    /// while it is the head of its path and still whole.
    fn resolve(&self, slot: Slot) -> Option<Change> {
        match slot {
            Slot::Change(change) => Some(change),
            Slot::Blob(blob) => self.space.blob_change(&self.node, &blob),
        }
    }
}

impl Stream for Changes {
    type Item = Result<Change, HeapError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.queue.poll(cx) {
                Poll::Ready(Some(slot)) => {
                    if let Some(change) = self.resolve(slot) {
                        return Poll::Ready(Some(Ok(change)));
                    }
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
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
    /// The blob heads whose pieces are not all held, by entry: what
    /// [`Self::unassembled`] lists. The pieces' own marker (`assembled/`)
    /// says when one is whole; nothing is read to know it.
    owed: Mutex<HashMap<EntryId, Blob>>,
    /// Alerts that stay true (evidence of rollback, of equivocation): a
    /// watcher that begins later is told them after the heads.
    standing: Mutex<Vec<Alert>>,
    /// The entries whose refusal was told, last [`REFUSED_MAX`], with the
    /// alert: a watcher that begins later is told them after the heads.
    refused: Mutex<VecDeque<(Name, Alert)>>,
}

/// The most standing alerts a space keeps for watchers that begin later.
const STANDING_MAX: usize = 32;

/// The most refused entries a space remembers having told.
const REFUSED_MAX: usize = 256;

/// A signing step run under the lock: `None` when there is nothing to sign.
type Sign<'a> = &'a mut (dyn FnMut(&mut Log) -> Result<Option<Step>, HeapError> + Send);

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

/// The digest of a set of revoked keys: what an epoch signed accounts for.
fn revocations_digest(revoked: &BTreeSet<Name>) -> [u8; 32] {
    let mut hash = Sha256::new();
    for key in revoked {
        hash.update(key.encode_to_tlv());
    }
    hash.finalize().into()
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
            owed: Mutex::new(HashMap::new()),
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
                && log.owner_only().is_ok()
                && (!log.fold().complete() || self.revocation_owed(node, log));
        }
        Routed {
            ticket,
            blobs: fx.blobs,
            repair,
            nudge: !fx.wants.is_empty() || fx.membership,
        }
    }

    /// What follows a routed call once the lock is let go: blobs whose
    /// pieces are all held to tell, the epoch to repair, the fetch to wake.
    pub(crate) fn finish(self: &Arc<Self>, node: &Arc<NodeInner>, routed: Routed) {
        for blob in routed.blobs {
            // One still to gather is told when its last piece is held.
            if self.is_whole(node, &blob) {
                self.tell_blob(&blob);
            } else {
                self.owed.lock().insert(blob.id.clone(), blob);
            }
        }
        if routed.repair {
            self.spawn_repair(node);
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
                return Err(FlushError::Stopped.into());
            }
            let wait = {
                let mut log = self.log.lock();
                self.own_key_refusal(node, &log)?;
                match step(&mut log)? {
                    None => return Ok(None),
                    Some(Step::Done(id, fx)) => {
                        let routed = self.route(node, &log, fx, true);
                        drop(log);
                        let ticket = routed.ticket.expect("a signed entry was written");
                        self.finish(node, routed);
                        return Ok(Some((id, ticket)));
                    }
                    Some(Step::Wait(ticket)) => ticket,
                }
            };
            node.flusher.wait_durable(wait).await?;
        }
    }

    /// [`Self::attempt`] for a step that always has something to sign.
    pub(crate) async fn sign_with(
        self: &Arc<Self>,
        node: &Arc<NodeInner>,
        mut step: impl FnMut(&mut Log) -> Result<Step, HeapError> + Send,
    ) -> Result<(EntryId, Ticket), HeapError> {
        let signed = self
            .attempt(node, &mut |log| step(log).map(Some))
            .await?
            .expect("a step that signs always yields");
        Ok(signed)
    }

    /// The revocations held here of keys under the namespace of a person the
    /// space reads for: the lost devices that may hold an epoch key.
    fn reader_revocations(&self, node: &NodeInner, log: &Log) -> BTreeSet<Name> {
        let Readers::Persons(readers) = log.fold().readers() else {
            return BTreeSet::new();
        };
        readers
            .iter()
            .flat_map(|person| node.judge.revoked_under(person, &self.name))
            .collect()
    }

    /// Whether this owner device owes the sealed space an epoch because a key
    /// of a reader's device is revoked (spec §6.6): a revocation changes no
    /// member, but the lost device holds the key in force and would open every
    /// later write. Owed while the revocations held are not those the last
    /// epoch this device signed accounted for (`revoked/<S>`).
    fn revocation_owed(&self, node: &NodeInner, log: &Log) -> bool {
        if self.follower
            || !log.sealed()
            || log.fold().create() != Some(false)
            || log.owner_only().is_err()
        {
            return false;
        }
        let revoked = self.reader_revocations(node, log);
        !revoked.is_empty()
            && node.store.get(&Kind::REVOKED.of(&self.name)).as_deref()
                != Some(&revocations_digest(&revoked)[..])
    }

    /// Spawn the epoch a revocation of a reader's device key owes, if any.
    pub(crate) fn repair_if_owed(self: &Arc<Self>, node: &Arc<NodeInner>) {
        if self.revocation_owed(node, &self.log.lock()) {
            self.spawn_repair(node);
        }
    }

    fn spawn_repair(self: &Arc<Self>, node: &Arc<NodeInner>) {
        let (space, node) = (Arc::clone(self), Arc::clone(node));
        rt::spawn(async move {
            if let Err(e) = space.repair_epoch(&node).await {
                tracing::warn!(space = %space.name, "the epoch is not repaired: {e}");
            }
        });
    }

    /// Sign a new Epoch for exactly the readers when the space is sealed and
    /// the epoch in force is not for them (spec §3.3, rule 7), or when a key of
    /// a reader's device is revoked and no epoch signed here accounts for it:
    /// an owner device owes it after every change of members, whoever signed
    /// it.
    pub(crate) async fn repair_epoch(
        self: &Arc<Self>,
        node: &Arc<NodeInner>,
    ) -> Result<Option<(EntryId, Ticket)>, HeapError> {
        let now = node.now();
        self.attempt(node, &mut |log| {
            let fold = log.fold();
            let owed = self.revocation_owed(node, log);
            if fold.create() != Some(false)
                || (fold.complete() && !owed)
                || log.owner_only().is_err()
            {
                return Ok(None);
            }
            let Readers::Persons(audience) = fold.readers() else {
                return Ok(None);
            };
            let accounted = revocations_digest(&self.reader_revocations(node, log));
            let step = log.sign_epoch(audience, now)?;
            if matches!(step, Step::Done(..)) {
                node.store.insert(
                    Kind::REVOKED.of(&self.name),
                    Bytes::copy_from_slice(&accounted),
                );
            }
            Ok(Some(step))
        })
        .await
    }

    /// Sign `ops` as Members entries, as many as the entry limits need (the
    /// first carries `create`, and one is signed for it even with no
    /// operations), then the epoch the new members owe. The entry signed
    /// last: its id and flush ticket.
    async fn sign_members(
        self: &Arc<Self>,
        node: &Arc<NodeInner>,
        mut create: Option<bool>,
        ops: Vec<Op>,
    ) -> Result<Option<(EntryId, Ticket)>, HeapError> {
        let mut batches = crate::log::pack_ops(ops);
        if create.is_some() && batches.is_empty() {
            batches.push(Vec::new());
        }
        let mut last = None;
        for ops in batches {
            let (create, now) = (create.take(), node.now());
            let body = |log: &mut Log| {
                let members = MembersBody {
                    create,
                    ops: ops.clone(),
                };
                log.sign_members(members, now)
            };
            last = Some(self.sign_with(node, body).await?);
        }
        Ok(self.repair_epoch(node).await?.or(last))
    }

    /// Sign the creation of a new space: its Members entries, then its first
    /// epoch when it is private. Returns after the covering flush.
    pub(crate) async fn sign_creation(
        self: &Arc<Self>,
        node: &Arc<NodeInner>,
        share: &Share,
    ) -> Result<(), HeapError> {
        let (anyone, readers) = match &share.readers {
            Readers::Anyone => (true, &[][..]),
            Readers::Persons(persons) => (false, &persons[..]),
        };
        let ops = adds(&share.writers, readers, None, |who, _| *who == node.ns);
        if let Some((_, ticket)) = self.sign_members(node, Some(anyone), ops).await? {
            node.flusher.wait_durable(ticket).await?;
        }
        Ok(())
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
            }) || self
                .group
                .heard_unheld(|device| removed.contains(&node.person_of(device)));
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
        } else if let Some(since) = node.suspicion.since(key) {
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

    /// Whether every piece of `blob` is held here and the value recorded
    /// whole (`assembled/<entry>`): one lookup, nothing read.
    fn is_whole(&self, node: &NodeInner, blob: &Blob) -> bool {
        node.store
            .contains(&Kind::ASSEMBLED.of(&blob.id.name(&self.name)))
    }

    /// The value in pieces of `blob`, joined from the store and opened
    /// (under its epoch key when the space is private): outside the lock. A
    /// value not recorded whole is not read at all, so nothing of the size
    /// its entry declares (up to 64 MiB) is allocated for one that cannot be
    /// returned.
    fn read_blob(&self, node: &NodeInner, blob: &Blob) -> Result<Bytes, HeapError> {
        let name = blob.id.name(&self.name);
        let key = self.blob_key(blob)?;
        if !self.is_whole(node, blob) {
            return Err(HeapError::Unavailable { name });
        }
        let body = ChunksBody {
            size: blob.size,
            root: blob.root,
        };
        let stored = pieces::read(&*node.store, &name, &body).map_err(|e| {
            // The store lost or damaged a piece it recorded whole: the value
            // is gathered again, from what the store still holds and the peers.
            node.store.remove(&Kind::ASSEMBLED.of(&name));
            node.flusher.note_write();
            self.owed.lock().insert(blob.id.clone(), blob.clone());
            node.nudge(&self.name);
            match e {
                pieces::PieceError::Incomplete { .. } => {
                    HeapError::Unavailable { name: name.clone() }
                }
                other => HeapError::Local {
                    reason: other.to_string(),
                },
            }
        })?;
        match key {
            None => Ok(Bytes::from(stored)),
            Some(key) => seal::open_payload(&key, &name, &stored)
                .map(Bytes::from)
                .ok_or_else(|| HeapError::Local {
                    reason: format!("the sealed value of {name} does not open under its epoch key"),
                }),
        }
    }

    /// The change that puts the value of `blob`, if it is still the head of
    /// its path and whole: read now, by the watcher that reaches it.
    fn blob_change(&self, node: &NodeInner, blob: &Blob) -> Option<Change> {
        let bytes = self.read_blob(node, blob).ok()?;
        let log = self.log.lock();
        let (path, head) = log.register().values().find(|(_, h)| h.entry == blob.id)?;
        Some(Change::Put(head.item(path, bytes)))
    }

    /// Tell every watcher a blob head that is whole: the queues hold the
    /// reference and each watcher reads the value when it gets to it. Nothing
    /// is told for a head that something newer superseded.
    fn tell_blob(&self, blob: &Blob) {
        let current = self
            .log
            .lock()
            .register()
            .values()
            .any(|(_, h)| h.entry == blob.id);
        if !current {
            return;
        }
        let mut watchers = self.watchers.lock();
        watchers.retain(|q| !q.is_closed());
        for q in watchers.iter() {
            q.push_blob(blob.clone());
        }
    }

    /// The last piece of `blob` is held: record the value whole (after its
    /// pieces, in write order) and tell.
    pub(crate) fn assembled(self: &Arc<Self>, node: &Arc<NodeInner>, blob: &Blob) {
        node.store.insert(
            Kind::ASSEMBLED.of(&blob.id.name(&self.name)),
            Bytes::from_static(&[1]),
        );
        node.flusher.note_write();
        self.owed.lock().remove(&blob.id);
        self.tell_blob(blob);
    }

    /// The blob heads of the log, as they stand at start, whose pieces are
    /// not all held: owed. One read of each head's entry, once; afterwards
    /// [`Self::finish`] adds what an entry newly makes a head.
    pub(crate) fn seed_owed(&self, node: &NodeInner) {
        let blobs = self.log.lock().items().1;
        let owed = blobs.into_iter().filter(|b| !self.is_whole(node, b));
        self.owed.lock().extend(owed.map(|b| (b.id.clone(), b)));
    }

    /// The values owed their pieces that are still the head of their path:
    /// what is fetched, and asked again while owed. One superseded is
    /// dropped (it comes back if a removal makes it the head again).
    pub(crate) fn unassembled(&self) -> Vec<Blob> {
        let mut owed = self.owed.lock();
        if owed.is_empty() {
            return Vec::new();
        }
        let heads: HashSet<EntryId> = {
            let log = self.log.lock();
            log.register()
                .values()
                .map(|(_, h)| h.entry.clone())
                .collect()
        };
        owed.retain(|id, _| heads.contains(id));
        owed.values().cloned().collect()
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
        let durable = opts
            .durable
            .unwrap_or_else(|| !self.inner.log.lock().has_peers());
        if durable {
            self.node.flusher.wait_durable(ticket).await?;
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
                    // The pieces and the mark that the value is whole go in
                    // the entry's own batch.
                    let mut ops = cut.ops();
                    ops.push(StoreOp::Insert(
                        Kind::ASSEMBLED.of(&name),
                        Bytes::from_static(&[1]),
                    ));
                    log.put(path, blob.clone(), ops, now).map(Some)
                })
                .await?;
            if let Some(signed) = signed {
                return Ok(signed);
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
            Some(head) if head.entry == blob.id => Ok(Some(head.item(path, bytes))),
            _ => log.get(path),
        }
    }

    /// Watch the space: first every head held now that `since` does not
    /// already cover, then the changes as they happen.
    pub async fn watch(&self, since: &Frontier) -> Result<Changes, HeapError> {
        let inner = &self.inner;
        let queue = {
            let log = inner.log.lock();
            inner.check_reader(&log)?;
            let (items, blobs) = log.items();
            let mut listed: VecDeque<Slot> = items
                .into_iter()
                .filter(|item| item.id.seq > since.get(&item.id.device))
                .map(|item| Slot::Change(Change::Put(item)))
                .collect();
            // A value in pieces is a reference here: it is read from the
            // store when the watch reaches it, and skipped then if its
            // pieces are not all held (it is told when its last is).
            listed.extend(
                blobs
                    .into_iter()
                    .filter(|blob| blob.id.seq > since.get(&blob.id.device))
                    .map(Slot::Blob),
            );
            listed.extend(
                inner
                    .standing
                    .lock()
                    .iter()
                    .cloned()
                    .map(|a| Slot::Change(Change::Alert(a))),
            );
            listed.extend(
                inner
                    .refused
                    .lock()
                    .iter()
                    .map(|(_, a)| Slot::Change(Change::Alert(a.clone()))),
            );
            let queue = Queue::new(listed, self.node.config.watch_queue);
            inner.watchers.lock().push(Arc::clone(&queue));
            queue
        };
        if let Some(why) = self.node.failure() {
            queue.push(Change::Alert(Alert::StoreFailed { why }));
        }
        Ok(Changes {
            queue,
            space: Arc::clone(&self.inner),
            node: Arc::clone(&self.node),
        })
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
        inner.log.lock().owner_only()?;
        inner.look_for_removed(node, &c.remove).await;
        let ops = {
            let log = inner.log.lock();
            let fold = log.fold();
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
            ops.extend(adds(
                &c.add_writers,
                &c.add_readers,
                fold.in_force(),
                |who, role| match role {
                    Role::Writer => fold.is_writer(who),
                    Role::Reader => fold.is_reader(who),
                },
            ));
            ops
        };
        let Some((id, ticket)) = inner.sign_members(node, None, ops).await? else {
            return Err(HeapError::BadRequest {
                why: "the change lists nobody to add or remove and the epoch is whole: nothing to \
                      sign"
                    .into(),
            });
        };
        node.flusher.wait_durable(ticket).await?;
        Ok(id)
    }
}

/// A fresh id for an Add.
pub(crate) fn new_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).expect("the operating system provides randomness");
    id
}

/// The Adds of `writers` and `readers` that `standing` does not say already
/// stand, each once. A reader's Add names `epoch`, the one in force: the
/// reader reads its history (spec §6.6).
fn adds(
    writers: &[Name],
    readers: &[Name],
    epoch: Option<EpochId>,
    standing: impl Fn(&Name, Role) -> bool,
) -> Vec<Op> {
    let mut added = BTreeSet::new();
    writers
        .iter()
        .map(|w| (w, Role::Writer))
        .chain(readers.iter().map(|r| (r, Role::Reader)))
        .filter(|&(who, role)| !standing(who, role) && added.insert((who, role as u8)))
        .map(|(who, role)| Op::Add {
            id: new_id(),
            who: who.clone(),
            role,
            epoch: epoch.clone().filter(|_| role == Role::Reader),
        })
        .collect()
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
        self.space.log.lock().held_count()
    }

    /// Stop carrying the space: it is left, and not carried after a restart.
    /// What was stored stays in the store.
    pub async fn close(self) {
        self.node.leave(&self.space.name).await;
    }
}
