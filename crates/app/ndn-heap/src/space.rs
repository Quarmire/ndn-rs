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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use futures::Stream;
use futures::task::AtomicWaker;
use ndn_foundation_types::Name;
use ndn_packet::Data;
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
use crate::trust::{Judged, Listing};
use crate::wire::{
    AUDIENCE_MAX, ChunksBody, EpochId, GrantAsk, INLINE_MAX, MembersBody, Op, PAYLOAD_MAX, Payload,
    Role, device_of, log_name, parse_log_name, signed_digest_of,
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

#[derive(Default)]
struct QueueState {
    /// Live changes, at most the queue's capacity.
    live: VecDeque<Slot>,
    /// Changes dropped since the watcher last read.
    missed: u64,
    closed: bool,
}

/// One watcher's live changes.
pub(crate) struct Queue {
    st: Mutex<QueueState>,
    waker: AtomicWaker,
    cap: usize,
}

impl Queue {
    fn new(cap: usize) -> Arc<Queue> {
        Arc::new(Queue {
            st: Mutex::default(),
            waker: AtomicWaker::new(),
            cap: cap.max(1),
        })
    }

    pub(crate) fn push(&self, change: Change) {
        self.put(Slot::Change(change));
    }

    fn put(&self, slot: Slot) {
        {
            let mut st = self.st.lock();
            if st.closed {
                return;
            }
            if st.missed > 0 || st.live.len() >= self.cap {
                st.missed += 1;
            } else {
                st.live.push_back(slot);
            }
        }
        self.waker.wake();
    }

    pub(crate) fn close(&self) {
        self.st.lock().closed = true;
        self.waker.wake();
    }

    fn is_closed(&self) -> bool {
        self.st.lock().closed
    }

    fn poll(&self, cx: &mut Context<'_>) -> Poll<Option<Slot>> {
        self.waker.register(cx.waker());
        let mut st = self.st.lock();
        if let Some(slot) = st.live.pop_front() {
            return Poll::Ready(Some(slot));
        }
        if st.missed > 0 {
            let missed = std::mem::take(&mut st.missed);
            return Poll::Ready(Some(Slot::Change(Change::Lagged { missed })));
        }
        if st.closed {
            return Poll::Ready(None);
        }
        Poll::Pending
    }
}

/// What a watch yields: every head the space held when it began, then the
/// changes as they happen. Ends when the node stops. A value in pieces is
/// read from the store as the watch reaches it, one at a time.
pub struct Changes {
    /// What the watch listed as it began: never lagged.
    listed: VecDeque<Slot>,
    queue: Arc<Queue>,
    space: Arc<SpaceInner>,
    node: Arc<NodeInner>,
}

impl Changes {
    /// The next change; `None` once the node has stopped and the queue is
    /// read.
    pub async fn next(&mut self) -> Option<Result<Change, HeapError>> {
        futures::StreamExt::next(self).await
    }
}

impl Stream for Changes {
    type Item = Result<Change, HeapError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let next = match self.listed.pop_front() {
                Some(slot) => Poll::Ready(Some(slot)),
                None => self.queue.poll(cx),
            };
            let Some(slot) = ready!(next) else {
                return Poll::Ready(None);
            };
            // A value in pieces is read now, and told only while it is the
            // head of its path and still whole.
            let change = match slot {
                Slot::Change(change) => Some(change),
                Slot::Blob(blob) => self.space.blob_change(&self.node, &blob),
            };
            if let Some(change) = change {
                return Poll::Ready(Some(Ok(change)));
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
    /// The [`Alert::RolledBack`] raised since the space was opened, standing or not
    /// ([`Heap::rollbacks`]).
    rollbacks: AtomicU64,
    /// The entries whose refusal was told, last [`REFUSED_MAX`], with the
    /// alert: a watcher that begins later is told them after the heads.
    refused: Mutex<VecDeque<(Name, Alert)>>,
    /// The keys of devices of readers this owner device granted epoch keys to whose
    /// certificates lapsed by this node's clock, as the last [`Self::sweep_lapsed`] found
    /// them: what owes the space a new epoch until one is signed (spec §6.5).
    lapsed: Mutex<BTreeSet<Name>>,
    /// For each granted key the last sweep could not judge, how many sweeps in a row it has
    /// stayed undecided ([`PENDING_SWEEPS_MAX`]): in memory only, so a restart counts again.
    pending: Mutex<BTreeMap<Name, u32>>,
    /// When this owner device last signed an epoch because keys of readers' devices were lost,
    /// by this node's clock ([`LOSS_EPOCH_INTERVAL_MS`]): in memory only, so a restart allows
    /// one more.
    last_loss_epoch: Mutex<Option<u64>>,
}

/// The most standing alerts a space keeps for watchers that begin later.
const STANDING_MAX: usize = 32;

/// The most refused entries a space remembers having told.
const REFUSED_MAX: usize = 256;

/// The most devices of one person an owner device keeps of those it granted epoch keys of one
/// space to (spec §6.5). A reader chooses how many devices she asks with, so the record is
/// bounded per person: no reader can fill it for the others. A person has few devices, and one
/// whose certificate lapsed leaves the record when the epoch it owes is signed.
pub(crate) const GRANTEES_PER_PERSON: usize = 32;

/// How many sweeps in a row ([`SpaceInner::sweep_lapsed`]) a grantee may stay undecided
/// (`Pending`: the certificates it is judged by can be had neither from the record nor from
/// this node) before it owes the epoch (spec §6.5, §9.9). It counts sweeps and not time: no
/// verdict is read off a clock. A node whose trust contexts or certificates are still being
/// loaded stays undecided for a sweep or two; one still undecided after five (five minutes at
/// the default `lapse_sweep`) cannot vouch for that key any more, and a key nobody can vouch
/// for is re-keyed, never trusted by default.
pub(crate) const PENDING_SWEEPS_MAX: u32 = 5;

/// The shortest time between two epochs an owner device signs because keys of readers'
/// devices are lost (revoked, suspected or lapsed), in ms by this node's clock: ten minutes.
/// Every epoch makes each reader device ask again, and nothing else bounds how often one
/// reader can lose keys (she mints a key and forks it, or a certificate lapses: spec §9.8,
/// §9.9). The losses that come inside the interval stay owed, are folded into one epoch (it
/// accounts for all those known when it is signed) and are rotated away when the interval ends,
/// never dropped. A cost bound, not a verdict: nothing is accepted or refused by it; a key
/// lost during the interval holds the key in force for at most that long after this node knows
/// of it. The mark of the last such epoch is kept in memory: a restart allows one more.
pub(crate) const LOSS_EPOCH_INTERVAL_MS: u64 = 10 * 60 * 1000;

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

/// The wait a refusal for want of a listing becomes for a device an offer
/// admitted.
const LISTING_AWAITED: &str = "an offer's answer admitted this device to the space, but the \
    members entry that lists its person has not arrived here yet; put again, or join again with \
    the same code (the offer answers the device it admitted)";

impl SpaceInner {
    pub(crate) fn new(
        log: Log,
        publisher: Publisher,
        group: Arc<Group>,
        follower: bool,
    ) -> SpaceInner {
        SpaceInner {
            name: log.space.clone(),
            log: Mutex::new(log),
            publisher,
            group,
            watchers: Mutex::new(Vec::new()),
            follower,
            closing: AtomicBool::new(false),
            owed: Mutex::new(HashMap::new()),
            standing: Mutex::new(Vec::new()),
            rollbacks: AtomicU64::new(0),
            refused: Mutex::new(VecDeque::new()),
            lapsed: Mutex::new(BTreeSet::new()),
            pending: Mutex::new(BTreeMap::new()),
            last_loss_epoch: Mutex::new(None),
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
        let fold = &log.fold;
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
        // A device caught signing two packets at one name is suspected (by the call that
        // returned this alert): if it is a reader's device it holds the key in force.
        let equivocated = fx
            .alerts
            .iter()
            .any(|alert| matches!(alert, Alert::Equivocation { .. }));
        for change in fx.changes {
            self.tell(change);
        }
        for alert in fx.alerts {
            tracing::warn!(space = %self.name, ?alert, "alert");
            if matches!(alert, Alert::RolledBack { .. }) {
                self.rollbacks.fetch_add(1, Ordering::AcqRel);
            }
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
            // The channels of this space judge their receivers (and the sender itself) again
            // at once, and announce.
            node.chan.wake();
            node.release_joined(log);
            // A reader removed from the space ends the records of her devices at once.
            self.forget_non_readers(node, log);
            repair = !self.follower
                && log.sealed()
                && log.owner_only().is_ok()
                && (!log.fold.complete() || self.loss_owed(node, log) || self.rule_owed(log));
        }
        if equivocated && !repair {
            repair = self.loss_owed(node, log);
        }
        Routed {
            ticket,
            blobs: fx.blobs,
            repair,
            nudge: !fx.wants.is_empty() || fx.membership,
        }
    }

    /// What follows a routed call once the lock is let go: blobs whose
    /// pieces are all held to tell, the epoch to repair, the fetch to wake (also when a value
    /// became owed its pieces: a key that opens a closed entry makes it a head whose pieces
    /// nothing else asks for).
    pub(crate) fn finish(self: &Arc<Self>, node: &Arc<NodeInner>, routed: Routed) {
        let mut nudge = routed.nudge;
        for blob in routed.blobs {
            // One still to gather is told when its last piece is held.
            if self.is_whole(node, &blob) {
                self.tell_blob(&blob);
            } else {
                self.owed.lock().insert(blob.id.clone(), blob);
                nudge = true;
            }
        }
        if routed.repair {
            self.spawn_repair(node);
        }
        if nudge {
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
                match step(&mut log).map_err(|e| self.awaiting_listing(node, &log, e))? {
                    None => return Ok(None),
                    Some(Step::Done(id, fx)) => {
                        let mut routed = self.route(node, &log, fx, true);
                        // The epoch an own Members entry owes is signed by its
                        // signer, in line ([`Self::sign_members`]): a task of
                        // its own could sign it after the caller returned, or
                        // before the caller's own repair and leave that one
                        // with nothing to sign and a ticket that does not cover
                        // the epoch.
                        routed.repair = false;
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

    /// The keys of devices of a person the space reads for that may hold an epoch key and are
    /// lost, as this node knows it: the revocations held here of keys under the person's
    /// namespace, and the keys this node marks suspected under it (spec §9.8).
    fn reader_losses(&self, node: &NodeInner, log: &Log) -> BTreeSet<Name> {
        let Readers::Persons(readers) = log.fold.readers() else {
            return BTreeSet::new();
        };
        let suspected = node.suspicion.keys();
        readers
            .iter()
            .flat_map(|person| {
                node.judge
                    .revoked_under(person, &self.name)
                    .into_iter()
                    .chain(
                        suspected
                            .iter()
                            .filter(|key| key.has_prefix(person))
                            .cloned(),
                    )
            })
            .collect()
    }

    /// Whether this owner device owes the sealed space an epoch because a key
    /// of a reader's device is lost (spec §6.6, §9.8): revoked, suspected here or lapsed
    /// ([`Self::loss_debt`]), and the last epoch signed for lost keys is at least
    /// [`LOSS_EPOCH_INTERVAL_MS`] old (§9.9): inside the interval the debt waits, whole, to be
    /// folded into the one epoch that follows it.
    fn loss_owed(&self, node: &NodeInner, log: &Log) -> bool {
        self.loss_debt(node, log) && self.loss_epoch_due(node.now())
    }

    /// Whether an epoch for lost keys may be signed at `now`: none was signed in the last
    /// [`LOSS_EPOCH_INTERVAL_MS`]. A clock that went back before the last one allows it, so the
    /// bound never holds a lost key un-rotated for longer than the interval.
    fn loss_epoch_due(&self, now: u64) -> bool {
        self.last_loss_epoch
            .lock()
            .is_none_or(|last| now < last || now - last >= LOSS_EPOCH_INTERVAL_MS)
    }

    /// Whether a key of a reader's device is lost and no epoch signed here accounts for it: it
    /// changes no member, but the lost device holds the key in force and would open every later
    /// write. Owed while the lost keys known here are not those the last epoch this device
    /// signed accounted for (`revoked/<S>`), or a granted device's certificate lapsed.
    fn loss_debt(&self, node: &NodeInner, log: &Log) -> bool {
        if self.follower
            || !log.sealed()
            || log.fold.create() != Some(false)
            || log.owner_only().is_err()
        {
            return false;
        }
        let lost = self.reader_losses(node, log);
        !self.lapsed_readers(log).is_empty()
            || (!lost.is_empty()
                && node.store.get(&Kind::REVOKED.of(&self.name)).as_deref()
                    != Some(&revocations_digest(&lost)[..]))
    }

    /// The granted devices of a person the space reads for whose certificate lapsed.
    fn lapsed_readers(&self, log: &Log) -> BTreeSet<Name> {
        let Readers::Persons(readers) = log.fold.readers() else {
            return BTreeSet::new();
        };
        self.lapsed
            .lock()
            .iter()
            .filter(|key| readers.iter().any(|person| key.has_prefix(person)))
            .cloned()
            .collect()
    }

    /// The persons the space lists as readers (none for a public space).
    fn reading_persons(log: &Log) -> BTreeSet<Name> {
        match log.fold.readers() {
            Readers::Persons(readers) => readers.into_iter().collect(),
            Readers::Anyone => BTreeSet::new(),
        }
    }

    /// End the records of the devices of every person the space does not list as a reader
    /// now (spec §6.5): she is granted nothing more and an epoch has already left her out
    /// (or will be signed), so her records no longer owe anything and must not take the
    /// room of another person's.
    fn forget_non_readers(&self, node: &NodeInner, log: &Log) {
        if self.follower {
            return;
        }
        let readers = Self::reading_persons(log);
        for (at, _) in node.store.scan_under(&Kind::GRANTED.listing(&self.name), 0) {
            let reads = Kind::GRANTED
                .parse_pair(&self.name, &at)
                .is_some_and(|(person, _)| readers.contains(&person));
            if !reads {
                node.store.remove(&at);
            }
        }
    }

    /// Look at the devices this owner device granted epoch keys of the space to
    /// ([`NodeInner::note_grantee`]); a lapse moves no counter, so this runs on a timer
    /// (`Config.lapse_sweep`). It first ends the records of persons who no longer read the
    /// space and of revoked keys (an epoch accounts for a revoked key by `revoked/<S>`, not by
    /// the record). Each other record is judged by the seal key packet it was granted by,
    /// with the certificate chain the ask carried, so a restart that lost every certificate of
    /// another person's device does not hide a lapse (nothing is fetched). A key whose
    /// certificate is `Lapsed` by this node's clock owes the epoch; a renewed certificate held
    /// here ends the lapse. One that stays undecided for [`PENDING_SWEEPS_MAX`] sweeps in a
    /// row owes it too (it fails closed).
    pub(crate) async fn sweep_lapsed(&self, node: &Arc<NodeInner>) {
        if self.follower {
            return;
        }
        let readers = Self::reading_persons(&self.log.lock());
        let before = self.pending.lock().clone();
        let (mut lapsed, mut undecided) = (BTreeMap::new(), BTreeMap::new());
        for (at, wire) in node.store.scan_under(&Kind::GRANTED.listing(&self.name), 0) {
            let Some((person, key)) = Kind::GRANTED.parse_pair(&self.name, &at) else {
                node.store.remove(&at);
                continue;
            };
            if !readers.contains(&person) || node.judge.key_revoked(&key, &self.name) {
                node.store.remove(&at);
                continue;
            }
            let judged = match (GrantAsk::decode(wire), device_of(&key)) {
                (Ok(ask), Some(device)) => match Data::decode(ask.seal_packet.clone()) {
                    Ok(data) => Some(
                        node.judge
                            .validate_asker_packet(&data, &device, &self.name, &ask.chain)
                            .await,
                    ),
                    Err(_) => None,
                },
                _ => None,
            };
            match judged {
                Some(Judged::Refused(Refusal::Lapsed { .. })) => {
                    lapsed.insert(key, at);
                }
                Some(Judged::Valid(_) | Judged::Refused(_)) => {}
                // Undecided, or a record that cannot be read: counted.
                Some(Judged::Pending(_)) | None => {
                    let waited = before.get(&key).map_or(1, |n| n.saturating_add(1));
                    if waited >= PENDING_SWEEPS_MAX {
                        lapsed.insert(key.clone(), at);
                    }
                    undecided.insert(key, waited);
                }
            }
        }
        // An epoch signed while this sweep judged ended some records: they owe nothing.
        lapsed.retain(|_, at| node.store.get(at).is_some());
        *self.lapsed.lock() = lapsed.into_keys().collect();
        *self.pending.lock() = undecided;
    }

    /// The epoch signed for the lapsed devices ends their record: they are granted no
    /// key until they renew and ask again.
    fn forget_lapsed(&self, node: &NodeInner) {
        let lapsed = std::mem::take(&mut *self.lapsed.lock());
        self.pending.lock().retain(|key, _| !lapsed.contains(key));
        for (at, _) in node.store.scan_under(&Kind::GRANTED.listing(&self.name), 0) {
            let owed = Kind::GRANTED
                .parse_pair(&self.name, &at)
                .is_some_and(|(_, key)| lapsed.contains(&key));
            if owed {
                node.store.remove(&at);
            }
        }
    }

    /// Whether this owner device owes the sealed space a fresh epoch because
    /// the space was stored under an older owner rule (spec §9.9): a guest
    /// or node device of the owner may hold the key in force, and would open
    /// every later write. Owed until the epoch is signed and the rule is
    /// recorded.
    fn rule_owed(&self, log: &Log) -> bool {
        log.rule_stale
            && !self.follower
            && log.sealed()
            && log.fold.create() == Some(false)
            && log.owner_only().is_ok()
    }

    /// Look again at what the space wants at once, and spawn the epoch a
    /// revocation of a reader's device key owes, if any.
    pub(crate) fn settle(self: &Arc<Self>, node: &Arc<NodeInner>) {
        node.nudge(&self.name);
        let owed = {
            let log = self.log.lock();
            node.release_joined(&log);
            self.loss_owed(node, &log) || self.rule_owed(&log)
        };
        if owed {
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
            let fold = &log.fold;
            let owed = self.loss_owed(node, log);
            let rule = self.rule_owed(log);
            if fold.create() != Some(false)
                || (fold.complete() && !owed && !rule)
                || log.owner_only().is_err()
            {
                return Ok(None);
            }
            let Readers::Persons(audience) = fold.readers() else {
                return Ok(None);
            };
            let accounted = revocations_digest(&self.reader_losses(node, log));
            let step = log.sign_epoch(audience, now)?;
            if matches!(step, Step::Done(..)) {
                node.store.insert(
                    Kind::REVOKED.of(&self.name),
                    Bytes::copy_from_slice(&accounted),
                );
                self.forget_lapsed(node);
                if owed {
                    *self.last_loss_epoch.lock() = Some(now);
                }
                if rule {
                    // The fresh epoch is the one in force: no key a guest or
                    // node device of the owner held opens what is written now.
                    log.rule_stale = false;
                    node.record_rule(&self.name);
                }
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
                .probes()
                .iter()
                .any(|(device, _)| removed.contains(&node.person_of(device)));
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
        let key = &log.key;
        let ctx = node.judge.validator.keyring().context_for(key);
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
            name: log_name(&log.device, &self.name, log.next_seq()),
            why,
        })
    }

    /// `refused`, a refusal to write for want of a listing, as it stands for
    /// this device: [`HeapError::NotAllowed`] ("ask the owner") becomes
    /// [`HeapError::NotReady`] while an offer's answer admitted the device
    /// ([`crate::Node::note_joined`]) and the fold does not list its person yet:
    /// the entry that does is on its way. Only a device that really is no
    /// member is told to ask the owner. Any other error is returned as it is.
    fn awaiting_listing(&self, node: &NodeInner, log: &Log, refused: HeapError) -> HeapError {
        if matches!(refused, HeapError::NotAllowed { .. }) && node.joining(log) {
            return HeapError::NotReady {
                name: self.name.clone(),
                why: LISTING_AWAITED.into(),
            };
        }
        refused
    }

    /// A writer that is no reader of a sealed space cannot seal in it: told
    /// as it is, not as a wait that never ends, unless the owner's logs have a
    /// hole below an entry held ([`Log::owner_whole`]): the audience is then
    /// only partly known, and the refusal waits for the hole.
    fn may_seal(&self, log: &Log) -> Result<(), HeapError> {
        let (fold, person) = (&log.fold, &log.person);
        if log.sealed() && fold.is_writer(person) && !fold.is_reader(person) {
            log.owner_whole()?;
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
    /// wait when the keys of the closed entries are to be granted to this
    /// device ([`Log::awaits_keys`]; the key comes by the grant pull), else
    /// [`HeapError::Sealed`].
    fn sealed_error(&self, log: &Log) -> HeapError {
        if log.awaits_keys() {
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

    /// Tell the watchers, once per entry, that `why` refused the packet
    /// `data`: the judge's refusals and the mark on its key, which the log
    /// alerts nothing of. A transient bad signature, a cut (the log alerts
    /// it) and the rest are not told here.
    pub(crate) fn alert_refused_packet(&self, data: &Data, why: &Refusal) {
        let name: &Name = &data.name;
        let told_here = matches!(
            why,
            Refusal::Lapsed { .. } | Refusal::Untrusted { .. } | Refusal::Suspected { .. }
        );
        let Some(entry) = parse_log_name(name).filter(|_| told_here) else {
            return;
        };
        let alert = Alert::Refused {
            id: EntryId {
                device: entry.device,
                seq: entry.seq,
                digest: signed_digest_of(data),
            },
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

    /// The reader check of `get` and `watch`: a sealed space shows nothing
    /// to a person outside its audience.
    fn check_reader(&self, log: &Log) -> Result<(), HeapError> {
        if log.sealed() && !log.fold.is_reader(&log.person) {
            return Err(HeapError::Sealed {
                space: self.name.clone(),
            });
        }
        Ok(())
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
        let key = (self.log.lock().entry_key(&blob.id))
            .ok_or_else(|| HeapError::Unavailable { name: name.clone() })?;
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
                other => HeapError::local(other),
            }
        })?;
        match key {
            None => Ok(Bytes::from(stored)),
            Some(key) => seal::open_payload(&key, &name, &stored)
                .map(Bytes::from)
                .ok_or_else(|| {
                    HeapError::local(format!(
                        "the sealed value of {name} does not open under its epoch key"
                    ))
                }),
        }
    }

    /// The change that puts the value of `blob`, if it is still the head of
    /// its path and whole: read now, by the watcher that reaches it.
    fn blob_change(&self, node: &NodeInner, blob: &Blob) -> Option<Change> {
        let bytes = self.read_blob(node, blob).ok()?;
        let log = self.log.lock();
        let head = log.register.values().find(|h| h.entry == blob.id)?;
        Some(Change::Put(head.item(bytes)))
    }

    /// Tell every watcher a blob head that is whole: the queues hold the
    /// reference and each watcher reads the value when it gets to it. Nothing
    /// is told for a head that something newer superseded.
    fn tell_blob(&self, blob: &Blob) {
        let current = self
            .log
            .lock()
            .register
            .values()
            .any(|h| h.entry == blob.id);
        if !current {
            return;
        }
        let mut watchers = self.watchers.lock();
        watchers.retain(|q| !q.is_closed());
        for q in watchers.iter() {
            q.put(Slot::Blob(blob.clone()));
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
            log.register.values().map(|h| h.entry.clone()).collect()
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
                    .and_then(|e| log.keys.key(&inner.name, e).cloned());
                (log.next_seq(), epoch, key)
            };
            let name = log_name(self.node.device(), &inner.name, seq);
            let carried = match &key {
                None => bytes.clone(),
                Some(key) => seal::seal_payload(key, &name, &bytes),
            };
            let cut = pieces::split(&name, &carried).map_err(HeapError::local)?;
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
    pub async fn kept(&self, path: &Name) -> Result<Option<Item>, HeapError> {
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
        match log.register.value(path) {
            Some(head) if head.entry == blob.id => Ok(Some(head.item(bytes))),
            _ => log.get(path),
        }
    }

    /// Watch the space: first every head held now that `since` does not
    /// already cover, then the changes as they happen.
    pub async fn watch(&self, since: &Frontier) -> Result<Changes, HeapError> {
        let inner = &self.inner;
        let (listed, queue) = {
            let log = inner.log.lock();
            inner.check_reader(&log)?;
            let (items, blobs) = log.items();
            // A value in pieces is a reference here: it is read from the
            // store when the watch reaches it, and skipped then if its
            // pieces are not all held (it is told when its last is).
            let heads = (items.into_iter())
                .filter(|item| item.id.seq > since.get(&item.id.device))
                .map(|item| Slot::Change(Change::Put(item)));
            let blobs = (blobs.into_iter())
                .filter(|blob| blob.id.seq > since.get(&blob.id.device))
                .map(Slot::Blob);
            let listed: VecDeque<Slot> = {
                let (standing, refused) = (inner.standing.lock(), inner.refused.lock());
                let alerts = (standing.iter())
                    .chain(refused.iter().map(|(_, alert)| alert))
                    .map(|alert| Slot::Change(Change::Alert(alert.clone())));
                heads.chain(blobs).chain(alerts).collect()
            };
            let queue = Queue::new(self.node.config.watch_queue);
            inner.watchers.lock().push(Arc::clone(&queue));
            (listed, queue)
        };
        if let Some(why) = self.node.flusher.failure() {
            queue.push(Change::Alert(Alert::StoreFailed {
                why: why.to_string(),
            }));
        }
        Ok(Changes {
            listed,
            queue,
            space: Arc::clone(&self.inner),
            node: Arc::clone(&self.node),
        })
    }

    /// Who the space lists, the owner first.
    pub fn members(&self) -> Members {
        self.inner.log.lock().members()
    }

    /// Whether this node has seen the space's creation: until then [`Self::members`] lists only the
    /// owner (named by the space), and whether the space is public is not known.
    pub fn members_known(&self) -> bool {
        self.inner.log.lock().fold.create().is_some()
    }

    /// Whether this device is an owner device of the space: its name is under the owner's, its
    /// key is vouched for as the owner's person and its role is `admin` or `member` (a guest or
    /// node device of the owner is none), the standing [`Self::change`] needs. `Err` is the
    /// [`HeapError::NotOwner`] a `change` would answer, with its next step: use a device of the
    /// owner that is one. A host that hands out something only an owner device can make good
    /// (an offer) asks first, so it never shows what cannot be used.
    pub fn owner_device(&self) -> Result<(), HeapError> {
        self.inner.log.lock().owner_only()
    }

    /// Whether the run before this node opened the space left it without a clean close (a stop
    /// the node did not make, or an image copied while it ran): a fixed fact of this open, which
    /// a restored old copy of the store can also show. A host that keeps its own notes beside
    /// the space reads it as: those notes may be older than what peers hold of this device.
    pub fn started_unclean(&self) -> bool {
        self.inner.log.lock().unclean()
    }

    /// Whether this node raised [`Alert::RolledBack`] for the space and keeps it standing: an
    /// entry under this device's own name lies above what it reserved, so the store here is an
    /// old image or a copy of it. A host that keeps its own notes beside the space reads it as:
    /// those notes may be older than what peers hold of this device.
    pub fn rolled_back(&self) -> bool {
        self.inner
            .standing
            .lock()
            .iter()
            .any(|alert| matches!(alert, Alert::RolledBack { .. }))
    }

    /// How many times this node has raised [`Alert::RolledBack`] for the space since it was
    /// opened. It only grows and counts every alert, also those the standing list behind
    /// [`Self::rolled_back`] no longer holds (it keeps `STANDING_MAX` distinct ones). A
    /// host that acted on a rollback compares it with the count it acted on: a later rollback
    /// is a new reason to distrust the notes it wrote since, which a standing flag cannot say.
    pub fn rollbacks(&self) -> u64 {
        self.inner.rollbacks.load(Ordering::Acquire)
    }

    /// The epoch writers seal in, as this node's fold holds it: its id (the owner device that
    /// signed the Epoch entry, and its seq) and whether it is for exactly the readers. `None` for
    /// a public space, or while no epoch is in force.
    pub fn epoch(&self) -> Option<(crate::wire::EpochId, bool)> {
        let log = self.inner.log.lock();
        let epoch = log.fold.in_force()?;
        let complete = log.fold.complete();
        Some((epoch, complete))
    }

    /// Whether a put of this node seals now instead of answering [`HeapError::NotReady`] while
    /// the key of the epoch in force is asked for (§6.5): it holds that key, or the space is
    /// public and needs none. `false` while the space's creation is not seen and, in a sealed
    /// space, while no epoch is in force.
    pub fn holds_epoch_key(&self) -> bool {
        let log = self.inner.log.lock();
        match log.fold.create() {
            None => false,
            Some(true) => true,
            Some(false) => log
                .fold
                .in_force()
                .is_some_and(|epoch| log.keys.key(&self.inner.name, &epoch).is_some()),
        }
    }

    /// Whether this node has applied the entry `id`: it holds exactly those
    /// signed bytes (the id's digest is the signed-region digest), verified
    /// and chained to its writer's log, and admitted it: the writer's person
    /// was a member, inside the cut if removed. An entry refused (not a
    /// member, outside a cut, a plain write in a sealed space, ...),
    /// waiting for the cut of a removed writer, held closed for want of its
    /// epoch's key, unreadable, withdrawn since, never held, or held as
    /// other bytes is not applied. Every applied entry counts, one a later
    /// write has superseded too, which [`get`](Self::get) no longer shows. It
    /// reads what is held under the space's lock and never waits for the
    /// network.
    pub fn applied(&self, id: &EntryId) -> bool {
        self.inner.log.lock().applied(id)
    }

    /// Whether the first catch-up is done: the space's creation is seen and
    /// everything heard of is held.
    pub fn ready(&self) -> bool {
        let log = self.inner.log.lock();
        log.fold.create().is_some() && log.missing().is_empty()
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
            let fold = &log.fold;
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
                // What already stands is what stands once the removals are made.
                |who, role| {
                    let removed = c.remove.contains(who) && who != fold.owner();
                    !removed
                        && match role {
                            Role::Writer => fold.is_writer(who),
                            Role::Reader => fold.is_reader(who),
                        }
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
