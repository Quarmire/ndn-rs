//! One space's log: own writes, admission, chain, equivocation, cuts (spec
//! §3, §4, §9).
//!
//! [`Log`] is the sans-IO state of ONE space on one device. The node keeps it
//! behind one `parking_lot::Mutex` per space and never holds that lock across
//! an `.await`. Every method is synchronous and does no network: the node
//! validates first (`trust::Judge`, async) and hands the log the
//! [`Verified`] it got; what the log wants fetched it returns as [`Want`]s.
//!
//! **One write, one batch.** A method that stores opens a [`Stage`] batch
//! around everything it writes (the entry at its own name, its `verified/`
//! marker, `ledger/`, `status/`, `head/`, `heads/`, `supers/`, `structural/`,
//! `epoch/`, `kept/`) and the batch reaches the store as ONE
//! `DataStore::apply` before the method returns. So the log's [`Effects`]
//! carry no store ops: they are already written; the node takes its flush
//! ticket after the call (`Flusher::note_write`) and routes
//! [`Effects::publish`] through the in-order publisher.
//!
//! **What the log holds.** O(devices + ranges + removed devices + heads): per
//! device its person, the held seqs and declared voids as ranges, the highest
//! seq heard, the chain tip; per removed device the ancestry its cut keeps.
//! No entry and no marker is resident: a marker is read when a decision needs
//! it, so a cold open of 100,000 entries reads one `ledger/` record per
//! device. An entry's state is its `status/` record (absent = applied).
//!
//! 1. **Open** ([`Log::open`]): `reserve/`, `head/`; the own head from the
//!    own device's `ledger/` record ([`Log::stored_head`]: it lists every
//!    stored own entry, decoding or not, and is one read); `structural/`
//!    replay rebuilds the [`Fold`]; `epoch/` keys into [`Keys`]; `heads/`
//!    into the [`Register`]; `ledger/` and `kept/`; `suspected/`.
//! 2. **Own write** ([`Log::put`], [`Log::sign_members`], [`Log::sign_epoch`],
//!    plan "Own put"): the seq is the next above the head, gated by
//!    [`Reservation::sign_gate`] (the node waits for [`Step::Wait`] outside
//!    the lock and calls again); `PREV` is the stored tip, with `PREV_SEQ`
//!    (the signed gap statement, [`Alert::GapSigned`]) when seqs lie between
//!    it and this entry, the zero digest with `PREV_SEQ 0` when nothing is
//!    held; sealed under the epoch in force when the space is not public;
//!    signed; stored and applied; the seq to publish and whether it is
//!    structural come back in [`Effects::publish`]. An Epoch's key is stored
//!    in the batch of its entry.
//! 3. **Admission** ([`Log::admit`], the eight steps of plan 3.5 in order):
//!    name and device; the judged [`Verified`]; the carrier rule (Members and
//!    Epoch only from an owner device); membership of the signer's PERSON
//!    (a writer, or removed and inside the cut); sealed bodies open under the
//!    epoch key, else the entry is held closed; the chain (the entry at
//!    `PREV_SEQ` must have the digest `PREV` names, else both are kept,
//!    [`Alert::Equivocation`], the key suspected); an own-name entry above
//!    `R_durable` is rollback evidence (stored, not applied); apply. An
//!    entry that verifies but does not decode is recorded as refused for what
//!    it carries, so walks through it complete. Every digest is a
//!    signed-region digest: a relay's re-signed copy changes nothing.
//! 4. **Cuts as tips** ([`chain::Kept`]): for a removed person, per device,
//!    the seqs reachable from the cut's tip through `verified/` markers
//!    alone. An entry is kept iff its seq is reached AND its signed digest is
//!    the one the chain names; other bytes at a kept seq are refused. Links
//!    not held are [`Want`]s with the exact digest; what is not yet connected
//!    waits ([`Outcome::Waiting`]) and never counts.
//! 5. **Re-check** ([`Log::admit`] of a Members entry, [`Log::key_arrived`],
//!    [`Log::withdraw`]): the held entries of the persons whose standing
//!    changed are judged again from the store; an applied one now refused
//!    leaves the register (the entries it superseded return) and is reported
//!    as [`Change::Withdrawn`].
//! 6. **Catch-up** ([`Log::held_prefix`], [`Log::missing`], [`Log::high`]):
//!    the holes below the highest seq held are wanted; a counter heard wants
//!    nothing (unsigned), except this device's own within what it reserved;
//!    what is wanted never shrinks except by holding it.
//!
//! The node validates with the judge and calls these; this module is the
//! only writer of everything it keeps.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_security::confidentiality::ContentKey;
use ndn_security::{Signer, public_key_digest};
use ndn_sync::DataStore;

use crate::error::{Cut, HeapError, NextStep, Refusal, Timestamp};
use crate::fold::{Fold, Readers};
use crate::register::{EntryId, Item, Register};
use crate::reserve::{Flusher, Gate, Reservation, Ticket};
use crate::seal::{self, Keys};
use crate::store::{
    self, Corrupt, Link, Marker, Stage, epoch_prefix, heads_prefix, kept_prefix, ledger_key,
    ledger_prefix, parse_epoch_key, parse_kept_key, parse_ledger_key, parse_structural_key,
    parse_suspected_key, status_prefix, structural_prefix, suspected_prefix,
};
use crate::trust::Verified;
use crate::wire::{
    self, Body, Entry, EntryRef, EpochId, Payload, PutBody, log_name, parse_space_name,
    signed_digest,
};

mod admit;
mod chain;
mod own;
mod view;

#[cfg(test)]
mod tests;

use chain::{Dev, Kept, Status};
pub(crate) use own::pack_ops;
pub(crate) use view::Standing;
use view::View;

// -- Types the node and the API consume -----------------------------------------

/// How a space is run on this device: what [`Log::open`] needs of the node.
pub(crate) struct Params {
    /// The space, `<O>/32=data/…`.
    pub space: Name,
    /// This device.
    pub device: Name,
    /// This device's person: the namespace of the context that vouches for
    /// its key.
    pub person: Name,
    /// The device key; it must sign synchronously.
    pub signer: Arc<dyn Signer>,
    /// This device's keys (its recipient key; epoch keys are added as they
    /// are restored, made or granted).
    pub keys: Keys,
    /// `Config.reserve_block`.
    pub block: u64,
}

/// An entry the log wants fetched. `first..=last` of `device` when `digest`
/// is `None`; the one entry `first` with exactly these signed bytes when it
/// is set (a removal cut names it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Want {
    /// The device whose entries.
    pub device: Name,
    /// The first seq.
    pub first: u64,
    /// The last seq.
    pub last: u64,
    /// The signed-region digest the bytes must have, when a cut names it.
    pub digest: Option<[u8; 32]>,
}

/// An own entry to publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Publish {
    /// Its seq.
    pub seq: u64,
    /// Members and Epoch entries are published only after a flush covers
    /// them (spec §4).
    pub structural: bool,
}

/// A blob head whose payload the pieces layer assembles: the log has only
/// its size and root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Blob {
    /// The entry that wrote it.
    pub id: EntryId,
    /// Octets of the (sealed, if sealed) payload.
    pub size: u64,
    /// The manifest tree's root digest.
    pub root: [u8; 32],
}

/// What a call asks of the node beyond the writes it already made.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Effects {
    /// Public-API changes, in order.
    pub changes: Vec<Change>,
    /// Alerts for the host.
    pub alerts: Vec<Alert>,
    /// Entries to fetch.
    pub wants: Vec<Want>,
    /// An own entry to publish.
    pub publish: Option<Publish>,
    /// Blob heads to assemble.
    pub blobs: Vec<Blob>,
    /// Keys newly suspected (already recorded here); the host may act.
    pub suspect: Vec<Name>,
    /// The members changed: tell the judge (`Judge::note`) what the space
    /// lists now.
    pub membership: bool,
}

/// What came of one entry offered to [`Log::admit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Taken and applied.
    Applied,
    /// Taken and held closed: sealed in an epoch whose key is not held.
    Closed,
    /// Taken, not applied: its writer was removed and the cut's chain is not
    /// whole yet.
    Waiting,
    /// Already held (another copy of the same signed bytes).
    Duplicate,
    /// Evidence, not applied: a second packet at one name.
    Evidence,
    /// It verifies and does not decode: recorded, never fetched again.
    Unreadable,
    /// Refused, with why (and `why.next()` for what to do).
    Refused(Refusal),
}

/// [`Log::admit`]'s answer.
#[derive(Debug)]
pub(crate) struct Admitted {
    /// What became of the entry.
    pub outcome: Outcome,
    /// What follows from it.
    pub effects: Effects,
}

/// The step an own write is at.
#[derive(Debug)]
pub(crate) enum Step<T> {
    /// Done.
    Done(T),
    /// The reservation covering the seq is written and not yet durable: wait
    /// for the ticket outside the lock (`Flusher::wait_durable`), then call
    /// again.
    Wait(Ticket),
}

/// An own entry signed, stored and applied.
#[derive(Debug)]
pub(crate) struct Signed {
    /// The entry.
    pub id: EntryId,
    /// What follows from it (`publish` is set).
    pub effects: Effects,
}

/// A change of a space, as `watch` yields it.
#[derive(Clone, Debug, PartialEq)]
pub enum Change {
    /// A path has a new value.
    Put(Item),
    /// A path was removed (its value is empty).
    Removed(Item),
    /// An applied entry was refused after the fact; what it superseded
    /// returns.
    Withdrawn {
        /// The entry.
        id: EntryId,
        /// Why.
        why: Refusal,
    },
    /// The members changed.
    Members(Members),
    /// Something the host should know.
    Alert(Alert),
    /// The watcher was too slow: this many changes were dropped.
    Lagged {
        /// How many.
        missed: u64,
    },
}

/// What the host should know of a space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Alert {
    /// A device signed two packets at one name.
    Equivocation {
        /// The device.
        device: Name,
        /// The seq.
        seq: u64,
    },
    /// An entry was refused as outside a removal cut.
    OutsideCut {
        /// The entry.
        id: EntryId,
    },
    /// An entry was refused.
    Refused {
        /// The entry.
        id: EntryId,
        /// Why.
        why: Refusal,
        /// What to do.
        next: NextStep,
    },
    /// An entry under this device's own name above its durable reservation:
    /// a key copy or a restored old image.
    RolledBack {
        /// The highest seq this device reserved durably.
        reserved: u64,
        /// The seq seen.
        seen: u64,
    },
    /// The first entry after an unclean start states the gap it skipped.
    GapSigned {
        /// The seq it chains to (0: nothing held).
        after: u64,
        /// Its own seq.
        resumed: u64,
    },
    /// A peer's counter names an own entry no fetched entry backs.
    UnbackedCounter {
        /// The device.
        device: Name,
        /// The counter heard.
        seen: u64,
    },
    /// The store failed to make writes durable.
    StoreFailed {
        /// The disk's reason.
        why: String,
    },
}

/// Who a space lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Members {
    /// The owner.
    pub owner: Name,
    /// The writers, the owner first.
    pub writers: Vec<Name>,
    /// The readers.
    pub readers: Readers,
}

/// A device → seq map: how far a watcher has seen each device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frontier(BTreeMap<Name, u64>);

impl Frontier {
    /// The empty frontier: nothing seen.
    pub fn new() -> Frontier {
        Frontier::default()
    }

    /// The seq seen of `device`, 0 for none.
    pub fn get(&self, device: &Name) -> u64 {
        self.0.get(device).copied().unwrap_or(0)
    }

    /// Say `device` was seen up to `seq`.
    pub fn set(&mut self, device: Name, seq: u64) {
        self.0.insert(device, seq);
    }
}

// -- The log ---------------------------------------------------------------------

/// What a re-check judges again.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Scope {
    /// Every held entry of these persons' devices.
    Persons(BTreeSet<Name>),
    /// Every held entry of every device (the space's creation decides what
    /// sealed means for all).
    All,
    /// The entries held closed.
    Closed,
    /// The entries of this device waiting for a cut's chain.
    Waiting(Name),
}

/// The membership as it decides admission, to see what a Members entry
/// changed.
#[derive(Clone, Debug, PartialEq)]
struct FoldView {
    writers: Vec<Name>,
    removed: Vec<(Name, Vec<EntryRef>)>,
    create: Option<bool>,
    readers: Readers,
    /// What decides whether the owner's devices owe an Epoch entry.
    in_force: Option<EpochId>,
    complete: bool,
}

/// One space on one device.
pub(crate) struct Log {
    space: Name,
    device: Name,
    person: Name,
    /// This device's key name and the digest of its public key.
    key: Name,
    key_digest: [u8; 32],
    signer: Arc<dyn Signer>,
    store: Arc<Stage>,
    fold: Fold,
    register: Register,
    keys: Keys,
    reservation: Arc<Reservation>,
    /// The seq the next own entry takes.
    next_seq: u64,
    /// The highest seq under this device's name in the store, whatever it is.
    own_head: u64,
    /// The durable `R` the previous run left (read before this run's
    /// extension): the highest seq an earlier run could have signed.
    floor_r: u64,
    /// The highest counter heard of this device's own name: unsigned, so
    /// believed only as far as `floor_r` ([`Self::high`]).
    own_heard: u64,
    /// The entry the next own entry chains to: the newest own entry applied.
    own_tip: Option<Link>,
    devices: BTreeMap<Name, Dev>,
    /// What each removed device's cut keeps.
    kept: BTreeMap<Name, Kept>,
    suspected: BTreeMap<Name, Timestamp>,
    /// Entries held closed.
    closed: u64,
    /// Re-checks owed.
    queue: Vec<Scope>,
}

impl Log {
    /// Open the space from the store (see the module docs, item 1).
    pub(crate) fn open(
        params: Params,
        raw: Arc<dyn DataStore>,
        stage: Arc<Stage>,
        flusher: Arc<Flusher>,
    ) -> Result<Log, HeapError> {
        let Params {
            space,
            device,
            person,
            signer,
            keys,
            block,
        } = params;
        let owner = parse_space_name(&space)
            .ok_or_else(|| HeapError::BadName {
                name: space.clone(),
                why: "a space is `<owner>/32=data/<name>`".into(),
            })?
            .owner;
        let local = |why: String| HeapError::Local { reason: why };
        let head = Self::stored_head(&*stage, &space, &device)?;
        let floor_r = store::read_reserve(&*stage, &space)
            .map_err(|e| local(e.to_string()))?
            .map_or(0, |r| r.r);
        let opened = Reservation::open(raw, flusher, &space, block, head)
            .map_err(|e| local(e.to_string()))?;
        let key_digest = signer
            .public_key()
            .map(|k| public_key_digest(&k))
            .ok_or_else(|| {
                local(format!(
                    "the device key {} has no public key",
                    signer.key_name()
                ))
            })?;
        let mut log = Log {
            key: signer.key_name().clone(),
            key_digest,
            fold: Fold::new(owner),
            register: Register::new(space.clone()),
            reservation: Arc::new(opened.reservation),
            next_seq: opened.resume.first_seq,
            own_head: head,
            floor_r,
            own_heard: 0,
            own_tip: None,
            devices: BTreeMap::new(),
            kept: BTreeMap::new(),
            suspected: BTreeMap::new(),
            closed: 0,
            queue: Vec::new(),
            space,
            device,
            person,
            signer,
            store: stage,
            keys,
        };
        log.restore_devices();
        log.replay_structural();
        log.restore_keys();
        log.restore_register()?;
        log.restore_cuts();
        log.restore_suspected();
        log.restore_own_tip(head);
        Ok(log)
    }

    /// The seen-so-far of every device from `ledger/`: one record each; no
    /// marker but the one at each device's highest seq.
    fn restore_devices(&mut self) {
        for (key, record) in self.store.scan_under(&ledger_prefix(&self.space), 0) {
            let Some(device) = parse_ledger_key(&self.space, &key) else {
                continue;
            };
            let Some(mut dev) = Dev::from_record(&record) else {
                tracing::warn!(%key, "a ledger record that cannot be read is ignored; the entries are held and will be found again");
                continue;
            };
            dev.tip = dev.held.max().and_then(|seq| {
                self.view().marker(&device, seq).map(|m| Link {
                    seq,
                    digest: m.signed_digest,
                })
            });
            self.devices.insert(device, dev);
        }
        let (mut closed, mut counted) = (0, Vec::new());
        for (key, value) in self.store.scan_under(&status_prefix(&self.space), 0) {
            match value.first() {
                Some(1) => closed += 1,
                Some(_) => counted.extend(store::parse_status_key(&self.space, &key)),
                None => {}
            }
        }
        self.closed = closed;
        for (device, _) in counted {
            if let Some(dev) = self.devices.get_mut(&device) {
                dev.nonvouching += 1;
            }
        }
    }

    /// The Members and Epoch entries applied, from `structural/`.
    fn replay_structural(&mut self) {
        for (key, _) in self.store.scan_under(&structural_prefix(&self.space), 0) {
            let Some((device, seq)) = parse_structural_key(&self.space, &key) else {
                continue;
            };
            for wire in self.view().wires_at(&device, seq) {
                let Some((entry, digest)) = decode_wire(&wire) else {
                    tracing::warn!(%key, "a structural entry that cannot be read is skipped");
                    continue;
                };
                let id = EntryRef {
                    device: device.clone(),
                    seq,
                    digest,
                };
                match &entry.body {
                    Body::Members(body) => self.fold.apply_members(&id, body),
                    Body::Epoch(body) => self.fold.apply_epoch(
                        EpochId {
                            creator: device.clone(),
                            seq,
                        },
                        body,
                        &entry.after,
                    ),
                    _ => {}
                }
            }
        }
    }

    /// The epoch keys this device holds, from `epoch/` (each checked against
    /// the Epoch entry naming it).
    fn restore_keys(&mut self) {
        for (key, stored) in self.store.scan_under(&epoch_prefix(&self.space), 0) {
            let Some((creator, seq)) = parse_epoch_key(&self.space, &key) else {
                continue;
            };
            let epoch = EpochId { creator, seq };
            let Some(check) = self.fold.epoch_body(&epoch).map(|b| b.key_check) else {
                continue;
            };
            if !self.keys.restore(&self.space, &epoch, &check, stored) {
                tracing::warn!(%key, "a stored epoch key does not match its Epoch entry and is dropped");
            }
        }
    }

    fn restore_register(&mut self) -> Result<(), HeapError> {
        let records = self.store.scan_under(&heads_prefix(&self.space), 0);
        let view = View::of(self);
        let restored = Register::restore(self.space.clone(), records, &|r| view.write_of(r))
            .map_err(|e| HeapError::Local {
                reason: e.to_string(),
            })?;
        for lost in &restored.missing {
            tracing::warn!(entry = %lost.name(&self.space), "a head the store names is not held and applied; it returns when the entry does");
        }
        self.register = restored.register;
        Ok(())
    }

    /// The cuts of removed devices: the records agree with the fold or are
    /// computed again.
    fn restore_cuts(&mut self) {
        for (key, record) in self.store.scan_under(&kept_prefix(&self.space), 0) {
            if let (Some(device), Some(kept)) = (
                parse_kept_key(&self.space, &key),
                Kept::from_record(&record),
            ) {
                self.kept.insert(device, kept);
            }
        }
        let mut fx = Effects::default();
        let batch = Arc::clone(&self.store);
        let _batch = batch.batch();
        self.sync_kept(&mut fx);
    }

    fn restore_suspected(&mut self) {
        for (key, since) in self.store.scan_under(&suspected_prefix(), 0) {
            if let Some(name) = parse_suspected_key(&key) {
                let since = since.as_ref().try_into().map_or(0, u64::from_be_bytes);
                self.suspected.insert(name, Timestamp(since));
            }
        }
    }

    /// The own tip: the newest own entry held.
    fn restore_own_tip(&mut self, head: u64) {
        if let Some(marker) = (head > 0)
            .then(|| self.view().marker(&self.device, head))
            .flatten()
        {
            self.own_tip = Some(Link {
                seq: head,
                digest: marker.signed_digest,
            });
        }
    }

    /// The highest own seq the store holds in `space`, from the own
    /// device's `ledger/` record, which lists every own entry stored (it is
    /// written in the batch that stores the entry, whether the entry decodes
    /// or not): one read, where listing the entries would read every own
    /// entry and piece. A record that cannot be read is an error: a device
    /// that cannot tell what it signed could sign a seq a peer saw again.
    fn stored_head(store: &dyn DataStore, space: &Name, device: &Name) -> Result<u64, HeapError> {
        let key = ledger_key(space, device);
        let Some(record) = store.get(&key) else {
            return Ok(0);
        };
        let dev = Dev::from_record(&record).ok_or_else(|| HeapError::Local {
            reason: Corrupt {
                key,
                what: "ledger record",
            }
            .to_string(),
        })?;
        Ok(dev.high)
    }

    // -- Reads --------------------------------------------------------------------

    fn view(&self) -> View<'_> {
        View::of(self)
    }

    /// The space.
    pub(crate) fn space(&self) -> &Name {
        &self.space
    }

    /// This device.
    pub(crate) fn device(&self) -> &Name {
        &self.device
    }

    /// The membership fold.
    pub(crate) fn fold(&self) -> &Fold {
        &self.fold
    }

    /// The register of heads.
    pub(crate) fn register(&self) -> &Register {
        &self.register
    }

    /// This device's keys.
    pub(crate) fn keys(&self) -> &Keys {
        &self.keys
    }

    /// This device's reservation.
    pub(crate) fn reservation(&self) -> &Arc<Reservation> {
        &self.reservation
    }

    /// The highest seq under this device's name in the store, 0 for none.
    pub(crate) fn head(&self) -> u64 {
        self.own_head
    }

    /// The seq the next own entry takes.
    pub(crate) fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Who the space lists.
    pub(crate) fn members(&self) -> Members {
        Members {
            owner: self.fold.owner().clone(),
            writers: self.fold.writers(),
            readers: self.fold.readers(),
        }
    }

    /// Whether any entry is held closed (its epoch key is not held).
    pub(crate) fn has_closed(&self) -> bool {
        self.closed > 0
    }

    /// Whether the space seals (its creation said readers are not everybody).
    pub(crate) fn sealed(&self) -> bool {
        self.fold.create() == Some(false)
    }

    /// The value at `path`. `Err(Sealed)` while any entry is held closed in
    /// a sealed space (a closed entry's path is unknown); a blob head is
    /// `Err(Unavailable)` here: the pieces layer assembles it.
    pub(crate) fn get(&self, path: &Name) -> Result<Option<Item>, HeapError> {
        if self.sealed() && self.has_closed() {
            return Err(HeapError::Sealed {
                space: self.space.clone(),
            });
        }
        let Some(head) = self.register.value(path) else {
            return Ok(None);
        };
        match self.view().payload_of(&head.entry) {
            Some(Payload::Inline(bytes)) => Ok(Some(head.item(path, bytes))),
            _ => Err(HeapError::Unavailable {
                name: head.entry.name(&self.space),
            }),
        }
    }

    /// Every path's current value that is inline, for a watcher's first
    /// listing, and the blob heads the pieces layer must assemble.
    pub(crate) fn items(&self) -> (Vec<Item>, Vec<Blob>) {
        let view = self.view();
        let (mut items, mut blobs) = (Vec::new(), Vec::new());
        for (path, head) in self.register.values() {
            match view.payload_of(&head.entry) {
                Some(Payload::Inline(bytes)) => items.push(head.item(path, bytes)),
                Some(Payload::Blob { size, root }) => blobs.push(Blob {
                    id: EntryId::from(&head.entry),
                    size,
                    root,
                }),
                None => {}
            }
        }
        (items, blobs)
    }

    /// The entries of the winning heads that are not in `seen`: references
    /// only, nothing is read from the store (what each carries is
    /// [`Self::payload_kinds`], read in batches by the caller).
    pub(crate) fn unsettled_heads(
        &self,
        seen: &std::collections::HashSet<EntryId>,
    ) -> Vec<EntryId> {
        self.register
            .values()
            .map(|(_, head)| EntryId::from(&head.entry))
            .filter(|id| !seen.contains(id))
            .collect()
    }

    /// What each of the entries `heads` carries, in order: `Some(None)` an
    /// inline value, `Some(Some(blob))` a value in pieces, `None` when the
    /// entry is not readable now (not held, or not applied).
    pub(crate) fn payload_kinds(&self, heads: &[EntryId]) -> Vec<Option<Option<Blob>>> {
        let view = self.view();
        heads
            .iter()
            .map(|id| {
                view.payload_of(&EntryRef::from(id))
                    .map(|payload| match payload {
                        Payload::Inline(_) => None,
                        Payload::Blob { size, root } => Some(Blob {
                            id: id.clone(),
                            size,
                            root,
                        }),
                    })
            })
            .collect()
    }

    /// The winning head of `path` when its payload is a blob (assembled by
    /// the pieces layer); `None` for an inline value, a removal or no head.
    pub(crate) fn blob_head(&self, path: &Name) -> Option<Blob> {
        let head = self.register.value(path)?;
        match self.view().payload_of(&head.entry)? {
            Payload::Blob { size, root } => Some(Blob {
                id: EntryId::from(&head.entry),
                size,
                root,
            }),
            Payload::Inline(_) => None,
        }
    }

    /// The epoch key the applied entry was sealed under: `Some(None)` for a
    /// plain write (public space), `Some(Some(key))` for a sealed one whose
    /// key is held; `None` when the entry is not held, not applied, not a
    /// write, or its key is missing.
    pub(crate) fn entry_key(&self, id: &EntryId) -> Option<Option<ContentKey>> {
        let id = EntryRef::from(id);
        let view = self.view();
        let wire = view.wire_at(&id.device, id.seq)?;
        if signed_digest(&wire) != id.digest || view.status(&id.device, id.seq).is_some() {
            return None;
        }
        match decode_wire(&wire)?.0.body {
            Body::Put(_) => Some(None),
            Body::Sealed(sealed) => self
                .keys
                .key(&self.space, &sealed.epoch)
                .map(|key| Some(key.clone())),
            Body::Members(_) | Body::Epoch(_) => None,
        }
    }

    /// The entry's packet, for serving: held, verified and not refused.
    pub(crate) fn served(&self, device: &Name, seq: u64) -> Option<Bytes> {
        let view = self.view();
        view.marker(device, seq)?;
        match view.status(device, seq) {
            None | Some(Status::Closed) => view.wire_at(device, seq),
            Some(_) => None,
        }
    }

    /// The names of every entry held of the devices of `person`: what a
    /// change of trust re-validates (loaded on demand).
    pub(crate) fn held_names(&self, person: &Name) -> Vec<Name> {
        self.devices
            .iter()
            .filter(|(_, d)| d.person == *person)
            .flat_map(|(device, d)| {
                d.held
                    .seqs()
                    .map(|seq| log_name(device, &self.space, seq))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// When `key` was suspected.
    pub(crate) fn suspected(&self, key: &Name) -> Option<Timestamp> {
        self.suspected.get(key).copied()
    }

    /// Mark `key` suspected from `since`: no new entry of it is taken.
    pub(crate) fn suspect(&mut self, key: &Name, since: Timestamp) {
        self.suspected.insert(key.clone(), since);
        self.store.insert(
            store::suspected_key(key),
            Bytes::copy_from_slice(&since.0.to_be_bytes()),
        );
    }

    /// Clear the mark. Whether there was one.
    pub(crate) fn unsuspect(&mut self, key: &Name) -> bool {
        let was = self.suspected.remove(key).is_some();
        if was {
            self.store.remove(&store::suspected_key(key));
        }
        was
    }

    // -- Catch-up -----------------------------------------------------------------

    /// Whether an admitted entry of `device` is held: one applied, or held
    /// closed for want of its epoch key. Refused, unreadable, waiting and
    /// evidence entries do not count: a stranger whose entries were all
    /// refused is not vouched for. From counts, no entry or marker is read.
    pub(crate) fn vouches(&self, device: &Name) -> bool {
        self.devices
            .get(device)
            .is_some_and(|d| d.held.count() > d.nonvouching)
    }

    /// Whether a device other than this one is vouched for: an admitted
    /// entry of it is held. What the group's unsigned vector says of who is
    /// there decides nothing.
    pub(crate) fn has_peers(&self) -> bool {
        self.devices
            .keys()
            .any(|device| *device != self.device && self.vouches(device))
    }

    /// The highest seq of `device` that is asked for without a probe: the
    /// highest seq held of it, and for this device also the counter heard of
    /// it as far as an earlier run could have signed (`R`, read at open). A
    /// counter is unsigned, so it is believed no further; what lies above is
    /// probed once, alone, and becomes a want only when the entry named
    /// there is held and verified.
    pub(crate) fn high(&self, device: &Name) -> u64 {
        let held = self.devices.get(device).map_or(0, |d| d.high);
        if *device == self.device {
            held.max(self.own_heard.min(self.floor_r))
        } else {
            held
        }
    }

    /// A counter heard of this device's own name (peers hold entries this
    /// device lost). Above what it holds it is [`Alert::UnbackedCounter`]:
    /// the head stays where fetched, verified entries put it (D17).
    pub(crate) fn note_own_counter(&mut self, seen: u64) -> Effects {
        self.own_heard = self.own_heard.max(seen);
        self.devices
            .entry(self.device.clone())
            .or_insert_with(|| Dev::new(self.person.clone()));
        let mut fx = Effects::default();
        if seen > self.own_head {
            fx.alerts.push(Alert::UnbackedCounter {
                device: self.device.clone(),
                seen,
            });
        }
        fx
    }

    /// The largest `n` such that every seq of `1..=n` of `device` is held or
    /// declared void.
    pub(crate) fn held_prefix(&self, device: &Name) -> u64 {
        self.devices
            .get(device)
            .map_or(0, |d| d.held.prefix_with(&d.voids))
    }

    /// Everything wanted: the holes below the highest seq held of each device
    /// it walks ([`Self::high`]), and the exact entries a removal cut names
    /// that are not held. A device is walked once an admitted entry of it is
    /// held (it vouches), or when it is this device or a removed one: a
    /// stranger's refused entry opens no walk below itself. A counter heard
    /// wants nothing here; the fetch probes the entry it names
    /// ([`Self::high`]). The node windows what it asks at a time.
    pub(crate) fn missing(&self) -> Vec<Want> {
        let mut out = Vec::new();
        for (device, dev) in &self.devices {
            let walked = *device == self.device
                || dev.held.count() > dev.nonvouching
                || self.kept.contains_key(device);
            if !walked {
                continue;
            }
            for (first, last) in dev.held.gaps(self.high(device), &dev.voids) {
                out.push(Want {
                    device: device.clone(),
                    first,
                    last,
                    digest: None,
                });
            }
        }
        for (device, kept) in &self.kept {
            out.extend(frontier_wants(device, kept));
        }
        out
    }

    // -- Keys ---------------------------------------------------------------------

    /// A key for `epoch` arrived (a grant). Held only if it matches the check
    /// of a held owner-signed Epoch entry; the entries held closed under it
    /// open. Whether it was taken.
    pub(crate) fn key_arrived(&mut self, epoch: EpochId, key: ContentKey) -> (bool, Effects) {
        let mut fx = Effects::default();
        let stage = Arc::clone(&self.store);
        let _batch = stage.batch();
        if !self.keys.take_named(&self.fold, &self.space, &epoch, key) {
            return (false, fx);
        }
        if let Some(Ok((name, stored))) = self.keys.record(&self.space, &epoch) {
            self.store.insert(name, stored);
        }
        self.queue.push(Scope::Closed);
        self.settle(&mut fx);
        (true, fx)
    }
}

/// The exact wants of a cut's frontier.
fn frontier_wants(device: &Name, kept: &Kept) -> Vec<Want> {
    kept.frontier
        .iter()
        .map(|f| Want {
            device: device.clone(),
            first: f.seq,
            last: f.seq,
            digest: Some(f.digest),
        })
        .collect()
}

/// An entry and its signed digest from a stored packet.
fn decode_wire(wire: &Bytes) -> Option<(Entry, [u8; 32])> {
    let data = Data::decode(wire.clone()).ok()?;
    let entry = Entry::decode(data.content()?).ok()?;
    Some((entry, signed_digest(wire)))
}
