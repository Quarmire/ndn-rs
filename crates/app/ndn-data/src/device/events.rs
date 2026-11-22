//! Device-wide events (spec §21): the book of what no folder owns, kept in the store under
//! `/localhost/ndn-data/events/`, and the verbs a host reads and acknowledges them with.
//!
//! An event reports what the layer already did fail-closed; nothing here decides acceptance.
//! The book is called with the `St` lock held, at the places the layer notes the cause
//! ([`Book::report`]), and writes the store directly (never published, never served).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use ndn_foundation_types::NameComponent;
use ndn_packet::{Data, Name};
use ndn_sync::{DataStore, StoreOp};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use super::{Clock, Device, Held, Inner, Line, St, held_signer, held_wire, local};
use crate::collection::Cut;
use crate::error::{DataError, Refusal};
use crate::events::{
    Cursor, DeviceEvent, DeviceEvents, EntryKind, EntryRef, EventDetail, EventId, EventKind,
    EventSubject, WithdrawnBy, decode_event, encode_event,
};
use crate::version::{VersionId, Writer};
use crate::wire::{self, Record, device_of};

impl St {
    /// Report one occurrence to the events book (spec §21). Nothing is reported while the store
    /// is read back at start: what it holds was reported when it arrived, and the events of
    /// that run are read back with it ([`Book::load`]).
    pub(super) fn report_event(&mut self, detail: EventDetail) {
        if !self.restoring {
            self.events.report(detail);
        }
    }

    /// Report that `wire`, a packet of `writer` of kind `record` under the log entry name `name`
    /// held already, is another thing than the packet held there: two packets of one key at one
    /// name, of any kinds, whose signed regions (name through `SignatureInfo`) differ (spec
    /// §21). The same packet again, a copy that differs only in its signature value, or one
    /// whose first packet this device holds no bytes of to compare, reports nothing.
    pub(super) fn report_twin(
        &mut self,
        name: &Name,
        writer: &Writer,
        record: &Record,
        wire: &Bytes,
    ) {
        let first = self.entry_ref(name);
        let (Some(held), Some(signed), Some(log)) = (
            self.held_signed(name),
            wire::signed_digest(wire),
            wire::parse_log_name(name),
        ) else {
            return;
        };
        if held == signed {
            return;
        }
        self.report_event(EventDetail::Equivocation {
            writer: writer.key().clone(),
            seq: log.seq,
            first,
            second: EntryRef {
                name: name.clone(),
                kind: Some(EntryKind::of(record)),
                digest: Some(wire::implicit_digest(wire)),
            },
        });
    }

    /// The digest of what the key signed in the entry held at `name` ([`wire::signed_digest`]),
    /// as far as this device holds it: of a members, hold, lease, prune or introduction record
    /// that it does not store too, which it noted when it took it.
    pub(super) fn held_signed(&self, name: &Name) -> Option<[u8; 32]> {
        match self.held.get(name)? {
            Held::Version(_) | Held::Locked | Held::Pruned(_) | Held::Expired(_) => {
                held_wire(self, name).and_then(|w| wire::signed_digest(&w))
            }
            Held::Snapshot(_) => self.store.get(name).and_then(|w| wire::signed_digest(&w)),
            Held::Record { signed, .. } => Some(*signed),
        }
    }

    /// Report that version `id` of `c`, delivered before, is refused now for `why` (what
    /// [`Change::Withdrawn`](crate::Change::Withdrawn) tells a watcher), whether or not anyone
    /// watches: a refusal a withdrawal does not say (it was never delivered) reports nothing.
    pub(super) fn report_withdrawn(&mut self, c: &Name, id: &VersionId, why: &Refusal) {
        let (Some(by), Some(device)) = (WithdrawnBy::of(why), device_of(id.writer.key())) else {
            return;
        };
        let name = wire::log_name(&device, Some(c), id.seq.0);
        let mut entry = self.entry_ref(&name);
        entry.kind = Some(EntryKind::Version);
        self.report_event(EventDetail::Withdrawal {
            writer: id.writer.key().clone(),
            collection: Some(c.clone()),
            entry,
            by,
        });
    }

    /// The held log entry `name` as evidence: its name, what it is and the digest of the packet
    /// this device verified, as far as it holds them (spec §21.2). Never its content.
    pub(super) fn entry_ref(&self, name: &Name) -> EntryRef {
        let digest_of = |w: Bytes| wire::implicit_digest(&w);
        let (kind, digest) = match self.held.get(name) {
            Some(Held::Version(_) | Held::Locked | Held::Pruned(_) | Held::Expired(_)) => (
                Some(EntryKind::Version),
                held_wire(self, name).map(digest_of),
            ),
            Some(Held::Snapshot(_)) => (
                Some(EntryKind::Snapshot),
                self.store.get(name).map(digest_of),
            ),
            Some(Held::Record { digest, .. }) => (
                self.store
                    .get(name)
                    .and_then(|w| Data::decode(w).ok())
                    .and_then(|d| wire::decode_record(d.content()?.clone()).ok())
                    .map(|r| EntryKind::of(&r)),
                Some(*digest),
            ),
            None => (None, None),
        };
        EntryRef {
            name: name.clone(),
            kind,
            digest,
        }
    }

    /// The events that the state this device holds implies, for [`Device::derive_events`]: the
    /// revocations of the trust contexts held, the cuts of the records in force that this device
    /// did not sign, and the withdrawal of each entry held and stored that a cut or its chain
    /// refuses (what was stored was delivered, so its withdrawal was told). In the order the live
    /// reports make them: revocations, cuts, withdrawals.
    pub(super) fn derived_events(&self, me: &Writer) -> Vec<EventDetail> {
        let mut out = Vec::new();
        let mut namespaces: Vec<&Name> = self.contexts.keys().collect();
        namespaces.sort();
        for ns in namespaces {
            let ctx = &self.contexts[ns];
            for revoked in ctx.revocations() {
                out.push(EventDetail::Revocation {
                    namespace: ns.clone(),
                    revoked: revoked.clone(),
                    version: ctx.version(),
                });
            }
        }
        let mut lines: Vec<(&Name, bool, &Line)> = self
            .colls
            .iter()
            .map(|(c, x)| (c, false, &x.line))
            .chain(self.folders.iter().map(|(f, x)| (f, true, &x.line)))
            .collect();
        lines.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        for (subject, folder, line) in lines {
            for cut in line.own.iter().flat_map(|own| &own.cuts) {
                out.extend(cut_event(line, subject, folder, cut, me, None));
            }
        }
        let mut refused: Vec<(&Name, &Refusal)> = self
            .refused
            .iter()
            .filter(|(_, why)| matches!(why, Refusal::OutsideCut(_) | Refusal::Untrusted { .. }))
            .collect();
        refused.sort_by(|a, b| a.0.cmp(b.0));
        for (name, why) in refused {
            let (Some(held), Some(by), Some(log)) = (
                self.held.get(name),
                WithdrawnBy::of(why),
                wire::parse_log_name(name),
            ) else {
                continue;
            };
            let Some(writer) = held_signer(self, name, held) else {
                continue;
            };
            if !self.store.contains(name) {
                continue;
            }
            out.push(EventDetail::Withdrawal {
                writer: writer.key().clone(),
                collection: log.subject,
                entry: self.entry_ref(name),
                by,
            });
        }
        out
    }
}

/// The `Cut` event of `cut`, a removal of the record in force of `subject` (`folder`: of a folder),
/// named after the held record of its signer that carries it first, or after `taken`, the seq and
/// revision of a record just taken. `None` for a cut this device signed (its host made the
/// gesture; another device of the owner reports it, spec §21.3) and for one no held record
/// carries.
pub(super) fn cut_event(
    line: &Line,
    subject: &Name,
    folder: bool,
    cut: &Cut,
    me: &Writer,
    taken: Option<(u64, u64)>,
) -> Option<EventDetail> {
    if cut.signer == *me {
        return None;
    }
    let device = device_of(cut.signer.key())?;
    let (seq, revision) = line.cut_record(cut).or(taken)?;
    Some(EventDetail::Cut {
        subject: subject.clone(),
        folder,
        of: cut.of.clone(),
        signer: cut.signer.key().clone(),
        record: wire::log_name(&device, Some(subject), seq),
        revision,
        kept: cut.accept.count(),
    })
}

/// The ledger's key for what an event of `detail` reports, when the layer can derive that from
/// what it holds ([`St::derived_events`]): a revocation by namespace and name (not by the context's
/// version: a later context that keeps the revocation is not another one), a cut by its subject,
/// key prefix, signer and how many versions it keeps, a withdrawal by the entry's name. Equivocation
/// is not derived: its entries are the evidence, and the book keeps theirs.
pub(super) fn fact_of(detail: &EventDetail) -> Option<Fact> {
    match detail {
        EventDetail::Revocation {
            namespace, revoked, ..
        } => Some(revocation_fact(namespace, revoked)),
        EventDetail::Cut {
            subject,
            folder,
            of,
            signer,
            kept,
            ..
        } => Some(cut_fact(subject, *folder, of, signer, *kept)),
        EventDetail::Withdrawal { entry, .. } => Some(withdrawal_fact(&entry.name)),
        EventDetail::Equivocation { .. } | EventDetail::Overflow { .. } => None,
    }
}

fn fact(kind: u8, names: &[&Name], tail: &[u8]) -> Fact {
    let mut h = Sha256::new();
    h.update(b"ndn-data/ledger/1");
    h.update([kind]);
    for n in names {
        h.update((n.len() as u64).to_be_bytes());
        for c in n.components() {
            h.update(c.typ.to_be_bytes());
            h.update((c.value.len() as u64).to_be_bytes());
            h.update(&c.value);
        }
    }
    h.update(tail);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

pub(super) fn revocation_fact(namespace: &Name, revoked: &Name) -> Fact {
    fact(b'r', &[namespace, revoked], &[])
}

pub(super) fn cut_fact(subject: &Name, folder: bool, of: &Name, signer: &Name, kept: u64) -> Fact {
    let mut tail = [0u8; 9];
    tail[0] = u8::from(folder);
    tail[1..].copy_from_slice(&kept.to_be_bytes());
    fact(b'c', &[subject, of, signer], &tail)
}

pub(super) fn withdrawal_fact(entry: &Name) -> Fact {
    fact(b'w', &[entry], &[])
}

/// The fact that this device holds a trust context of `namespace`: the ledger's way of knowing
/// whether a context it meets is the first of its namespace.
pub(super) fn namespace_fact(namespace: &Name) -> Fact {
    fact(b'n', &[namespace], &[])
}

/// `/localhost/ndn-data/events`: the device's own reserved namespace for its events, under no
/// prefix any device serves.
fn events_prefix() -> Name {
    "/localhost/ndn-data/events".parse().expect("a valid name")
}

/// Where the next cursor is kept (`<events>/head`, 8 octets big-endian): written before an event
/// uses a cursor below it, so a restart never gives a cursor twice.
fn head_name() -> Name {
    sub(&events_prefix(), b"head", None)
}

/// Where the unacknowledged event at `c` is kept (`<events>/e/<8 octets>`).
fn event_name(c: Cursor) -> Name {
    sub(&events_prefix(), b"e", Some(c))
}

/// Where the tombstone of the acknowledged event that was at `c` is kept (`<events>/a/<8 octets>`;
/// its value the event's id).
fn tomb_name(c: Cursor) -> Name {
    sub(&events_prefix(), b"a", Some(c))
}

/// Where the mark that the store has a ledger is kept (`<events>/lb`): written when a store has
/// none, before anything else of this run is.
fn begun_name() -> Name {
    sub(&events_prefix(), b"lb", None)
}

/// Where the ledger's fact entered `n`th is kept (`<events>/l/<8 octets>`; its value the fact's 16
/// octets).
fn fact_name(n: u64) -> Name {
    sub(&events_prefix(), b"l", Some(Cursor(n)))
}

/// A fact the ledger records: the first 16 octets of SHA-256 over what an event of it reports
/// ([`fact_of`]).
pub(super) type Fact = [u8; 16];

fn sub(prefix: &Name, dir: &'static [u8], c: Option<Cursor>) -> Name {
    let mut comps: Vec<NameComponent> = prefix.components().to_vec();
    comps.push(NameComponent::generic(Bytes::from_static(dir)));
    if let Some(c) = c {
        comps.push(NameComponent::generic(Bytes::copy_from_slice(
            &c.0.to_be_bytes(),
        )));
    }
    Name::from_components(comps)
}

/// What a stored name under the events prefix is.
enum Stored {
    Head,
    Event(Cursor),
    Tomb(Cursor),
    /// The mark that this store has a ledger.
    Begun,
    /// The ledger's fact entered `n`th.
    Fact(u64),
}

fn parse(name: &Name) -> Option<Stored> {
    let prefix = events_prefix();
    if !name.has_prefix(&prefix) {
        return None;
    }
    let rest = &name.components()[prefix.len()..];
    let cursor = |c: &NameComponent| {
        <[u8; 8]>::try_from(&c.value[..])
            .ok()
            .map(|b| Cursor(u64::from_be_bytes(b)))
    };
    match rest {
        [h] if h.value[..] == *b"head" => Some(Stored::Head),
        [h] if h.value[..] == *b"lb" => Some(Stored::Begun),
        [d, c] if d.value[..] == *b"e" => cursor(c).map(Stored::Event),
        [d, c] if d.value[..] == *b"a" => cursor(c).map(Stored::Tomb),
        [d, c] if d.value[..] == *b"l" => cursor(c).map(|c| Stored::Fact(c.0)),
        _ => None,
    }
}

/// Whether `name` is one of the events' stored names (the restore of the log skips them).
pub(super) fn is_stored(name: &Name) -> bool {
    name.has_prefix(&events_prefix())
}

/// A way to find the namespace that governs a key or name.
pub(super) type NamespaceOf = Arc<dyn Fn(&Name) -> Name + Send + Sync>;

/// A namespace's share of the cap is this fraction: no namespace takes more than a quarter of the
/// events kept (a kind's is `1 /` the kinds kept, [`EventKind::KEPT`]).
const NAMESPACE_SHARE: usize = 4;

/// The events of a device: unacknowledged ones, the tombstones of acknowledged ones, and the
/// counter that orders them (spec §21.4, §21.5).
pub(super) struct Book {
    store: Arc<dyn DataStore>,
    clock: Clock,
    /// Most `(kind, subject)` events kept unacknowledged ([`Config::events_unacked`]), at least 1.
    ///
    /// [`Config::events_unacked`]: super::Config::events_unacked
    cap: usize,
    /// Tombstones kept ([`Config::events_acked`]).
    ///
    /// [`Config::events_acked`]: super::Config::events_acked
    tomb_cap: usize,
    /// The next cursor.
    next: u64,
    pending: BTreeMap<Cursor, DeviceEvent>,
    /// The retained event of each `(kind, subject)`.
    by_subject: HashMap<(EventKind, EventSubject), Cursor>,
    by_id: HashMap<EventId, Cursor>,
    /// How many retained events of each kind, the overflow notice not counted.
    per_kind: HashMap<EventKind, usize>,
    acked: BTreeMap<Cursor, EventId>,
    acked_ids: HashSet<EventId>,
    /// The ledger: the facts whose event was reported (or had none to report), each with its place
    /// in the order they were entered (spec §21.6).
    facts: HashMap<Fact, u64>,
    order: BTreeMap<u64, Fact>,
    next_fact: u64,
    /// Most facts kept: `events_unacked + events_acked`, so that what the book still remembers
    /// is in the ledger too.
    fact_cap: usize,
    /// Whether the store held no ledger when this run began ([`Book::baseline`]).
    baseline: bool,
    /// The namespace governing a key or name: the context held for it, which an event's subject
    /// is counted under (the limit per namespace, [`Book::namespace_cap`]).
    namespace_of: NamespaceOf,
    /// How many retained events there are about each namespace, the overflow notice not counted.
    per_ns: HashMap<Name, usize>,
    ns_of: HashMap<Cursor, Name>,
    /// Told when an event is created, and when the device stops.
    wake: Arc<Notify>,
}

impl Book {
    /// What the last run left in `store`: its unacknowledged events (served again), its
    /// tombstones and its counter. A record that does not decode is dropped.
    pub(super) fn load(
        store: Arc<dyn DataStore>,
        clock: Clock,
        cap: usize,
        tomb_cap: usize,
        namespace_of: NamespaceOf,
    ) -> Book {
        let mut book = Book {
            store: Arc::clone(&store),
            clock,
            cap: cap.max(1),
            tomb_cap,
            next: 1,
            pending: BTreeMap::new(),
            by_subject: HashMap::new(),
            by_id: HashMap::new(),
            per_kind: HashMap::new(),
            acked: BTreeMap::new(),
            acked_ids: HashSet::new(),
            facts: HashMap::new(),
            order: BTreeMap::new(),
            next_fact: 1,
            fact_cap: cap.max(1).saturating_add(tomb_cap),
            baseline: false,
            namespace_of,
            per_ns: HashMap::new(),
            ns_of: HashMap::new(),
            wake: Arc::new(Notify::new()),
        };
        let (mut next, mut began) = (1, false);
        for (name, wire) in store.scan_under(&events_prefix(), 0) {
            match parse(&name) {
                Some(Stored::Head) => {
                    if let Some(h) = wire.get(..8).and_then(|b| <[u8; 8]>::try_from(b).ok()) {
                        next = next.max(u64::from_be_bytes(h));
                    }
                }
                Some(Stored::Event(c)) => match decode_event(c, wire) {
                    Ok(e) => {
                        next = next.max(c.0.saturating_add(1));
                        book.hold(e);
                    }
                    Err(why) => {
                        tracing::warn!(%name, %why, "a stored event does not decode: dropped");
                        store.remove(&name);
                    }
                },
                Some(Stored::Tomb(c)) => match <[u8; 16]>::try_from(&wire[..]) {
                    Ok(id) => {
                        next = next.max(c.0.saturating_add(1));
                        book.acked.insert(c, EventId(id));
                        book.acked_ids.insert(EventId(id));
                    }
                    Err(_) => store.remove(&name),
                },
                Some(Stored::Begun) => began = true,
                Some(Stored::Fact(at)) => match Fact::try_from(&wire[..]) {
                    Ok(fact) => {
                        book.next_fact = book.next_fact.max(at.saturating_add(1));
                        book.facts.insert(fact, at);
                        book.order.insert(at, fact);
                    }
                    Err(_) => store.remove(&name),
                },
                None => store.remove(&name),
            }
        }
        book.next = next;
        // A store with no ledger is one of an earlier revision or a new one: this run notes what
        // it holds without reporting it, and the ledger is there from now on.
        if !began {
            book.baseline = true;
            store.insert(begun_name(), Bytes::from_static(&[1]));
        }
        book
    }

    /// The signal that wakes a stream: an event was created, or the device stopped.
    pub(super) fn wake(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }

    /// The namespace an event is about: what governs the key or name it names, else its first
    /// component. `None` for the overflow notice.
    fn namespace(&self, detail: &EventDetail) -> Option<Name> {
        let about = detail.about()?;
        let ns = (self.namespace_of)(about);
        Some(if ns.is_empty() {
            Name::from_components(
                about
                    .components()
                    .iter()
                    .take(1)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        } else {
            ns
        })
    }

    /// Index `e` as retained.
    fn hold(&mut self, e: DeviceEvent) {
        let kind = e.kind();
        self.by_subject.insert((kind, e.subject()), e.cursor);
        self.by_id.insert(e.id, e.cursor);
        if kind != EventKind::Overflow {
            *self.per_kind.entry(kind).or_default() += 1;
            if let Some(ns) = self.namespace(&e.detail) {
                *self.per_ns.entry(ns.clone()).or_default() += 1;
                self.ns_of.insert(e.cursor, ns);
            }
        }
        self.pending.insert(e.cursor, e);
    }

    /// The most of one kind kept: the cap shared among the kinds events are kept for, so that no
    /// two kinds take the room of the rest.
    fn kind_cap(&self) -> usize {
        (self.cap / EventKind::KEPT.len()).max(1)
    }

    /// The most events about one namespace kept: a quarter of the cap, so that a namespace whose
    /// keys one party mints without end cannot take the room of the others.
    fn namespace_cap(&self) -> usize {
        (self.cap / NAMESPACE_SHARE).max(1)
    }

    /// Report one occurrence (spec §21.5): coalesced into the event kept for its `(kind,
    /// subject)`, else kept as a new event if there is room for it, else counted in the overflow
    /// notice. Nothing kept is ever evicted. Evidence already acknowledged is not reported again.
    /// What a derivable event reports ([`fact_of`]) is entered in the ledger with it, whichever of
    /// these happens to it, and the event and the ledger are written as one batch (spec §21.6).
    pub(super) fn report(&mut self, detail: EventDetail) {
        let fact = fact_of(&detail);
        let mut ops = Vec::new();
        self.report_into(detail, &mut ops);
        if let Some(fact) = fact {
            self.note_into(fact, &mut ops);
        }
        if !ops.is_empty() {
            self.store.apply(ops);
        }
    }

    fn report_into(&mut self, detail: EventDetail, ops: &mut Vec<StoreOp>) {
        let kind = detail.kind();
        if kind == EventKind::Overflow {
            return;
        }
        let key = (kind, detail.subject());
        if let Some(&c) = self.by_subject.get(&key) {
            let e = self.pending.get_mut(&c).expect("indexed events are kept");
            if e.detail == detail || e.last.as_ref() == Some(&detail) {
                return;
            }
            e.count = e.count.saturating_add(1);
            e.last = Some(detail);
            ops.push(StoreOp::Insert(event_name(c), encode_event(e)));
            return;
        }
        let id = EventId::of(&detail, Cursor(self.next));
        if self.acked_ids.contains(&id) {
            return;
        }
        let kept = self.per_kind.get(&kind).copied().unwrap_or(0);
        let in_ns = self
            .namespace(&detail)
            .and_then(|ns| self.per_ns.get(&ns).copied())
            .unwrap_or(0);
        let room = self.per_kind.values().sum::<usize>() < self.cap
            && kept < self.kind_cap()
            && in_ns < self.namespace_cap();
        if room {
            let e = self.create(detail, id, ops);
            tracing::info!(id = %e.id, kind = %e.kind(), "{}", e.why());
            self.hold(e);
            self.wake.notify_waiters();
        } else {
            self.overflow(kind, ops);
        }
    }

    /// Whether the ledger holds `fact`: its event was reported, or there was none to report.
    pub(super) fn covered(&self, fact: &Fact) -> bool {
        self.facts.contains_key(fact)
    }

    /// Whether the store held no ledger when this run began: a store of an earlier revision, or a
    /// new one. What it holds then is the baseline, not news ([`Device::derive_events`]).
    pub(super) fn baseline(&self) -> bool {
        self.baseline
    }

    /// Enter `fact` in the ledger, which keeps at most `events_unacked + events_acked` facts: the
    /// oldest goes when there are more. A fact entered already stays where it is.
    pub(super) fn note(&mut self, fact: Fact) {
        let mut ops = Vec::new();
        self.note_into(fact, &mut ops);
        if !ops.is_empty() {
            self.store.apply(ops);
        }
    }

    fn note_into(&mut self, fact: Fact, ops: &mut Vec<StoreOp>) {
        if self.facts.contains_key(&fact) {
            return;
        }
        let at = self.next_fact;
        self.next_fact += 1;
        self.facts.insert(fact, at);
        self.order.insert(at, fact);
        ops.push(StoreOp::Insert(
            fact_name(at),
            Bytes::copy_from_slice(&fact),
        ));
        while self.order.len() > self.fact_cap {
            let Some((old, fact)) = self.order.pop_first() else {
                break;
            };
            self.facts.remove(&fact);
            ops.push(StoreOp::Remove(fact_name(old)));
        }
    }

    /// Take `fact` out of the ledger: what it records is lifted, so a later occurrence is news.
    pub(super) fn forget(&mut self, fact: &Fact) {
        let Some(at) = self.facts.remove(fact) else {
            return;
        };
        self.order.remove(&at);
        self.store.remove(&fact_name(at));
    }

    /// Enter `fact`, or enter it again if it is there, so that it is the newest.
    pub(super) fn renew(&mut self, fact: Fact) {
        let mut ops = Vec::new();
        if let Some(at) = self.facts.remove(&fact) {
            self.order.remove(&at);
            ops.push(StoreOp::Remove(fact_name(at)));
        }
        self.note_into(fact, &mut ops);
        self.store.apply(ops);
    }

    /// A new event at the next cursor, stored (the counter first).
    fn create(&mut self, detail: EventDetail, id: EventId, ops: &mut Vec<StoreOp>) -> DeviceEvent {
        let cursor = Cursor(self.next);
        self.next += 1;
        ops.push(StoreOp::Insert(
            head_name(),
            Bytes::copy_from_slice(&self.next.to_be_bytes()),
        ));
        let e = DeviceEvent {
            id,
            cursor,
            first_seen: (self.clock)(),
            detail,
            count: 1,
            last: None,
        };
        ops.push(StoreOp::Insert(event_name(cursor), encode_event(&e)));
        e
    }

    /// Count one occurrence of `kind` not kept, in the overflow notice: made if there is none.
    fn overflow(&mut self, kind: EventKind, ops: &mut Vec<StoreOp>) {
        let key = (EventKind::Overflow, EventSubject::Device);
        if let Some(&c) = self.by_subject.get(&key) {
            let e = self.pending.get_mut(&c).expect("indexed events are kept");
            if let EventDetail::Overflow { dropped } = &mut e.detail {
                match dropped.iter_mut().find(|(k, _)| *k == kind) {
                    Some((_, n)) => *n = n.saturating_add(1),
                    None => {
                        dropped.push((kind, 1));
                        dropped.sort();
                    }
                }
            }
            e.count = e.count.saturating_add(1);
            ops.push(StoreOp::Insert(event_name(c), encode_event(e)));
            return;
        }
        let detail = EventDetail::Overflow {
            dropped: vec![(kind, 1)],
        };
        let id = EventId::of(&detail, Cursor(self.next));
        let e = self.create(detail, id, ops);
        tracing::warn!(id = %e.id, "{}", e.why());
        self.hold(e);
        self.wake.notify_waiters();
    }

    /// The unacknowledged events, in cursor order.
    pub(super) fn pending(&self) -> Vec<DeviceEvent> {
        self.pending.values().cloned().collect()
    }

    /// The unacknowledged events above `after`, in cursor order.
    pub(super) fn after(&self, after: Cursor) -> Vec<DeviceEvent> {
        use std::ops::Bound::{Excluded, Unbounded};
        self.pending
            .range((Excluded(after), Unbounded))
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// Acknowledge `ids`: each kept event is removed and leaves a tombstone, the oldest tombstone
    /// going when more than the cap are kept. An id acknowledged already is accepted again. An
    /// id neither kept nor a tombstone refuses the whole call with nothing changed, saying which.
    pub(super) fn acknowledge(&mut self, ids: &[EventId]) -> Result<(), String> {
        let unseen: Vec<String> = ids
            .iter()
            .filter(|id| !self.by_id.contains_key(id) && !self.acked_ids.contains(id))
            .map(|id| id.to_string())
            .collect();
        if !unseen.is_empty() {
            return Err(format!(
                "this device has no event {}, pending or acknowledged: acknowledge ids taken \
                 from its events() or pending_events(), as delivered",
                unseen.join(", ")
            ));
        }
        for id in ids {
            let Some(c) = self.by_id.remove(id) else {
                continue;
            };
            let e = self.pending.remove(&c).expect("indexed events are kept");
            self.by_subject.remove(&(e.kind(), e.subject()));
            if e.kind() != EventKind::Overflow {
                if let Some(n) = self.per_kind.get_mut(&e.kind()) {
                    *n = n.saturating_sub(1);
                }
                if let Some(ns) = self.ns_of.remove(&c)
                    && let Some(n) = self.per_ns.get_mut(&ns)
                {
                    *n = n.saturating_sub(1);
                }
            }
            self.store.remove(&event_name(c));
            self.store
                .insert(tomb_name(c), Bytes::copy_from_slice(&id.0));
            self.acked.insert(c, *id);
            self.acked_ids.insert(*id);
        }
        while self.acked.len() > self.tomb_cap {
            let Some((c, id)) = self.acked.pop_first() else {
                break;
            };
            self.acked_ids.remove(&id);
            self.store.remove(&tomb_name(c));
        }
        Ok(())
    }
}

impl Device {
    /// The events no folder owns (spec §21): the unacknowledged ones with a cursor above `after`,
    /// in cursor order, and then every new one, as they come; the stream ends when the device
    /// stops. Delivery is at least once: every call starts again from what is unacknowledged
    /// (pass [`Cursor::default`] for all of it), and so does a restart, so a host deduplicates by
    /// [`EventId`] and [`acknowledge`](Self::acknowledge)s what it handled. An event reports what
    /// this device already did; nothing here decides what it accepts.
    pub fn events(&self, after: Cursor) -> DeviceEvents {
        let weak = Arc::downgrade(&self.inner);
        let wake = self.inner.st.lock().events.wake();
        Box::pin(futures::stream::unfold(
            (weak, wake, after, VecDeque::<DeviceEvent>::new()),
            |(weak, wake, mut after, mut queue)| async move {
                loop {
                    if let Some(e) = queue.pop_front() {
                        after = e.cursor;
                        return Some((e, (weak, wake, after, queue)));
                    }
                    // Armed before the book is read, so an event created in between wakes it.
                    let notified = wake.notified();
                    {
                        let inner = weak.upgrade()?;
                        if inner.stopped.load(Ordering::Relaxed) {
                            return None;
                        }
                        queue.extend(inner.st.lock().events.after(after));
                    }
                    if queue.is_empty() {
                        notified.await;
                    }
                }
            },
        ))
    }

    /// The unacknowledged events now, in cursor order, with the counts coalesced so far.
    pub fn pending_events(&self) -> Vec<DeviceEvent> {
        self.inner.st.lock().events.pending()
    }

    /// Acknowledge events the host handled (spec §21.4): each is removed and will not be
    /// delivered again, a restart included; returns once that is behind the store's barrier. An
    /// acknowledgement covers every occurrence coalesced into the event so far. An id
    /// acknowledged already is accepted again with no effect. An id this device never had is
    /// refused, with nothing changed: [`DataError::BadRequest`] saying which, and to take ids
    /// from [`events`](Self::events) or [`pending_events`](Self::pending_events).
    pub async fn acknowledge(&self, ids: &[EventId]) -> Result<(), DataError> {
        self.inner
            .st
            .lock()
            .events
            .acknowledge(ids)
            .map_err(|why| DataError::BadRequest {
                name: events_prefix(),
                why,
            })?;
        if !self.inner.barrier().await {
            return Err(local(
                "the device stopped before the acknowledgement was durable; acknowledge again \
                 after it starts",
            ));
        }
        Ok(())
    }
}

impl Inner {
    /// Report, once the store is read back and judged again, the events whose cause the held state
    /// holds and the ledger does not cover (spec §21.6): a revocation of a trust context held, a
    /// cut of a record in force this device did not sign, the withdrawal of a stored entry a
    /// cut or its chain refuses. What an earlier run did not get to report — it stopped, or was
    /// killed, after the cause was held and before its event was written — is reported now; what
    /// it reported, acknowledged or not, is in the ledger and is not reported again. On a store
    /// with no ledger (an earlier revision's, or a new one) what is held is the baseline: entered
    /// in the ledger and not reported, as the first context of a namespace reports none of its own.
    /// The events and the ledger entries are one batch.
    pub(super) fn derive_events(&self) {
        let mut st = self.st.lock();
        let _batch = self.stage.batch();
        let derived = st.derived_events(self.me());
        let baseline = st.events.baseline();
        // The namespaces whose first context an earlier run had already entered: a revocation
        // of any other is no news (the first context of a namespace reports none of its own).
        let namespaces: Vec<Name> = st.contexts.keys().cloned().collect();
        let known: HashSet<Name> = namespaces
            .iter()
            .filter(|ns| st.events.covered(&namespace_fact(ns)))
            .cloned()
            .collect();
        for detail in derived {
            let Some(fact) = fact_of(&detail) else {
                continue;
            };
            let first = matches!(&detail, EventDetail::Revocation { namespace, .. }
                if !known.contains(namespace));
            if baseline || first {
                st.events.note(fact);
            } else if !st.events.covered(&fact) {
                st.events.report(detail);
            }
        }
        // Entered (or entered again, so that it is the last the ledger lets go).
        for ns in &namespaces {
            st.events.renew(namespace_fact(ns));
        }
    }
}
