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
use ndn_sync::DataStore;
use tokio::sync::Notify;

use super::{Clock, Device, Held, St, held_wire, local};
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
        [d, c] if d.value[..] == *b"e" => cursor(c).map(Stored::Event),
        [d, c] if d.value[..] == *b"a" => cursor(c).map(Stored::Tomb),
        _ => None,
    }
}

/// Whether `name` is one of the events' stored names (the restore of the log skips them).
pub(super) fn is_stored(name: &Name) -> bool {
    name.has_prefix(&events_prefix())
}

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
            wake: Arc::new(Notify::new()),
        };
        let mut next = 1;
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
                None => store.remove(&name),
            }
        }
        book.next = next;
        book
    }

    /// The signal that wakes a stream: an event was created, or the device stopped.
    pub(super) fn wake(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }

    /// Index `e` as retained.
    fn hold(&mut self, e: DeviceEvent) {
        let kind = e.kind();
        self.by_subject.insert((kind, e.subject()), e.cursor);
        self.by_id.insert(e.id, e.cursor);
        if kind != EventKind::Overflow {
            *self.per_kind.entry(kind).or_default() += 1;
        }
        self.pending.insert(e.cursor, e);
    }

    /// The most of one kind kept: half the cap, rounded up, so no kind takes the room of all.
    fn kind_cap(&self) -> usize {
        self.cap.div_ceil(2)
    }

    /// Report one occurrence (spec §21.5): coalesced into the event kept for its `(kind,
    /// subject)`, else kept as a new event if there is room for it, else counted in the overflow
    /// notice. Nothing kept is ever evicted. Evidence already acknowledged is not reported again.
    pub(super) fn report(&mut self, detail: EventDetail) {
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
            self.store.insert(event_name(c), encode_event(e));
            return;
        }
        let id = EventId::of(&detail, Cursor(self.next));
        if self.acked_ids.contains(&id) {
            return;
        }
        let kept = self.per_kind.get(&kind).copied().unwrap_or(0);
        let room = self.per_kind.values().sum::<usize>() < self.cap && kept < self.kind_cap();
        if room {
            let e = self.create(detail, id);
            tracing::info!(id = %e.id, kind = %e.kind(), "{}", e.why());
            self.hold(e);
            self.wake.notify_waiters();
        } else {
            self.overflow(kind);
        }
    }

    /// A new event at the next cursor, stored (the counter first).
    fn create(&mut self, detail: EventDetail, id: EventId) -> DeviceEvent {
        let cursor = Cursor(self.next);
        self.next += 1;
        self.store.insert(
            head_name(),
            Bytes::copy_from_slice(&self.next.to_be_bytes()),
        );
        let e = DeviceEvent {
            id,
            cursor,
            first_seen: (self.clock)(),
            detail,
            count: 1,
            last: None,
        };
        self.store.insert(event_name(cursor), encode_event(&e));
        e
    }

    /// Count one occurrence of `kind` not kept, in the overflow notice: made if there is none.
    fn overflow(&mut self, kind: EventKind) {
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
            self.store.insert(event_name(c), encode_event(e));
            return;
        }
        let detail = EventDetail::Overflow {
            dropped: vec![(kind, 1)],
        };
        let id = EventId::of(&detail, Cursor(self.next));
        let e = self.create(detail, id);
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
            if e.kind() != EventKind::Overflow
                && let Some(n) = self.per_kind.get_mut(&e.kind())
            {
                *n = n.saturating_sub(1);
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
