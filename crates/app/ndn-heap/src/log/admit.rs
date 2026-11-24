//! Admission of a received entry (plan 3.5) and the re-check that follows
//! every change of what decides admission.
//!
//! [`Log::admit`] takes one entry the judge verified. The decision about an
//! entry ([`Log::assess`]) is a pure function of what is held (the fold, the
//! keys, the cuts), so it is made again, by the same function, whenever any of
//! it changes ([`Log::settle`]): an entry never depends on the order things
//! arrived in.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Data;

use super::chain::{RANGES_MAX, Ranges, Status};
use super::view::{View, head_for};
use super::*;
use crate::error::Timestamp;
use crate::register::ValueChange;
use crate::wire::{Prev, parse_log_name, signed_digest_of};

/// What admission is given about the entry that arrived: its ref, its bytes,
/// the verified signer, the time, and whether only an unsigned counter asked
/// for it.
struct Arrival<'a> {
    id: EntryRef,
    wire: &'a Bytes,
    data: &'a Data,
    v: &'a Verified,
    now: u64,
    probe: bool,
}

/// A new entry to store. `verdict`: `Ok` with the entry when it is applied,
/// else the status it is held under.
pub(super) struct Fresh<'a> {
    pub id: &'a EntryRef,
    pub wire: &'a Bytes,
    pub person: &'a Name,
    pub key_digest: [u8; 32],
    /// The chain link the entry states (`PREV`, the seq it names); zeros when
    /// the entry cannot be read, so it states nothing.
    pub link: ([u8; 32], u64),
    pub verdict: Result<&'a Entry, Status>,
}

/// An entry held, as the store has it.
struct Loaded {
    id: EntryRef,
    marker: Marker,
    status: Option<Status>,
    entry: Entry,
    key: Name,
    person: Name,
}

/// How a held entry is judged again ([`Log::reassess`]).
pub(super) enum Rejudge {
    /// By what is held now: a change of facts.
    Held,
    /// By what is held now, for another copy the judge verified: what was
    /// refused for trust is judged too.
    Verified,
    /// Refused outright, by the judge or the host.
    Refused(Refusal),
}

/// Whether a status counts the entry as admitted: applied, or closed for want
/// of a key.
fn admitted(status: Option<&Status>) -> bool {
    matches!(status, None | Some(Status::Closed))
}

impl From<Status> for Outcome {
    fn from(status: Status) -> Outcome {
        match status {
            Status::Closed => Outcome::Closed,
            Status::Waiting => Outcome::Waiting,
            Status::Unreadable => Outcome::Unreadable,
            Status::Refused(why) => Outcome::Refused(why),
        }
    }
}

/// The entry in a packet, and the link it states to the one before: the
/// digest and the seq of that entry (0 and zeros: none, or lost).
pub(super) fn shape(data: &Data, seq: u64) -> Option<(Entry, [u8; 32], u64)> {
    let entry = Entry::decode(data.content()?).ok()?;
    let (digest, prev_seq) = link_of(&entry.prev, seq)?;
    Some((entry, digest, prev_seq))
}

/// The link an entry at `seq` that states `prev` makes: the digest and seq
/// of the entry before it. `None`: no link a chain can follow.
pub(super) fn link_of(prev: &Option<Prev>, seq: u64) -> Option<([u8; 32], u64)> {
    match (prev, seq) {
        (None, 1) => Some(([0; 32], 0)),
        (Some(p), s) if s > 1 => match p.seq {
            None => Some((p.digest, s - 1)),
            Some(ps) if ps < s => Some((p.digest, ps)),
            _ => None,
        },
        _ => None,
    }
}

/// The link a packet states even when its body cannot be read.
fn stated_link(data: &Data, seq: u64) -> Option<([u8; 32], u64)> {
    link_of(&Entry::decode_prev(data.content()?)?, seq)
}

impl Log {
    /// Take an entry the judge verified (`verified` says who signed it and by
    /// which key) at `now` (`Config.clock`, ms). All the writes are one
    /// batch.
    ///
    /// `probe`: the entry was fetched only because an unsigned counter named
    /// it (not something the log wants). If its signer is no member and
    /// nothing of that device is vouched for, it is stored and told only when
    /// it is the first this log holds of the device: what a stranger
    /// advertises grows neither the store nor the host's alerts.
    pub(crate) fn admit(
        &mut self,
        wire: &Bytes,
        data: &Data,
        verified: &Verified,
        now: u64,
        probe: bool,
    ) -> (Outcome, Effects) {
        let mut fx = Effects::default();
        let outcome = self.admit_in(wire, data, verified, now, &mut fx, probe);
        self.settle(&mut fx);
        (outcome, fx)
    }

    fn admit_in(
        &mut self,
        wire: &Bytes,
        data: &Data,
        v: &Verified,
        now: u64,
        fx: &mut Effects,
        probe: bool,
    ) -> Outcome {
        // 1. The name parses, names this space, and its device is the key's.
        let id = match parse_log_name(&data.name) {
            Some(p) if p.space == self.space && p.device == v.device && p.seq > 0 => EntryRef {
                device: p.device,
                seq: p.seq,
                digest: signed_digest_of(data),
            },
            _ => return Outcome::Refused(Refusal::BadSignature),
        };
        let a = Arrival {
            id,
            wire,
            data,
            v,
            now,
            probe,
        };
        let (device, seq) = (&a.id.device, a.id.seq);
        let held = self.view().marker(device, seq);
        if let Some(held) = held {
            if held.signed_digest == a.id.digest {
                return self.duplicate(&a, fx);
            }
            if !self.displaces(&a) {
                return self.second_packet(&a, fx);
            }
        }
        if let Some(why) = self.suspicion(v) {
            return Outcome::Refused(why);
        }
        // Other bytes were refused here as not on the cut's chain; these are
        // the bytes it names. They take the name; what was refused stays as
        // evidence.
        let displaced = held.and_then(|_| {
            let old = self.view().status(device, seq);
            self.set_status(device, seq, old.as_ref(), None);
            self.view().wire_at(device, seq)
        });
        let outcome = self.take(&a, fx);
        if let Some(old) = displaced {
            self.store
                .insert(Kind::EQUIVOCAL.of(&a.id.name(&self.space)), old);
            self.equivocated(&a, seq, fx);
        }
        outcome
    }

    /// The device of `id` signed two packets at `seq` (one name, or a chain
    /// that forks there): told to the host, and its key suspected.
    fn equivocated(&self, a: &Arrival<'_>, seq: u64, fx: &mut Effects) {
        fx.alerts.push(Alert::Equivocation {
            device: a.id.device.clone(),
            seq,
        });
        self.suspicion.mark_new(&a.v.key, Timestamp(a.now));
    }

    /// A suspected key's new entries are not taken, unless the owner's cut
    /// names them: a removed writer's entries are judged by the cut alone.
    fn suspicion(&self, v: &Verified) -> Option<Refusal> {
        let since = self.suspicion.since(&v.key)?;
        self.fold.is_writer(&v.person).then(|| Refusal::Suspected {
            key: v.key.clone(),
            since,
        })
    }

    /// Whether the held packet at this name was refused as outside a removal
    /// cut (or waits on it), and this one is applied: the cut names these
    /// bytes, and the others must not keep them from coming.
    fn displaces(&self, a: &Arrival<'_>) -> bool {
        matches!(
            self.view().status(&a.id.device, a.id.seq),
            Some(Status::Refused(Refusal::OutsideCut(_)) | Status::Waiting)
        ) && shape(a.data, a.id.seq)
            .is_some_and(|(entry, _, _)| self.assess(&a.id, &a.v.person, &a.v.key, &entry).is_ok())
    }

    /// Another copy of an entry held: nothing new, unless what it was refused
    /// for can change.
    fn duplicate(&mut self, a: &Arrival<'_>, fx: &mut Effects) -> Outcome {
        let (device, seq) = (&a.id.device, a.id.seq);
        if let Some(dev) = self.devices.get_mut(device)
            && dev.person != a.v.person
        {
            dev.person = a.v.person.clone();
            self.write_ledger(device);
        }
        if self
            .view()
            .status(device, seq)
            .is_some_and(|s| s.can_change())
        {
            self.reassess(device, seq, Rejudge::Verified, fx);
        }
        Outcome::Duplicate
    }

    /// A packet of other signed bytes at a name already held: the device
    /// signed two. Both are kept, the key is suspected; a second Members or
    /// Epoch entry is a fact of the space as the first is, so every holder
    /// agrees whichever came first.
    fn second_packet(&mut self, a: &Arrival<'_>, fx: &mut Effects) -> Outcome {
        let (id, v) = (&a.id, a.v);
        let at = Kind::EQUIVOCAL.of(&id.name(&self.space));
        if let Some(held) = self.store.get(&at) {
            return if signed_digest(&held) == id.digest {
                Outcome::Duplicate
            } else {
                Outcome::Evidence
            };
        }
        self.store.insert(at, a.wire.clone());
        self.equivocated(a, id.seq, fx);
        // What the entry first held here said is absent is no longer taken as
        // said: its writer signed two.
        self.count_gap(&id.device, id.seq, 0, false);
        if let Some((entry, _, _)) = shape(a.data, id.seq)
            && matches!(entry.body, Body::Members(_) | Body::Epoch(_))
            && self.assess(id, &v.person, &v.key, &entry).is_ok()
        {
            self.set_applied(id, &v.person, &entry, true, fx);
        }
        Outcome::Evidence
    }

    /// Whether taking the entry `id`, which states `link`, would make its
    /// device's runs or gap statements more than [`RANGES_MAX`].
    fn fragments(&self, id: &EntryRef, link: Option<([u8; 32], u64)>) -> bool {
        let Some(dev) = self.devices.get(&id.device) else {
            return false;
        };
        let states_gap = link.is_some_and(|(_, prev_seq)| prev_seq + 1 < id.seq);
        (dev.held.runs() >= RANGES_MAX && dev.held.grows_by(id.seq, id.seq))
            || (states_gap && dev.gaps.len() >= RANGES_MAX)
    }

    /// Plan 3.5 steps 3 to 8 for an entry at a fresh name.
    fn take(&mut self, a: &Arrival<'_>, fx: &mut Effects) -> Outcome {
        let (id, v) = (&a.id, a.v);
        let shaped = shape(a.data, id.seq);

        // 7. An own-name entry is adopted only if this device's key signed it,
        // and then once it chains to what is held ([`Log::assess`]: until it
        // does it waits, held, and the entries below it are asked for).
        // Above what an earlier run could have reserved it is a restored old
        // image or a key copy: told as `RolledBack`, and applied all the
        // same, as every peer applied it, so this device and its peers
        // agree; this device resumes above it.
        if id.device == self.device {
            if v.key != self.key {
                return Outcome::Refused(Refusal::BadSignature);
            }
            // The durable `R` an earlier run left, not the extension this
            // run wrote at open.
            let reserved = self.reservation.floor_r;
            if id.seq > reserved {
                fx.alerts.push(Alert::RolledBack {
                    reserved,
                    seen: id.seq,
                });
            }
            self.next_seq = self.next_seq.max(id.seq.saturating_add(1));
        }

        // The ledger is written with every entry, so a device keeps only so
        // many separate runs and gap statements of another's.
        let stated = shaped
            .as_ref()
            .map(|(_, digest, prev_seq)| (*digest, *prev_seq))
            .or_else(|| stated_link(a.data, id.seq));
        if id.device != self.device && self.fragments(id, stated) {
            return Outcome::Refused(Refusal::Fragmented);
        }

        // 6. The chain: the entry at `PREV_SEQ` must be the one `PREV` names.
        // 3 to 5: carrier, membership, sealing.
        let verdict = match &shaped {
            None => {
                tracing::warn!(name = %id.name(&self.space), "an entry that verifies and cannot be read is recorded as refused");
                Err(Status::Unreadable)
            }
            Some((entry, prev, prev_seq)) => match self.chain_conflict(id, prev, *prev_seq) {
                Some(conflict) => {
                    self.equivocated(a, conflict, fx);
                    Err(Status::Refused(Refusal::Chain))
                }
                None => self.assess(id, &v.person, &v.key, entry).map(|()| entry),
            },
        };
        if let Err(Status::Refused(why)) = &verdict {
            // A probe of a device nothing vouches for keeps one refused
            // entry here, the first: it is the one a later membership
            // change takes back. Its other counters are probed and
            // answered, and neither stored nor told, so what a stranger
            // advertises grows neither the store nor the host's alerts.
            // An entry the log asked for (a hole, a cut's tip) is stored.
            if a.probe
                && matches!(why, Refusal::NotMember)
                && self
                    .devices
                    .get(&id.device)
                    .is_some_and(|d| d.held.count() > 0)
                && !self.vouches(&id.device)
            {
                return Outcome::Refused(why.clone());
            }
            refuse_alert(id, why, fx);
        }
        let outcome = match &verdict {
            Ok(_) => Outcome::Applied,
            Err(status) => status.clone().into(),
        };
        let fresh = Fresh {
            id,
            wire: a.wire,
            person: &v.person,
            key_digest: v.key_digest,
            link: stated.unwrap_or_default(),
            verdict,
        };
        self.store_fresh(fresh, a.now, fx);
        outcome
    }

    /// Whether an own entry chaining to `(prev, prev_seq)` extends what this
    /// device holds of itself: the entry it names is held as those bytes and
    /// was admitted (not refused, not waiting for its own predecessor).
    fn own_chains(&self, prev_seq: u64, prev: &[u8; 32]) -> bool {
        let view = self.view();
        match prev_seq {
            0 => true,
            seq => {
                view.marker(&self.device, seq)
                    .is_some_and(|m| m.signed_digest == *prev)
                    && matches!(
                        view.status(&self.device, seq),
                        None | Some(Status::Closed | Status::Unreadable)
                    )
            }
        }
    }

    /// An own entry is applied: the next one chains to it and the head record
    /// says it; own entries that waited for it may chain now.
    fn adopt_own(&mut self, link: Link) {
        if self.own_tip.is_none_or(|t| t.seq < link.seq) {
            self.own_tip = Some(link);
            self.store.insert(Kind::HEAD.of(&self.space), link.encode());
        }
        if self
            .devices
            .get(&self.device)
            .is_some_and(|d| d.nonvouching > 0)
        {
            self.queue.push(Scope::Waiting(self.device.clone()));
        }
    }

    /// The seq at which this entry and a held one disagree about the chain:
    /// what it names at `prev_seq` is not what is held there, or the nearest
    /// held successor names another entry at this seq.
    fn chain_conflict(&self, id: &EntryRef, prev: &[u8; 32], prev_seq: u64) -> Option<u64> {
        let view = self.view();
        if prev_seq > 0
            && let Some(m) = view.marker(&id.device, prev_seq)
            && m.signed_digest != *prev
        {
            return Some(prev_seq);
        }
        let next = self.devices.get(&id.device)?.held.above(id.seq)?;
        let m = view.marker(&id.device, next)?;
        (m.prev_seq == id.seq && m.prev != id.digest).then_some(id.seq)
    }

    /// The decision about an entry from what is held: plan 3.5 steps 3 to 5.
    /// `Ok`: apply it; `Err`: hold it under that status. Pure; made again by
    /// [`Log::reassess`] whenever the facts change.
    fn assess(
        &self,
        id: &EntryRef,
        person: &Name,
        key: &Name,
        entry: &Entry,
    ) -> Result<(), Status> {
        let refuse = |why| Err(Status::Refused(why));
        // 2. An own entry is adopted once it chains to an own entry held
        // (what this device signed, in order); until then it waits for it.
        if id.device == self.device
            && let Some((prev, prev_seq)) = link_of(&entry.prev, id.seq)
            && !self.own_chains(prev_seq, &prev)
        {
            return Err(Status::Waiting);
        }
        let structural = matches!(entry.body, Body::Members(_) | Body::Epoch(_));
        // 3. Only an owner device carries Members and Epoch entries.
        if structural && !(wire::owns(&self.space, key) && person == self.fold.owner()) {
            return refuse(Refusal::NotMember);
        }
        // 4. The signer's person writes, or was removed and the entry is
        // inside the cut.
        if !self.fold.is_writer(person) {
            self.cutting(id, person)?;
        }
        // 5. Sealing.
        let create = self.fold.create();
        match &entry.body {
            Body::Put(_) if create == Some(false) => refuse(Refusal::Unsealed),
            Body::Sealed(_) if create == Some(true) => refuse(Refusal::Sealed),
            Body::Sealed(sealed) => {
                if self.keys.key(&self.space, &sealed.epoch).is_none() {
                    return Err(Status::Closed);
                }
                let opened = self.view().opened_put(entry, &id.name(&self.space));
                opened
                    .map(drop)
                    .ok_or(Status::Refused(Refusal::BadSignature))
            }
            Body::Put(_) | Body::Members(_) | Body::Epoch(_) => Ok(()),
        }
    }

    /// What a removed writer's cut says of the entry: `Ok` when the cut keeps
    /// it.
    fn cutting(&self, id: &EntryRef, person: &Name) -> Result<(), Status> {
        let tips = self.fold.removal_tips(person);
        if !tips.iter().any(|t| t.device == id.device) {
            return Err(Status::Refused(Refusal::NotMember));
        }
        let kept = self.kept.get(&id.device).ok_or(Status::Waiting)?;
        kept.keeps(&self.store, &self.space, id)
    }
}

impl Log {
    // -- Storing -------------------------------------------------------------------

    /// Store a new entry: the packet at its name, its marker, the device's
    /// ledger, its status, and, if it is applied, its effect on the fold or
    /// the register. All in the open batch.
    pub(super) fn store_fresh(&mut self, f: Fresh<'_>, now: u64, fx: &mut Effects) {
        let (device, seq) = (&f.id.device, f.id.seq);
        let name = f.id.name(&self.space);
        self.store.insert(name.clone(), f.wire.clone());
        let (prev, prev_seq) = f.link;
        let marker = Marker {
            signed_digest: f.id.digest,
            key_digest: f.key_digest,
            prev,
            prev_seq,
            at: now,
        };
        self.store.insert(Kind::VERIFIED.of(&name), marker.encode());
        let dev = self
            .devices
            .entry(device.clone())
            .or_insert_with(|| Dev::new(f.person.clone()));
        dev.person = f.person.clone();
        dev.held.insert(seq);
        let status = f.verdict.as_ref().err();
        self.count_gap(device, seq, prev_seq, admitted(status));
        self.set_status(device, seq, None, status);
        if *device == self.device && status.is_none() {
            let digest = f.id.digest;
            self.adopt_own(Link { seq, digest });
        }
        if let Ok(entry) = f.verdict {
            self.set_applied(f.id, f.person, entry, true, fx);
        }
        self.advance_cut(device, fx);
    }

    /// An entry of a removed device arrived: the cut's walk goes on from
    /// where it stopped.
    fn advance_cut(&mut self, device: &Name, fx: &mut Effects) {
        let Some(kept) = self.kept.get_mut(device) else {
            return;
        };
        let before = kept.clone();
        kept.advance(&self.store, device, &self.space);
        if *kept == before {
            return;
        }
        fx.wants.extend(frontier_wants(device, kept));
        self.queue.push(Scope::Waiting(device.clone()));
    }

    pub(super) fn write_ledger(&self, device: &Name) {
        if let Some(dev) = self.devices.get(device) {
            self.store
                .insert(Kind::LEDGER.device(&self.space, device), dev.record());
        }
    }

    /// An entry's gap statement counts while the entry is admitted and its
    /// name is not equivocal: what a refused or equivocating entry says is
    /// absent is not taken as said. `counts`: it is admitted now (else it
    /// stopped counting); `prev_seq` is the link it states.
    pub(super) fn count_gap(&mut self, device: &Name, seq: u64, prev_seq: u64, counts: bool) {
        let equivocal = || {
            let name = log_name(device, &self.space, seq);
            self.store.get(&Kind::EQUIVOCAL.of(&name)).is_some()
        };
        let add = counts && prev_seq + 1 < seq && !equivocal();
        if let Some(dev) = self.devices.get_mut(device) {
            if add {
                dev.gaps.insert(seq, prev_seq);
            } else if !counts {
                dev.gaps.remove(&seq);
            }
        }
        self.write_ledger(device);
    }

    /// Replace the status record of an entry (`old` is what it is now).
    fn set_status(&mut self, device: &Name, seq: u64, old: Option<&Status>, new: Option<&Status>) {
        let closed = |s| u64::from(s == Some(&Status::Closed));
        self.closed = (self.closed + closed(new)).saturating_sub(closed(old));
        let counts = |s| u64::from(!admitted(s));
        if let Some(dev) = self.devices.get_mut(device) {
            dev.nonvouching = (dev.nonvouching + counts(new)).saturating_sub(counts(old));
        }
        let key = Kind::STATUS.seq(&self.space, device, seq);
        match new {
            Some(status) => self
                .store
                .insert(key, Bytes::copy_from_slice(&[status.code()])),
            None if old.is_some() => self.store.remove(&key),
            None => {}
        }
    }

    // -- Applying ------------------------------------------------------------------

    fn fold_view(&self) -> FoldView {
        let writers = self.fold.writers().into_iter();
        let mut standing: BTreeMap<_, _> = writers.map(|p| (p, (true, Vec::new()))).collect();
        for (person, tips) in self.fold.removed_writers() {
            standing.insert(person, (false, tips));
        }
        FoldView {
            standing,
            create: self.fold.create(),
            readers: self.fold.readers(),
            in_force: self.fold.in_force(),
            complete: self.fold.complete(),
        }
    }

    /// Put an accepted entry into the fold or the register (`on`), or take it
    /// out again: what it superseded returns.
    fn set_applied(
        &mut self,
        id: &EntryRef,
        person: &Name,
        entry: &Entry,
        on: bool,
        fx: &mut Effects,
    ) {
        match &entry.body {
            Body::Put(_) | Body::Sealed(_) => {
                let changes = self.register_step(id, person, entry, on);
                self.value_changes(changes, fx);
            }
            Body::Members(body) => {
                let before = self.fold_view();
                if on {
                    self.fold.apply_members(id, body);
                } else {
                    self.fold.withdraw_members(id);
                }
                self.structural(id, on);
                self.fold_changed(before, fx);
            }
            Body::Epoch(body) => {
                if on {
                    self.fold.apply_epoch(EpochId::from(id), body, &entry.after);
                } else {
                    self.fold.withdraw_epoch(&EpochId::from(id));
                }
                self.structural(id, on);
                self.queue.push(Scope::Closed);
                fx.membership = true;
            }
        }
    }

    /// The register takes in (`on`) or gives back an entry, and the writes it
    /// makes go in the batch. The changes of the winners are returned.
    fn register_step(
        &mut self,
        id: &EntryRef,
        person: &Name,
        entry: &Entry,
        on: bool,
    ) -> Vec<ValueChange> {
        let view = View {
            store: &self.store,
            space: &self.space,
            keys: &self.keys,
            devices: &self.devices,
        };
        let (namers, load) = (&|x: &EntryRef| view.namers(x), &|x: &EntryRef| {
            view.head_of(x)
        });
        let eff = if on {
            let put = view
                .opened_put(entry, &id.name(&self.space))
                .expect("a write that is applied is opened");
            let head = head_for(id, &put, person.clone());
            self.register.apply(&head, &entry.after, namers, load)
        } else {
            self.register.withdraw(id, &entry.after, namers, load)
        };
        self.store.apply(eff.writes);
        eff.changes
    }

    /// Mark (or unmark) a Members or Epoch entry as applied: start replays
    /// only these.
    fn structural(&self, id: &EntryRef, on: bool) {
        let key = Kind::STRUCTURAL.seq(&self.space, &id.device, id.seq);
        match on {
            true => self.store.insert(key, Bytes::new()),
            false => self.store.remove(&key),
        }
    }

    /// An applied entry is refused after the fact: out of the fold or the
    /// register (what it superseded returns), and told to the host.
    fn unapply(&mut self, l: &Loaded, why: &Status, fx: &mut Effects) {
        let why = self.withdrawn_why(why, &l.id.device);
        fx.changes.push(Change::Withdrawn {
            id: l.id.clone(),
            why,
        });
        self.set_applied(&l.id, &l.person, &l.entry, false, fx);
    }

    fn withdrawn_why(&self, status: &Status, device: &Name) -> Refusal {
        match status {
            Status::Refused(why) => why.clone(),
            Status::Waiting => Refusal::OutsideCut(Cut {
                device: device.clone(),
                keeps_to: self.kept.get(device).map_or(0, |k| k.keeps_to()),
            }),
            Status::Closed | Status::Unreadable => Refusal::Untrusted {
                why: "its epoch key is no longer held".into(),
            },
        }
    }

    /// Changes of the register's winners as the API says them.
    fn value_changes(&self, changes: Vec<ValueChange>, fx: &mut Effects) {
        for ValueChange { was, now } in changes {
            match (now, was) {
                (Some(head), _) if !head.removal => match self.shown(&head) {
                    Some(Ok(item)) => fx.changes.push(Change::Put(item)),
                    Some(Err(blob)) => fx.blobs.push(blob),
                    None => {}
                },
                (Some(gone), _) | (None, Some(gone)) => {
                    fx.changes.push(Change::Removed(gone.item(Bytes::new())))
                }
                (None, None) => {}
            }
        }
    }

    /// The members changed: tell the host, bring the cuts up to date, and owe
    /// a re-check of the persons whose standing changed.
    fn fold_changed(&mut self, before: FoldView, fx: &mut Effects) {
        let after = self.fold_view();
        if after == before {
            return;
        }
        fx.membership = true;
        fx.changes.push(Change::Members(self.members()));
        self.sync_kept(fx);
        if before.create != after.create {
            self.queue.push(Scope::All);
            return;
        }
        let (was, now) = (&before.standing, &after.standing);
        let persons = was
            .keys()
            .chain(now.keys())
            .filter(|p| was.get(*p) != now.get(*p));
        self.queue.push(Scope::Persons(persons.cloned().collect()));
    }

    /// The cut of each removed device: kept as long as the tips the fold says
    /// are its tips, else computed again from the markers. Nothing of a cut
    /// is stored: [`Log::open`] computes them all.
    pub(super) fn sync_kept(&mut self, fx: &mut Effects) {
        let mut want: std::collections::BTreeMap<Name, Vec<Link>> = Default::default();
        for (_, tips) in self.fold.removed_writers() {
            for t in tips {
                want.entry(t.device).or_default().push(Link {
                    seq: t.seq,
                    digest: t.digest,
                });
            }
        }
        for tips in want.values_mut() {
            tips.sort_by_key(|l| l.seq);
            tips.dedup();
        }
        self.kept.retain(|device, _| want.contains_key(device));
        for (device, tips) in want {
            if self.kept.get(&device).is_some_and(|k| k.tips == tips) {
                continue;
            }
            let kept = Kept::compute(&self.store, &device, &self.space, tips);
            fx.wants.extend(frontier_wants(&device, &kept));
            self.kept.insert(device, kept);
        }
    }

    // -- Re-check -------------------------------------------------------------------

    /// Judge the entries a change of facts may have changed, until none does,
    /// then hand everything the call wrote to the store as one batch. Applying
    /// and withdrawing only ever add facts the owner signed, so this ends. The
    /// last step of every call that stores.
    pub(super) fn settle(&mut self, fx: &mut Effects) {
        while let Some(scope) = self.queue.pop() {
            for (device, seqs) in self.candidates(&scope) {
                for seq in seqs.seqs() {
                    self.reassess(&device, seq, Rejudge::Held, fx);
                }
            }
        }
        self.store.commit();
    }

    fn candidates(&self, scope: &Scope) -> Vec<(Name, Ranges)> {
        let held = |keep: &dyn Fn(&Dev) -> bool| -> Vec<(Name, Ranges)> {
            self.devices
                .iter()
                .filter(|(_, d)| keep(d))
                .map(|(n, d)| (n.clone(), d.held.clone()))
                .collect()
        };
        let by_status = |code: u8, only: Option<&Name>| {
            let mut found: std::collections::BTreeMap<Name, Ranges> = Default::default();
            for (key, value) in self.store.scan_under(&Kind::STATUS.listing(&self.space), 0) {
                let Some((device, seq)) = Kind::STATUS.parse_seq(&self.space, &key) else {
                    continue;
                };
                if value.first() == Some(&code) && only.is_none_or(|o| *o == device) {
                    found.entry(device).or_default().insert(seq);
                }
            }
            found.into_iter().collect()
        };
        match scope {
            Scope::Persons(persons) => held(&|d| persons.contains(&d.person)),
            Scope::All => held(&|_| true),
            Scope::Closed => by_status(1, None),
            Scope::Waiting(device) => by_status(2, Some(device)),
        }
    }

    fn load_entry(&self, device: &Name, seq: u64) -> Option<Loaded> {
        let view = self.view();
        let marker = view.marker(device, seq)?;
        let data = Data::decode(view.wire_at(device, seq)?).ok()?;
        let key = data.sig_info()?.key_locator_name()?;
        let (entry, _, _) = shape(&data, seq)?;
        Some(Loaded {
            id: EntryRef {
                device: device.clone(),
                seq,
                digest: marker.signed_digest,
            },
            marker,
            status: view.status(device, seq),
            entry,
            key: (*key).clone(),
            person: self.devices.get(device)?.person.clone(),
        })
    }

    /// Judge a held entry again, and move it between applied, held and
    /// refused as the new verdict says (or as `how` says outright).
    pub(super) fn reassess(&mut self, device: &Name, seq: u64, how: Rejudge, fx: &mut Effects) {
        let Some(l) = self.load_entry(device, seq) else {
            return;
        };
        let new = match how {
            Rejudge::Refused(why) => Some(Status::Refused(match why {
                Refusal::BadSignature => Refusal::Untrusted {
                    why: "it did not verify when judged again with what this device holds now"
                        .into(),
                },
                why => why,
            })),
            Rejudge::Held | Rejudge::Verified => {
                let held_for_trust =
                    matches!(l.status, Some(Status::Refused(Refusal::Untrusted { .. })));
                if l.status.as_ref().is_some_and(|s| !s.can_change())
                    || (held_for_trust && matches!(how, Rejudge::Held))
                {
                    return;
                }
                self.assess(&l.id, &l.person, &l.key, &l.entry).err()
            }
        };
        if l.status.as_ref().map(Status::code) == new.as_ref().map(Status::code) {
            return;
        }
        self.set_status(device, seq, l.status.as_ref(), new.as_ref());
        if admitted(l.status.as_ref()) != admitted(new.as_ref()) {
            let counts = admitted(new.as_ref());
            self.count_gap(device, seq, l.marker.prev_seq, counts);
        }
        match (&l.status, &new) {
            (Some(_), None) => {
                if *device == self.device {
                    self.adopt_own(Link {
                        seq,
                        digest: l.id.digest,
                    });
                }
                self.set_applied(&l.id, &l.person, &l.entry, true, fx);
            }
            (None, Some(new)) => self.unapply(&l, new, fx),
            _ => {}
        }
    }

    /// The host (or the judge, after a change of trust) says an entry is
    /// refused for `why`: it leaves the register or the fold, and stays
    /// refused until it is offered again and verifies.
    ///
    /// A cause that may pass (`BadSignature`: a certificate not found, a key
    /// store that failed) is kept as `Untrusted`, which a later copy that
    /// verifies re-assesses; kept as itself it would be final.
    pub(crate) fn withdraw(&mut self, device: &Name, seq: u64, why: Refusal) -> Effects {
        let mut fx = Effects::default();
        self.reassess(device, seq, Rejudge::Refused(why), &mut fx);
        self.settle(&mut fx);
        fx
    }

    /// The judge now accepts a held entry that was refused (a cut re-admitted it, or a
    /// certificate arrived): it is judged again as when another copy of it verifies, and returns
    /// to the register or the fold if nothing else refuses it.
    pub(crate) fn reinstate(&mut self, device: &Name, seq: u64) -> Effects {
        let mut fx = Effects::default();
        self.reassess(device, seq, Rejudge::Verified, &mut fx);
        self.settle(&mut fx);
        fx
    }
}

/// An alert for a refusal the host should see.
fn refuse_alert(id: &EntryRef, why: &Refusal, fx: &mut Effects) {
    fx.alerts.push(match why {
        Refusal::OutsideCut(_) => Alert::OutsideCut { id: id.clone() },
        _ => Alert::Refused {
            id: id.clone(),
            why: why.clone(),
            next: why.next(),
        },
    });
}
