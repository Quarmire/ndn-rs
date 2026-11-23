//! Admission of a received entry (plan 3.5) and the re-check that follows
//! every change of what decides admission.
//!
//! [`Log::admit`] takes one entry the judge verified. The decision about an
//! entry ([`Log::assess`]) is a pure function of what is held (the fold, the
//! keys, the cuts), so it is made again, by the same function, whenever any of
//! it changes ([`Log::settle`]): an entry never depends on the order things
//! arrived in.

use std::collections::BTreeSet;
use std::sync::Arc;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Data;

use super::chain::{Keeps, RANGES_MAX, Ranges, Status};
use super::view::{View, write_for};
use super::*;
use crate::error::Timestamp;
use crate::register::ValueChange;
use crate::wire::{Prev, parse_log_name, signed_digest_of};

/// The facts an entry is judged by.
pub(super) struct Subject<'a> {
    pub device: &'a Name,
    pub person: &'a Name,
    pub key: &'a Name,
    pub seq: u64,
    pub digest: [u8; 32],
    pub name: &'a Name,
}

/// What [`Log::assess`] says of an entry.
pub(super) enum Verdict {
    /// Apply it; a write comes with its path and payload (opened if sealed).
    Apply(Option<PutBody>),
    /// Sealed in an epoch whose key is not held.
    Closed,
    /// Its writer's cut is not whole yet.
    Waiting,
    /// Refused.
    Refuse(Refusal),
}

/// An entry to put into the fold or the register.
pub(super) struct Applying {
    pub id: EntryRef,
    pub person: Name,
    pub entry: Entry,
    pub put: Option<PutBody>,
}

/// What `take` is given about the entry that arrived: its name, bytes, the
/// verified signer, the time, and whether only an unsigned counter asked for it.
struct Arrival<'a> {
    id: &'a EntryRef,
    wire: &'a Bytes,
    data: &'a Data,
    v: &'a Verified,
    now: u64,
    probe: bool,
}

/// A new entry to store.
pub(super) struct Fresh<'a> {
    pub id: &'a EntryRef,
    pub wire: &'a Bytes,
    pub person: &'a Name,
    pub key_digest: [u8; 32],
    /// The chain link the entry states (`PREV`, the seq it names); `None`
    /// when the entry cannot be read, so it states nothing.
    pub link: Option<([u8; 32], u64)>,
    /// `None`: applied.
    pub status: Option<Status>,
    pub applying: Option<Applying>,
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

/// The entry in a packet, and the link it states to the one before: the
/// digest and the seq of that entry (0 and zeros: none, or lost).
pub(super) fn shape(data: &Data, seq: u64) -> Option<(Entry, [u8; 32], u64)> {
    let entry = Entry::decode(data.content()?).ok()?;
    let (digest, prev_seq) = link_of(&entry.prev, seq)?;
    Some((entry, digest, prev_seq))
}

/// The link an entry at `seq` that states `prev` makes: the digest and seq
/// of the entry before it. `None`: no link a chain can follow.
fn link_of(prev: &Option<Prev>, seq: u64) -> Option<([u8; 32], u64)> {
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
        let stage = Arc::clone(&self.store);
        let _batch = stage.batch();
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
        let name = (*data.name).clone();
        let id = match parse_log_name(&name) {
            Some(p) if p.space == self.space && p.device == v.device && p.seq > 0 => EntryRef {
                device: p.device,
                seq: p.seq,
                digest: signed_digest_of(data),
            },
            _ => return Outcome::Refused(Refusal::BadSignature),
        };
        let mut displaced = None;
        if let Some(held) = self.view().marker(&id.device, id.seq) {
            if held.signed_digest == id.digest {
                return self.duplicate(&id, v, fx);
            }
            if !self.displaces(&id, &name, data, v) {
                return self.second_packet(&id, wire, data, v, now, fx);
            }
            // Other bytes were refused here as not on the cut's chain; these
            // are the bytes it names. They take the name; what was refused
            // stays as evidence.
            if let Some(why) = self.suspicion(v) {
                return Outcome::Refused(why);
            }
            let old = self.view().status(&id.device, id.seq);
            self.set_status(&id.device, id.seq, old.as_ref(), None);
            displaced = self.view().wire_at(&id.device, id.seq);
        }
        if let Some(why) = self.suspicion(v) {
            return Outcome::Refused(why);
        }
        let arrival = Arrival {
            id: &id,
            wire,
            data,
            v,
            now,
            probe,
        };
        let outcome = self.take(arrival, fx);
        if let Some(old) = displaced {
            self.store.insert(store::equivocal_key(&name), old);
            fx.alerts.push(Alert::Equivocation {
                device: id.device.clone(),
                seq: id.seq,
            });
            self.suspicion.mark_new(&v.key, Timestamp(now));
        }
        outcome
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
    fn displaces(&self, id: &EntryRef, name: &Name, data: &Data, v: &Verified) -> bool {
        matches!(
            self.view().status(&id.device, id.seq),
            Some(Status::Refused(Refusal::OutsideCut(_)) | Status::Waiting)
        ) && shape(data, id.seq).is_some_and(|(entry, _, _)| {
            let subject = Subject {
                device: &id.device,
                person: &v.person,
                key: &v.key,
                seq: id.seq,
                digest: id.digest,
                name,
            };
            matches!(self.assess(&subject, &entry), Verdict::Apply(_))
        })
    }

    /// Another copy of an entry held: nothing new, unless what it was refused
    /// for can change.
    fn duplicate(&mut self, id: &EntryRef, v: &Verified, fx: &mut Effects) -> Outcome {
        if let Some(dev) = self.devices.get_mut(&id.device)
            && dev.person != v.person
        {
            dev.person = v.person.clone();
            self.write_ledger(&id.device);
        }
        if self
            .view()
            .status(&id.device, id.seq)
            .is_some_and(|s| s.can_change())
        {
            self.reassess(&id.device, id.seq, Rejudge::Verified, fx);
        }
        Outcome::Duplicate
    }

    /// A packet of other signed bytes at a name already held: the device
    /// signed two. Both are kept, the key is suspected; a second Members or
    /// Epoch entry is a fact of the space as the first is, so every holder
    /// agrees whichever came first.
    fn second_packet(
        &mut self,
        id: &EntryRef,
        wire: &Bytes,
        data: &Data,
        v: &Verified,
        now: u64,
        fx: &mut Effects,
    ) -> Outcome {
        let name = id.name(&self.space);
        let at = store::equivocal_key(&name);
        if let Some(held) = self.store.get(&at) {
            return if signed_digest(&held) == id.digest {
                Outcome::Duplicate
            } else {
                Outcome::Evidence
            };
        }
        self.store.insert(at, wire.clone());
        fx.alerts.push(Alert::Equivocation {
            device: id.device.clone(),
            seq: id.seq,
        });
        self.suspicion.mark_new(&v.key, Timestamp(now));
        // What the entry first held here said is absent is no longer taken as
        // said: its writer signed two.
        let retracted = self
            .devices
            .get_mut(&id.device)
            .is_some_and(|dev| dev.retract_gap(id.seq));
        if retracted {
            self.write_ledger(&id.device);
        }
        if let Some((entry, _, _)) = shape(data, id.seq)
            && matches!(entry.body, Body::Members(_) | Body::Epoch(_))
        {
            let subject = Subject {
                device: &id.device,
                person: &v.person,
                key: &v.key,
                seq: id.seq,
                digest: id.digest,
                name: &name,
            };
            if let Verdict::Apply(put) = self.assess(&subject, &entry) {
                let applying = Applying {
                    id: id.clone(),
                    person: v.person.clone(),
                    entry,
                    put,
                };
                self.apply_entry(&applying, fx);
            }
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
    fn take(&mut self, arrival: Arrival<'_>, fx: &mut Effects) -> Outcome {
        let Arrival {
            id,
            wire,
            data,
            v,
            now,
            probe,
        } = arrival;
        let name = id.name(&self.space);
        let shaped = shape(data, id.seq);
        let fresh = |status: Option<Status>, link, applying| Fresh {
            id,
            wire,
            person: &v.person,
            key_digest: v.key_digest,
            link,
            status,
            applying,
        };

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
            let reserved = self.floor_r;
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
            .or_else(|| stated_link(data, id.seq));
        if id.device != self.device && self.fragments(id, stated) {
            return Outcome::Refused(Refusal::Fragmented);
        }

        let Some((entry, prev, prev_seq)) = shaped else {
            tracing::warn!(%name, "an entry that verifies and cannot be read is recorded as refused");
            self.store_fresh(fresh(Some(Status::Unreadable), stated, None), now, fx);
            return Outcome::Unreadable;
        };
        let link = Some((prev, prev_seq));

        // 6. The chain: the entry at `PREV_SEQ` must be the one `PREV` names.
        if let Some(conflict) = self.chain_conflict(id, &prev, prev_seq) {
            fx.alerts.push(Alert::Equivocation {
                device: id.device.clone(),
                seq: conflict,
            });
            self.suspicion.mark_new(&v.key, Timestamp(now));
            let why = Refusal::Chain;
            self.store_fresh(
                fresh(Some(Status::Refused(why.clone())), link, None),
                now,
                fx,
            );
            refuse_alert(id, &why, fx);
            return Outcome::Refused(why);
        }

        // 3 to 5: carrier, membership, sealing.
        let subject = Subject {
            device: &id.device,
            person: &v.person,
            key: &v.key,
            seq: id.seq,
            digest: id.digest,
            name: &name,
        };
        match self.assess(&subject, &entry) {
            Verdict::Apply(put) => {
                let applying = Applying {
                    id: id.clone(),
                    person: v.person.clone(),
                    entry,
                    put,
                };
                self.store_fresh(fresh(None, link, Some(applying)), now, fx);
                Outcome::Applied
            }
            Verdict::Closed => {
                self.store_fresh(fresh(Some(Status::Closed), link, None), now, fx);
                Outcome::Closed
            }
            Verdict::Waiting => {
                self.store_fresh(fresh(Some(Status::Waiting), link, None), now, fx);
                Outcome::Waiting
            }
            Verdict::Refuse(why) => {
                // A probe of a device nothing vouches for keeps one refused
                // entry here, the first: it is the one a later membership
                // change takes back. Its other counters are probed and
                // answered, and neither stored nor told, so what a stranger
                // advertises grows neither the store nor the host's alerts.
                // An entry the log asked for (a hole, a cut's tip) is stored.
                if probe
                    && matches!(why, Refusal::NotMember)
                    && self
                        .devices
                        .get(&id.device)
                        .is_some_and(|d| d.held.count() > 0)
                    && !self.vouches(&id.device)
                {
                    return Outcome::Refused(why);
                }
                self.store_fresh(
                    fresh(Some(Status::Refused(why.clone())), link, None),
                    now,
                    fx,
                );
                refuse_alert(id, &why, fx);
                Outcome::Refused(why)
            }
        }
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
            self.store.apply(vec![store::head_op(
                &self.space,
                store::Head {
                    seq: link.seq,
                    digest: link.digest,
                },
            )]);
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
    /// Pure; made again by [`Log::reassess`] whenever the facts change.
    pub(super) fn assess(&self, s: &Subject<'_>, entry: &Entry) -> Verdict {
        // 2. An own entry is adopted once it chains to an own entry held
        // (what this device signed, in order); until then it waits for it.
        if *s.device == self.device
            && let Some((prev, prev_seq)) = link_of(&entry.prev, s.seq)
            && !self.own_chains(prev_seq, &prev)
        {
            return Verdict::Waiting;
        }
        let structural = matches!(entry.body, Body::Members(_) | Body::Epoch(_));
        // 3. Only an owner device carries Members and Epoch entries.
        if structural && !(wire::owns(&self.space, s.key) && s.person == self.fold.owner()) {
            return Verdict::Refuse(Refusal::NotMember);
        }
        // 4. The signer's person writes, or was removed and the entry is
        // inside the cut.
        if !self.fold.is_writer(s.person)
            && let Some(forced) = self.cutting(s)
        {
            return forced;
        }
        // 5. Sealing.
        let create = self.fold.create();
        match &entry.body {
            Body::Put(put) => match create {
                Some(false) => Verdict::Refuse(Refusal::Unsealed),
                _ => Verdict::Apply(Some(put.clone())),
            },
            Body::Sealed(sealed) => {
                if create == Some(true) {
                    return Verdict::Refuse(Refusal::Sealed);
                }
                if self.keys.key(&self.space, &sealed.epoch).is_none() {
                    return Verdict::Closed;
                }
                match self.view().opened_put(entry, s.name) {
                    Some(put) => Verdict::Apply(Some(put)),
                    None => Verdict::Refuse(Refusal::BadSignature),
                }
            }
            Body::Members(_) | Body::Epoch(_) => Verdict::Apply(None),
        }
    }

    /// What a removed writer's cut forces on the entry: `None` when the cut
    /// keeps it.
    fn cutting(&self, s: &Subject<'_>) -> Option<Verdict> {
        let has_tip = self
            .fold
            .removal_tips(s.person)
            .iter()
            .any(|t| t.device == *s.device);
        if !has_tip {
            return Some(Verdict::Refuse(Refusal::NotMember));
        }
        let Some(kept) = self.kept.get(s.device) else {
            return Some(Verdict::Waiting);
        };
        match kept.keeps(&*self.store, s.device, &self.space, s.seq, &s.digest) {
            Keeps::Yes => None,
            Keeps::Waiting => Some(Verdict::Waiting),
            Keeps::No => Some(Verdict::Refuse(Refusal::OutsideCut(Cut {
                device: s.device.clone(),
                keeps_to: kept.keeps_to(),
            }))),
        }
    }

    // -- Storing -------------------------------------------------------------------

    /// Store a new entry: the packet at its name, its marker, the device's
    /// ledger, its status, and, if it is applied, its effect on the fold or
    /// the register. All in the open batch.
    pub(super) fn store_fresh(&mut self, f: Fresh<'_>, now: u64, fx: &mut Effects) {
        let (device, seq) = (&f.id.device, f.id.seq);
        let name = f.id.name(&self.space);
        self.store.insert(name.clone(), f.wire.clone());
        let (prev, prev_seq) = f.link.unwrap_or(([0; 32], 0));
        self.store.apply(vec![store::verified_op(
            &name,
            &Marker {
                signed_digest: f.id.digest,
                key_digest: f.key_digest,
                prev,
                prev_seq,
                at: now,
            },
        )]);
        let dev = self
            .devices
            .entry(device.clone())
            .or_insert_with(|| Dev::new(f.person.clone()));
        dev.person = f.person.clone();
        dev.held.insert(seq);
        if matches!(f.status, None | Some(Status::Closed)) && f.link.is_some() && prev_seq + 1 < seq
        {
            dev.state_gap(seq, prev_seq);
        }
        dev.high = dev.high.max(seq);
        let link = Link {
            seq,
            digest: f.id.digest,
        };
        if dev.tip.is_none_or(|t| t.seq < seq) {
            dev.tip = Some(link);
        }
        self.write_ledger(device);
        self.set_status(device, seq, None, f.status.as_ref());
        if *device == self.device {
            self.own_head = self.own_head.max(seq);
            if f.status.is_none() {
                self.adopt_own(link);
            }
        }
        if let Some(applying) = &f.applying {
            self.apply_entry(applying, fx);
        }
        self.advance_cut(device, fx);
    }

    /// An entry of a removed device arrived: the cut's walk goes on from
    /// where it stopped.
    fn advance_cut(&mut self, device: &Name, fx: &mut Effects) {
        let Some(kept) = self.kept.get_mut(device) else {
            return;
        };
        let before = (kept.ranges.clone(), kept.frontier.clone());
        kept.advance(&*self.store, device, &self.space);
        if (kept.ranges.clone(), kept.frontier.clone()) == before {
            return;
        }
        fx.wants.extend(frontier_wants(device, kept));
        self.queue.push(Scope::Waiting(device.clone()));
    }

    pub(super) fn write_ledger(&self, device: &Name) {
        if let Some(dev) = self.devices.get(device) {
            self.store
                .insert(store::ledger_key(&self.space, device), dev.record());
        }
    }

    /// An entry's gap statement counts while the entry is admitted (applied,
    /// or closed for want of a key) and its name is not equivocal: what a
    /// refused or equivocating entry says is absent is not taken as said.
    /// `was` and `now` are its status before and after a change.
    fn count_gap(
        &mut self,
        device: &Name,
        seq: u64,
        marker: &Marker,
        was: Option<&Status>,
        now: Option<&Status>,
    ) {
        let admitted = |s: Option<&Status>| matches!(s, None | Some(Status::Closed));
        if admitted(was) == admitted(now) {
            return;
        }
        let name = log_name(device, &self.space, seq);
        let equivocal = self.store.get(&store::equivocal_key(&name)).is_some();
        let Some(dev) = self.devices.get_mut(device) else {
            return;
        };
        let changed = if admitted(now) {
            let gap = marker.prev_seq + 1 < seq;
            if gap && !equivocal {
                dev.state_gap(seq, marker.prev_seq);
            }
            gap && !equivocal
        } else {
            dev.retract_gap(seq)
        };
        if changed {
            self.write_ledger(device);
        }
    }

    /// Replace the status record of an entry (`old` is what it is now).
    fn set_status(&mut self, device: &Name, seq: u64, old: Option<&Status>, new: Option<&Status>) {
        if old == Some(&Status::Closed) {
            self.closed = self.closed.saturating_sub(1);
        }
        if new == Some(&Status::Closed) {
            self.closed += 1;
        }
        let counts = |s: Option<&Status>| s.is_some_and(|s| *s != Status::Closed);
        if let Some(dev) = self.devices.get_mut(device) {
            dev.nonvouching =
                (dev.nonvouching + u64::from(counts(new))).saturating_sub(u64::from(counts(old)));
        }
        let key = store::status_key(&self.space, device, seq);
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
        FoldView {
            writers: self.fold.writers(),
            removed: self.fold.removed_writers(),
            create: self.fold.create(),
            readers: self.fold.readers(),
            in_force: self.fold.in_force(),
            complete: self.fold.complete(),
        }
    }

    /// Put an accepted entry into the fold or the register.
    pub(super) fn apply_entry(&mut self, a: &Applying, fx: &mut Effects) {
        match &a.entry.body {
            Body::Put(_) | Body::Sealed(_) => {
                let put = a.put.as_ref().expect("a write that is applied is opened");
                let write = write_for(put, a.person.clone());
                let view = View {
                    store: &*self.store,
                    space: &self.space,
                    keys: &self.keys,
                    devices: &self.devices,
                };
                let eff =
                    self.register
                        .apply(&a.id, &write, &a.entry.after, &|x| view.namers(x), &|x| {
                            view.write_of(x)
                        });
                self.store.apply(eff.writes);
                self.value_changes(eff.changes, Some((&a.id, put)), fx);
            }
            Body::Members(body) => {
                let before = self.fold_view();
                self.fold.apply_members(&a.id, body);
                self.mark_structural(&a.id);
                self.fold_changed(before, fx);
            }
            Body::Epoch(body) => {
                self.fold.apply_epoch(
                    EpochId {
                        creator: a.id.device.clone(),
                        seq: a.id.seq,
                    },
                    body,
                    &a.entry.after,
                );
                self.mark_structural(&a.id);
                self.queue.push(Scope::Closed);
                fx.membership = true;
            }
        }
    }

    fn mark_structural(&self, id: &EntryRef) {
        self.store.insert(
            store::structural_key(&self.space, &id.device, id.seq),
            Bytes::new(),
        );
    }

    /// An applied entry is refused after the fact: out of the fold or the
    /// register (what it superseded returns), and told to the host.
    fn unapply(&mut self, a: &Applying, why: &Status, fx: &mut Effects) {
        let why = self.withdrawn_why(why, &a.id.device);
        fx.changes.push(Change::Withdrawn {
            id: EntryId::from(&a.id),
            why,
        });
        match &a.entry.body {
            Body::Put(_) | Body::Sealed(_) => {
                let view = View {
                    store: &*self.store,
                    space: &self.space,
                    keys: &self.keys,
                    devices: &self.devices,
                };
                let eff =
                    self.register
                        .withdraw(&a.id, &a.entry.after, &|x| view.namers(x), &|x| {
                            view.write_of(x)
                        });
                self.store.apply(eff.writes);
                self.value_changes(eff.changes, None, fx);
            }
            Body::Members(_) => {
                let before = self.fold_view();
                self.fold.withdraw_members(&a.id);
                self.unmark_structural(&a.id);
                self.fold_changed(before, fx);
            }
            Body::Epoch(_) => {
                self.fold.withdraw_epoch(&EpochId {
                    creator: a.id.device.clone(),
                    seq: a.id.seq,
                });
                self.unmark_structural(&a.id);
                fx.membership = true;
            }
        }
    }

    fn unmark_structural(&self, id: &EntryRef) {
        self.store
            .remove(&store::structural_key(&self.space, &id.device, id.seq));
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
    fn value_changes(
        &self,
        changes: Vec<ValueChange>,
        fresh: Option<(&EntryRef, &PutBody)>,
        fx: &mut Effects,
    ) {
        for vc in changes {
            match (vc.now, vc.was) {
                (Some(head), _) if head.removal => fx
                    .changes
                    .push(Change::Removed(head.item(&vc.path, Bytes::new()))),
                (Some(head), _) => {
                    let payload = match fresh {
                        Some((id, put)) if *id == head.entry => Some(put.payload.clone()),
                        _ => self.view().payload_of(&head.entry),
                    };
                    match payload {
                        Some(Payload::Inline(bytes)) => {
                            fx.changes.push(Change::Put(head.item(&vc.path, bytes)));
                        }
                        Some(blob) => fx.blobs.extend(Blob::of(EntryId::from(&head.entry), &blob)),
                        None => {}
                    }
                }
                (None, Some(was)) => fx
                    .changes
                    .push(Change::Removed(was.item(&vc.path, Bytes::new()))),
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
        let mut persons: BTreeSet<Name> = before
            .writers
            .iter()
            .chain(&after.writers)
            .filter(|p| before.writers.contains(p) != after.writers.contains(p))
            .cloned()
            .collect();
        for (person, _) in before.removed.iter().chain(&after.removed) {
            let tips_of = |side: &[(Name, Vec<EntryRef>)]| {
                side.iter()
                    .find(|(p, _)| p == person)
                    .map(|(_, t)| t.clone())
            };
            if tips_of(&before.removed) != tips_of(&after.removed) {
                persons.insert(person.clone());
            }
        }
        if !persons.is_empty() {
            self.queue.push(Scope::Persons(persons));
        }
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
            let kept = Kept::compute(&*self.store, &device, &self.space, tips);
            fx.wants.extend(frontier_wants(&device, &kept));
            self.kept.insert(device, kept);
        }
    }

    // -- Re-check -------------------------------------------------------------------

    /// Judge the entries a change of facts may have changed, until none does.
    /// Applying and withdrawing only ever add facts the owner signed, so this
    /// ends.
    pub(super) fn settle(&mut self, fx: &mut Effects) {
        while let Some(scope) = self.queue.pop() {
            for (device, seqs) in self.candidates(&scope) {
                for seq in seqs.seqs() {
                    self.reassess(&device, seq, Rejudge::Held, fx);
                }
            }
        }
    }

    fn candidates(&self, scope: &Scope) -> Vec<(Name, Ranges)> {
        let held = |keep: &dyn Fn(&Dev) -> bool| -> Vec<(Name, Ranges)> {
            self.devices
                .iter()
                .filter(|(_, d)| keep(d))
                .map(|(n, d)| (n.clone(), d.held.clone()))
                .collect()
        };
        let by_status = |prefix: Name, code: u8, only: Option<&Name>| {
            let mut found: std::collections::BTreeMap<Name, Ranges> = Default::default();
            for (key, value) in self.store.scan_under(&prefix, 0) {
                let Some((device, seq)) = store::parse_status_key(&self.space, &key) else {
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
            Scope::Closed => by_status(status_prefix(&self.space), 1, None),
            Scope::Waiting(device) => by_status(status_prefix(&self.space), 2, Some(device)),
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
        let name = l.id.name(&self.space);
        let new = match how {
            Rejudge::Refused(why) => Status::Refused(match why {
                Refusal::BadSignature => Refusal::Untrusted {
                    why: "it did not verify when judged again with what this device holds now"
                        .into(),
                },
                why => why,
            }),
            Rejudge::Held | Rejudge::Verified => {
                let held_for_trust =
                    matches!(l.status, Some(Status::Refused(Refusal::Untrusted { .. })));
                if l.status.as_ref().is_some_and(|s| !s.can_change())
                    || (held_for_trust && matches!(how, Rejudge::Held))
                {
                    return;
                }
                let subject = Subject {
                    device,
                    person: &l.person,
                    key: &l.key,
                    seq,
                    digest: l.id.digest,
                    name: &name,
                };
                match self.assess(&subject, &l.entry) {
                    Verdict::Apply(put) => {
                        if l.status.is_some() {
                            self.set_status(device, seq, l.status.as_ref(), None);
                            self.count_gap(device, seq, &l.marker, l.status.as_ref(), None);
                            if *device == self.device {
                                self.adopt_own(Link {
                                    seq,
                                    digest: l.id.digest,
                                });
                            }
                            let applying = Applying {
                                id: l.id,
                                person: l.person,
                                entry: l.entry,
                                put,
                            };
                            self.apply_entry(&applying, fx);
                        }
                        return;
                    }
                    Verdict::Closed => Status::Closed,
                    Verdict::Waiting => Status::Waiting,
                    Verdict::Refuse(why) => Status::Refused(why),
                }
            }
        };
        if l.status.as_ref().is_some_and(|s| s.code() == new.code()) {
            return;
        }
        self.set_status(device, seq, l.status.as_ref(), Some(&new));
        self.count_gap(device, seq, &l.marker, l.status.as_ref(), Some(&new));
        if l.status.is_none() {
            let put = self.view().opened_put(&l.entry, &name);
            let applying = Applying {
                id: l.id,
                person: l.person,
                entry: l.entry,
                put,
            };
            self.unapply(&applying, &new, fx);
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
        let stage = Arc::clone(&self.store);
        let _batch = stage.batch();
        let mut fx = Effects::default();
        self.reassess(device, seq, Rejudge::Refused(why), &mut fx);
        self.settle(&mut fx);
        fx
    }
}

/// An alert for a refusal the host should see.
fn refuse_alert(id: &EntryRef, why: &Refusal, fx: &mut Effects) {
    fx.alerts.push(match why {
        Refusal::OutsideCut(_) => Alert::OutsideCut {
            id: EntryId::from(id),
        },
        _ => Alert::Refused {
            id: EntryId::from(id),
            why: why.clone(),
            next: why.next(),
        },
    });
}
