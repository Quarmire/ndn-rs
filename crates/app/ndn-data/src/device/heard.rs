//! The devices a reader hears in a namespace's sync group, and which of
//! them it asks for another device's packets (spec §12, §13.5). Sync
//! Interests are unsigned: anyone who can send one names any devices it
//! likes. So the list of devices heard is bounded per group, the devices
//! signed data held here does not vouch for dropped first, and only a
//! device that signed data held here vouches for — a member or a holder,
//! not a name a Sync Interest carried — is asked to answer for another
//! (a relay, a granter), at most [`RELAYS_ASKED`] of them per ask. A name
//! heard and not vouched for is still walked toward itself, as any device
//! a notice names: that costs one device's asks, never more.

use super::*;

/// The most devices kept as heard in one sync group: past it, the device
/// heard longest ago that nothing held vouches for is dropped
/// ([`Heard::hear`]), so a Sync Interest naming many devices costs a
/// bounded list, whatever it names.
pub(super) const HEARD_MAX: usize = 64;

/// The most devices one ask for another device's packet goes to at once
/// (spec §13.5): every relay and granter is vouched for by signed data
/// held here ([`Inner::vouched`]), those whose root of the namespace this
/// device verified first, so one packet costs at most this many asks per
/// round, however many devices are heard.
pub(super) const RELAYS_ASKED: usize = 8;

/// The devices heard in one sync group ([`SyncGroup::members`]), each with
/// when it was last heard, at most [`HEARD_MAX`].
#[derive(Default)]
pub(super) struct Heard {
    /// Each device heard, with the tick it was last heard at.
    at: BTreeMap<Name, u64>,
    /// The tick of the newest hearing.
    tick: u64,
}

impl Heard {
    pub(super) fn contains(&self, device: &Name) -> bool {
        self.at.contains_key(device)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.at.is_empty()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &Name> {
        self.at.keys()
    }

    /// Note `device` heard, as one Sync Interest carrying it would.
    #[cfg(test)]
    pub(super) fn insert(&mut self, device: Name) {
        self.hear(device, |_| true);
    }

    /// Note `device` heard now. Past [`HEARD_MAX`] devices, the one heard
    /// longest ago that `vouched` does not vouch for is dropped — `device`
    /// itself when every other one is vouched for — else the one heard
    /// longest ago: a name a Sync Interest carried never displaces a
    /// device signed data held here vouches for. The device dropped, if
    /// any. `vouched` is asked from the oldest on, until one it does not
    /// vouch for: under a flood of names, about once per device vouched
    /// for.
    fn hear(&mut self, device: Name, vouched: impl Fn(&Name) -> bool) -> Option<Name> {
        self.tick += 1;
        self.at.insert(device, self.tick);
        if self.at.len() <= HEARD_MAX {
            return None;
        }
        let mut by_age: Vec<(u64, &Name)> = self.at.iter().map(|(d, t)| (*t, d)).collect();
        by_age.sort_unstable();
        let dropped = by_age
            .iter()
            .find(|(_, d)| !vouched(d))
            .or(by_age.first())
            .map(|(_, d)| (*d).clone())?;
        self.at.remove(&dropped);
        Some(dropped)
    }
}

impl Inner {
    /// Note `device` heard in `ns`'s group ([`Heard::hear`]); whether it is
    /// kept among the devices heard. A device dropped that no group hears
    /// any more loses what this device noted of it without verifying
    /// anything of it ([`Peer`] entries with no root verified, walked or
    /// kept), unless an adoption since owes its walk ([`Unjudged::Adopted`],
    /// spec §17.1: nothing another party sends ends an owed walk): a flood
    /// of names leaves nothing behind it.
    pub(super) fn hear(&self, st: &mut St, ns: &Name, device: &Name) -> bool {
        let Some(mut heard) = st
            .groups
            .get_mut(ns)
            .map(|g| std::mem::take(&mut g.members))
        else {
            return true;
        };
        let dropped = heard.hear(device.clone(), |d| self.vouched_heard(st, d, ns));
        if let Some(g) = st.groups.get_mut(ns) {
            g.members = heard;
        }
        let Some(dropped) = dropped else {
            return true;
        };
        if !st.groups.values().any(|g| g.members.contains(&dropped)) {
            st.peers.retain(|(d, _), p| {
                *d != dropped
                    || p.head > 0
                    || p.kept > 0
                    || p.walked > 0
                    || p.root.is_some()
                    || p.unjudged == Some(Unjudged::Adopted)
            });
        }
        dropped != *device
    }

    /// Whether signed data held here vouches for `device` as a member or a
    /// holder of namespace `ns` (spec §13.5): a summary root of it for `ns`
    /// verified here (in this run, or kept from an earlier one); a version
    /// of it applied in a collection of `ns`; a lease or hold record of a
    /// collection of `ns` naming it as a holder; or a members record in
    /// force of a collection or folder of `ns` listing it — its device
    /// name or one of its keys as a writer, the device as a reader. A
    /// writer prefix naming a whole namespace or person vouches for no
    /// device under it: a Sync Interest may carry any name there.
    pub(super) fn vouched(&self, st: &St, device: &Name, ns: &Name) -> bool {
        if st
            .peers
            .get(&(device.clone(), ns.clone()))
            .is_some_and(|p| p.head > 0 || p.kept > 0 || p.root.is_some())
        {
            return true;
        }
        let names = |w: &Name| w == device || device_of(w).as_ref() == Some(device);
        let listed = |m: &Members| {
            m.writers.iter().any(names)
                || m.readers
                    .iter()
                    .any(|a| matches!(a, Audience::Device(d) if d == device))
        };
        let of_ns = |c: &Name| namespace_of(c).as_ref() == Some(ns);
        st.colls.iter().filter(|(c, _)| of_ns(c)).any(|(_, x)| {
            x.applied.keys().any(|w| names(w.key()))
                || x.leases.contains_key(device)
                || x.holds.values().any(|(_, _, h)| h.holders.contains(device))
                || x.members.as_ref().is_some_and(listed)
        }) || st
            .folders
            .iter()
            .filter(|(f, _)| of_ns(f))
            .any(|(_, x)| x.members.as_ref().is_some_and(listed))
    }

    /// [`Self::vouched`] for `device` heard in `ns`'s group: for `ns`, or
    /// for a namespace it writes into by the records held
    /// ([`Self::written_by`]) — a member's device heard in its own
    /// namespace's group.
    pub(super) fn vouched_heard(&self, st: &St, device: &Name, ns: &Name) -> bool {
        self.vouched(st, device, ns)
            || self
                .written_by(st, device)
                .iter()
                .any(|t| t != ns && self.vouched(st, device, t))
    }

    /// Whether `device`'s refresh loop of `ns` begins another pass: its
    /// walk is owed by data verified here ([`St::owes_walk`]), it is still
    /// heard in some group, or signed data held here vouches for it
    /// ([`Self::vouched`]). A name a Sync Interest carried that was
    /// dropped from the devices heard ([`Heard::hear`]) is asked no more.
    pub(super) fn walks_on(&self, st: &St, ns: &Name, device: &Name) -> bool {
        st.owes_walk(device, ns)
            || st.groups.values().any(|g| g.members.contains(device))
            || self.vouched(st, device, ns)
    }

    /// Note that the walks of `device`'s summary of `ns` spent their tries
    /// with no root of it verified ([`Peer::unreached`]). The first time,
    /// with nothing held vouching for it, the erasures of `ns`'s folders it
    /// may have held back are judged again ([`Self::not_walked`]).
    pub(super) fn mark_unreached(&self, st: &mut St, device: &Name, ns: &Name) {
        let peer = st.peers.entry((device.clone(), ns.clone())).or_default();
        if std::mem::replace(&mut peer.unreached, true) || self.vouched(st, device, ns) {
            return;
        }
        let folders: Vec<Name> = st
            .folders
            .keys()
            .filter(|f| namespace_of(f).as_ref() == Some(ns))
            .cloned()
            .collect();
        for f in folders {
            self.erase_folder(st, &f);
        }
    }

    /// Whether `device` lies in a person's namespace that a members record
    /// in force here lists as a writer (spec §6.3): its roots, judged by no
    /// context held yet, wait for that namespace's adoption, which owes its
    /// walk — not a walk that ended unreached ([`Self::mark_unreached`]).
    pub(super) fn awaits_adoption(&self, st: &St, device: &Name) -> bool {
        let Some(person) = ndn_security::self_certifying::personal_namespace_of(device) else {
            return false;
        };
        let lists = |m: &Members| {
            m.writers
                .iter()
                .chain(m.cuts.iter().map(|c| &c.of))
                .any(|w| w.has_prefix(&person))
        };
        st.colls
            .values()
            .filter_map(|x| x.members.as_ref())
            .chain(st.folders.values().filter_map(|x| x.members.as_ref()))
            .any(lists)
    }

    /// The devices asked to answer for `writer`'s packets of namespace
    /// `ns` while it does not (spec §13.5): of the devices heard for `ns`
    /// ([`Self::known_for`]), neither this device, `writer`, one in `skip`
    /// nor one ended here, those signed data held here vouches for
    /// ([`Self::vouched`]) — those whose root of `ns` was verified here
    /// first — at most [`RELAYS_ASKED`].
    pub(super) fn relays(&self, st: &St, ns: &Name, writer: &Name, skip: &[Name]) -> Vec<Name> {
        let mut out: Vec<(bool, Name)> = self
            .known_for(st, ns)
            .into_iter()
            .filter(|d| d != &self.device && d != writer && !skip.contains(d) && !self.ended(st, d))
            .filter(|d| self.vouched(st, d, ns))
            .map(|d| {
                let rooted = st
                    .peers
                    .get(&(d.clone(), ns.clone()))
                    .is_some_and(|p| p.head > 0 || p.kept > 0 || p.root.is_some());
                (!rooted, d)
            })
            .collect();
        out.sort();
        out.truncate(RELAYS_ASKED);
        out.into_iter().map(|(_, d)| d).collect()
    }

    /// The devices one round of asks for an epoch key of a collection of
    /// `ns` goes to, in order (spec §9): the epoch's creator, then the
    /// devices answering for others ([`Self::relays`]) — vouched for by
    /// signed data held here, at most [`RELAYS_ASKED`] — so a round never
    /// waits behind names a Sync Interest carried.
    pub(super) fn granters(&self, st: &St, ns: &Name, creator: &Name) -> Vec<Name> {
        let mut out = Vec::with_capacity(RELAYS_ASKED + 1);
        if *creator != self.device {
            out.push(creator.clone());
        }
        out.extend(self.relays(st, ns, creator, &[]));
        out
    }
}
