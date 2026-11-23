//! The devices a reader hears in a space's sync group, and which of them it
//! asks for another device's packets (spec §7). Sync Interests are
//! unsigned: anyone who can send one names any devices it likes. So the list
//! of devices heard is bounded per group, the devices signed data held here
//! does not vouch for dropped first, a device named at counter 0 (nothing to
//! fetch, nothing vouching) not kept at all, and only a device that signed
//! data held here vouches for — a member, not a name a Sync Interest carried
//! — is asked to answer for another (a relay, a granter), at most
//! [`RELAYS_ASKED`] of them per ask. A name heard and not vouched for is
//! still walked toward itself, as any device a notice names: that costs one
//! device's asks, never more.
//!
//! The list knows nothing of the log: what vouches for a device, what has
//! ended it, and which devices are held to be first are asked of the caller
//! as closures, so the list is a plain value that the sync driver's own
//! vouching ([`ndn_sync::ProducerVouch`]) and the relay choice share.

use std::collections::BTreeMap;

use ndn_foundation_types::Name;

/// The most devices kept as heard in one sync group: past it, the device
/// heard longest ago that nothing held vouches for is dropped
/// ([`Heard::hear`]), so a Sync Interest naming many devices costs a
/// bounded list, whatever it names.
pub(crate) const HEARD_MAX: usize = 64;

/// The most devices one ask for another device's packet goes to at once
/// (spec §7): every relay and granter is vouched for by signed data held
/// here, those held first leading, so one packet costs at most this many
/// asks per round, however many devices are heard.
pub(crate) const RELAYS_ASKED: usize = 8;

/// What [`Heard::hear`] did with a name.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Hearing {
    /// Whether the device is kept among the devices heard: when not, the
    /// caller walks no further toward it (a notice of a dropped name costs
    /// nothing).
    pub kept: bool,
    /// The device dropped to make room, when one was: the one heard longest
    /// ago that nothing vouched for, the device heard itself when every
    /// other one is vouched for.
    pub dropped: Option<Name>,
}

/// The devices heard in one sync group, each with when it was last heard, at
/// most [`HEARD_MAX`].
#[derive(Default)]
pub(crate) struct Heard {
    /// Each device heard, with the tick it was last heard at.
    at: BTreeMap<Name, u64>,
    /// The tick of the newest hearing.
    tick: u64,
}

/// What the tests inspect of the devices heard.
#[cfg(test)]
impl Heard {
    /// Whether `device` is heard.
    pub(crate) fn contains(&self, device: &Name) -> bool {
        self.at.contains_key(device)
    }

    /// How many devices are heard.
    pub(crate) fn len(&self) -> usize {
        self.at.len()
    }

    /// The devices heard, by name.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Name> {
        self.at.keys()
    }
}

impl Heard {
    /// Note `device` heard now at counter `high` of its log. Past
    /// [`HEARD_MAX`] devices, the one heard longest ago that `vouched` does
    /// not vouch for is dropped — `device` itself when every other one is
    /// vouched for — else the one heard longest ago: a name a Sync Interest
    /// carried never displaces a device signed data held here vouches for.
    /// `vouched` is asked from the oldest on, until one it does not vouch
    /// for: under a flood of names, about once per device vouched for.
    ///
    /// A device at counter 0 has written nothing: it is not heard, takes no
    /// room and displaces no one.
    pub(crate) fn hear(
        &mut self,
        device: Name,
        high: u64,
        vouched: impl Fn(&Name) -> bool,
    ) -> Hearing {
        if high == 0 {
            return Hearing {
                kept: false,
                dropped: None,
            };
        }
        self.tick += 1;
        self.at.insert(device.clone(), self.tick);
        if self.at.len() <= HEARD_MAX {
            return Hearing {
                kept: true,
                dropped: None,
            };
        }
        let mut by_age: Vec<(u64, &Name)> = self.at.iter().map(|(d, t)| (*t, d)).collect();
        by_age.sort_unstable();
        let dropped = by_age
            .iter()
            .find(|(_, d)| !vouched(d))
            .or(by_age.first())
            .map(|(_, d)| (*d).clone());
        if let Some(dropped) = &dropped {
            self.at.remove(dropped);
        }
        Hearing {
            kept: dropped.as_ref() != Some(&device),
            dropped,
        }
    }

    /// The devices asked to answer for `writer`'s packets while it does not
    /// (spec §7): of the devices heard, neither `me`, `writer` nor one in
    /// `skip`, and those `standing` says to ask — `None` for a device not
    /// vouched for by signed data held here or one ended, `Some(true)` for
    /// one whose entries were held first, who lead — at most
    /// [`RELAYS_ASKED`].
    pub(crate) fn relays(
        &self,
        me: &Name,
        writer: &Name,
        skip: &[Name],
        standing: impl Fn(&Name) -> Option<bool>,
    ) -> Vec<Name> {
        let mut out: Vec<(bool, &Name)> = self
            .at
            .keys()
            .filter(|d| *d != me && *d != writer && !skip.contains(d))
            .filter_map(|d| standing(d).map(|first| (!first, d)))
            .collect();
        out.sort();
        out.truncate(RELAYS_ASKED);
        out.into_iter().map(|(_, d)| d.clone()).collect()
    }

    /// The devices one round of asks for an epoch key goes to, in order
    /// (spec §6.5): the epoch's `creator` unless it is `me`, then the
    /// devices answering for others ([`Self::relays`]), so a round never
    /// waits behind names a Sync Interest carried.
    pub(crate) fn granters(
        &self,
        me: &Name,
        creator: &Name,
        standing: impl Fn(&Name) -> Option<bool>,
    ) -> Vec<Name> {
        let mut out = Vec::with_capacity(RELAYS_ASKED + 1);
        if creator != me {
            out.push(creator.clone());
        }
        out.extend(self.relays(me, creator, &[], standing));
        out
    }
}

#[cfg(test)]
#[path = "heard_tests.rs"]
mod tests;
