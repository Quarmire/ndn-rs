//! What the log keeps in memory of each device's chain, and its records:
//! held seqs as ranges, declared voids, and the ancestry a removal cut keeps.
//!
//! Memory is O(devices + ranges + removed devices): no entry and no marker
//! is held. A marker is read from the store when a decision needs it.

use std::collections::BTreeMap;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ndn_foundation_types::Name;
use ndn_sync::DataStore;

use crate::error::{Cut, Refusal};
use crate::store::{Kind, Link, Marker};
use crate::wire::{EntryRef, log_name};

/// The most separate runs of held seqs, and the most gap statements, this
/// device keeps for one device: the `ledger/` record is rewritten with every
/// entry and so must not grow without bound. A device signing with gaps
/// (one per unclean start) reaches it after as many restarts.
pub(super) const RANGES_MAX: usize = 1024;

/// A set of seqs as sorted, disjoint, non-adjacent inclusive ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Ranges(Vec<(u64, u64)>);

impl Ranges {
    pub(super) fn insert(&mut self, seq: u64) {
        match self.0.last_mut() {
            Some((_, hi)) if hi.checked_add(1) == Some(seq) => *hi = seq,
            Some((_, hi)) if *hi >= seq => *self = self.union(&Ranges(vec![(seq, seq)])),
            _ => self.0.push((seq, seq)),
        }
    }

    /// The set of the runs `all`, in any order, overlapping or touching.
    fn merged(mut all: Vec<(u64, u64)>) -> Ranges {
        all.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(all.len());
        for (a, b) in all {
            match merged.last_mut() {
                Some((_, hi)) if a <= hi.saturating_add(1) => *hi = (*hi).max(b),
                _ => merged.push((a, b)),
            }
        }
        Ranges(merged)
    }

    /// How many seqs the set holds.
    pub(super) fn count(&self) -> u64 {
        self.0.iter().fold(0u64, |n, &(lo, hi)| {
            n.saturating_add((hi - lo).saturating_add(1))
        })
    }

    /// How many separate runs the set has.
    pub(super) fn runs(&self) -> usize {
        self.0.len()
    }

    /// Whether inserting `lo..=hi` would make another run: no run touches or
    /// overlaps it.
    pub(super) fn grows_by(&self, lo: u64, hi: u64) -> bool {
        let at = self.0.partition_point(|&(_, h)| h.saturating_add(1) < lo);
        self.0
            .get(at)
            .is_none_or(|&(l, _)| l > hi.saturating_add(1))
    }

    pub(super) fn contains(&self, seq: u64) -> bool {
        let at = self.0.partition_point(|&(_, hi)| hi < seq);
        self.0.get(at).is_some_and(|&(lo, _)| lo <= seq)
    }

    pub(super) fn max(&self) -> Option<u64> {
        self.0.last().map(|&(_, hi)| hi)
    }

    /// The largest seq in the set below `seq`.
    pub(super) fn below(&self, seq: u64) -> Option<u64> {
        let at = self.0.partition_point(|&(lo, _)| lo < seq);
        let &(lo, hi) = self.0.get(at.checked_sub(1)?)?;
        Some(hi.min(seq - 1)).filter(|s| *s >= lo)
    }

    /// The smallest seq in the set above `seq`.
    pub(super) fn above(&self, seq: u64) -> Option<u64> {
        let at = self.0.partition_point(|&(_, hi)| hi <= seq);
        let &(lo, _) = self.0.get(at)?;
        Some(lo.max(seq + 1))
    }

    /// The union of this set and `also`.
    fn union(&self, also: &Ranges) -> Ranges {
        Ranges::merged(self.0.iter().chain(&also.0).copied().collect())
    }

    /// The largest `n` with every seq of `1..=n` in the union with `also`.
    pub(super) fn prefix_with(&self, also: &Ranges) -> u64 {
        match self.union(also).0.first() {
            Some(&(1, hi)) => hi,
            _ => 0,
        }
    }

    /// The seqs of `1..=upto` in neither this set nor `also`, as ranges.
    pub(super) fn gaps(&self, upto: u64, also: &Ranges) -> Vec<(u64, u64)> {
        let all = self.union(also);
        let mut out = Vec::new();
        let mut next = 1;
        for &(lo, hi) in &all.0 {
            if lo > upto {
                break;
            }
            if lo > next {
                out.push((next, lo - 1));
            }
            next = hi.saturating_add(1);
        }
        if next <= upto {
            out.push((next, upto));
        }
        out
    }

    #[cfg(test)]
    pub(super) fn to_vec(&self) -> Vec<(u64, u64)> {
        self.0.clone()
    }

    /// Every seq in the set, ascending.
    pub(super) fn seqs(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.iter().flat_map(|&(lo, hi)| lo..=hi)
    }

    fn take(input: &mut Bytes) -> Option<Ranges> {
        let mut ranges = Ranges::default();
        for (lo, hi) in take_pairs(input)? {
            if lo > hi || ranges.max().is_some_and(|m| lo <= m.saturating_add(1)) {
                return None;
            }
            ranges.0.push((lo, hi));
        }
        Some(ranges)
    }
}

/// A count, then that many pairs of `u64`: how a `ledger/` record keeps
/// ranges and gaps.
fn put_pairs(out: &mut BytesMut, pairs: impl ExactSizeIterator<Item = (u64, u64)>) {
    out.put_u32(pairs.len() as u32);
    for (a, b) in pairs {
        out.put_u64(a);
        out.put_u64(b);
    }
}

fn take_pairs(input: &mut Bytes) -> Option<Vec<(u64, u64)>> {
    let n = (input.remaining() >= 4).then(|| input.get_u32())? as usize;
    if input.remaining() < n.checked_mul(16)? {
        return None;
    }
    Some((0..n).map(|_| (input.get_u64(), input.get_u64())).collect())
}

/// What the log keeps of one device of the space.
#[derive(Clone, Debug)]
pub(super) struct Dev {
    /// The device's person: the namespace of the context that vouched for
    /// its key, as of the last entry taken from it.
    pub person: Name,
    /// Whether the device may act as an owner device where its person owns
    /// the space ([`crate::trust::owner_capable`]), as of the last entry
    /// taken from it.
    pub owner_capable: bool,
    /// The seqs with a marker: every verified entry, applied or not.
    pub held: Ranges,
    /// The gap statements that count: seq of the admitted, non-equivocal
    /// entry that stated one → the `PREV_SEQ` it named. What it declares
    /// absent is `(PREV_SEQ + 1, seq - 1)`.
    pub gaps: BTreeMap<u64, u64>,
    /// How many held entries have a status other than closed: refused,
    /// unreadable, waiting, evidence. The rest were admitted.
    pub nonvouching: u64,
}

impl Dev {
    pub(super) fn new(person: Name, owner_capable: bool) -> Dev {
        Dev {
            person,
            owner_capable,
            held: Ranges::default(),
            gaps: BTreeMap::new(),
            nonvouching: 0,
        }
    }

    /// The highest seq held of it. A counter heard raises nothing here.
    pub(super) fn high(&self) -> u64 {
        self.held.max().unwrap_or(0)
    }

    /// The seqs the counting gap statements declared absent.
    pub(super) fn voids(&self) -> Ranges {
        let runs = self.gaps.iter().map(|(&seq, &prev)| (prev + 1, seq - 1));
        Ranges::merged(runs.collect())
    }

    /// The `ledger/<S>/<device>` record.
    pub(super) fn record(&self) -> Bytes {
        let person = self.person.encode_to_tlv();
        let mut out = BytesMut::new();
        out.put_u16(person.len() as u16);
        out.put_slice(&person);
        put_pairs(&mut out, self.held.0.iter().copied());
        put_pairs(&mut out, self.gaps.iter().map(|(&seq, &prev)| (seq, prev)));
        out.put_u8(u8::from(self.owner_capable));
        out.freeze()
    }

    /// The device a record says.
    pub(super) fn from_record(record: &Bytes) -> Option<Dev> {
        let mut input = record.clone();
        if input.remaining() < 2 {
            return None;
        }
        let len = input.get_u16() as usize;
        if input.remaining() < len {
            return None;
        }
        let person = Name::decode_from_tlv(input.split_to(len)).ok()?;
        let held = Ranges::take(&mut input)?;
        let mut gaps = BTreeMap::new();
        for (seq, prev_seq) in take_pairs(&mut input)? {
            if prev_seq.checked_add(1)? >= seq || gaps.insert(seq, prev_seq).is_some() {
                return None;
            }
        }
        // The flag follows the pairs; a record from before it was kept (the
        // rule of spec §9.9 version 0) reads as "owner device", which the
        // one re-assessment at open settles.
        let owner_capable = input.first().is_none_or(|&flag| flag != 0);
        Some(Dev {
            held,
            gaps,
            ..Dev::new(person, owner_capable)
        })
    }
}

/// Why a held entry is not applied: the `status/` record. An applied entry
/// has none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Status {
    /// Sealed in an epoch whose key is not held: opens when it arrives.
    Closed,
    /// Its writer was removed and the cut's chain is not whole: judged again
    /// when the missing links arrive. Never applied meanwhile.
    Waiting,
    /// It verifies and does not decode: recorded so a chain walk through it
    /// completes and nobody fetches it again.
    Unreadable,
    /// Refused for what it carries.
    Refused(Refusal),
}

impl Status {
    /// The one octet of the `status/` record: the kind, nothing more. What a
    /// refusal says besides its kind (the seq a cut keeps to, the judge's
    /// text) is told to the host when the refusal is made and read from no
    /// record, so none is stored; a status read back has those payloads
    /// empty and compares by its code.
    pub(super) fn code(&self) -> u8 {
        match self {
            Status::Closed => 1,
            Status::Waiting => 2,
            Status::Unreadable => 3,
            Status::Refused(Refusal::NotMember) => 4,
            Status::Refused(Refusal::OutsideCut(_)) => 5,
            Status::Refused(Refusal::Unsealed) => 6,
            Status::Refused(Refusal::Sealed) => 7,
            Status::Refused(Refusal::Untrusted { .. }) => 8,
            Status::Refused(Refusal::Chain) => 10,
            Status::Refused(Refusal::NotOwnerDevice) => 12,
            Status::Refused(Refusal::NotOwnerEpoch) => 13,
            // The rest are never kept as a status (Lapsed and Suspected are
            // not recorded); they read back as the refusal that closes a
            // copy's way in.
            Status::Refused(_) => 11,
        }
    }

    pub(super) fn decode(record: &[u8], device: &Name) -> Option<Status> {
        Some(match record.first()? {
            1 => Status::Closed,
            2 => Status::Waiting,
            3 => Status::Unreadable,
            4 => Status::Refused(Refusal::NotMember),
            5 => Status::Refused(Refusal::OutsideCut(Cut {
                device: device.clone(),
                keeps_to: 0,
            })),
            6 => Status::Refused(Refusal::Unsealed),
            7 => Status::Refused(Refusal::Sealed),
            8 => Status::Refused(Refusal::Untrusted { why: String::new() }),
            10 => Status::Refused(Refusal::Chain),
            11 => Status::Refused(Refusal::BadSignature),
            12 => Status::Refused(Refusal::NotOwnerDevice),
            13 => Status::Refused(Refusal::NotOwnerEpoch),
            _ => return None,
        })
    }

    /// Whether judging the entry again can change what it is: a refusal
    /// that depends on what is held (membership, a cut, the space's seal, a
    /// key) can; one about the entry itself (its bytes, its chain, its
    /// number) cannot.
    pub(super) fn can_change(&self) -> bool {
        match self {
            Status::Closed | Status::Waiting => true,
            Status::Unreadable => false,
            Status::Refused(why) => matches!(
                why,
                Refusal::NotMember
                    | Refusal::NotOwnerDevice
                    | Refusal::NotOwnerEpoch
                    | Refusal::OutsideCut(_)
                    | Refusal::Unsealed
                    | Refusal::Sealed
                    | Refusal::Untrusted { .. }
            ),
        }
    }
}

/// What a removal cut keeps of one device: the seqs reachable from its tips
/// by `PREV`/`PREV_SEQ` through markers, and where that walk stopped for
/// want of a marker.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Kept {
    /// The tips the cut names for the device.
    pub tips: Vec<Link>,
    /// The next link of each chain not walked to its first entry: the entry
    /// the chain names there, which is not held (or is held as other bytes).
    pub frontier: Vec<Link>,
    /// The seqs reached.
    pub ranges: Ranges,
}

impl Kept {
    /// The ancestry of `tips`, walked as far as the markers go.
    pub(super) fn compute(
        store: &dyn DataStore,
        device: &Name,
        space: &Name,
        tips: Vec<Link>,
    ) -> Kept {
        let mut kept = Kept {
            frontier: tips.clone(),
            tips,
            ranges: Ranges::default(),
        };
        kept.advance(store, device, space);
        kept
    }

    /// Walk on from every link the chain was waiting at, through the
    /// `verified/` markers alone (no entry is read, so nothing is decoded):
    /// each entry reached is kept. A walk ends at the chain's first entry,
    /// and at a marker that cannot be read or does not link to a lower seq
    /// (nothing more to wait for), or at a link whose marker is not held or
    /// records other bytes than the chain names there: that link is the
    /// frontier, the entry to fetch. Call it when an entry of the device
    /// arrived.
    pub(super) fn advance(&mut self, store: &dyn DataStore, device: &Name, space: &Name) {
        for mut at in std::mem::take(&mut self.frontier) {
            let stopped = loop {
                let key = Kind::VERIFIED.of(&log_name(device, space, at.seq));
                let Some(wire) = store.get(&key) else {
                    break Some(at);
                };
                let Some(m) = Marker::decode(&wire) else {
                    break None;
                };
                if m.signed_digest != at.digest {
                    break Some(at);
                }
                let genesis = m.prev == [0; 32] && m.prev_seq == 0;
                if !genesis && (m.prev_seq == 0 || m.prev_seq >= at.seq) {
                    break None;
                }
                self.ranges.insert(at.seq);
                if genesis {
                    break None;
                }
                at = Link {
                    seq: m.prev_seq,
                    digest: m.prev,
                };
            };
            if let Some(next) = stopped
                && !self.frontier.contains(&next)
            {
                self.frontier.push(next);
            }
        }
    }

    /// The highest seq the cut keeps of the device.
    pub(super) fn keeps_to(&self) -> u64 {
        self.tips.iter().map(|t| t.seq).max().unwrap_or(0)
    }

    /// What the cut says of the entry `id`: `Ok` when it is on a kept chain
    /// as the very bytes the chain names. Else the status it is held under:
    /// waiting while the chain below it is not whole (undecided until the
    /// missing links arrive; never accepted meanwhile), refused when it is
    /// off every kept chain or other bytes than the chain names.
    pub(super) fn keeps(
        &self,
        store: &dyn DataStore,
        space: &Name,
        id: &EntryRef,
    ) -> Result<(), Status> {
        let (device, seq) = (&id.device, id.seq);
        let outside = || {
            Status::Refused(Refusal::OutsideCut(Cut {
                device: device.clone(),
                keeps_to: self.keeps_to(),
            }))
        };
        if let Some(f) = self.frontier.iter().find(|f| f.seq == seq)
            && f.digest == id.digest
        {
            return Ok(());
        }
        if self.ranges.contains(seq) {
            return match Marker::read(store, device, space, seq) {
                Some(m) if m.signed_digest == id.digest => Ok(()),
                _ => Err(outside()),
            };
        }
        Err(if self.frontier.iter().any(|f| seq < f.seq) {
            Status::Waiting
        } else {
            outside()
        })
    }
}
