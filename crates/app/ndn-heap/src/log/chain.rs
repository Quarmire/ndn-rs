//! What the log keeps in memory of each device's chain, and its records:
//! held seqs as ranges, declared voids, and the ancestry a removal cut keeps.
//!
//! Memory is O(devices + ranges + removed devices): no entry and no marker
//! is held. A marker is read from the store when a decision needs it.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ndn_foundation_types::Name;
use ndn_sync::DataStore;

use crate::error::{Cut, Refusal};
use crate::store::{ChainEnd, Link, Marker, verified_key, walk_chain};
use crate::wire::log_name;

/// A set of seqs as sorted, disjoint, non-adjacent inclusive ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Ranges(Vec<(u64, u64)>);

impl Ranges {
    pub(super) fn insert(&mut self, seq: u64) {
        match self.0.last_mut() {
            Some((_, hi)) if *hi + 1 == seq => *hi = seq,
            Some((_, hi)) if *hi >= seq => self.insert_range(seq, seq),
            _ => self.0.push((seq, seq)),
        }
    }

    pub(super) fn insert_range(&mut self, lo: u64, hi: u64) {
        if lo > hi {
            return;
        }
        self.0.push((lo, hi));
        self.0.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.0.len());
        for &(a, b) in &self.0 {
            match merged.last_mut() {
                Some((_, hi)) if a <= hi.saturating_add(1) => *hi = (*hi).max(b),
                _ => merged.push((a, b)),
            }
        }
        self.0 = merged;
    }

    /// How many seqs the set holds.
    pub(super) fn count(&self) -> u64 {
        self.0.iter().map(|&(lo, hi)| hi - lo + 1).sum()
    }

    pub(super) fn contains(&self, seq: u64) -> bool {
        let at = self.0.partition_point(|&(_, hi)| hi < seq);
        self.0.get(at).is_some_and(|&(lo, _)| lo <= seq)
    }

    pub(super) fn max(&self) -> Option<u64> {
        self.0.last().map(|&(_, hi)| hi)
    }

    /// The largest `n` with every seq of `1..=n` in the set.
    pub(super) fn prefix(&self) -> u64 {
        match self.0.first() {
            Some(&(1, hi)) => hi,
            _ => 0,
        }
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

    /// [`Self::prefix`] of the union with `also`.
    pub(super) fn prefix_with(&self, also: &Ranges) -> u64 {
        let mut all = self.clone();
        for &(a, b) in &also.0 {
            all.insert_range(a, b);
        }
        all.prefix()
    }
    /// The seqs of `1..=upto` in neither this set nor `also`, as ranges.
    pub(super) fn gaps(&self, upto: u64, also: &Ranges) -> Vec<(u64, u64)> {
        let mut all = self.clone();
        for &(a, b) in &also.0 {
            all.insert_range(a, b);
        }
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

    fn put(&self, out: &mut BytesMut) {
        out.put_u32(self.0.len() as u32);
        for &(lo, hi) in &self.0 {
            out.put_u64(lo);
            out.put_u64(hi);
        }
    }

    fn take(input: &mut Bytes) -> Option<Ranges> {
        let n = take_u32(input)? as usize;
        if input.remaining() < n.checked_mul(16)? {
            return None;
        }
        let mut ranges = Ranges::default();
        for _ in 0..n {
            let (lo, hi) = (input.get_u64(), input.get_u64());
            if lo > hi || ranges.max().is_some_and(|m| lo <= m.saturating_add(1)) {
                return None;
            }
            ranges.0.push((lo, hi));
        }
        Some(ranges)
    }
}

fn take_u32(input: &mut Bytes) -> Option<u32> {
    (input.remaining() >= 4).then(|| input.get_u32())
}

fn take_link(input: &mut Bytes) -> Option<Link> {
    if input.remaining() < 40 {
        return None;
    }
    let seq = input.get_u64();
    let mut digest = [0; 32];
    input.copy_to_slice(&mut digest);
    Some(Link { seq, digest })
}

fn put_link(out: &mut BytesMut, link: &Link) {
    out.put_u64(link.seq);
    out.put_slice(&link.digest);
}

/// What the log keeps of one device of the space.
#[derive(Clone, Debug)]
pub(super) struct Dev {
    /// The device's person: the namespace of the context that vouched for
    /// its key, as of the last entry taken from it.
    pub person: Name,
    /// The seqs with a marker: every verified entry, applied or not.
    pub held: Ranges,
    /// The seqs its entries declared absent: `(PREV_SEQ, seq)` of a gap
    /// statement.
    pub voids: Ranges,
    /// The highest seq heard of it (a notice) or held. Never lowered.
    pub high: u64,
    /// The highest held seq and its signed digest; read from its marker.
    pub tip: Option<Link>,
    /// How many held entries have a status other than closed: refused,
    /// unreadable, waiting, evidence. The rest were admitted.
    pub nonvouching: u64,
}

impl Dev {
    pub(super) fn new(person: Name) -> Dev {
        Dev {
            person,
            held: Ranges::default(),
            voids: Ranges::default(),
            high: 0,
            tip: None,
            nonvouching: 0,
        }
    }

    /// The `ledger/<S>/<device>` record.
    pub(super) fn record(&self) -> Bytes {
        let person = self.person.encode_to_tlv();
        let mut out = BytesMut::new();
        out.put_u16(person.len() as u16);
        out.put_slice(&person);
        self.held.put(&mut out);
        self.voids.put(&mut out);
        out.freeze()
    }

    /// The device a record says, without its tip (the marker of its highest
    /// seq is the log's to read).
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
        let voids = Ranges::take(&mut input)?;
        let high = held.max().unwrap_or(0);
        Some(Dev {
            person,
            held,
            voids,
            high,
            tip: None,
            nonvouching: 0,
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
    pub(super) fn encode(&self) -> Bytes {
        let mut out = BytesMut::new();
        match self {
            Status::Closed => out.put_u8(1),
            Status::Waiting => out.put_u8(2),
            Status::Unreadable => out.put_u8(3),
            Status::Refused(Refusal::NotMember) => out.put_u8(4),
            Status::Refused(Refusal::OutsideCut(cut)) => {
                out.put_u8(5);
                out.put_u64(cut.keeps_to);
            }
            Status::Refused(Refusal::Unsealed) => out.put_u8(6),
            Status::Refused(Refusal::Sealed) => out.put_u8(7),
            Status::Refused(Refusal::Untrusted { why }) => {
                out.put_u8(8);
                out.put_slice(why.as_bytes());
            }
            Status::Refused(Refusal::AboveReservation { reserved }) => {
                out.put_u8(9);
                out.put_u64(*reserved);
            }
            Status::Refused(Refusal::Chain) => out.put_u8(10),
            // The rest are never kept as a status (Lapsed and Suspected are
            // not recorded, Rollback is not an entry's); they read back as
            // the refusal that closes a copy's way in.
            Status::Refused(_) => out.put_u8(11),
        }
        out.freeze()
    }

    pub(super) fn decode(record: &[u8], device: &Name) -> Option<Status> {
        let (&code, rest) = record.split_first()?;
        let be = |b: &[u8]| Some(u64::from_be_bytes(b.try_into().ok()?));
        Some(match code {
            1 => Status::Closed,
            2 => Status::Waiting,
            3 => Status::Unreadable,
            4 => Status::Refused(Refusal::NotMember),
            5 => Status::Refused(Refusal::OutsideCut(Cut {
                device: device.clone(),
                keeps_to: be(rest)?,
            })),
            6 => Status::Refused(Refusal::Unsealed),
            7 => Status::Refused(Refusal::Sealed),
            8 => Status::Refused(Refusal::Untrusted {
                why: String::from_utf8_lossy(rest).into_owned(),
            }),
            9 => Status::Refused(Refusal::AboveReservation {
                reserved: be(rest)?,
            }),
            10 => Status::Refused(Refusal::Chain),
            11 => Status::Refused(Refusal::BadSignature),
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

/// What a cut says of one entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Keeps {
    /// On a kept chain, as the very bytes the chain names.
    Yes,
    /// Not on any kept chain, or other bytes than the chain names.
    No,
    /// The chain is not whole below it: undecided until the missing links
    /// arrive. Never accepted meanwhile.
    Waiting,
}

fn marker_at(store: &dyn DataStore, device: &Name, space: &Name, seq: u64) -> Option<Marker> {
    Marker::decode(&store.get(&verified_key(&log_name(device, space, seq)))?)
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

    /// Walk on from every link the chain was waiting at. Call it when an
    /// entry of the device arrived.
    pub(super) fn advance(&mut self, store: &dyn DataStore, device: &Name, space: &Name) {
        let pending = std::mem::take(&mut self.frontier);
        for link in pending {
            let walk = walk_chain(store, device, space, link);
            for l in &walk.links {
                self.ranges.insert(l.seq);
            }
            let next = match walk.end {
                ChainEnd::Genesis | ChainEnd::Corrupt { .. } => None,
                ChainEnd::Diverges { seq, expected, .. } => Some(Link {
                    seq,
                    digest: expected,
                }),
                ChainEnd::Missing { .. } => Some(match walk.links.last() {
                    None => link,
                    Some(last) => {
                        let m = marker_at(store, device, space, last.seq)
                            .expect("a walked link has its marker");
                        Link {
                            seq: m.prev_seq,
                            digest: m.prev,
                        }
                    }
                }),
            };
            if let Some(next) = next
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

    /// What the cut says of the entry `(seq, digest)` of the device.
    pub(super) fn keeps(
        &self,
        store: &dyn DataStore,
        device: &Name,
        space: &Name,
        seq: u64,
        digest: &[u8; 32],
    ) -> Keeps {
        if let Some(f) = self.frontier.iter().find(|f| f.seq == seq)
            && f.digest == *digest
        {
            return Keeps::Yes;
        }
        if self.ranges.contains(seq) {
            return match marker_at(store, device, space, seq) {
                Some(m) if m.signed_digest == *digest => Keeps::Yes,
                _ => Keeps::No,
            };
        }
        if self.frontier.iter().any(|f| seq < f.seq) {
            Keeps::Waiting
        } else {
            Keeps::No
        }
    }

    /// The `kept/<S>/<device>` record.
    pub(super) fn record(&self) -> Bytes {
        let mut out = BytesMut::new();
        out.put_u32(self.tips.len() as u32);
        for t in &self.tips {
            put_link(&mut out, t);
        }
        out.put_u32(self.frontier.len() as u32);
        for f in &self.frontier {
            put_link(&mut out, f);
        }
        self.ranges.put(&mut out);
        out.freeze()
    }

    pub(super) fn from_record(record: &Bytes) -> Option<Kept> {
        let mut input = record.clone();
        let links = |input: &mut Bytes| {
            let n = take_u32(input)? as usize;
            (0..n).map(|_| take_link(input)).collect::<Option<Vec<_>>>()
        };
        let tips = links(&mut input)?;
        let frontier = links(&mut input)?;
        let ranges = Ranges::take(&mut input)?;
        Some(Kept {
            tips,
            frontier,
            ranges,
        })
    }
}
