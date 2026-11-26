//! What a sender keeps for receivers that join later (docs/specs/channel.md, Modes and Standing):
//! the window of a `Window` channel, and the standing values.
//!
//! Both are pure state; every operation takes the instant it happens at.

use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;

use super::verbs::{STAND_MAX, STANDING_BYTES_MAX, STANDING_NAMES_MAX, Window};
use crate::rt::Instant;

/// A message the window holds: what was sent.
#[derive(Clone, Debug)]
pub(crate) struct Held {
    /// The sequence it went out under.
    pub(crate) seq: u64,
    /// The name's octets.
    pub(crate) name: Bytes,
    /// The payload.
    pub(crate) payload: Bytes,
    /// When it was sent.
    pub(crate) at: Instant,
}

/// The last messages a `Window` sender sent: at most `messages`, `bytes` and `age`, whichever is
/// least.
#[derive(Default)]
pub(crate) struct History {
    items: VecDeque<Held>,
    bytes: usize,
}

impl History {
    /// Messages held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    /// Payload octets held.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    fn prune(&mut self, window: &Window, now: Instant) {
        while let Some(front) = self.items.front() {
            let over = self.items.len() > window.messages
                || self.bytes > window.bytes
                || now.saturating_duration_since(front.at) > window.age;
            if !over {
                break;
            }
            if let Some(gone) = self.items.pop_front() {
                self.bytes -= gone.payload.len();
            }
        }
    }

    /// Hold a message that was just sent; the oldest that no longer fit the window are forgotten.
    pub(crate) fn record(&mut self, held: Held, window: &Window, now: Instant) {
        self.bytes += held.payload.len();
        self.items.push_back(held);
        self.prune(window, now);
    }

    /// What a joiner that needs everything from `since` on (everything held when `None`) is given,
    /// oldest first.
    pub(crate) fn since(&mut self, since: Option<u64>, window: &Window, now: Instant) -> Vec<Held> {
        self.prune(window, now);
        self.items
            .iter()
            .filter(|h| since.is_none_or(|s| h.seq >= s))
            .cloned()
            .collect()
    }
}

/// A value that stands for a late receiver.
#[derive(Clone, Debug)]
pub(crate) struct Stood {
    /// The sequence the emission took.
    pub(crate) seq: u64,
    /// The name's octets.
    pub(crate) name: Bytes,
    /// The payload.
    pub(crate) payload: Bytes,
    expires: Instant,
}

/// What a stand is refused for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StandFull {
    /// [`STANDING_NAMES_MAX`] names already stand.
    Names {
        /// How many would.
        would_be: usize,
    },
    /// [`STANDING_BYTES_MAX`] octets already stand.
    Bytes {
        /// How many would.
        would_be: usize,
    },
}

/// The last emission of each name that stood, until its lifetime passes.
#[derive(Default)]
pub(crate) struct Standing {
    by_name: super::FastMap<Bytes, Stood>,
    bytes: usize,
}

impl Standing {
    /// Names standing (some may have expired and not been purged yet).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Payload octets standing.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    fn purge(&mut self, now: Instant) {
        let bytes = &mut self.bytes;
        self.by_name.retain(|_, s| {
            let live = now < s.expires;
            if !live {
                *bytes -= s.payload.len();
            }
            live
        });
    }

    /// Whether a payload of `len` octets could stand as the last emission of `name` now, without
    /// changing what stands (expired values are purged).
    pub(crate) fn check(&mut self, name: &[u8], len: usize, now: Instant) -> Result<(), StandFull> {
        self.purge(now);
        let replaced = self.by_name.get(name).map_or(0, |s| s.payload.len());
        if !self.by_name.contains_key(name) && self.by_name.len() >= STANDING_NAMES_MAX {
            return Err(StandFull::Names {
                would_be: self.by_name.len() + 1,
            });
        }
        let would_be = self.bytes - replaced + len;
        if would_be > STANDING_BYTES_MAX {
            return Err(StandFull::Bytes { would_be });
        }
        Ok(())
    }

    /// `payload` is the last emission of `name` and stands for `lifetime` (at most [`STAND_MAX`]).
    /// Refused when it would make more than [`STANDING_NAMES_MAX`] names or
    /// [`STANDING_BYTES_MAX`] octets stand; the name's earlier standing value stays then.
    pub(crate) fn set(
        &mut self,
        name: Bytes,
        seq: u64,
        payload: Bytes,
        lifetime: Duration,
        now: Instant,
    ) -> Result<(), StandFull> {
        self.check(&name, payload.len(), now)?;
        let replaced = self.by_name.get(&name).map_or(0, |s| s.payload.len());
        let would_be = self.bytes - replaced + payload.len();
        let lifetime = lifetime.min(STAND_MAX);
        self.bytes = would_be;
        self.by_name.insert(
            name.clone(),
            Stood {
                seq,
                name,
                payload,
                expires: now + lifetime,
            },
        );
        Ok(())
    }

    /// Whether nothing stands (an expired value that was not purged yet still counts).
    pub(crate) fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// The last emission of `name` did not stand: nothing of it stands any more.
    pub(crate) fn clear(&mut self, name: &[u8]) {
        // Nothing stands for most paths: such an emission hashes nothing here.
        if self.by_name.is_empty() {
            return;
        }
        if let Some(gone) = self.by_name.remove(name) {
            self.bytes -= gone.payload.len();
        }
    }

    /// What stands at `now`, oldest sequence first, each with the whole seconds left (rounded up,
    /// at least one): what a new session is given.
    pub(crate) fn replay(&mut self, now: Instant) -> Vec<(Stood, u64)> {
        self.purge(now);
        let mut out: Vec<(Stood, u64)> = self
            .by_name
            .values()
            .map(|s| {
                let left = s.expires.saturating_duration_since(now);
                (
                    s.clone(),
                    left.as_secs() + u64::from(left.subsec_nanos() > 0),
                )
            })
            .collect();
        out.sort_by_key(|(s, _)| s.seq);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(seq: u64, len: usize, at: Instant) -> Held {
        Held {
            seq,
            name: Bytes::from_static(b"n"),
            payload: Bytes::from(vec![0u8; len]),
            at,
        }
    }

    fn window(messages: usize, bytes: usize, secs: u64) -> Window {
        Window {
            messages,
            bytes,
            age: Duration::from_secs(secs),
        }
    }

    #[test]
    fn a_window_keeps_the_least_of_its_messages_bytes_and_age() {
        let t0 = Instant::now();
        // Messages: the last 3 of 5.
        let w = window(3, 1 << 20, 10);
        let mut h = History::default();
        for seq in 1..=5 {
            h.record(held(seq, 10, t0), &w, t0);
        }
        assert_eq!(
            h.since(None, &w, t0)
                .iter()
                .map(|x| x.seq)
                .collect::<Vec<_>>(),
            [3, 4, 5]
        );
        // Bytes: 100-octet messages in a 250-octet window leave two.
        let w = window(256, 250, 10);
        let mut h = History::default();
        for seq in 1..=5 {
            h.record(held(seq, 100, t0), &w, t0);
        }
        assert_eq!(h.len(), 2);
        assert_eq!(h.bytes(), 200);
        // Age: a message older than the window goes, the newer stay.
        let w = window(256, 1 << 20, 10);
        let mut h = History::default();
        h.record(held(1, 1, t0), &w, t0);
        h.record(
            held(2, 1, t0 + Duration::from_secs(6)),
            &w,
            t0 + Duration::from_secs(6),
        );
        let at = t0 + Duration::from_secs(11);
        assert_eq!(
            h.since(None, &w, at)
                .iter()
                .map(|x| x.seq)
                .collect::<Vec<_>>(),
            [2]
        );
        assert_eq!(h.bytes(), 1);
        // A joiner that needs from a sequence on gets that and later.
        let mut h = History::default();
        for seq in 1..=5 {
            h.record(held(seq, 1, t0), &w, t0);
        }
        assert_eq!(
            h.since(Some(4), &w, t0)
                .iter()
                .map(|x| x.seq)
                .collect::<Vec<_>>(),
            [4, 5]
        );
        assert!(h.since(Some(9), &w, t0).is_empty());
    }

    #[test]
    fn a_message_larger_than_the_window_is_not_kept() {
        let t0 = Instant::now();
        let w = window(256, 50, 10);
        let mut h = History::default();
        h.record(held(1, 100, t0), &w, t0);
        assert_eq!(h.len(), 0);
        assert_eq!(h.bytes(), 0);
    }

    #[test]
    fn the_last_emission_of_a_name_stands_until_its_lifetime_passes() {
        let t0 = Instant::now();
        let mut s = Standing::default();
        let n = Bytes::from_static(b"name");
        s.set(
            n.clone(),
            1,
            Bytes::from_static(b"one"),
            Duration::from_secs(10),
            t0,
        )
        .unwrap();
        s.set(
            n.clone(),
            2,
            Bytes::from_static(b"two!"),
            Duration::from_secs(10),
            t0,
        )
        .unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.bytes(), 4);
        let got = s.replay(t0 + Duration::from_millis(2_500));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.seq, 2);
        assert_eq!(got[0].1, 8, "7.5 s left, rounded up");
        assert!(s.replay(t0 + Duration::from_secs(10)).is_empty());
        assert_eq!(s.bytes(), 0);
        // An emission that did not stand clears it.
        s.set(
            n.clone(),
            3,
            Bytes::from_static(b"x"),
            Duration::from_secs(10),
            t0,
        )
        .unwrap();
        s.clear(&n);
        assert_eq!(s.len(), 0);
        assert_eq!(s.bytes(), 0);
    }

    #[test]
    fn standing_is_limited_to_256_names_and_64_kib() {
        let t0 = Instant::now();
        let mut s = Standing::default();
        for i in 0..256u32 {
            s.set(
                Bytes::from(i.to_be_bytes().to_vec()),
                1,
                Bytes::from_static(b"x"),
                Duration::from_secs(60),
                t0,
            )
            .unwrap();
        }
        assert_eq!(
            s.set(
                Bytes::from_static(b"one more"),
                9,
                Bytes::from_static(b"x"),
                Duration::from_secs(60),
                t0
            ),
            Err(StandFull::Names { would_be: 257 })
        );
        // A name that stands already may be replaced at the limit.
        s.set(
            Bytes::from(0u32.to_be_bytes().to_vec()),
            9,
            Bytes::from_static(b"y"),
            Duration::from_secs(60),
            t0,
        )
        .unwrap();
        // Bytes: 65 KiB of one name is over, and the earlier value of the name stays.
        let mut b = Standing::default();
        let name = Bytes::from_static(b"big");
        b.set(
            name.clone(),
            1,
            Bytes::from_static(b"keep"),
            Duration::from_secs(60),
            t0,
        )
        .unwrap();
        assert_eq!(
            b.set(
                name.clone(),
                2,
                Bytes::from(vec![0; 65 * 1024]),
                Duration::from_secs(60),
                t0
            ),
            Err(StandFull::Bytes {
                would_be: 65 * 1024
            })
        );
        assert_eq!(b.replay(t0)[0].0.payload, Bytes::from_static(b"keep"));
        b.set(
            name,
            3,
            Bytes::from(vec![0; 64 * 1024]),
            Duration::from_secs(60),
            t0,
        )
        .unwrap();
        assert_eq!(b.bytes(), STANDING_BYTES_MAX);
        // Expired entries free their room.
        let later = t0 + Duration::from_secs(61);
        b.set(
            Bytes::from_static(b"other"),
            4,
            Bytes::from(vec![0; 1000]),
            Duration::from_secs(60),
            later,
        )
        .unwrap();
        assert_eq!(b.bytes(), 1000);
    }

    #[test]
    fn a_lifetime_over_an_hour_is_cut_to_an_hour() {
        let t0 = Instant::now();
        let mut s = Standing::default();
        s.set(
            Bytes::from_static(b"n"),
            1,
            Bytes::new(),
            Duration::from_secs(86_400),
            t0,
        )
        .unwrap();
        assert_eq!(s.replay(t0)[0].1, 3600);
    }
}
