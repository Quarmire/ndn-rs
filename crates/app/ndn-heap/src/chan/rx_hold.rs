//! The hold of channel frames whose channel id this device holds no session of (yet)
//! (docs/specs/channel.md, The receiver).
//!
//! A sender queues `HELLO`, its binds, its standing values and a `Window`'s replay when it builds
//! the session Data, and the stream carries them on a path of its own: they can reach the receiver
//! before it has judged the Data and installed the session. A stream frame cannot be asked for
//! again, so the receiver keeps such frames, **copied** (a frame is kept in an allocation of its
//! own, not as a slice of the host's read buffer), at most 64 frames and 512 KiB in all and at most
//! 2 s each, and takes them in arrival order when a session of that id is installed.
//!
//! A held frame is not decrypted and decides nothing: it is bytes with a header that passed the
//! checks that need no key. The hold is pure state; every operation takes the instant it happens at
//! (a monotonic clock the caller reads, so a test moves it by hand), and nothing runs on a timer: a
//! frame, a session's install, an `Items` poll and the node's maintenance pass sweep it.

use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;

use crate::rt::Instant;

/// The most frames held in all.
pub(crate) const FRAMES: usize = 64;

/// The most octets held in all.
pub(crate) const BYTES: usize = 512 * 1024;

/// How long a frame is held.
pub(crate) const FOR: Duration = Duration::from_secs(2);

/// A frame the hold gives back.
pub(crate) struct Held {
    pub(crate) frame: Bytes,
    /// The face it came over.
    pub(crate) ingress: u64,
}

struct Entry {
    channel: u64,
    frame: Bytes,
    ingress: u64,
    at: Instant,
}

/// The hold is full: 64 frames or 512 KiB.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Full;

/// The frames of unknown channels, in arrival order.
#[derive(Default)]
pub(crate) struct Hold {
    entries: VecDeque<Entry>,
    bytes: usize,
}

impl Hold {
    /// Drop what has been held [`FOR`] or more at `now`; returns how many.
    pub(crate) fn sweep(&mut self, now: Instant) -> usize {
        let mut dropped = 0;
        while let Some(front) = self.entries.front() {
            if now.saturating_duration_since(front.at) < FOR {
                break;
            }
            self.bytes -= front.frame.len();
            self.entries.pop_front();
            dropped += 1;
        }
        dropped
    }

    /// Keep a copy of `frame`, which belongs to channel `channel`. The caller sweeps first.
    pub(crate) fn hold(
        &mut self,
        channel: u64,
        frame: &[u8],
        ingress: u64,
        now: Instant,
    ) -> Result<(), Full> {
        if self.entries.len() >= FRAMES || self.bytes + frame.len() > BYTES {
            return Err(Full);
        }
        self.bytes += frame.len();
        self.entries.push_back(Entry {
            channel,
            frame: Bytes::copy_from_slice(frame),
            ingress,
            at: now,
        });
        Ok(())
    }

    /// Take the frames held for `channel`, in the order they arrived; the others stay.
    pub(crate) fn take(&mut self, channel: u64) -> Vec<Held> {
        let mut taken = Vec::new();
        let mut kept = VecDeque::with_capacity(self.entries.len());
        for entry in self.entries.drain(..) {
            if entry.channel == channel {
                self.bytes -= entry.frame.len();
                taken.push(Held {
                    frame: entry.frame,
                    ingress: entry.ingress,
                });
            } else {
                kept.push_back(entry);
            }
        }
        self.entries = kept;
        taken
    }

    /// How many frames are held, and their octets.
    pub(crate) fn size(&self) -> (usize, usize) {
        (self.entries.len(), self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(first: u8, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        v[0] = first;
        v
    }

    #[test]
    fn at_most_64_frames_are_held() {
        let (mut hold, t0) = (Hold::default(), Instant::now());
        for i in 0..FRAMES as u64 {
            assert_eq!(hold.hold(i, &frame(0, 50), 1, t0), Ok(()));
        }
        assert_eq!(hold.hold(99, &frame(0, 50), 1, t0), Err(Full));
        assert_eq!(hold.size().0, FRAMES);
    }

    #[test]
    fn at_most_512_kib_are_held_in_all() {
        let (mut hold, t0) = (Hold::default(), Instant::now());
        assert_eq!(hold.hold(1, &frame(0, BYTES - 100), 1, t0), Ok(()));
        assert_eq!(hold.hold(2, &frame(0, 101), 1, t0), Err(Full));
        assert_eq!(hold.hold(2, &frame(0, 100), 1, t0), Ok(()));
        assert_eq!(hold.size(), (2, BYTES));
        assert_eq!(hold.hold(3, &frame(0, 1), 1, t0), Err(Full));
    }

    #[test]
    fn a_frame_is_held_two_seconds_and_no_longer() {
        let (mut hold, t0) = (Hold::default(), Instant::now());
        hold.hold(1, &frame(0, 50), 1, t0).unwrap();
        hold.hold(2, &frame(0, 50), 1, t0 + Duration::from_millis(1500))
            .unwrap();
        assert_eq!(hold.sweep(t0 + Duration::from_millis(1999)), 0);
        assert_eq!(hold.sweep(t0 + Duration::from_secs(2)), 1);
        assert_eq!(hold.size(), (1, 50));
        assert_eq!(hold.sweep(t0 + Duration::from_millis(3500)), 1);
        assert_eq!(hold.size(), (0, 0));
    }

    #[test]
    fn the_frames_of_a_channel_come_back_in_arrival_order_and_the_others_stay() {
        let (mut hold, t0) = (Hold::default(), Instant::now());
        for (channel, tag) in [(7, 1), (8, 2), (7, 3), (9, 4), (7, 5)] {
            hold.hold(channel, &frame(tag, 60), tag.into(), t0).unwrap();
        }
        let taken = hold.take(7);
        assert_eq!(
            taken.iter().map(|h| h.frame[0]).collect::<Vec<_>>(),
            [1, 3, 5]
        );
        assert_eq!(
            taken.iter().map(|h| h.ingress).collect::<Vec<_>>(),
            [1, 3, 5],
            "with the face each came over"
        );
        assert_eq!(hold.size(), (2, 120));
        assert!(hold.take(7).is_empty());
        assert_eq!(hold.take(9).len(), 1);
    }

    #[test]
    fn a_held_frame_is_a_copy() {
        let (mut hold, t0) = (Hold::default(), Instant::now());
        let big = Bytes::from(vec![5u8; 4096]);
        hold.hold(1, &big[..60], 1, t0).unwrap();
        drop(big);
        let held = hold.take(1);
        assert_eq!(held[0].frame.len(), 60);
        assert_eq!(held[0].frame[0], 5);
    }
}
