//! The hold of channel frames whose channel id this device holds no session of (yet)
//! (docs/specs/channel.md, The receiver).
//!
//! A sender queues `HELLO`, its binds, its standing values and a `Window`'s replay when it builds
//! the session Data, and the stream carries them on a path of its own: they can reach the receiver
//! before it has judged the Data and installed the session. A stream frame cannot be asked for
//! again, so the receiver keeps such frames, **copied** (a frame is kept in an allocation of its
//! own, not as a slice of the host's read buffer), and takes them in arrival order when a session
//! of that id is installed. Only the stream's frames are held: a datagram that is early is lost, as
//! a datagram may be (the caller decides, by the frame's class).
//!
//! **Bounds, and who they are shared with.** A frame is not authenticated, so any face can fill
//! the hold with frames of channel ids it makes up. The hold is therefore bounded **per face**
//! ([`INGRESS_FRAMES`] frames and [`INGRESS_BYTES`] octets: a frame that does not fit its own
//! face's share is refused, so the earliest frames of a face, the `HELLO` and the binds, are the
//! ones kept) and **in all** ([`FRAMES`] and [`BYTES`], which cover the stream frame a face grants,
//! [`STREAM_FRAME_GRANT`]). When the node's bound is reached, the oldest frame of the face that
//! holds the most is pushed out for a frame of a face that holds less; if the arriving frame's own
//! face holds the most, the arriving frame is refused. A face that floods the hold can therefore
//! never keep another face's early frames out. A frame is held at most [`FOR`].
//!
//! A held frame is not decrypted and decides nothing: it is bytes with a header that passed the
//! checks that need no key. The hold is pure state; every operation takes the instant it happens at
//! (a monotonic clock the caller reads, so a test moves it by hand), and nothing runs on a timer: a
//! frame, a session's install, an `Items` poll and the node's maintenance pass sweep it.

use std::cmp::Reverse;
use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;
use ndn_transport::side_header::STREAM_FRAME_GRANT;

use crate::rt::Instant;

/// The most octets one face's held frames take: two stream frames of the grant.
pub(crate) const INGRESS_BYTES: usize = 2 * STREAM_FRAME_GRANT;

/// The most frames one face has held.
pub(crate) const INGRESS_FRAMES: usize = 16;

/// The most octets held in all: four stream frames of the grant, so two faces can each hold their
/// two and a third face still gets one by pushing out the oldest of the largest.
pub(crate) const BYTES: usize = 4 * STREAM_FRAME_GRANT;

/// The most frames held in all.
pub(crate) const FRAMES: usize = 64;

const _: () = assert!(
    INGRESS_BYTES >= STREAM_FRAME_GRANT && BYTES >= 2 * INGRESS_BYTES && FRAMES > INGRESS_FRAMES,
    "a frame of the grant must fit a face's share, and the node must hold more than one face's"
);

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

/// Why a frame was not held. Nothing was changed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The frame is longer than a face's share ([`INGRESS_BYTES`]).
    TooLarge,
    /// The face that sent it holds its share already ([`INGRESS_FRAMES`] frames or
    /// [`INGRESS_BYTES`] octets).
    Ingress,
    /// The node's hold is full and the face that sent it holds the most of it.
    Largest,
}

impl Refused {
    /// What happened and what to do, for a log.
    pub(crate) fn why(&self) -> &'static str {
        match self {
            Refused::TooLarge => {
                "the frame is larger than one face's share of the hold, so it can only be delivered \
                 once a session of its channel is installed: have the sender make the session \
                 known before it sends frames this large"
            }
            Refused::Ingress => {
                "this face holds its whole share of early frames already: the frames it sent \
                 first are kept, and the sender's later ones are lost until its session is installed"
            }
            Refused::Largest => {
                "the hold is full and this face holds the most of it: a face that sends fewer \
                 early frames is served first, so ask the sender again once the session is \
                 installed"
            }
        }
    }
}

/// What one face holds, while a frame is being made room for.
struct Face {
    ingress: u64,
    frames: usize,
    bytes: usize,
    /// Positions of its frames in the hold, oldest first, and their lengths.
    at: VecDeque<(usize, usize)>,
}

impl Face {
    fn new(ingress: u64) -> Self {
        Self {
            ingress,
            frames: 0,
            bytes: 0,
            at: VecDeque::new(),
        }
    }

    fn add(&mut self, at: usize, len: usize) {
        self.frames += 1;
        self.bytes += len;
        self.at.push_back((at, len));
    }

    /// Its share of the hold: the larger of its fraction of the frames and of the octets (both
    /// over the common denominator `FRAMES * BYTES`).
    fn share(&self) -> usize {
        (self.frames * BYTES).max(self.bytes * FRAMES)
    }

    /// The position of its oldest frame; `usize::MAX` when it holds none.
    fn oldest(&self) -> usize {
        self.at.front().map_or(usize::MAX, |&(at, _)| at)
    }

    fn pop_oldest(&mut self) -> (usize, usize) {
        let (at, len) = self
            .at
            .pop_front()
            .expect("a face with a share holds a frame");
        self.frames -= 1;
        self.bytes -= len;
        (at, len)
    }
}

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

    /// Keep a copy of `frame`, which belongs to channel `channel` and came over face `ingress`.
    /// The caller sweeps first. Returns how many frames of other faces were pushed out to make
    /// room: when the node's bound is reached, the oldest frame of the face that holds the most
    /// goes, and the arriving frame is refused instead if its own face holds the most (nothing
    /// is pushed out then).
    pub(crate) fn hold(
        &mut self,
        channel: u64,
        frame: &[u8],
        ingress: u64,
        now: Instant,
    ) -> Result<usize, Refused> {
        let len = frame.len();
        if len > INGRESS_BYTES {
            return Err(Refused::TooLarge);
        }
        let (own_frames, own_bytes) = self.share_of(ingress);
        if own_frames >= INGRESS_FRAMES || own_bytes + len > INGRESS_BYTES {
            return Err(Refused::Ingress);
        }
        let evict = self.room_for(ingress, len)?;
        for &at in evict.iter().rev() {
            if let Some(gone) = self.entries.remove(at) {
                self.bytes -= gone.frame.len();
            }
        }
        self.bytes += len;
        self.entries.push_back(Entry {
            channel,
            frame: Bytes::copy_from_slice(frame),
            ingress,
            at: now,
        });
        Ok(evict.len())
    }

    /// The entries (by position, oldest first) to push out so that a frame of `len` octets from
    /// face `ingress` fits the node's bound; none when it fits. `Largest` when, after pushing
    /// out what the larger faces hold, the arriving frame's own face is the one that holds the
    /// most: nothing is changed by this.
    fn room_for(&self, ingress: u64, len: usize) -> Result<Vec<usize>, Refused> {
        let (mut frames, mut bytes) = (self.entries.len(), self.bytes);
        if frames < FRAMES && bytes + len <= BYTES {
            return Ok(Vec::new());
        }
        // What each face holds, and where its frames are: the arriving face is among them.
        let mut faces: Vec<Face> = Vec::new();
        for (at, entry) in self.entries.iter().enumerate() {
            let face = match faces.iter().position(|f| f.ingress == entry.ingress) {
                Some(face) => face,
                None => {
                    faces.push(Face::new(entry.ingress));
                    faces.len() - 1
                }
            };
            faces[face].add(at, entry.frame.len());
        }
        if !faces.iter().any(|f| f.ingress == ingress) {
            faces.push(Face::new(ingress));
        }
        let mut evict = Vec::new();
        while frames >= FRAMES || bytes + len > BYTES {
            // The largest share; a tie goes to the arriving face (its frame is refused rather
            // than pushing out an equal's), then to the face whose frame has waited longest.
            let largest = faces
                .iter_mut()
                .max_by_key(|f| (f.share(), f.ingress == ingress, Reverse(f.oldest())))
                .expect("the arriving face is among them");
            if largest.ingress == ingress {
                return Err(Refused::Largest);
            }
            let (at, octets) = largest.pop_oldest();
            evict.push(at);
            frames -= 1;
            bytes -= octets;
        }
        // Positions of one face's frames come oldest first, but the faces interleave.
        evict.sort_unstable();
        Ok(evict)
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

    /// How many frames face `ingress` has held, and their octets.
    pub(crate) fn share_of(&self, ingress: u64) -> (usize, usize) {
        self.entries
            .iter()
            .filter(|e| e.ingress == ingress)
            .fold((0, 0), |(frames, bytes), e| {
                (frames + 1, bytes + e.frame.len())
            })
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
    fn a_face_holds_at_most_16_frames_and_two_grants() {
        let (mut hold, t0) = (Hold::default(), Instant::now());
        for i in 0..INGRESS_FRAMES as u64 {
            assert_eq!(hold.hold(i, &frame(0, 50), 1, t0), Ok(0));
        }
        assert_eq!(hold.hold(99, &frame(0, 50), 1, t0), Err(Refused::Ingress));
        assert_eq!(hold.share_of(1).0, INGRESS_FRAMES);

        let mut hold = Hold::default();
        assert_eq!(hold.hold(1, &frame(0, INGRESS_BYTES - 100), 1, t0), Ok(0));
        assert_eq!(hold.hold(2, &frame(0, 101), 1, t0), Err(Refused::Ingress));
        assert_eq!(hold.hold(2, &frame(0, 100), 1, t0), Ok(0));
        assert_eq!(hold.share_of(1), (2, INGRESS_BYTES));
        assert_eq!(hold.hold(3, &frame(0, 1), 1, t0), Err(Refused::Ingress));
        // Another face is not held back by it.
        assert_eq!(hold.hold(3, &frame(0, 1), 2, t0), Ok(0));
    }

    #[test]
    fn a_frame_larger_than_a_faces_share_is_refused_and_one_of_the_grant_fits() {
        let (mut hold, t0) = (Hold::default(), Instant::now());
        assert_eq!(
            hold.hold(1, &frame(0, INGRESS_BYTES + 1), 1, t0),
            Err(Refused::TooLarge)
        );
        assert_eq!(hold.size(), (0, 0));
        assert_eq!(
            hold.hold(1, &frame(0, STREAM_FRAME_GRANT), 1, t0),
            Ok(0),
            "the frame a face grants fits"
        );
    }

    #[test]
    fn the_node_holds_at_most_64_frames_and_4_grants_in_all() {
        let (mut hold, t0) = (Hold::default(), Instant::now());
        // Four faces at their 16 frames: the frames' bound.
        for face in 1..=4u64 {
            for i in 0..INGRESS_FRAMES as u64 {
                assert_eq!(hold.hold(face * 100 + i, &frame(0, 50), face, t0), Ok(0));
            }
        }
        assert_eq!(hold.size().0, FRAMES);
        // The octets' bound: two faces at their two frames of the grant.
        let mut hold = Hold::default();
        for face in 1..=2u64 {
            for i in 0..2u64 {
                assert_eq!(
                    hold.hold(face * 100 + i, &frame(0, STREAM_FRAME_GRANT), face, t0),
                    Ok(0)
                );
            }
        }
        assert_eq!(hold.size(), (4, BYTES));
    }

    #[test]
    fn when_full_the_oldest_frame_of_the_largest_face_goes_and_the_octets_are_kept_true() {
        let (mut hold, t0) = (Hold::default(), Instant::now());
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        // Four faces hold 16 frames each, face 1's the oldest: 64 frames.
        let mut tag = 0u8;
        for face in 1..=4u64 {
            for _ in 0..INGRESS_FRAMES {
                tag += 1;
                let frame = frame(tag, 40 + face as usize);
                hold.hold(u64::from(tag), &frame, face, at(face)).unwrap();
            }
        }
        let before = hold.size();
        assert_eq!(before.0, FRAMES);
        // All four hold 16: the tie goes to the face whose frame has waited longest, face 1; its
        // oldest frame (channel 1) is pushed out for face 5's.
        assert_eq!(hold.hold(500, &frame(0, 10), 5, at(10)), Ok(1));
        assert!(
            hold.take(1).is_empty(),
            "channel 1 was face 1's oldest frame"
        );
        assert_eq!(hold.share_of(1).0, INGRESS_FRAMES - 1);
        assert_eq!(hold.share_of(5), (1, 10));
        let octets: usize = (1..=5).map(|face| hold.share_of(face).1).sum();
        assert_eq!(
            hold.size(),
            (FRAMES, octets),
            "the octets count what is held"
        );
    }

    #[test]
    fn a_frame_from_the_face_that_holds_the_most_is_refused_and_nothing_is_pushed_out() {
        let (mut hold, t0) = (Hold::default(), Instant::now());
        let mut channel = 0;
        for (face, frames) in [(1u64, 15), (2, 15), (3, 15), (4, 15), (5, 4)] {
            for _ in 0..frames {
                channel += 1;
                hold.hold(channel, &frame(0, 50), face, t0).unwrap();
            }
        }
        let before = hold.size();
        // Face 1 ties with the largest: it is its own frame that is refused.
        assert_eq!(hold.hold(900, &frame(0, 50), 1, t0), Err(Refused::Largest));
        assert_eq!(hold.size(), before);
        assert_eq!(hold.share_of(1).0, 15);
        // A face that holds less pushes one out instead.
        assert_eq!(hold.hold(901, &frame(0, 50), 5, t0), Ok(1));
    }

    #[test]
    fn a_share_is_the_larger_of_a_faces_fraction_of_the_frames_and_of_the_octets() {
        let (mut hold, t0) = (Hold::default(), Instant::now());
        // Faces 1 to 3 hold 16 small frames each, face 4 one frame of 1.5 grants, face 5 15
        // small ones: 64 frames. By octets face 4 holds more than any other face: 3/8 of the
        // octets against 16/64 of the frames.
        let mut channel = 0;
        for face in 1..=3u64 {
            for _ in 0..16 {
                channel += 1;
                hold.hold(channel, &frame(0, 50), face, t0).unwrap();
            }
        }
        hold.hold(
            1_000,
            &frame(0, STREAM_FRAME_GRANT + STREAM_FRAME_GRANT / 2),
            4,
            t0,
        )
        .unwrap();
        for _ in 0..15 {
            channel += 1;
            hold.hold(channel, &frame(0, 50), 5, t0).unwrap();
        }
        assert_eq!(hold.size().0, FRAMES);
        assert_eq!(hold.hold(2_000, &frame(0, 50), 6, t0), Ok(1));
        assert_eq!(hold.share_of(4), (0, 0), "face 4's one large frame went");
        assert_eq!(hold.share_of(1).0, 16, "and no small one did");
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
