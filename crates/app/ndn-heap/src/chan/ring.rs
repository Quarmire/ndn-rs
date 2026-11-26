//! The frames a channel sent, and their hashes (channel.md, Checkpoints): the data a checkpoint
//! signs.
//!
//! A sender records, per channel, `(seq0, frame)` for every frame it hands to a carrier: the
//! frame's own `Bytes` (a reference, no copy). The hash `h` a checkpoint signs is the first 16
//! octets of `H(frame octets)`: SHA-256 for a frame of at most 2,048 octets and BLAKE3 above (so
//! nothing is negotiated: the frame's length selects the hash). **It is computed when the ring is
//! drained** (what a checkpoint covers), not when the frame is recorded: nothing reads the hashes
//! before a checkpoint is built (stage 5), and a hash on the writer's path cost a sixth of the
//! writer thread at 1 KiB and 8 KiB (SHAPES-CHANNEL.md 18.x). The ring holds at most 4,096 frames
//! **and** at most [`RING_BYTES`] octets of them (a recorded frame is kept alive by it until it is
//! drained); a frame recorded past either bound pushes out the oldest, which is forgotten and
//! **counted**, so a checkpoint can say how many frames it no longer covers. Nothing here verifies
//! anything: writing the ring is the sender's part, and a checkpoint that signs it is a later
//! stage's.

use std::collections::VecDeque;

use bytes::Bytes;
use sha2::{Digest, Sha256};

/// Octets of a recorded hash.
pub(crate) const HASH_LEN: usize = 16;

/// Frames of at most this many octets are hashed with SHA-256, longer ones
/// with BLAKE3.
pub(crate) const BLAKE3_ABOVE: usize = 2_048;

/// The most frames a channel's ring holds.
pub(crate) const RING_FRAMES: usize = 4_096;

/// The most octets of frames a channel's ring keeps alive: 4 MiB, which holds 4,096 frames of up to
/// 1 KiB (a larger frame makes the ring cover fewer, and the ones it pushes out are counted).
pub(crate) const RING_BYTES: usize = 4 << 20;

/// The checkpoint hash of `frame`: the first 16 octets of SHA-256 (frames of
/// at most 2,048 octets) or BLAKE3 (longer ones).
pub(crate) fn frame_hash(frame: &[u8]) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    if frame.len() <= BLAKE3_ABOVE {
        out.copy_from_slice(&Sha256::digest(frame)[..HASH_LEN]);
    } else {
        out.copy_from_slice(&blake3::hash(frame).as_bytes()[..HASH_LEN]);
    }
    out
}

/// A bounded ring of `(seq0, frame)` for the frames one channel sent since its last checkpoint.
#[derive(Debug)]
pub(crate) struct SentFrames {
    frames: VecDeque<(u64, Bytes)>,
    capacity: usize,
    byte_budget: usize,
    bytes: usize,
    forgotten: u64,
    hashed: u64,
}

impl SentFrames {
    /// An empty ring of [`RING_FRAMES`] and [`RING_BYTES`].
    pub(crate) fn new() -> Self {
        Self::with_limits(RING_FRAMES, RING_BYTES)
    }

    /// An empty ring of `capacity` frames, clamped to 1 up to [`RING_FRAMES`], and `byte_budget`
    /// octets, clamped to 1 up to [`RING_BYTES`].
    pub(crate) fn with_limits(capacity: usize, byte_budget: usize) -> Self {
        Self {
            frames: VecDeque::new(),
            capacity: capacity.clamp(1, RING_FRAMES),
            byte_budget: byte_budget.clamp(1, RING_BYTES),
            bytes: 0,
            forgotten: 0,
            hashed: 0,
        }
    }

    /// Records a sent frame (its whole octets, header and tag included) whose first sequence is
    /// `seq0`: a reference to `frame`, nothing hashed. When the ring is over a bound the oldest
    /// frames are forgotten and counted.
    pub(crate) fn record(&mut self, seq0: u64, frame: &Bytes) {
        self.bytes += frame.len();
        self.frames.push_back((seq0, frame.clone()));
        while self.frames.len() > self.capacity || self.bytes > self.byte_budget {
            let Some((_, old)) = self.frames.pop_front() else {
                break;
            };
            self.bytes -= old.len();
            self.forgotten += 1;
        }
    }

    /// Frames held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether no frame is held.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Octets of frames held.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Hashes computed so far (a test asks: recording computes none).
    #[cfg(test)]
    pub(crate) fn hashed(&self) -> u64 {
        self.hashed
    }

    /// The frames held, oldest first, with their hashes (computed here, not counted as drained).
    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = (u64, [u8; HASH_LEN])> + '_ {
        self.frames
            .iter()
            .map(|(seq0, frame)| (*seq0, frame_hash(frame)))
    }

    /// Frames pushed out unrecorded by a checkpoint since the last
    /// [`take_forgotten`](Self::take_forgotten).
    #[allow(dead_code)] // stage 5: a checkpoint says how many frames it no longer covers
    pub(crate) fn forgotten(&self) -> u64 {
        self.forgotten
    }

    /// Reads and clears the forgotten count (a checkpoint reports it).
    #[allow(dead_code)] // stage 5: a checkpoint reports the frames the ring forgot
    pub(crate) fn take_forgotten(&mut self) -> u64 {
        std::mem::take(&mut self.forgotten)
    }

    /// Removes and yields the frames held, oldest first, as `(seq0, hash)`: what a checkpoint
    /// covers. **The hashes are computed here**, one per frame as the iterator is advanced (a frame
    /// the caller does not take is dropped unhashed). The ring keeps its storage.
    #[allow(dead_code)] // stage 5: a checkpoint signs the frames the ring holds
    pub(crate) fn drain(&mut self) -> impl Iterator<Item = (u64, [u8; HASH_LEN])> + '_ {
        self.bytes = 0;
        let hashed = &mut self.hashed;
        self.frames.drain(..).map(move |(seq0, frame)| {
            *hashed += 1;
            (seq0, frame_hash(&frame))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_up_to_2048_octets_hashes_with_sha256_and_longer_with_blake3() {
        // SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
        assert_eq!(
            frame_hash(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23
            ]
        );
        // The empty frame is short, so SHA-256 (e3b0c442 98fc1c14 9afbf4c8 996fb924 ...).
        assert_eq!(
            frame_hash(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24
            ]
        );
        let at = vec![7u8; BLAKE3_ABOVE];
        let above = vec![7u8; BLAKE3_ABOVE + 1];
        assert_eq!(frame_hash(&at)[..], Sha256::digest(&at)[..HASH_LEN]);
        assert_eq!(
            frame_hash(&above)[..],
            blake3::hash(&above).as_bytes()[..HASH_LEN]
        );
        assert_ne!(frame_hash(&above)[..], Sha256::digest(&above)[..HASH_LEN]);
    }

    #[test]
    fn the_ring_forgets_the_oldest_past_its_bound_and_counts_them() {
        let mut ring = SentFrames::with_limits(3, RING_BYTES);
        for seq0 in 0..5u64 {
            ring.record(seq0 * 10, &Bytes::copy_from_slice(&seq0.to_be_bytes()));
        }
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.forgotten(), 2);
        let held: Vec<u64> = ring.iter().map(|(s, _)| s).collect();
        assert_eq!(held, [20, 30, 40]);
        assert_eq!(
            ring.iter().next().unwrap().1,
            frame_hash(&2u64.to_be_bytes())
        );
        assert_eq!(ring.take_forgotten(), 2);
        assert_eq!(ring.forgotten(), 0);
        let drained: Vec<u64> = ring.drain().map(|(s, _)| s).collect();
        assert_eq!(drained, [20, 30, 40]);
        assert!(ring.is_empty());
        assert_eq!(ring.bytes(), 0);
    }

    #[test]
    fn the_bound_is_4096_frames_and_cannot_be_raised_or_zeroed() {
        let mut ring = SentFrames::new();
        let frame = Bytes::from_static(b"frame");
        for seq0 in 0..(RING_FRAMES as u64 + 10) {
            ring.record(seq0, &frame);
        }
        assert_eq!(ring.len(), RING_FRAMES);
        assert_eq!(ring.forgotten(), 10);
        assert_eq!(ring.iter().next().unwrap().0, 10);
        assert_eq!(
            SentFrames::with_limits(usize::MAX, usize::MAX).capacity,
            RING_FRAMES
        );
        assert_eq!(
            SentFrames::with_limits(usize::MAX, usize::MAX).byte_budget,
            RING_BYTES
        );
        assert_eq!(SentFrames::with_limits(0, 0).capacity, 1);
        assert_eq!(SentFrames::with_limits(0, 0).byte_budget, 1);
    }

    /// The ring keeps frames alive, so it is bounded in octets too: past the budget the oldest are
    /// forgotten and counted, and a frame that is alone over the budget is itself forgotten.
    #[test]
    fn the_ring_is_bounded_in_octets_and_counts_what_it_forgets() {
        let mut ring = SentFrames::with_limits(RING_FRAMES, 10_000);
        let frame = Bytes::from(vec![9u8; 3_000]);
        for seq0 in 0..5u64 {
            ring.record(seq0, &frame);
        }
        assert_eq!(ring.len(), 3, "three frames of 3,000 octets fit 10,000");
        assert_eq!(ring.bytes(), 9_000);
        assert_eq!(ring.forgotten(), 2);
        assert_eq!(ring.iter().next().unwrap().0, 2);
        ring.record(9, &Bytes::from(vec![1u8; 20_000]));
        assert!(ring.is_empty(), "a frame over the whole budget is not kept");
        assert_eq!(ring.bytes(), 0);
        assert_eq!(ring.forgotten(), 2 + 3 + 1);
    }

    /// Recording a frame computes no hash and copies nothing; the hashes are computed when the ring
    /// is drained, by the definition of `frame_hash` (SHA-256 to 2,048 octets, BLAKE3 above),
    /// and only for the frames the caller takes.
    #[test]
    fn recording_hashes_nothing_and_a_drain_hashes_each_frame_it_yields() {
        let mut ring = SentFrames::new();
        let small = Bytes::from(vec![3u8; 1_090]);
        let large = Bytes::from(vec![4u8; 8_962]);
        for seq0 in 0..10u64 {
            ring.record(seq0, if seq0 % 2 == 0 { &small } else { &large });
        }
        assert_eq!(ring.hashed(), 0, "nothing was hashed by recording");
        let mut drain = ring.drain();
        let first = drain.next().unwrap();
        let second = drain.next().unwrap();
        drop(drain);
        assert_eq!(first, (0, frame_hash(&small)));
        assert_eq!(second, (1, frame_hash(&large)));
        assert_eq!(
            ring.hashed(),
            2,
            "one hash for each frame the drain yielded"
        );
        assert!(
            ring.is_empty(),
            "the frames not taken were dropped, unhashed"
        );
    }

    /// After a drain the ring records again without allocating.
    #[test]
    fn recording_after_a_drain_does_not_allocate() {
        use crate::chan::alloc_probe::count_allocations;
        let mut ring = SentFrames::new();
        let frame = Bytes::from(vec![0u8; 100]);
        for seq0 in 0..100 {
            ring.record(seq0, &frame);
        }
        ring.drain().for_each(drop);
        let ((), n) = count_allocations(|| {
            for seq0 in 0..100 {
                ring.record(seq0, &frame);
            }
        });
        assert_eq!(n, 0);
    }
}
