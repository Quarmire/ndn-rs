//! The hashes of the frames a channel sent (channel.md, Checkpoints): the data
//! a checkpoint signs.
//!
//! A sender records, per channel, `(seq0, h)` for every frame it hands to a
//! carrier, where `h` is the first 16 octets of `H(frame octets)`: SHA-256 for a
//! frame of at most 2,048 octets and BLAKE3 above (so nothing is negotiated:
//! the frame's length selects the hash). The ring holds at most 4,096 frames; a
//! frame recorded past that pushes out the oldest, which is forgotten and
//! **counted**, so a checkpoint can say how many frames it no longer covers.
//! Nothing here verifies anything: writing the ring is the sender's part, and
//! a checkpoint that signs it is a later stage's.

use std::collections::VecDeque;
use std::collections::vec_deque::Drain;

use sha2::{Digest, Sha256};

/// Octets of a recorded hash.
pub(crate) const HASH_LEN: usize = 16;

/// Frames of at most this many octets are hashed with SHA-256, longer ones
/// with BLAKE3.
pub(crate) const BLAKE3_ABOVE: usize = 2_048;

/// The most frames a channel's ring holds.
pub(crate) const RING_FRAMES: usize = 4_096;

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

/// A bounded ring of `(seq0, hash)` for the frames one channel sent since its
/// last checkpoint.
#[derive(Debug)]
pub(crate) struct SentFrames {
    frames: VecDeque<(u64, [u8; HASH_LEN])>,
    capacity: usize,
    forgotten: u64,
}

impl SentFrames {
    /// An empty ring of [`RING_FRAMES`].
    pub(crate) fn new() -> Self {
        Self::with_capacity(RING_FRAMES)
    }

    /// An empty ring of `capacity` frames, clamped to 1 up to [`RING_FRAMES`].
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            frames: VecDeque::new(),
            capacity: capacity.clamp(1, RING_FRAMES),
            forgotten: 0,
        }
    }

    /// Records a sent frame (its whole octets, header and tag included) whose
    /// first sequence is `seq0`. When the ring is full the oldest frame is
    /// forgotten and counted.
    pub(crate) fn record(&mut self, seq0: u64, frame: &[u8]) {
        if self.frames.len() == self.capacity {
            self.frames.pop_front();
            self.forgotten += 1;
        }
        self.frames.push_back((seq0, frame_hash(frame)));
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

    /// The frames held, oldest first.
    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &(u64, [u8; HASH_LEN])> {
        self.frames.iter()
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

    /// Removes and yields the frames held, oldest first (what a checkpoint
    /// covers). The ring keeps its storage.
    #[allow(dead_code)] // stage 5: a checkpoint signs the frames the ring holds
    pub(crate) fn drain(&mut self) -> Drain<'_, (u64, [u8; HASH_LEN])> {
        self.frames.drain(..)
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
        let mut ring = SentFrames::with_capacity(3);
        for seq0 in 0..5u64 {
            ring.record(seq0 * 10, &seq0.to_be_bytes());
        }
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.forgotten(), 2);
        let held: Vec<u64> = ring.iter().map(|&(s, _)| s).collect();
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
    }

    #[test]
    fn the_bound_is_4096_frames_and_cannot_be_raised_or_zeroed() {
        let mut ring = SentFrames::new();
        for seq0 in 0..(RING_FRAMES as u64 + 10) {
            ring.record(seq0, b"frame");
        }
        assert_eq!(ring.len(), RING_FRAMES);
        assert_eq!(ring.forgotten(), 10);
        assert_eq!(ring.iter().next().unwrap().0, 10);
        assert_eq!(SentFrames::with_capacity(usize::MAX).capacity, RING_FRAMES);
        assert_eq!(SentFrames::with_capacity(0).capacity, 1);
    }

    /// After a drain the ring records again without allocating.
    #[test]
    fn recording_after_a_drain_does_not_allocate() {
        use crate::chan::alloc_probe::count_allocations;
        let mut ring = SentFrames::new();
        let frame = [0u8; 100];
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
