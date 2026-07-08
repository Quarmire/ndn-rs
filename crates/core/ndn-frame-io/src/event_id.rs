//! Shared-event identification (named-time **Cut 4**).
//!
//! Common-view (M3) needs to know that two receivers heard the *same* physical transmission before
//! it can subtract their [`LinkStamp`](crate::LinkStamp)s. An [`EventId`] provides that key over any
//! broadcast medium: it is a frame's content digest bound to the channel it was heard on. Two
//! receivers of one frame compute the *same* id (so their stamps pair), while unrelated frames — or
//! the same content on a different channel — yield different ids. The Wi-Fi frame is then just one
//! instance of a stampable shared event; an optical cone or a LoRa chirp works identically.

/// An identifier for a shared physical event — a transmitted frame observed on a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventId {
    /// A 128-bit content digest of the frame body — collision-resistant enough to pair receptions.
    pub digest: u128,
    /// The channel the frame was heard on (a frame is only "the same event" on the same channel).
    pub channel: u8,
}

impl EventId {
    /// Compute the id for a received frame `body` heard on `channel`. Deterministic across
    /// receivers, so two nodes that heard one transmission agree; a distinct frame or channel gives
    /// a distinct id.
    ///
    /// The digest is a dependency-free 128-bit FNV-1a (two independent streams) — cheap and adequate
    /// for honest pairing. Where an *adversary* could grind a collision to mis-pair receivers, swap
    /// in a cryptographic hash (the field type is unchanged).
    pub fn from_frame(body: &[u8], channel: u8) -> Self {
        EventId {
            digest: fnv128(body),
            channel,
        }
    }
}

/// FNV-1a over `bytes` seeded with `basis` (64-bit).
fn fnv1a64(bytes: &[u8], basis: u64) -> u64 {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = basis;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// Two independent 64-bit FNV-1a streams (distinct bases) concatenated into a 128-bit digest.
fn fnv128(bytes: &[u8]) -> u128 {
    let lo = fnv1a64(bytes, 0xcbf2_9ce4_8422_2325); // canonical FNV-1a offset basis
    let hi = fnv1a64(bytes, 0x9e37_79b9_7f4a_7c15); // a distinct basis for the high half
    (u128::from(hi) << 64) | u128::from(lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_frame_agrees_distinct_frames_differ() {
        let f = b"\x08\x00\x00\x00beacon-content-seq-42";
        // Two receivers of the same frame on the same channel agree.
        assert_eq!(EventId::from_frame(f, 36), EventId::from_frame(f, 36));
        // Same content, different channel -> different event.
        assert_ne!(EventId::from_frame(f, 36), EventId::from_frame(f, 40));
        // Different content -> different event.
        assert_ne!(
            EventId::from_frame(f, 36),
            EventId::from_frame(b"\x08\x00\x00\x00beacon-content-seq-43", 36)
        );
        // Empty vs one byte don't collide trivially.
        assert_ne!(EventId::from_frame(b"", 1), EventId::from_frame(b"\x00", 1));
    }
}
