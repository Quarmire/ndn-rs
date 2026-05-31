//! F3 — link-layer inter-flow (COPE-style) network coding (feature `f3-link`).
//!
//! Distinct from F1/F2: this is **inter-flow** coding on a *shared broadcast
//! medium*, not named Data. A relay XORs native frames destined for
//! **different** next-hops into one broadcast frame; each recipient, having
//! **overheard** the other natives, XORs them back out to recover its own.
//! It is link-layer (doctrine F3): the unit is an opaque frame, the gain
//! comes from wireless overhearing, and there is no producer signature on the
//! XOR — so it lives entirely below the trust layer (the recovered *native*
//! is whatever signed packet it always was; coding is transparent framing,
//! like NDNLP fragmentation, never crossing the signing boundary).
//!
//! This module is the **pure coding core** — the COPE coding rule and the
//! encode/decode arithmetic — mirroring how the F1/F2 cores live here while
//! their face/engine wiring lives elsewhere. Driving it from a real broadcast
//! face (a `LinkServiceFeature` that consults reception reports and emits
//! coded frames) is the deployment seam and is **not** in this crate.
//!
//! Reference: RFC 9273 §1 (NC taxonomy, inter-flow is out of its scope);
//! Katti et al., "XORs in the Air: Practical Wireless Network Coding" (COPE).

use std::collections::{HashMap, HashSet};

use bytes::Bytes;

/// Abstract neighbor / next-hop identifier (a face or link-peer id).
pub type NeighborId = u64;
/// Frame identifier (unique per native frame in flight at the relay).
pub type FrameId = u64;

/// A native (un-coded) frame queued at the relay for one next-hop.
#[derive(Debug, Clone)]
pub struct NativeFrame {
    pub id: FrameId,
    pub next_hop: NeighborId,
    pub payload: Bytes,
}

/// A coded broadcast frame: the XOR of its members' payloads (zero-padded to
/// the longest), plus the per-member `(id, native_length)` header a receiver
/// needs to identify and trim the recovered native.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodedFrame {
    pub members: Vec<(FrameId, usize)>,
    pub payload: Bytes,
}

impl CodedFrame {
    /// `true` if this frame actually combines ≥2 natives (a coding gain); a
    /// single-member frame is just a native passthrough.
    pub fn is_coded(&self) -> bool {
        self.members.len() >= 2
    }
}

/// A relay's COPE coder: an output queue of native frames plus reception
/// reports (which frame ids each neighbor is believed to already hold from
/// overhearing). [`encode_next`](Self::encode_next) greedily forms a coded
/// frame under the COPE rule.
#[derive(Debug, Default)]
pub struct CopeCoder {
    pending: Vec<NativeFrame>,
    holds: HashMap<NeighborId, HashSet<FrameId>>,
}

impl CopeCoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a native frame for transmission.
    pub fn enqueue(&mut self, frame: NativeFrame) {
        self.pending.push(frame);
    }

    /// Record that `neighbor` holds (has overheard) frame `id`.
    pub fn report(&mut self, neighbor: NeighborId, id: FrameId) {
        self.holds.entry(neighbor).or_default().insert(id);
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    fn neighbor_holds(&self, neighbor: NeighborId, id: FrameId) -> bool {
        self.holds.get(&neighbor).is_some_and(|s| s.contains(&id))
    }

    /// Greedily form the next frame to broadcast (COPE rule): start from the
    /// head-of-line native and add further pending natives — for *distinct*
    /// next-hops — only while **every recipient in the set holds all the
    /// other members**, so each can decode. Removes the chosen natives from
    /// the queue. Returns `None` only when the queue is empty; a returned
    /// frame may be a single native ([`CodedFrame::is_coded`] is `false`)
    /// when nothing could be safely combined with the head.
    pub fn encode_next(&mut self) -> Option<CodedFrame> {
        if self.pending.is_empty() {
            return None;
        }
        let mut chosen = vec![0usize];
        let mut recipients = vec![self.pending[0].next_hop];
        let mut ids = vec![self.pending[0].id];

        for i in 1..self.pending.len() {
            let g = &self.pending[i];
            if recipients.contains(&g.next_hop) {
                continue; // at most one native per recipient per coded frame
            }
            // g's recipient must already hold every native currently in the set …
            let g_can_decode = ids.iter().all(|&id| self.neighbor_holds(g.next_hop, id));
            // … and every current recipient must hold g's native.
            let others_can_decode = recipients.iter().all(|&r| self.neighbor_holds(r, g.id));
            if g_can_decode && others_can_decode {
                chosen.push(i);
                recipients.push(g.next_hop);
                ids.push(g.id);
            }
        }

        // Remove chosen frames (highest index first to keep indices valid).
        let mut frames = Vec::with_capacity(chosen.len());
        for &i in chosen.iter().rev() {
            frames.push(self.pending.remove(i));
        }
        frames.reverse();

        let max_len = frames.iter().map(|f| f.payload.len()).max().unwrap_or(0);
        let mut payload = vec![0u8; max_len];
        let mut members = Vec::with_capacity(frames.len());
        for f in &frames {
            xor_into(&mut payload, &f.payload);
            members.push((f.id, f.payload.len()));
        }
        Some(CodedFrame {
            members,
            payload: Bytes::from(payload),
        })
    }
}

/// Decode a coded frame at a receiver that holds some of its members (the
/// natives it overheard). Succeeds iff the receiver is missing **exactly
/// one** member — it XORs the held members out and trims to the missing
/// native's length, recovering `(missing_id, native_payload)`. `None` if it
/// holds all members (nothing to recover) or misses more than one (cannot
/// decode — COPE's "all but one" condition).
pub fn decode(coded: &CodedFrame, held: &HashMap<FrameId, Bytes>) -> Option<(FrameId, Bytes)> {
    let missing: Vec<&(FrameId, usize)> = coded
        .members
        .iter()
        .filter(|(id, _)| !held.contains_key(id))
        .collect();
    if missing.len() != 1 {
        return None;
    }
    let (missing_id, missing_len) = *missing[0];
    let mut acc = coded.payload.to_vec();
    for (id, _) in &coded.members {
        if let Some(p) = held.get(id) {
            xor_into(&mut acc, p);
        }
    }
    acc.truncate(missing_len);
    Some((missing_id, Bytes::from(acc)))
}

/// `acc[i] ^= src[i]` for the overlap (acc is the longest, zero-padded).
fn xor_into(acc: &mut [u8], src: &[u8]) {
    for (a, &s) in acc.iter_mut().zip(src) {
        *a ^= s;
    }
}

// A COPE link carries two opaque frame shapes, distinguished by a 1-byte tag.
// This is link-layer framing (below the trust boundary, like NDNLP fragments);
// the carried native is whatever signed packet it always was.

const TAG_NATIVE: u8 = 0;
const TAG_CODED: u8 = 1;
const TAG_REPORT: u8 = 2;

/// A decoded COPE link frame: a tagged native, a coded combination, or a
/// **reception report** (the control message of the COPE coding rule — a
/// neighbor announcing which frame ids it currently holds from overhearing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopeWire {
    Native { id: FrameId, payload: Bytes },
    Coded(CodedFrame),
    Report { from: NeighborId, ids: Vec<FrameId> },
}

/// Frame a native for the medium: `[TAG_NATIVE][id u64 BE][payload]`.
pub fn encode_native(id: FrameId, payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(9 + payload.len());
    out.push(TAG_NATIVE);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(payload);
    Bytes::from(out)
}

/// Frame a coded combination:
/// `[TAG_CODED][count u16][ (id u64, len u32) * count ][xor payload]`.
pub fn encode_coded(coded: &CodedFrame) -> Bytes {
    let mut out = Vec::with_capacity(3 + coded.members.len() * 12 + coded.payload.len());
    out.push(TAG_CODED);
    out.extend_from_slice(&(coded.members.len() as u16).to_be_bytes());
    for (id, len) in &coded.members {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&(*len as u32).to_be_bytes());
    }
    out.extend_from_slice(&coded.payload);
    Bytes::from(out)
}

/// Frame a reception report: `[TAG_REPORT][from u64][count u16][ids u64*count]`.
/// `from` is the announcing neighbor; `ids` are the frames it holds.
pub fn encode_report(from: NeighborId, ids: &[FrameId]) -> Bytes {
    let mut out = Vec::with_capacity(11 + ids.len() * 8);
    out.push(TAG_REPORT);
    out.extend_from_slice(&from.to_be_bytes());
    out.extend_from_slice(&(ids.len() as u16).to_be_bytes());
    for id in ids {
        out.extend_from_slice(&id.to_be_bytes());
    }
    Bytes::from(out)
}

/// Parse a framed COPE link frame. `None` on a malformed frame.
pub fn decode_wire(bytes: &[u8]) -> Option<CopeWire> {
    let (&tag, rest) = bytes.split_first()?;
    match tag {
        TAG_REPORT => {
            if rest.len() < 10 {
                return None;
            }
            let from = u64::from_be_bytes(rest[..8].try_into().ok()?);
            let count = u16::from_be_bytes([rest[8], rest[9]]) as usize;
            let mut p = 10;
            let mut ids = Vec::with_capacity(count);
            for _ in 0..count {
                if rest.len() < p + 8 {
                    return None;
                }
                ids.push(u64::from_be_bytes(rest[p..p + 8].try_into().ok()?));
                p += 8;
            }
            Some(CopeWire::Report { from, ids })
        }
        TAG_NATIVE => {
            if rest.len() < 8 {
                return None;
            }
            let id = u64::from_be_bytes(rest[..8].try_into().ok()?);
            Some(CopeWire::Native {
                id,
                payload: Bytes::copy_from_slice(&rest[8..]),
            })
        }
        TAG_CODED => {
            if rest.len() < 2 {
                return None;
            }
            let count = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            let mut p = 2;
            let mut members = Vec::with_capacity(count);
            for _ in 0..count {
                if rest.len() < p + 12 {
                    return None;
                }
                let id = u64::from_be_bytes(rest[p..p + 8].try_into().ok()?);
                let len = u32::from_be_bytes(rest[p + 8..p + 12].try_into().ok()?) as usize;
                members.push((id, len));
                p += 12;
            }
            Some(CopeWire::Coded(CodedFrame {
                members,
                payload: Bytes::copy_from_slice(&rest[p..]),
            }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: NeighborId = 1;
    const BOB: NeighborId = 2;
    const CARLA: NeighborId = 3;

    /// Canonical COPE Alice↔Bob via a relay: the relay holds p1 (→Bob) and p2
    /// (→Alice); Alice overheard p1, Bob overheard p2. One XOR broadcast lets
    /// both recover their packet — two transmissions saved to one.
    #[test]
    fn alice_bob_relay_xor() {
        let p1 = Bytes::from_static(b"packet-to-bob");
        let p2 = Bytes::from_static(b"the-packet-for-alice"); // different length on purpose
        let mut relay = CopeCoder::new();
        relay.enqueue(NativeFrame {
            id: 1,
            next_hop: BOB,
            payload: p1.clone(),
        });
        relay.enqueue(NativeFrame {
            id: 2,
            next_hop: ALICE,
            payload: p2.clone(),
        });
        relay.report(ALICE, 1); // Alice overheard p1
        relay.report(BOB, 2); // Bob overheard p2

        let coded = relay.encode_next().unwrap();
        assert!(coded.is_coded(), "p1 and p2 coded together");
        assert_eq!(relay.pending_len(), 0);

        // Alice holds p1 → recovers p2.
        let alice_held = HashMap::from([(1u64, p1.clone())]);
        assert_eq!(decode(&coded, &alice_held), Some((2, p2.clone())));
        // Bob holds p2 → recovers p1.
        let bob_held = HashMap::from([(2u64, p2.clone())]);
        assert_eq!(decode(&coded, &bob_held), Some((1, p1.clone())));
    }

    #[test]
    fn wire_framing_round_trips() {
        let n = encode_native(7, b"hello");
        assert_eq!(
            decode_wire(&n),
            Some(CopeWire::Native {
                id: 7,
                payload: Bytes::from_static(b"hello")
            })
        );
        let coded = CodedFrame {
            members: vec![(1, 4), (2, 6)],
            payload: Bytes::from_static(b"xxxxxx"),
        };
        let c = encode_coded(&coded);
        assert_eq!(decode_wire(&c), Some(CopeWire::Coded(coded)));

        let r = encode_report(42, &[1, 2, 3]);
        assert_eq!(
            decode_wire(&r),
            Some(CopeWire::Report {
                from: 42,
                ids: vec![1, 2, 3]
            })
        );

        assert_eq!(decode_wire(b""), None);
        assert_eq!(decode_wire(&[9, 9, 9]), None); // unknown tag
    }

    #[test]
    fn not_codeable_without_overhearing() {
        let mut relay = CopeCoder::new();
        relay.enqueue(NativeFrame {
            id: 1,
            next_hop: BOB,
            payload: Bytes::from_static(b"aaaa"),
        });
        relay.enqueue(NativeFrame {
            id: 2,
            next_hop: ALICE,
            payload: Bytes::from_static(b"bbbb"),
        });
        // No reception reports: neither recipient holds the other's native.
        let coded = relay.encode_next().unwrap();
        assert!(!coded.is_coded(), "head sent uncoded; can't safely combine");
        // The second frame remains queued.
        assert_eq!(relay.pending_len(), 1);
    }

    #[test]
    fn three_way_coding_and_partial_failure() {
        let p1 = Bytes::from_static(b"one1");
        let p2 = Bytes::from_static(b"two2");
        let p3 = Bytes::from_static(b"three3");
        let mut relay = CopeCoder::new();
        relay.enqueue(NativeFrame {
            id: 1,
            next_hop: ALICE,
            payload: p1.clone(),
        });
        relay.enqueue(NativeFrame {
            id: 2,
            next_hop: BOB,
            payload: p2.clone(),
        });
        relay.enqueue(NativeFrame {
            id: 3,
            next_hop: CARLA,
            payload: p3.clone(),
        });
        // Each recipient overheard the other two.
        relay.report(ALICE, 2);
        relay.report(ALICE, 3);
        relay.report(BOB, 1);
        relay.report(BOB, 3);
        relay.report(CARLA, 1);
        relay.report(CARLA, 2);

        let coded = relay.encode_next().unwrap();
        assert_eq!(coded.members.len(), 3);

        // Alice holds 2,3 → recovers 1.
        let alice = HashMap::from([(2u64, p2.clone()), (3u64, p3.clone())]);
        assert_eq!(decode(&coded, &alice), Some((1, p1.clone())));
        // A node missing two members cannot decode.
        let missing_two = HashMap::from([(2u64, p2.clone())]);
        assert_eq!(decode(&coded, &missing_two), None);
        // A node holding all members has nothing to recover.
        let all = HashMap::from([(1u64, p1), (2u64, p2), (3u64, p3)]);
        assert_eq!(decode(&coded, &all), None);
    }
}
