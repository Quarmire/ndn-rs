//! Intra-flow **link-layer FEC** over opaque frames — broadcast erasure
//! recovery without ARQ (reuses the F1 codec).
//!
//! A *generation* of K frames is transmitted as N = K+R tagged frames; a
//! receiver recovers all K from **any** K of the N. This is the reliability
//! lever for a broadcast radio (fire-and-forget, no acknowledgements): send R
//! parity frames and tolerate up to R losses per generation.
//!
//! ## Where it sits (three distinct coding axes — see also `fec`, `cope`)
//!
//! - **F1 [`fec`]** — end-to-end K-of-N over *named, signed Data* segments.
//! - **F3 [`cope`]** — *inter-flow* COPE (XORs in the Air): throughput via
//!   overhearing, codes frames for *different* next-hops.
//! - **link-FEC (here)** — *intra-flow* erasure FEC over *opaque link frames*
//!   on one broadcast hop. Below the trust layer (a recovered frame is whatever
//!   signed bytes it always was — coding is transparent framing, like NDNLP
//!   fragmentation). Reuses the F1 systematic K-of-N codec ([`fec`]) at the link
//!   layer over arbitrary bytes, not named Data.
//!
//! ## Systematic = deliver source immediately, recover only on loss
//!
//! The code is systematic: the K source frames go out unchanged (indices
//! `0..K`), the R parity frames after (`K..N`). The receiver delivers each
//! source frame the instant it arrives ([`LinkFecRx::absorb`] returns it), and
//! only when a generation is completed by parity does it recover-and-deliver the
//! *missing* sources. So the common no-loss path adds zero latency, and an
//! arrived source is never withheld even if its generation never completes.
//!
//! ## Interleaving (the cross-layer trap this exists to dodge)
//!
//! The N frames of a generation **must be spread across separate transmissions**
//! (separate A-MSDUs/MPDUs). If a whole generation rides in one A-MSDU and that
//! MPDU's FCS fails, ALL N are lost together and the code recovers nothing — a
//! correlated burst erasure. The face wiring sends each FEC frame as its own
//! MPDU for exactly this reason (FEC reliability vs A-MSDU bundling is a
//! deliberate per-face choice).
//!
//! ## Variable-length frames
//!
//! The codec needs equal-length segments, but link frames vary. Each source is
//! wrapped `[len: u16 BE] || payload` and zero-padded to the generation's max
//! length before encoding; the length prefix travels *through* the code, so a
//! parity-recovered source is trimmed back to its true length on the receiver.

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;

use crate::fec::{Decoder, Encoder};
use crate::{CodingError, Result};

/// First byte of a link-FEC frame — lets a mixed stream tell coded frames from
/// plain ones (route FEC frames on a dedicated ethertype/marker in practice).
pub const LINK_FEC_MAGIC: u8 = 0xFC;

/// Per-frame header: `MAGIC(1) | generation(2 LE) | k(1) | n(1) | index(1)`.
const HDR: usize = 6;

fn frame(generation: u16, k: u16, n: u16, index: u16, body: &[u8]) -> Bytes {
    let mut v = Vec::with_capacity(HDR + body.len());
    v.push(LINK_FEC_MAGIC);
    v.extend_from_slice(&generation.to_le_bytes());
    v.push(k as u8);
    v.push(n as u8);
    v.push(index as u8);
    v.extend_from_slice(body);
    Bytes::from(v)
}

/// Trim a recovered/source segment `[len][payload](padding)` back to `payload`.
fn untrim(seg: &Bytes) -> Bytes {
    if seg.len() < 2 {
        return Bytes::new();
    }
    let len = u16::from_be_bytes([seg[0], seg[1]]) as usize;
    seg.slice(2..(2 + len).min(seg.len()))
}

/// Encoder: each generation of K frames → N = K+R tagged frames. K is per-call
/// (the actual frames flushed); `R` (redundancy) is fixed; the generation
/// counter persists across calls so the receiver can group frames.
pub struct LinkFecTx {
    generation: u16,
    redundancy: u16,
}

impl LinkFecTx {
    /// `redundancy` = parity frames per generation (losses tolerated).
    pub fn new(redundancy: u16) -> Self {
        Self {
            generation: 0,
            redundancy,
        }
    }

    /// Parity frames per generation.
    pub fn redundancy(&self) -> u16 {
        self.redundancy
    }

    /// Encode `payloads` (the generation's K source frames) into K+R tagged
    /// frames — the K source frames then R parity. **Spread these across
    /// separate transmissions** (the face sends one MPDU each); never put a whole
    /// generation in one A-MSDU.
    pub fn encode(&mut self, payloads: Vec<Bytes>) -> Result<Vec<Bytes>> {
        let k = payloads.len() as u16;
        if k == 0 {
            return Err(CodingError::InvalidParameters { k, n: k });
        }
        let n = k.saturating_add(self.redundancy);
        if n > 255 {
            return Err(CodingError::InvalidParameters { k, n });
        }
        // Wrap each source `[len][payload]` and pad to the generation max length.
        let mut segs: Vec<Vec<u8>> = payloads
            .iter()
            .map(|p| {
                let mut v = Vec::with_capacity(2 + p.len());
                v.extend_from_slice(&(p.len() as u16).to_be_bytes());
                v.extend_from_slice(p);
                v
            })
            .collect();
        let seg_len = segs.iter().map(Vec::len).max().unwrap_or(0);
        let g = self.generation;
        self.generation = self.generation.wrapping_add(1);

        let mut enc = Encoder::new(k, n)?;
        let mut out = Vec::with_capacity(n as usize);
        for (i, s) in segs.iter_mut().enumerate() {
            s.resize(seg_len, 0);
            let b = Bytes::from(std::mem::take(s));
            enc.feed(b.clone())?;
            out.push(frame(g, k, n, i as u16, &b));
        }
        for index in k..n {
            out.push(frame(g, k, n, index, &enc.parity(index)?));
        }
        Ok(out)
    }
}

struct GenState {
    dec: Decoder,
    delivered: Vec<bool>,
    done: bool,
}

/// Decoder: absorbs tagged frames and returns the payloads to deliver *now*
/// (source frames as they arrive; recovered missing sources when parity
/// completes a generation). Each payload is delivered exactly once.
pub struct LinkFecRx {
    gens: HashMap<u16, GenState>,
    order: VecDeque<u16>,
    cap: usize,
}

impl Default for LinkFecRx {
    fn default() -> Self {
        Self::with_capacity(64)
    }
}

impl LinkFecRx {
    pub fn new() -> Self {
        Self::default()
    }

    /// `cap` = max in-flight generations kept (the oldest is evicted past it, so
    /// a too-lossy generation that never completes can't leak memory).
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            gens: HashMap::new(),
            order: VecDeque::new(),
            cap: cap.max(1),
        }
    }

    /// Is `frame` a link-FEC frame (vs a plain one to pass through)?
    pub fn is_fec(frame: &[u8]) -> bool {
        frame.len() >= HDR && frame[0] == LINK_FEC_MAGIC
    }

    /// Absorb one frame; return the payload(s) to deliver now (0, 1, or several).
    /// A non-FEC frame returns an empty vec (the caller delivers it as-is).
    pub fn absorb(&mut self, frame: Bytes) -> Result<Vec<Bytes>> {
        if !Self::is_fec(&frame) {
            return Ok(Vec::new());
        }
        let g = u16::from_le_bytes([frame[1], frame[2]]);
        let k = frame[3] as u16;
        let n = frame[4] as u16;
        let index = frame[5] as u16;
        let body = frame.slice(HDR..);

        if !self.gens.contains_key(&g) {
            if self.gens.len() >= self.cap
                && let Some(old) = self.order.pop_front()
            {
                self.gens.remove(&old);
            }
            self.gens
                .insert(g, GenState {
                    dec: Decoder::new(k, n)?,
                    delivered: vec![false; k as usize],
                    done: false,
                });
            self.order.push_back(g);
        }
        let st = self.gens.get_mut(&g).unwrap();

        let mut out = Vec::new();
        // Systematic: a source frame is delivered immediately.
        if index < k {
            let i = index as usize;
            if i < st.delivered.len() && !st.delivered[i] {
                st.delivered[i] = true;
                out.push(untrim(&body));
            }
        }
        st.dec.absorb(index, body)?;
        // Once parity completes the generation, deliver the still-missing sources.
        if !st.done && st.dec.is_complete() {
            st.done = true;
            let segs = st.dec.recover()?;
            for (i, seg) in segs.iter().enumerate() {
                if !st.delivered[i] {
                    st.delivered[i] = true;
                    out.push(untrim(seg));
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(rx: &mut LinkFecRx, frames: impl IntoIterator<Item = Bytes>) -> Vec<Bytes> {
        let mut got = Vec::new();
        for f in frames {
            got.extend(rx.absorb(f).unwrap());
        }
        got
    }

    #[test]
    fn recovers_generation_losing_two_sources() {
        // 4 source + 2 parity (redundancy 2); lose two source frames → recover all.
        let payloads = vec![
            Bytes::from_static(b"alpha"),
            Bytes::from_static(b"bb"),
            Bytes::from_static(b"gamma-is-longer"),
            Bytes::from_static(b"d"),
        ];
        let frames = LinkFecTx::new(2).encode(payloads.clone()).unwrap();
        assert_eq!(frames.len(), 6);

        // Drop source indices 0 and 2; deliver 1,3 (sources) + 4,5 (parity).
        let kept: Vec<Bytes> = frames
            .into_iter()
            .enumerate()
            .filter(|(i, _)| *i != 0 && *i != 2)
            .map(|(_, f)| f)
            .collect();
        let mut rx = LinkFecRx::new();
        let mut got = drain(&mut rx, kept);
        got.sort();
        let mut want = payloads;
        want.sort();
        assert_eq!(got, want, "recovered the full generation");
    }

    #[test]
    fn no_loss_delivers_sources_immediately() {
        let payloads: Vec<Bytes> = (0..4u8).map(|i| Bytes::from(vec![i; 6])).collect();
        let frames = LinkFecTx::new(2).encode(payloads.clone()).unwrap();
        let mut rx = LinkFecRx::new();
        // Deliver only the 4 source frames (no parity) — all must come through.
        let got = drain(&mut rx, frames.into_iter().take(4));
        assert_eq!(got, payloads);
    }

    #[test]
    fn too_many_losses_keeps_arrived_sources() {
        let payloads: Vec<Bytes> = (0..4u8).map(|i| Bytes::from(vec![i; 8])).collect();
        let frames = LinkFecTx::new(2).encode(payloads.clone()).unwrap();
        let mut rx = LinkFecRx::new();
        // Only source 1 + the 2 parity arrive (3 < K) — can't recover, but the
        // one source that DID arrive is still delivered (never withheld).
        let kept = vec![frames[1].clone(), frames[4].clone(), frames[5].clone()];
        let got = drain(&mut rx, kept);
        assert_eq!(got, vec![payloads[1].clone()]);
    }

    #[test]
    fn plain_frame_passes_through() {
        let mut rx = LinkFecRx::new();
        assert!(
            rx.absorb(Bytes::from_static(b"\x01plain-not-fec"))
                .unwrap()
                .is_empty()
        );
        assert!(!LinkFecRx::is_fec(b"\x01plain"));
    }
}
