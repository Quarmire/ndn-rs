//! Systematic K-of-N FEC encoder/decoder over `bytes::Bytes`.
//!
//! ## Encoding
//!
//! Source segments are emitted unchanged (rows `0..K` of the
//! encoding matrix are the K×K identity). Parity row `p` (for
//! `p ∈ [0, N-K)`) carries Vandermonde coefficients
//! `[v_p^0, v_p^1, …, v_p^(K-1)]` with `v_p = p + 1` evaluated in
//! GF(2^8). Distinct nonzero `v_p` plus the Vandermonde structure
//! guarantee any K of the N rows are linearly independent, which is
//! exactly the MDS property we need: any K received segments
//! decode the generation.
//!
//! Constraint: `N ≤ K + 255` because `v_p` must fit in a nonzero
//! byte. `Encoder::new` enforces this via `n ≤ 255`.
//!
//! ## Decoding
//!
//! `Decoder::absorb` runs incremental Gauss–Jordan elimination
//! maintaining reduced row-echelon form. Each received segment
//! contributes one row of `(coeffs, payload)`:
//!
//! - Source segment at index `j` (`j < K`): coeffs is the basis
//!   vector `e_j`.
//! - Parity segment at index `j` (`K ≤ j < N`): coeffs is the
//!   Vandermonde row for `v = j - K + 1`.
//!
//! After K linearly independent absorptions, `rows[i].payload`
//! holds source segment `i` directly.

use bytes::Bytes;

use crate::field;
use crate::{CodingError, Result};

/// Producer-side encoder; one instance per generation.
pub struct Encoder {
    k: u16,
    n: u16,
    sources: Vec<Bytes>,
    seg_len: Option<usize>,
}

impl Encoder {
    pub fn new(k: u16, n: u16) -> Result<Self> {
        if k == 0 || n < k || n > 255 {
            return Err(CodingError::InvalidParameters { k, n });
        }
        Ok(Self {
            k,
            n,
            sources: Vec::with_capacity(k as usize),
            seg_len: None,
        })
    }

    pub fn k(&self) -> u16 {
        self.k
    }

    pub fn n(&self) -> u16 {
        self.n
    }

    pub fn fed(&self) -> u16 {
        self.sources.len() as u16
    }

    /// Append the next source segment. Must be called exactly `K` times
    /// before any [`Self::parity`] call; all segments must share a length.
    pub fn feed(&mut self, seg: Bytes) -> Result<()> {
        if self.sources.len() >= self.k as usize {
            return Err(CodingError::SourceCountMismatch {
                have: self.sources.len() as u16 + 1,
                needed: self.k,
            });
        }
        match self.seg_len {
            None => self.seg_len = Some(seg.len()),
            Some(expected) if expected != seg.len() => {
                return Err(CodingError::SegmentLengthMismatch {
                    have: seg.len(),
                    expected,
                });
            }
            _ => {}
        }
        self.sources.push(seg);
        Ok(())
    }

    /// Compute the parity segment at absolute `index` (`K ≤ index < N`).
    pub fn parity(&self, index: u16) -> Result<Bytes> {
        if index < self.k || index >= self.n {
            return Err(CodingError::IndexOutOfRange { index, n: self.n });
        }
        if self.sources.len() != self.k as usize {
            return Err(CodingError::SourceCountMismatch {
                have: self.sources.len() as u16,
                needed: self.k,
            });
        }
        let seg_len = self.seg_len.unwrap_or(0);
        let v = (index - self.k + 1) as u8;
        let mut out = vec![0u8; seg_len];
        // out = Σ_j v^j · source_j
        let mut coeff = 1u8;
        for source in &self.sources {
            field::mul_add(&mut out, source, coeff);
            coeff = field::mul(coeff, v);
        }
        Ok(Bytes::from(out))
    }
}

/// Consumer-side decoder. One instance per generation. Maintains
/// reduced row-echelon form so that once rank = K, `rows[i].payload`
/// is exactly source segment `i`.
pub struct Decoder {
    k: u16,
    n: u16,
    seg_len: Option<usize>,
    rows: Vec<Option<Row>>,
    rank: u16,
}

struct Row {
    coeffs: Vec<u8>,
    payload: Vec<u8>,
}

impl Decoder {
    pub fn new(k: u16, n: u16) -> Result<Self> {
        if k == 0 || n < k || n > 255 {
            return Err(CodingError::InvalidParameters { k, n });
        }
        let mut rows = Vec::with_capacity(k as usize);
        for _ in 0..k {
            rows.push(None);
        }
        Ok(Self {
            k,
            n,
            seg_len: None,
            rows,
            rank: 0,
        })
    }

    pub fn k(&self) -> u16 {
        self.k
    }

    pub fn n(&self) -> u16 {
        self.n
    }

    pub fn rank(&self) -> u16 {
        self.rank
    }

    pub fn is_complete(&self) -> bool {
        self.rank == self.k
    }

    /// Absorb a segment at absolute index (`< K` source, `≥ K` parity).
    /// Returns `Ok(true)` if rank increased; `Ok(false)` for a duplicate
    /// or linearly dependent segment.
    pub fn absorb(&mut self, index: u16, bytes: Bytes) -> Result<bool> {
        if index >= self.n {
            return Err(CodingError::IndexOutOfRange { index, n: self.n });
        }
        match self.seg_len {
            None => self.seg_len = Some(bytes.len()),
            Some(expected) if expected != bytes.len() => {
                return Err(CodingError::SegmentLengthMismatch {
                    have: bytes.len(),
                    expected,
                });
            }
            _ => {}
        }
        let coeffs = self.row_coeffs(index);
        let payload = bytes.to_vec();
        Ok(self.absorb_row(coeffs, payload))
    }

    fn row_coeffs(&self, index: u16) -> Vec<u8> {
        let k = self.k as usize;
        let mut coeffs = vec![0u8; k];
        if index < self.k {
            coeffs[index as usize] = 1;
        } else {
            let v = (index - self.k + 1) as u8;
            let mut acc = 1u8;
            for c in coeffs.iter_mut() {
                *c = acc;
                acc = field::mul(acc, v);
            }
        }
        coeffs
    }

    /// Incremental Gauss–Jordan. Returns true iff rank increased.
    fn absorb_row(&mut self, mut coeffs: Vec<u8>, mut payload: Vec<u8>) -> bool {
        let k = self.k as usize;

        for col in 0..k {
            if coeffs[col] == 0 {
                continue;
            }
            if let Some(pivot) = &self.rows[col] {
                let factor = coeffs[col];
                field::mul_add(&mut coeffs, &pivot.coeffs, factor);
                field::mul_add(&mut payload, &pivot.payload, factor);
                debug_assert_eq!(coeffs[col], 0);
            }
        }

        let new_col = match coeffs.iter().position(|&c| c != 0) {
            Some(c) => c,
            None => return false,
        };

        let normalizer = field::inv(coeffs[new_col]);
        field::scale(&mut coeffs, normalizer);
        field::scale(&mut payload, normalizer);
        debug_assert_eq!(coeffs[new_col], 1);

        // Eliminate the new pivot column from every other row to stay in RREF.
        for col in 0..k {
            if col == new_col {
                continue;
            }
            let factor = match &self.rows[col] {
                Some(r) if r.coeffs[new_col] != 0 => r.coeffs[new_col],
                _ => continue,
            };
            let mut other = self.rows[col].take().unwrap();
            field::mul_add(&mut other.coeffs, &coeffs, factor);
            field::mul_add(&mut other.payload, &payload, factor);
            self.rows[col] = Some(other);
        }

        self.rows[new_col] = Some(Row { coeffs, payload });
        self.rank += 1;
        true
    }

    /// Recover the K source segments; errors with `InsufficientRank`
    /// until [`Self::is_complete`].
    pub fn recover(&self) -> Result<Vec<Bytes>> {
        if !self.is_complete() {
            return Err(CodingError::InsufficientRank {
                have: self.rank,
                needed: self.k,
            });
        }
        let mut out = Vec::with_capacity(self.k as usize);
        for slot in &self.rows {
            let row = slot.as_ref().expect("rank == k implies every slot is Some");
            out.push(Bytes::from(row.payload.clone()));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_segments(k: u16, len: usize) -> Vec<Bytes> {
        (0..k)
            .map(|j| {
                let v: Vec<u8> = (0..len).map(|i| ((j as usize + i) * 17) as u8).collect();
                Bytes::from(v)
            })
            .collect()
    }

    #[test]
    fn rejects_bad_params() {
        assert!(Encoder::new(0, 4).is_err());
        assert!(Encoder::new(4, 3).is_err());
        assert!(Encoder::new(4, 256).is_err());
        assert!(Decoder::new(0, 4).is_err());
    }

    #[test]
    fn encoder_parity_shape() {
        let k = 4u16;
        let n = 6u16;
        let mut enc = Encoder::new(k, n).unwrap();
        for seg in source_segments(k, 8) {
            enc.feed(seg).unwrap();
        }
        for i in k..n {
            let p = enc.parity(i).unwrap();
            assert_eq!(p.len(), 8);
        }
        assert!(enc.parity(k - 1).is_err());
        assert!(enc.parity(n).is_err());
    }

    #[test]
    fn decoder_from_pure_source() {
        let k = 6u16;
        let n = 10u16;
        let sources = source_segments(k, 32);
        let mut dec = Decoder::new(k, n).unwrap();
        for (j, seg) in sources.iter().enumerate() {
            let added = dec.absorb(j as u16, seg.clone()).unwrap();
            assert!(added);
        }
        assert!(dec.is_complete());
        let recovered = dec.recover().unwrap();
        for (a, b) in recovered.iter().zip(sources.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn decoder_handles_duplicate() {
        let k = 4u16;
        let n = 6u16;
        let sources = source_segments(k, 16);
        let mut dec = Decoder::new(k, n).unwrap();
        assert!(dec.absorb(0, sources[0].clone()).unwrap());
        assert!(!dec.absorb(0, sources[0].clone()).unwrap());
        assert_eq!(dec.rank(), 1);
    }

    #[test]
    fn round_trip_with_losses() {
        let k = 8u16;
        let n = 12u16;
        let seg_len = 64usize;
        let sources = source_segments(k, seg_len);
        let mut enc = Encoder::new(k, n).unwrap();
        for s in &sources {
            enc.feed(s.clone()).unwrap();
        }

        let mut all: Vec<(u16, Bytes)> = Vec::new();
        for (j, s) in sources.iter().enumerate() {
            all.push((j as u16, s.clone()));
        }
        for i in k..n {
            all.push((i, enc.parity(i).unwrap()));
        }

        let lost: [u16; 3] = [1, 3, 6];
        let mut delivered: Vec<(u16, Bytes)> = all
            .into_iter()
            .filter(|(idx, _)| !lost.contains(idx))
            .collect();
        delivered.swap(0, 5);
        delivered.swap(2, 7);

        let mut dec = Decoder::new(k, n).unwrap();
        for (idx, bytes) in delivered.into_iter().take(k as usize) {
            dec.absorb(idx, bytes).unwrap();
        }
        assert!(dec.is_complete(), "rank={} k={}", dec.rank(), k);
        let recovered = dec.recover().unwrap();
        for (j, src) in sources.iter().enumerate() {
            assert_eq!(&recovered[j], src, "segment {j} mismatch");
        }
    }

    #[test]
    fn round_trip_all_parity() {
        // Every source lost; reconstruct entirely from parity (requires N-K >= K).
        let k = 4u16;
        let n = 8u16;
        let seg_len = 16usize;
        let sources = source_segments(k, seg_len);
        let mut enc = Encoder::new(k, n).unwrap();
        for s in &sources {
            enc.feed(s.clone()).unwrap();
        }

        let mut dec = Decoder::new(k, n).unwrap();
        for i in k..n {
            let p = enc.parity(i).unwrap();
            dec.absorb(i, p).unwrap();
        }
        assert!(dec.is_complete());
        let recovered = dec.recover().unwrap();
        for (j, src) in sources.iter().enumerate() {
            assert_eq!(&recovered[j], src);
        }
    }

    #[test]
    fn segment_length_mismatch_detected() {
        let mut enc = Encoder::new(2, 4).unwrap();
        enc.feed(Bytes::from_static(&[1, 2, 3])).unwrap();
        assert!(enc.feed(Bytes::from_static(&[1, 2])).is_err());

        let mut dec = Decoder::new(2, 4).unwrap();
        dec.absorb(0, Bytes::from_static(&[1, 2, 3])).unwrap();
        assert!(dec.absorb(1, Bytes::from_static(&[1, 2])).is_err());
    }
}
