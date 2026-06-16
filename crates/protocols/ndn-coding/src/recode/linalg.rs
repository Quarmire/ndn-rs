//! GF(2^8) / Gaussian-elimination source-recovery helpers for the F2 recode
//! module.
//!
//! Pure-code extraction from `recode.rs`; behavior is unchanged. Kept private
//! to the F2 module (`pub(super)`).

use super::*;

/// GF(2^8) dot product (XOR-sum of products).
pub(super) fn gf_dot(a: &[u8], b: &[u8]) -> u8 {
    a.iter()
        .zip(b)
        .fold(0u8, |acc, (&x, &y)| acc ^ field::mul(x, y))
}

/// Fast-path recovery when the held packets are **systematic** — each a unit
/// coding vector covering `0..k`. Recovers sources by index with **no GF
/// work** (vs the O(k²·symbol) Gauss-Jordan). `None` if not systematic, so the
/// caller falls back to [`solve_sources`].
pub(super) fn systematic_sources(
    packets: &[CodedPacket],
    k: usize,
    symbol_size: usize,
) -> Option<Vec<Vec<u8>>> {
    if packets.len() != k {
        return None;
    }
    let mut slots: Vec<Option<&Bytes>> = vec![None; k];
    for p in packets {
        // The vector must be a unit vector: exactly one coefficient, equal to 1.
        let mut idx = None;
        for (i, &c) in p.vector.0.iter().enumerate() {
            if c != 0 {
                if idx.is_some() || c != 1 {
                    return None;
                }
                idx = Some(i);
            }
        }
        let i = idx?;
        if i >= k || slots[i].is_some() || p.payload.len() != symbol_size {
            return None;
        }
        slots[i] = Some(&p.payload);
    }
    slots.into_iter().map(|s| s.map(|b| b.to_vec())).collect()
}

/// Recover the K source rows by Gauss-Jordan elimination over GF(2^8) on the
/// `(coefficient | payload)` augmented matrix of the held packets. Returns
/// the K source rows in index order, or `None` if rank < K.
pub(super) fn solve_sources(
    packets: &[CodedPacket],
    k: usize,
    symbol_size: usize,
) -> Option<Vec<Vec<u8>>> {
    // Augmented rows: K coefficient columns followed by symbol_size payload columns.
    let mut rows: Vec<Vec<u8>> = packets
        .iter()
        .map(|p| {
            let mut row = p.vector.0.clone();
            row.extend_from_slice(&p.payload);
            row
        })
        .collect();
    let cols = k + symbol_size;
    let mut pivot_row = 0;
    for col in 0..k {
        // find a row at/after pivot_row with nonzero in `col`
        let sel = (pivot_row..rows.len()).find(|&r| rows[r][col] != 0)?;
        rows.swap(pivot_row, sel);
        let inv = field::inv(rows[pivot_row][col]);
        field::scale(&mut rows[pivot_row], inv);
        let pivot = rows[pivot_row].clone();
        #[allow(clippy::needless_range_loop)] // need the index to skip the pivot row
        for r in 0..rows.len() {
            if r != pivot_row && rows[r][col] != 0 {
                let c = rows[r][col];
                field::mul_add(&mut rows[r], &pivot, c);
            }
        }
        pivot_row += 1;
        if pivot_row == rows.len() {
            break;
        }
    }
    if pivot_row < k {
        return None; // insufficient rank
    }
    // After RREF the first k rows' coefficient block is the identity; the
    // payload block is the recovered source row.
    let mut out = Vec::with_capacity(k);
    for (i, row) in rows.iter().take(k).enumerate() {
        debug_assert_eq!(row[i], 1);
        out.push(row[k..cols].to_vec());
    }
    Some(out)
}

/// Verify recovered source rows against the descriptor commitment (SHA-256).
pub(super) fn verify_sources(sources: &[Vec<u8>], commitment: &SourceCommitment) -> bool {
    use sha2::{Digest, Sha256};
    let hashes: Vec<[u8; 32]> = sources
        .iter()
        .map(|row| {
            let mut h = Sha256::new();
            h.update(row);
            h.finalize().into()
        })
        .collect();
    match commitment {
        SourceCommitment::RowHashes(expected) => {
            expected.len() == hashes.len() && *expected == hashes
        }
        SourceCommitment::MerkleRoot(root) => merkle_root(&hashes) == *root,
    }
}
