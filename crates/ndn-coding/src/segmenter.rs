//! Producer-side segmentation: turn a payload into K source + (N−K) parity
//! Data Content bodies, each prefixed by a `FecMetadata` TLV. All N segments
//! in a generation share the same row length.

use bytes::Bytes;

use crate::fec::Encoder;
use crate::metadata::{FecMetadata, SegmentRole, prepend_metadata};
use crate::policy::FecPolicy;
use crate::{CodingError, Result};

#[derive(Debug, Clone)]
pub struct EmittedSegment {
    pub index: u16,
    pub content: Bytes,
}

/// Encode `payload` as one generation under `policy`. Short payloads are
/// zero-padded; the padding count is stamped into every segment's
/// `FecMetadata.padding_len` so consumers can trim regardless of arrival
/// order.
pub fn segment_payload(
    payload: &[u8],
    policy: &FecPolicy,
    generation_id: u64,
) -> Result<Vec<EmittedSegment>> {
    let k = policy.k as usize;
    let n = policy.n as usize;
    if k == 0 || n < k || n > 255 {
        return Err(CodingError::InvalidParameters {
            k: policy.k,
            n: policy.n,
        });
    }
    // Empty payload still yields one byte per source segment so the encoder's
    // uniform-row-length invariant holds without a special case.
    let seg_len = payload.len().div_ceil(k).max(1);
    let total_source = seg_len * k;
    let padding = (total_source - payload.len()) as u32;
    let padding_len = if padding > 0 { Some(padding) } else { None };

    let mut sources: Vec<Bytes> = Vec::with_capacity(k);
    for j in 0..k {
        let start = j * seg_len;
        let end = (start + seg_len).min(payload.len());
        let mut buf = vec![0u8; seg_len];
        if start < payload.len() {
            buf[..(end - start)].copy_from_slice(&payload[start..end]);
        }
        sources.push(Bytes::from(buf));
    }

    let mut enc = Encoder::new(policy.k, policy.n)?;
    for src in &sources {
        enc.feed(src.clone())?;
    }

    let mut out = Vec::with_capacity(n);
    for (i, source) in sources.iter().enumerate().take(k) {
        let meta = FecMetadata {
            generation_id,
            role: SegmentRole::Source,
            index: i as u16,
            k: policy.k,
            n: policy.n,
            field: policy.field,
            padding_len,
        };
        let content = prepend_metadata(&meta, source);
        out.push(EmittedSegment {
            index: i as u16,
            content,
        });
    }
    for i in k..n {
        let parity = enc.parity(i as u16)?;
        let meta = FecMetadata {
            generation_id,
            role: SegmentRole::Parity,
            index: i as u16,
            k: policy.k,
            n: policy.n,
            field: policy.field,
            padding_len,
        };
        let content = prepend_metadata(&meta, &parity);
        out.push(EmittedSegment {
            index: i as u16,
            content,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Field;

    #[test]
    fn segments_payload_into_n_pieces() {
        let policy = FecPolicy {
            k: 4,
            n: 6,
            field: Field::Gf8,
        };
        let payload = b"the quick brown fox jumps over the lazy dog!";
        let plan = segment_payload(payload, &policy, 42).unwrap();
        assert_eq!(plan.len(), 6);
        let first_len = plan[0].content.len();
        for s in &plan {
            assert_eq!(s.content.len(), first_len);
        }
    }

    #[test]
    fn padding_recorded_for_short_payload() {
        let policy = FecPolicy {
            k: 4,
            n: 5,
            field: Field::Gf8,
        };
        let payload = b"abc"; // 3 bytes → seg_len 1 → total 4 → padding 1.
        let plan = segment_payload(payload, &policy, 7).unwrap();
        let (meta, _) = crate::metadata::split_metadata(&plan[0].content).unwrap();
        assert_eq!(meta.padding_len, Some(1));
    }
}
