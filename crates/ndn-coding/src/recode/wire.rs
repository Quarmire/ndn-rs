//! Local TLV varint/codec helpers for the F2 recode module.
//!
//! Pure-code extraction of the wire helpers from `recode.rs`; behavior is
//! unchanged. Kept private to the F2 module (`pub(super)`).

use super::*;

pub(super) fn field_code(f: Field) -> u8 {
    match f {
        Field::Gf8 => 0,
    }
}

pub(super) fn field_from_code(c: u8) -> Result<Field> {
    match c {
        0 => Ok(Field::Gf8),
        _ => Err(CodingError::MalformedMetadata),
    }
}

pub(super) fn one_byte(v: &[u8]) -> Result<u8> {
    if v.len() != 1 {
        return Err(CodingError::MalformedMetadata);
    }
    Ok(v[0])
}

pub(super) fn encode_commitment(c: &SourceCommitment) -> Vec<u8> {
    let mut out = Vec::new();
    match c {
        SourceCommitment::RowHashes(hs) => {
            out.push(0);
            for h in hs {
                out.extend_from_slice(h);
            }
        }
        SourceCommitment::MerkleRoot(root) => {
            out.push(1);
            out.extend_from_slice(root);
        }
    }
    out
}

pub(super) fn decode_commitment(v: &[u8]) -> Result<SourceCommitment> {
    let (&kind, rest) = v.split_first().ok_or(CodingError::MalformedMetadata)?;
    match kind {
        0 => {
            if rest.len() % 32 != 0 {
                return Err(CodingError::MalformedMetadata);
            }
            let hashes = rest
                .chunks_exact(32)
                .map(|c| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(c);
                    a
                })
                .collect();
            Ok(SourceCommitment::RowHashes(hashes))
        }
        1 => {
            if rest.len() != 32 {
                return Err(CodingError::MalformedMetadata);
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(rest);
            Ok(SourceCommitment::MerkleRoot(a))
        }
        _ => Err(CodingError::MalformedMetadata),
    }
}

pub(super) fn decode_fingerprint(v: Bytes) -> Result<LinearFingerprint> {
    let mut r = TlvReader::new(v);
    let (mut rr, mut hh, mut seed) = (None, None, None);
    while !r.is_empty() {
        let (t, val) = r.read_tlv().map_err(|_| CodingError::MalformedMetadata)?;
        match t {
            TYPE_FP_R => rr = Some(val.to_vec()),
            TYPE_FP_H => hh = Some(val.to_vec()),
            TYPE_FP_SEED_HASH => {
                if val.len() != 32 {
                    return Err(CodingError::MalformedMetadata);
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&val);
                seed = Some(a);
            }
            _ => {}
        }
    }
    Ok(LinearFingerprint {
        r: rr.ok_or(CodingError::MalformedMetadata)?,
        h: hh.ok_or(CodingError::MalformedMetadata)?,
        seed_hash: seed,
    })
}

pub(super) fn encode_u64_be(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0];
    }
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[first..].to_vec()
}

pub(super) fn decode_u64_be(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(CodingError::MalformedMetadata);
    }
    let mut v = 0u64;
    for &b in bytes {
        v = (v << 8) | b as u64;
    }
    Ok(v)
}

pub(super) fn decode_u16_be(bytes: &[u8]) -> Result<u16> {
    if bytes.len() != 2 {
        return Err(CodingError::MalformedMetadata);
    }
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(super) fn decode_u32_be(bytes: &[u8]) -> Result<u32> {
    if bytes.len() != 4 {
        return Err(CodingError::MalformedMetadata);
    }
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
