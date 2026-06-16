//! `MurmurHash3_x86_32` — the hash family used by PSync's IBF cell
//! selection and `keyCheck` field. Constants `N_HASH = 3`,
//! `N_HASHCHECK = 11` per `PSync/detail/iblt.hpp`. Ported byte-for-byte
//! from the PSync reference; verified against canonical SMHasher
//! vectors in the in-module tests.

const C1: u32 = 0xcc9e2d51;
const C2: u32 = 0x1b873593;

/// `PSync/detail/iblt.hpp` line 102.
pub const N_HASHCHECK: u32 = 11;

/// `PSync/detail/iblt.hpp` line 101.
pub const N_HASH: u32 = 3;

pub fn murmur3_x86_32(key: &[u8], seed: u32) -> u32 {
    let nblocks = key.len() / 4;
    let mut h1 = seed;

    for i in 0..nblocks {
        let off = i * 4;
        let mut k1 = u32::from_le_bytes([key[off], key[off + 1], key[off + 2], key[off + 3]]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);
    }

    let tail = &key[nblocks * 4..];
    if !tail.is_empty() {
        let mut k1: u32 = 0;
        if tail.len() >= 3 {
            k1 ^= (tail[2] as u32) << 16;
        }
        if tail.len() >= 2 {
            k1 ^= (tail[1] as u32) << 8;
        }
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }

    h1 ^= key.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85ebca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2ae35);
    h1 ^= h1 >> 16;
    h1
}

/// Matches C++ `murmurHash3(uint32_t seed, uint32_t value)` in
/// `PSync/detail/util.hpp`; x86 stores `uint32_t` little-endian.
pub fn murmur3_u32(value: u32, seed: u32) -> u32 {
    murmur3_x86_32(&value.to_le_bytes(), seed)
}

pub fn murmur3_u64(value: u64, seed: u32) -> u32 {
    murmur3_x86_32(&value.to_le_bytes(), seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smhasher_canonical_vectors() {
        assert_eq!(murmur3_x86_32(b"", 0), 0x0000_0000);
        assert_eq!(murmur3_x86_32(b"", 1), 0x514E_28B7);
        assert_eq!(murmur3_x86_32(b"", 0xffff_ffff), 0x81F1_6F39);
        assert_eq!(murmur3_x86_32(b"aaaa", 0x9747_b28c), 0x5A97_808A);
        assert_eq!(murmur3_x86_32(b"Hello, world!", 0), 0xC036_3E43);
    }

    #[test]
    fn tail_lengths_one_through_three_handled() {
        let _ = murmur3_x86_32(b"a", 0);
        let _ = murmur3_x86_32(b"ab", 0);
        let _ = murmur3_x86_32(b"abc", 0);
        let _ = murmur3_x86_32(b"abcd", 0);
    }

    #[test]
    fn u64_hash_is_le_bytes() {
        let v: u64 = 0x0123_4567_89ab_cdef;
        assert_eq!(murmur3_u64(v, 11), murmur3_x86_32(&v.to_le_bytes(), 11));
    }
}
