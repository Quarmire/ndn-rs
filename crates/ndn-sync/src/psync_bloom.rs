//! Bloom filter wire-compatible with `PSync/detail/bloom-filter.cpp`
//! (Arash Partow's `bloom` filter, MurmurHash3-keyed). Used by Partial
//! Sync: a consumer encodes its subscription set as a Bloom filter and
//! appends it to the Sync Interest so the `PartialProducer` only returns
//! updates for prefixes the consumer subscribed to.
//!
//! Conformance anchors (from `PSync/tests/test-bloom-filter.cpp`):
//! `BloomFilter(100, 0.001)` ⇒ `appendToName` emits `count = 100`,
//! `fpp*1000 = 1`, and a 180-byte table (10 hashes, 1440 bits); a
//! `BloomFilter(200, 0.001, bytes)` rejects those 180 bytes because its
//! own table is 360 bytes. The optimal-parameter search, the predefined
//! salt table, the `(seed * 0xA5A5A5A5)+1` seed mixing, and the
//! `murmurHash3(salt, name.wireValue)` hashing are ported byte-for-byte
//! so a filter built here is decodable by C++ PSync and vice versa.

use bytes::Bytes;
use ndn_packet::{Name, NameComponent};

use crate::murmur3::murmur3_x86_32;
use crate::psync_sync::name_wire_value;
use crate::tlv::{decode_nni, encode_nni};

const BITS_PER_CHAR: usize = 8;

/// A Bloom filter over NDN [`Name`]s, encodable into / decodable from a
/// Sync Interest name (`count`, `fpp*1000`, raw-bit-table components).
#[derive(Clone, Debug)]
pub struct BloomFilter {
    salt: Vec<u32>,
    bit_table: Vec<u8>,
    /// Table size in bits (always a multiple of 8).
    table_size: u32,
    projected_element_count: u32,
    false_positive_probability: f64,
}

impl BloomFilter {
    /// Build an empty filter sized for `projected_element_count` elements
    /// at `false_positive_probability` (Arash Partow optimal parameters).
    pub fn new(projected_element_count: u32, false_positive_probability: f64) -> Self {
        let (num_hashes, table_size) =
            compute_optimal_parameters(projected_element_count, false_positive_probability);
        let salt = generate_salt(num_hashes);
        BloomFilter {
            salt,
            bit_table: vec![0u8; (table_size as usize) / BITS_PER_CHAR],
            table_size,
            projected_element_count,
            false_positive_probability,
        }
    }

    /// Reconstruct the filter a peer encoded: the same `(count, fpp)`
    /// parameters plus its raw bit-table bytes. Errors if the byte length
    /// doesn't match the table size those parameters imply (the C++
    /// "Bloom filter cannot be decoded!" guard).
    pub fn from_bits(
        projected_element_count: u32,
        false_positive_probability: f64,
        bits: &[u8],
    ) -> Result<Self, BloomError> {
        let mut bf = BloomFilter::new(projected_element_count, false_positive_probability);
        if bits.len() != bf.bit_table.len() {
            return Err(BloomError::SizeMismatch {
                expected: bf.bit_table.len(),
                got: bits.len(),
            });
        }
        bf.bit_table = bits.to_vec();
        Ok(bf)
    }

    /// Insert a name (hashed over its TLV component bytes, as C++).
    pub fn insert(&mut self, key: &Name) {
        let value = name_wire_value(key);
        for &salt in &self.salt {
            let hash = murmur3_x86_32(&value, salt);
            let bit_index = (hash % self.table_size) as usize;
            self.bit_table[bit_index / BITS_PER_CHAR] |= 1u8 << (bit_index % BITS_PER_CHAR);
        }
    }

    /// Probabilistic membership test (no false negatives).
    pub fn contains(&self, key: &Name) -> bool {
        let value = name_wire_value(key);
        for &salt in &self.salt {
            let hash = murmur3_x86_32(&value, salt);
            let bit_index = (hash % self.table_size) as usize;
            let mask = 1u8 << (bit_index % BITS_PER_CHAR);
            if self.bit_table[bit_index / BITS_PER_CHAR] & mask != mask {
                return false;
            }
        }
        true
    }

    /// Reset every bit (C++ `clear`); keeps the same parameters/salt.
    pub fn clear(&mut self) {
        self.bit_table.iter_mut().for_each(|b| *b = 0);
    }

    /// Append `count`, `fpp*1000`, and the raw bit table to `name` as three
    /// components — the `PSync::detail::BloomFilter::appendToName` layout a
    /// `PartialProducer` parses back with [`Self::from_bits`].
    pub fn append_to_name(&self, name: &Name) -> Name {
        let with_count = name
            .clone()
            .append_component(NameComponent::generic(Bytes::from(encode_nni(
                self.projected_element_count as u64,
            ))));
        let with_fpp =
            with_count.append_component(NameComponent::generic(Bytes::from(encode_nni(
                (self.false_positive_probability * 1000.0) as u64,
            ))));
        with_fpp.append_component(NameComponent::generic(Bytes::from(self.bit_table.clone())))
    }

    /// Decode a filter from the trailing three components of a name
    /// (`…/count/fpp/bits`), e.g. the BF portion of a Sync Interest.
    pub fn from_name_suffix(comps: &[NameComponent]) -> Option<BloomFilter> {
        if comps.len() < 3 {
            return None;
        }
        let n = comps.len();
        let count = decode_nni(&comps[n - 3].value) as u32;
        let fpp = decode_nni(&comps[n - 2].value) as f64 / 1000.0;
        BloomFilter::from_bits(count, fpp, &comps[n - 1].value).ok()
    }
}

/// Why a peer's encoded Bloom filter couldn't be reconstructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BloomError {
    /// The bit-table byte count doesn't match the `(count, fpp)` params.
    SizeMismatch { expected: usize, got: usize },
}

impl std::fmt::Display for BloomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BloomError::SizeMismatch { expected, got } => {
                write!(f, "bloom filter cannot be decoded: expected {expected} bytes, got {got}")
            }
        }
    }
}

impl std::error::Error for BloomError {}

/// Port of `bloom_parameters::compute_optimal_parameters` — searches
/// `k = 1..1000` for the `(num_hashes, table_bits)` minimising storage at
/// the target false-positive rate, rounding the table up to a whole byte.
fn compute_optimal_parameters(n: u32, p: f64) -> (u32, u32) {
    let mut min_m = f64::INFINITY;
    let mut min_k = 0.0f64;
    let mut k = 1.0f64;
    while k < 1000.0 {
        let numerator = -k * n as f64;
        let denominator = (1.0 - p.powf(1.0 / k)).ln();
        let curr_m = numerator / denominator;
        if curr_m < min_m {
            min_m = curr_m;
            min_k = k;
        }
        k += 1.0;
    }
    let mut num_hashes = min_k as u32;
    let mut table_size = min_m as u32;
    let rem = table_size % BITS_PER_CHAR as u32;
    if rem != 0 {
        table_size += BITS_PER_CHAR as u32 - rem;
    }
    // C++ clamps to [minimum_number_of_hashes=1, max=u32::MAX] and
    // [minimum_size=1, max=u32::MAX]; only the lower bounds can bind.
    if num_hashes < 1 {
        num_hashes = 1;
    }
    if table_size < 1 {
        table_size = 1;
    }
    (num_hashes, table_size)
}

/// Port of `BloomFilter::generate_unique_salt`: take `num_hashes` entries
/// from the predefined salt table, then mix in the (fixed) random seed
/// exactly as C++ does (`salt[i] = salt[i]*salt[(i+3)%k] + seed32`,
/// in-place so later entries see updated earlier ones).
fn generate_salt(num_hashes: u32) -> Vec<u32> {
    // random_seed_ = (0xA5A5A5A55A5A5A5A * 0xA5A5A5A5) + 1 (64-bit), then
    // the salt mix uses its low 32 bits.
    let random_seed_: u64 = 0xA5A5_A5A5_5A5A_5A5A_u64
        .wrapping_mul(0xA5A5_A5A5_u64)
        .wrapping_add(1);
    let seed32 = random_seed_ as u32;

    let k = num_hashes as usize;
    // C++ falls through to a different path when k > 128; PSync never sizes
    // that many hashes, so mirror only the predefined-salt branch.
    let take = k.min(PREDEF_SALT.len());
    let mut salt: Vec<u32> = PREDEF_SALT[..take].to_vec();
    let len = salt.len();
    for i in 0..len {
        salt[i] = salt[i]
            .wrapping_mul(salt[(i + 3) % len])
            .wrapping_add(seed32);
    }
    salt
}

/// The 128 predefined salts from `bloom-filter.cpp::generate_unique_salt`.
#[rustfmt::skip]
const PREDEF_SALT: [u32; 128] = [
    0xAAAAAAAA, 0x55555555, 0x33333333, 0xCCCCCCCC,
    0x66666666, 0x99999999, 0xB5B5B5B5, 0x4B4B4B4B,
    0xAA55AA55, 0x55335533, 0x33CC33CC, 0xCC66CC66,
    0x66996699, 0x99B599B5, 0xB54BB54B, 0x4BAA4BAA,
    0xAA33AA33, 0x55CC55CC, 0x33663366, 0xCC99CC99,
    0x66B566B5, 0x994B994B, 0xB5AAB5AA, 0xAAAAAA33,
    0x555555CC, 0x33333366, 0xCCCCCC99, 0x666666B5,
    0x9999994B, 0xB5B5B5AA, 0xFFFFFFFF, 0xFFFF0000,
    0xB823D5EB, 0xC1191CDF, 0xF623AEB3, 0xDB58499F,
    0xC8D42E70, 0xB173F616, 0xA91A5967, 0xDA427D63,
    0xB1E8A2EA, 0xF6C0D155, 0x4909FEA3, 0xA68CC6A7,
    0xC395E782, 0xA26057EB, 0x0CD5DA28, 0x467C5492,
    0xF15E6982, 0x61C6FAD3, 0x9615E352, 0x6E9E355A,
    0x689B563E, 0x0C9831A8, 0x6753C18B, 0xA622689B,
    0x8CA63C47, 0x42CC2884, 0x8E89919B, 0x6EDBD7D3,
    0x15B6796C, 0x1D6FDFE4, 0x63FF9092, 0xE7401432,
    0xEFFE9412, 0xAEAEDF79, 0x9F245A31, 0x83C136FC,
    0xC3DA4A8C, 0xA5112C8C, 0x5271F491, 0x9A948DAB,
    0xCEE59A8D, 0xB5F525AB, 0x59D13217, 0x24E7C331,
    0x697C2103, 0x84B0A460, 0x86156DA9, 0xAEF2AC68,
    0x23243DA5, 0x3F649643, 0x5FA495A8, 0x67710DF8,
    0x9A6C499E, 0xDCFB0227, 0x46A43433, 0x1832B07A,
    0xC46AFF3C, 0xB9C8FFF0, 0xC9500467, 0x34431BDF,
    0xB652432B, 0xE367F12B, 0x427F4C1B, 0x224C006E,
    0x2E7E5A89, 0x96F99AA5, 0x0BEB452A, 0x2FD87C39,
    0x74B2E1FB, 0x222EFD24, 0xF357F60C, 0x440FCB1E,
    0x8BBE030F, 0x6704DC29, 0x1144D12F, 0x948B1355,
    0x6D8FD7E9, 0x1C11A014, 0xADD1592F, 0xFB3C712E,
    0xFC77642F, 0xF9C4CE8C, 0x31312FB9, 0x08B0DD79,
    0x318FA6E7, 0xC040D23D, 0xC0589AA7, 0x0CA5C075,
    0xF874B172, 0x0CF914D5, 0x784D3280, 0x4E8CFEBC,
    0xC569F575, 0xCDB2A091, 0x2CC016B4, 0x5C5F4421,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn optimal_parameters_match_cpp() {
        // From PSync test golden + hand-computed table sizes.
        assert_eq!(compute_optimal_parameters(100, 0.001), (10, 1440));
        assert_eq!(compute_optimal_parameters(200, 0.001), (10, 2880));
    }

    #[test]
    fn insert_then_contains() {
        let mut bf = BloomFilter::new(100, 0.001);
        let name = n("/memphis");
        assert!(!bf.contains(&name));
        bf.insert(&name);
        assert!(bf.contains(&name));
        // A name never inserted is (almost surely) absent.
        assert!(!bf.contains(&n("/not/inserted/anywhere")));
    }

    #[test]
    fn append_and_extract_roundtrips() {
        // Mirrors test-bloom-filter.cpp::NameAppendAndExtract.
        let base = n("/test");
        let mut bf = BloomFilter::new(100, 0.001);
        bf.insert(&n("/memphis"));
        let bf_name = bf.append_to_name(&base);

        let comps = bf_name.components();
        // /test=0, count=1, fpp=2, bits=3
        assert_eq!(decode_nni(&comps[1].value), 100);
        assert_eq!(decode_nni(&comps[2].value), 1);
        assert_eq!(comps[3].value.len(), 180, "1440 bits / 8 = 180 bytes");

        let restored = BloomFilter::from_name_suffix(&comps[1..]).expect("decode");
        assert_eq!(restored.bit_table, bf.bit_table);
        assert!(restored.contains(&n("/memphis")));
    }

    #[test]
    fn wrong_param_table_size_rejected() {
        // A 180-byte (100,0.001) table can't be loaded as (200,0.001) → 360 B.
        let bf = BloomFilter::new(100, 0.001);
        let bits = vec![0u8; bf.bit_table.len()];
        assert_eq!(
            BloomFilter::from_bits(200, 0.001, &bits).unwrap_err(),
            BloomError::SizeMismatch { expected: 360, got: 180 },
        );
    }

    #[test]
    fn clear_empties_table() {
        let mut bf = BloomFilter::new(50, 0.01);
        bf.insert(&n("/a"));
        bf.insert(&n("/b"));
        bf.clear();
        assert!(!bf.contains(&n("/a")));
        assert!(bf.bit_table.iter().all(|&b| b == 0));
    }
}
