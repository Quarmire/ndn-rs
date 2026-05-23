use std::collections::HashSet;

use crate::murmur3::{N_HASH, N_HASHCHECK, murmur3_u32};

/// IBLT cell. Mirrors C++ `HashTableEntry` in `PSync/detail/iblt.hpp`:
/// `int32_t count`, `uint32_t keySum`, `uint32_t keyCheck`. Wire shape
/// (big-endian): count(4) + keySum(4) + keyCheck(4) = 12 bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IbfCell {
    pub count: i32,
    pub key_sum: u32,
    pub key_check: u32,
}

impl IbfCell {
    /// True iff this cell holds exactly one element:
    /// `count == ±1 && murmur3(N_HASHCHECK, key_sum) == key_check`.
    pub fn is_pure(&self) -> bool {
        (self.count == 1 || self.count == -1)
            && murmur3_u32(self.key_sum, N_HASHCHECK) == self.key_check
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0 && self.key_sum == 0 && self.key_check == 0
    }
}

/// IBLT over `u32` element hashes (C++ `IBLT` in
/// `PSync/detail/iblt.hpp`). Cell count = `expected + expected/2`
/// rounded up to a multiple of `N_HASH=3`.
#[derive(Clone, Debug)]
pub struct Ibf {
    cells: Vec<IbfCell>,
}

impl Ibf {
    /// Caller picks a cell count divisible by `N_HASH`.
    pub fn new(n_cells: usize) -> Self {
        let n = n_cells.max(N_HASH as usize);
        Self {
            cells: vec![IbfCell::default(); n],
        }
    }

    pub fn from_expected(expected_entries: usize) -> Self {
        let mut n = expected_entries + expected_entries / 2;
        let rem = n % N_HASH as usize;
        if rem != 0 {
            n += N_HASH as usize - rem;
        }
        Self::new(n.max(N_HASH as usize))
    }

    pub fn from_raw_cells(raw: Vec<(i32, u32, u32)>) -> Self {
        Self {
            cells: raw
                .into_iter()
                .map(|(count, key_sum, key_check)| IbfCell {
                    count,
                    key_sum,
                    key_check,
                })
                .collect(),
        }
    }

    pub fn raw_cells(&self) -> Vec<(i32, u32, u32)> {
        self.cells
            .iter()
            .map(|c| (c.count, c.key_sum, c.key_check))
            .collect()
    }

    pub fn n_cells(&self) -> usize {
        self.cells.len()
    }

    /// Sectioned: hash `i` maps into section `i` only —
    /// `cell = i * (n/N_HASH) + murmurHash3(i, key) % (n/N_HASH)`.
    #[cfg(test)]
    fn cell_indices(&self, key: u32) -> [usize; 3] {
        let section = self.cells.len() / N_HASH as usize;
        let h0 = murmur3_u32(key, 0) as usize;
        let h1 = murmur3_u32(key, 1) as usize;
        let h2 = murmur3_u32(key, 2) as usize;
        [
            h0 % section,
            section + h1 % section,
            2 * section + h2 % section,
        ]
    }

    pub fn insert(&mut self, key: u32) {
        iblt_update(&mut self.cells, 1, key);
    }

    pub fn erase(&mut self, key: u32) {
        iblt_update(&mut self.cells, -1, key);
    }

    /// Compute the symmetric-difference IBF: `self - other`.
    ///
    /// Each cell: `count = self.count - other.count`,
    ///            `key_sum = self.key_sum ^ other.key_sum`,
    ///            `key_check = self.key_check ^ other.key_check`.
    /// (`PSync/detail/iblt.cpp` `operator-`, lines 176-185)
    pub fn subtract(&self, other: &Ibf) -> Ibf {
        let cells = self
            .cells
            .iter()
            .zip(&other.cells)
            .map(|(a, b)| IbfCell {
                count: a.count - b.count,
                key_sum: a.key_sum ^ b.key_sum,
                key_check: a.key_check ^ b.key_check,
            })
            .collect();
        Ibf { cells }
    }

    /// Eppstein peeling. `Some((self_only, other_only))` on success,
    /// `None` when the difference is too large to decode.
    pub fn decode(&self) -> Option<(HashSet<u32>, HashSet<u32>)> {
        let mut cells = self.cells.clone();
        let mut positive = HashSet::new();
        let mut negative = HashSet::new();

        loop {
            let pure_idx = cells.iter().position(|c| c.is_pure());
            let Some(idx) = pure_idx else { break };
            let key = cells[idx].key_sum;
            let count = cells[idx].count;
            if count == 1 {
                positive.insert(key);
            } else {
                negative.insert(key);
            }
            iblt_update(&mut cells, -count, key);
        }

        if cells.iter().all(|c| c.is_empty()) {
            Some((positive, negative))
        } else {
            None
        }
    }
}

/// Mirrors C++ `ibltUpdate`.
fn iblt_update(cells: &mut [IbfCell], plus_or_minus: i32, key: u32) {
    let section = cells.len() / N_HASH as usize;
    for i in 0..N_HASH as usize {
        let h = murmur3_u32(key, i as u32) as usize;
        let idx = i * section + h % section;
        cells[idx].count += plus_or_minus;
        cells[idx].key_sum ^= key;
        cells[idx].key_check ^= murmur3_u32(key, N_HASHCHECK);
    }
}

/// Tracks a local set of `u32` content hashes and an IBLT over them.
/// `expected_entries = 80` matches the C++ `FullProducer` default.
pub struct PSyncNode {
    local_set: HashSet<u32>,
    expected_entries: usize,
}

impl PSyncNode {
    pub fn new(expected_entries: usize) -> Self {
        Self {
            local_set: HashSet::new(),
            expected_entries: expected_entries.max(3),
        }
    }

    pub fn insert(&mut self, hash: u32) {
        self.local_set.insert(hash);
    }

    /// `true` if the hash was present.
    pub fn remove(&mut self, hash: u32) -> bool {
        self.local_set.remove(&hash)
    }

    pub fn contains(&self, hash: u32) -> bool {
        self.local_set.contains(&hash)
    }

    pub fn len(&self) -> usize {
        self.local_set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.local_set.is_empty()
    }

    pub fn build_ibf(&self) -> Ibf {
        let mut ibf = Ibf::from_expected(self.expected_entries);
        for &h in &self.local_set {
            ibf.insert(h);
        }
        ibf
    }

    /// `Some((self_only, peer_only))` or `None` when the difference is
    /// too large to decode.
    pub fn reconcile(&self, peer_ibf: &Ibf) -> Option<(HashSet<u32>, HashSet<u32>)> {
        self.build_ibf().subtract(peer_ibf).decode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::murmur3::murmur3_x86_32;

    /// Wire-format test vector from `PSync/tests/test-iblt.cpp` —
    /// Name `/test/memphis/1`, expected `keySum = 0x5C5BF267,
    /// keyCheck = 0x4224EE6C`.
    #[test]
    fn ibf_cell_vector_matches_psync_cpp() {
        let name_value: &[u8] = &[
            0x08, 0x04, 0x74, 0x65, 0x73, 0x74, 0x08, 0x07, 0x6d, 0x65, 0x6d, 0x70, 0x68, 0x69,
            0x73, 0x08, 0x01, 0x01,
        ];

        let key = murmur3_x86_32(name_value, N_HASHCHECK);
        assert_eq!(key, 0x5C5BF267, "name hash must match C++ test vector");

        let key_check = murmur3_u32(key, N_HASHCHECK);
        assert_eq!(key_check, 0x4224EE6C, "keyCheck must match C++ test vector");

        let cell = IbfCell {
            count: 1,
            key_sum: key,
            key_check,
        };
        assert!(cell.is_pure(), "cell with single element must be pure");
    }

    #[test]
    fn ibf_insert_erase_is_identity() {
        let mut ibf = Ibf::from_expected(10);
        let key: u32 = 0x5C5BF267;
        ibf.insert(key);
        ibf.erase(key);
        assert!(
            ibf.cells.iter().all(|c| c.is_empty()),
            "all cells must be zero after insert+erase"
        );
    }

    #[test]
    fn from_expected_cell_count() {
        let ibf = Ibf::from_expected(10);
        assert_eq!(ibf.n_cells(), 15, "from_expected(10) → 15 cells");

        let ibf80 = Ibf::from_expected(80);
        assert_eq!(ibf80.n_cells(), 120, "from_expected(80) → 120 cells");
    }

    #[test]
    fn cell_indices_are_sectioned() {
        let ibf = Ibf::from_expected(10); // 15 cells, section=5
        let key: u32 = 0x5C5BF267;
        let [i0, i1, i2] = ibf.cell_indices(key);
        assert!(i0 < 5, "hash-0 must map into section 0 (cells 0-4)");
        assert!(
            (5..10).contains(&i1),
            "hash-1 must map into section 1 (cells 5-9)"
        );
        assert!(
            (10..15).contains(&i2),
            "hash-2 must map into section 2 (cells 10-14)"
        );
    }

    #[test]
    fn reconcile_identical_sets_returns_empty_diff() {
        let mut a = PSyncNode::new(64);
        let mut b = PSyncNode::new(64);
        for i in 0u32..10 {
            a.insert(i);
            b.insert(i);
        }
        let (a_extra, b_extra) = a.reconcile(&b.build_ibf()).unwrap();
        assert!(a_extra.is_empty());
        assert!(b_extra.is_empty());
    }

    #[test]
    fn reconcile_one_sided_difference() {
        let mut a = PSyncNode::new(64);
        let b = PSyncNode::new(64);
        a.insert(0x5C5BF267u32);
        let (a_has, b_has) = a.reconcile(&b.build_ibf()).unwrap();
        assert!(a_has.contains(&0x5C5BF267u32));
        assert!(b_has.is_empty());
    }

    #[test]
    fn reconcile_disjoint_sets() {
        let mut a = PSyncNode::new(64);
        let mut b = PSyncNode::new(64);
        a.insert(0x01020304u32);
        a.insert(0x11121314u32);
        b.insert(0x21222324u32);

        let (a_has, b_has) = a.reconcile(&b.build_ibf()).unwrap();
        assert!(a_has.contains(&0x01020304u32));
        assert!(a_has.contains(&0x11121314u32));
        assert!(b_has.contains(&0x21222324u32));
    }

    #[test]
    fn reconcile_both_sides_have_extras() {
        let mut a = PSyncNode::new(64);
        let mut b = PSyncNode::new(64);
        a.insert(0xAA000001u32);
        b.insert(0xBB000001u32);
        b.insert(0xBB000002u32);

        let (a_has, b_has) = a.reconcile(&b.build_ibf()).unwrap();
        assert_eq!(a_has.len(), 1);
        assert!(a_has.contains(&0xAA000001u32));
        assert_eq!(b_has.len(), 2);
    }

    /// G.03 reconcile-N=5 variant used by the witness script.
    #[test]
    fn g03_reconcile_n5() {
        let mut a = PSyncNode::new(80);
        let mut b = PSyncNode::new(80);
        // shared baseline
        for i in 0u32..20 {
            a.insert(0xBACE0000u32.wrapping_add(i));
            b.insert(0xBACE0000u32.wrapping_add(i));
        }
        // A has 5 extras
        for i in 0u32..5 {
            a.insert(0xAAAA0000u32 | i);
        }
        let (a_has, b_has) = a.reconcile(&b.build_ibf()).unwrap();
        assert_eq!(a_has.len(), 5);
        assert!(b_has.is_empty());
    }

    /// G.03 reconcile-N=20 variant.
    #[test]
    fn g03_reconcile_n20() {
        let mut a = PSyncNode::new(80);
        let mut b = PSyncNode::new(80);
        for i in 0u32..20 {
            a.insert(0xAAAA0000u32 | i);
        }
        for i in 0u32..20 {
            b.insert(0xBBBB0000u32 | i);
        }
        let (a_has, b_has) = a.reconcile(&b.build_ibf()).unwrap();
        assert_eq!(a_has.len(), 20);
        assert_eq!(b_has.len(), 20);
    }

    /// G.03 decode-failure: IBF too full → returns None.
    #[test]
    fn g03_reconcile_decode_failure_returns_none() {
        // IBF sized for 10 expected; insert 60 into each side with no overlap
        // → difference of 120, far beyond capacity.
        let mut a = PSyncNode::new(10);
        let mut b = PSyncNode::new(10);
        for i in 0u32..60 {
            a.insert(0xAAAA0000u32 | i);
            b.insert(0xBBBB0000u32 | i);
        }
        assert!(
            a.reconcile(&b.build_ibf()).is_none(),
            "oversaturated IBF must fail to decode"
        );
    }
}
