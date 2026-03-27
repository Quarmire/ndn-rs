use std::collections::HashSet;

/// Hash a value to a checksum used to verify pure IBF cells.
///
/// Uses a different multiplier than the cell-selection hash so that the
/// checksum is independent of the cell index computation.
fn cell_hash(v: u64) -> u64 {
    v.wrapping_mul(0x517cc1b727220a95)
        .rotate_right(17)
        .wrapping_add(0xdeadbeefcafe1234)
}

/// A single cell in an Invertible Bloom Filter.
///
/// A cell is "pure" (contains exactly one logical element) when
/// `count == ±1` AND `cell_hash(xor_sum) == hash_sum`. This rules out
/// the common false-positive where several values cancel each other to
/// produce the same xor_sum as a legitimate element.
#[derive(Clone, Debug, Default)]
struct IbfCell {
    xor_sum:  u64,
    hash_sum: u64,
    count:    i64,
}

impl IbfCell {
    fn is_pure(&self) -> bool {
        (self.count == 1 || self.count == -1)
            && cell_hash(self.xor_sum) == self.hash_sum
    }
}

/// A fixed-width Invertible Bloom Filter over `u64` hash values.
///
/// `k` hash functions are simulated by rotating a seed before each cell
/// selection. For PSync, set elements are hashes of NDN name strings.
#[derive(Clone, Debug)]
pub struct Ibf {
    cells: Vec<IbfCell>,
    k:     usize,
}

impl Ibf {
    /// Create an IBF with `size` cells and `k` hash functions.
    pub fn new(size: usize, k: usize) -> Self {
        Self {
            cells: vec![IbfCell::default(); size.max(1)],
            k:     k.max(1),
        }
    }

    fn cell_indices(&self, value: u64) -> Vec<usize> {
        let n = self.cells.len();
        (0..self.k)
            .map(|i| {
                // splitmix64 finalizer after mixing in the seed index.
                let mut h = value ^ (i as u64).wrapping_mul(0x9e3779b97f4a7c15);
                h = (h ^ (h >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                h = (h ^ (h >> 27)).wrapping_mul(0x94d049bb133111eb);
                h = h ^ (h >> 31);
                h as usize % n
            })
            .collect()
    }

    /// Insert a hash value into the IBF.
    pub fn insert(&mut self, value: u64) {
        let ch = cell_hash(value);
        for idx in self.cell_indices(value) {
            self.cells[idx].xor_sum  ^= value;
            self.cells[idx].hash_sum ^= ch;
            self.cells[idx].count    += 1;
        }
    }

    /// Remove a hash value from the IBF.
    pub fn remove(&mut self, value: u64) {
        let ch = cell_hash(value);
        for idx in self.cell_indices(value) {
            self.cells[idx].xor_sum  ^= value;
            self.cells[idx].hash_sum ^= ch;
            self.cells[idx].count    -= 1;
        }
    }

    /// Subtract `other` from `self` (XOR fields, subtract counts).
    ///
    /// The result encodes the symmetric difference of the two sets.
    pub fn subtract(&self, other: &Ibf) -> Ibf {
        let mut result = self.clone();
        for (a, b) in result.cells.iter_mut().zip(&other.cells) {
            a.xor_sum  ^= b.xor_sum;
            a.hash_sum ^= b.hash_sum;
            a.count    -= b.count;
        }
        result
    }

    /// Attempt to decode the symmetric difference from a subtracted IBF.
    ///
    /// Returns `Some((in_self_not_other, in_other_not_self))` on success, or
    /// `None` if the difference is too large for the IBF to decode.
    pub fn decode(&self) -> Option<(HashSet<u64>, HashSet<u64>)> {
        let mut ibf  = self.clone();
        let mut in_a = HashSet::new();
        let mut in_b = HashSet::new();

        loop {
            // Find the first verifiably pure cell.
            let pure_idx = ibf.cells.iter().position(|c| c.is_pure());
            let Some(idx) = pure_idx else { break };

            let val      = ibf.cells[idx].xor_sum;
            let positive = ibf.cells[idx].count == 1;

            if positive {
                in_a.insert(val);
                ibf.remove(val);
            } else {
                in_b.insert(val);
                ibf.insert(val);
            }
        }

        // Successful decode: all cells must be empty.
        if ibf.cells.iter().all(|c| c.count == 0 && c.xor_sum == 0 && c.hash_sum == 0) {
            Some((in_a, in_b))
        } else {
            None
        }
    }
}

/// Partial Sync (PSync) node.
///
/// Maintains a local set of content name hashes and an IBF over that set.
/// To reconcile with a peer: compute `local_ibf.subtract(peer_ibf)` and
/// call `decode()` to find which hashes each side is missing.
pub struct PSyncNode {
    local_set: HashSet<u64>,
    ibf_size:  usize,
    ibf_k:     usize,
}

impl PSyncNode {
    /// Create a node with an IBF of `ibf_size` cells and k=3 hash functions.
    ///
    /// `ibf_size` should be significantly larger than the expected set
    /// difference; 80 cells handles differences up to ~40 elements with k=3.
    pub fn new(ibf_size: usize) -> Self {
        Self {
            local_set: HashSet::new(),
            ibf_size:  ibf_size.max(4),
            ibf_k:     3,
        }
    }

    /// Insert a content hash into the local set.
    pub fn insert(&mut self, hash: u64) {
        self.local_set.insert(hash);
    }

    /// Remove a content hash from the local set.  Returns `true` if present.
    pub fn remove(&mut self, hash: u64) -> bool {
        self.local_set.remove(&hash)
    }

    pub fn contains(&self, hash: u64) -> bool {
        self.local_set.contains(&hash)
    }

    pub fn len(&self) -> usize {
        self.local_set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.local_set.is_empty()
    }

    /// Build an IBF over the current local set.
    pub fn build_ibf(&self) -> Ibf {
        let mut ibf = Ibf::new(self.ibf_size, self.ibf_k);
        for &h in &self.local_set {
            ibf.insert(h);
        }
        ibf
    }

    /// Reconcile with a peer IBF.
    ///
    /// Returns `Some((hashes_we_have_that_peer_lacks, hashes_peer_has_that_we_lack))`
    /// or `None` if the difference is too large to decode.
    pub fn reconcile(&self, peer_ibf: &Ibf) -> Option<(HashSet<u64>, HashSet<u64>)> {
        self.build_ibf().subtract(peer_ibf).decode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ibf_insert_and_remove_is_identity() {
        let mut ibf = Ibf::new(16, 3);
        ibf.insert(42);
        ibf.remove(42);
        assert!(ibf.cells.iter().all(|c| c.count == 0 && c.xor_sum == 0 && c.hash_sum == 0));
    }

    #[test]
    fn psync_contains_after_insert() {
        let mut node = PSyncNode::new(16);
        node.insert(100);
        assert!(node.contains(100));
        assert_eq!(node.len(), 1);
    }

    #[test]
    fn psync_remove() {
        let mut node = PSyncNode::new(16);
        node.insert(1);
        assert!(node.remove(1));
        assert!(node.is_empty());
    }

    #[test]
    fn reconcile_identical_sets_returns_empty_diff() {
        let mut a = PSyncNode::new(64);
        let mut b = PSyncNode::new(64);
        for i in 0..10u64 {
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
        let b     = PSyncNode::new(64);
        a.insert(999);

        let (a_has, b_has) = a.reconcile(&b.build_ibf()).unwrap();
        assert!(a_has.contains(&999));
        assert!(b_has.is_empty());
    }

    #[test]
    fn reconcile_disjoint_sets() {
        let mut a = PSyncNode::new(64);
        let mut b = PSyncNode::new(64);
        // Use large distinct values so cell-hash collisions are implausible.
        a.insert(0x0102030405060708);
        a.insert(0x1112131415161718);
        b.insert(0x2122232425262728);

        let (a_has, b_has) = a.reconcile(&b.build_ibf()).unwrap();
        assert!(a_has.contains(&0x0102030405060708));
        assert!(a_has.contains(&0x1112131415161718));
        assert!(b_has.contains(&0x2122232425262728));
    }

    #[test]
    fn reconcile_both_sides_have_extras() {
        let mut a = PSyncNode::new(64);
        let mut b = PSyncNode::new(64);
        // A-only
        a.insert(0xAA00000000000001);
        // B-only
        b.insert(0xBB00000000000001);
        b.insert(0xBB00000000000002);

        let (a_has, b_has) = a.reconcile(&b.build_ibf()).unwrap();
        assert_eq!(a_has.len(), 1);
        assert!(a_has.contains(&0xAA00000000000001));
        assert_eq!(b_has.len(), 2);
        assert!(b_has.contains(&0xBB00000000000001));
        assert!(b_has.contains(&0xBB00000000000002));
    }
}
