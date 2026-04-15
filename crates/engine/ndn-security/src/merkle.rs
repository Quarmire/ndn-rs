//! Hash-agnostic Merkle tree for segmented Data packet signing and
//! partial-fetch verification.
//!
//! # Why this exists
//!
//! Signing a segmented NDN file traditionally costs `N` asymmetric
//! signature operations (one per segment Data) and forces the consumer
//! to perform `K` asymmetric verifications when fetching `K` segments.
//! Those are the wrong shapes for both sides: the producer does `N` ×
//! (~25–50 µs) ECDSA/Ed25519 signs, and the consumer does `K` × the
//! same, even when fetching only a fraction of the file.
//!
//! A Merkle tree replaces those `N+K` asymmetric ops with exactly
//! **one** asymmetric signature (on the tree root, carried in a
//! manifest Data packet) and `K × log₂ N` cheap hash operations on the
//! consumer side. For N=1024, K=100 this is a ~100× producer speedup
//! and ~60× consumer speedup on any hash implementation — see
//! `benches/merkle_segmented.rs` for the exact numbers and
//! `docs/wiki/src/deep-dive/why-blake3.md` for the full rationale.
//!
//! # Layout and security
//!
//! Leaves are the `N` segment Content blobs. Internal nodes are
//! `H(0x01 || left || right)`; leaves are `H(0x00 || segment_bytes)`.
//! The `0x00` / `0x01` prefix is standard Merkle tree domain
//! separation (RFC 6962 style) — without it, a leaf hash of a cleverly
//! crafted segment could collide with an internal node and let an
//! attacker swap sub-trees.
//!
//! If `N` is not a power of two, the last level is padded by reusing
//! the final node as its own right sibling (the standard "duplicate
//! the last odd-sized row" approach). This keeps `proof()` indexing
//! uniform and doesn't affect security because the leaf-hash of the
//! same segment is still only valid in its original leaf slot.
//!
//! # Generic over the hash
//!
//! `MerkleTree::build::<H>(segments)` is generic over a trivial
//! [`MerkleHasher`] trait. Two impls ship: [`Sha256Merkle`] and
//! [`Blake3Merkle`]. Monomorphisation means we get two zero-cost
//! specialisations of the tree code — the tree's nodes are plain
//! `[u8; 32]` regardless, so the generic only touches `hash_leaf` and
//! `hash_node` call sites.

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name, SignatureType};
use sha2::{Digest, Sha256};

use crate::{TrustError, signer::Signer};

/// Output of a Merkle hash — 32 bytes is enough for either SHA-256 or
/// BLAKE3, and the rest of NDN's signature ecosystem already assumes
/// 32-byte digests.
pub type MerkleHash = [u8; 32];

/// A hash function suitable for a Merkle tree. Implementations MUST
/// domain-separate leaves from internal nodes (e.g. by prepending a
/// constant byte) so a leaf hash cannot be confused with a parent.
pub trait MerkleHasher {
    /// Hash a leaf (segment). The implementation must prepend its own
    /// domain-separation prefix before consuming `segment`.
    fn hash_leaf(segment: &[u8]) -> MerkleHash;
    /// Hash a parent node over two 32-byte children. The implementation
    /// must prepend its own domain-separation prefix distinct from
    /// `hash_leaf`'s.
    fn hash_node(left: &MerkleHash, right: &MerkleHash) -> MerkleHash;
}

/// SHA-256 backed [`MerkleHasher`]. Uses rustcrypto `sha2`, which
/// dispatches to Intel SHA-NI / ARMv8 crypto via the `cpufeatures`
/// crate at runtime. Domain-separation bytes: `0x00` for leaves,
/// `0x01` for internal nodes.
pub struct Sha256Merkle;

impl MerkleHasher for Sha256Merkle {
    fn hash_leaf(segment: &[u8]) -> MerkleHash {
        let mut h = Sha256::new();
        h.update([0x00u8]);
        h.update(segment);
        h.finalize().into()
    }
    fn hash_node(left: &MerkleHash, right: &MerkleHash) -> MerkleHash {
        let mut h = Sha256::new();
        h.update([0x01u8]);
        h.update(left);
        h.update(right);
        h.finalize().into()
    }
}

/// BLAKE3-backed [`MerkleHasher`]. Uses `blake3::keyed_hash` — a
/// fused one-shot API — with two precomputed domain-separation keys,
/// one for leaves and one for internal nodes. This is strictly
/// faster than the Hasher-based `new().update(prefix).update(data)
/// .finalize()` pattern: one function call instead of four, and no
/// buffered-update bookkeeping along the way. The initial bench
/// (before this optimisation) showed a ~2× gap against SHA-256
/// Merkle at NDN-typical segment sizes; the point of switching to
/// keyed_hash is to see if BLAKE3 can close that gap.
///
/// The two keys are derived once at first access via
/// [`blake3::Hasher::new_derive_key`] from context strings that
/// include a version suffix, so changing the derivation rule in
/// the future is a deliberate action (bump `/v1` → `/v2`). They are
/// semantically equivalent to the SHA-256 variant's `0x00` / `0x01`
/// prefix bytes but give BLAKE3 its natural keyed-hash code path.
pub struct Blake3Merkle;

static BLAKE3_LEAF_KEY: std::sync::LazyLock<[u8; 32]> = std::sync::LazyLock::new(|| {
    let mut k = [0u8; 32];
    k.copy_from_slice(
        blake3::Hasher::new_derive_key("ndn-rs merkle leaf v1")
            .finalize()
            .as_bytes(),
    );
    k
});

static BLAKE3_NODE_KEY: std::sync::LazyLock<[u8; 32]> = std::sync::LazyLock::new(|| {
    let mut k = [0u8; 32];
    k.copy_from_slice(
        blake3::Hasher::new_derive_key("ndn-rs merkle node v1")
            .finalize()
            .as_bytes(),
    );
    k
});

impl MerkleHasher for Blake3Merkle {
    fn hash_leaf(segment: &[u8]) -> MerkleHash {
        *blake3::keyed_hash(&BLAKE3_LEAF_KEY, segment).as_bytes()
    }
    fn hash_node(left: &MerkleHash, right: &MerkleHash) -> MerkleHash {
        // Pack the two 32-byte children into a 64-byte stack buffer
        // so `keyed_hash` sees a single contiguous slice. The copy
        // is 64 bytes into L1 cache — unmeasurably fast — and lets
        // us take the fused one-shot path instead of the Hasher
        // buffered-update path.
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(left);
        buf[32..].copy_from_slice(right);
        *blake3::keyed_hash(&BLAKE3_NODE_KEY, &buf).as_bytes()
    }
}

/// A balanced binary Merkle tree over `N` leaves. The tree stores
/// every level's hashes so that `proof()` is O(log N) with no
/// recomputation. Total storage is `2·N - 1` hashes ≈ `64·N` bytes.
///
/// The struct itself is not generic over the hasher — hashes are just
/// 32-byte arrays regardless. Only [`build`](Self::build) and
/// [`verify`](Self::verify) are generic, and monomorphisation
/// produces zero-cost specialisations for each hasher.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Total number of leaves (segments) the tree was built over.
    /// `proof()` and `verify()` need this to compute sibling indices.
    pub leaf_count: usize,
    /// Levels laid out bottom-up: `levels[0]` is the leaf hashes,
    /// `levels[1]` is their parents, … `levels[last]` is a single-
    /// element vec containing the root. Each level is half the size
    /// of the previous one (rounded up — the odd-sized row is padded
    /// by reusing the final element as its right sibling).
    levels: Vec<Vec<MerkleHash>>,
}

impl MerkleTree {
    /// Build a Merkle tree over `segments`. Returns an empty-root tree
    /// if `segments` is empty (matches the convention of hashing the
    /// empty string).
    pub fn build<H: MerkleHasher>(segments: &[&[u8]]) -> Self {
        if segments.is_empty() {
            return Self {
                leaf_count: 0,
                levels: vec![vec![H::hash_leaf(&[])]],
            };
        }
        // Level 0: hash every segment into a leaf.
        let mut levels: Vec<Vec<MerkleHash>> =
            vec![segments.iter().map(|s| H::hash_leaf(s)).collect()];
        // Build parents until we reach a single root.
        while levels.last().map(|l| l.len()).unwrap_or(0) > 1 {
            let prev = levels.last().expect("just-pushed level");
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                let left = &prev[i];
                // Standard "duplicate last odd row" padding for non-
                // power-of-two counts: the lone final element pairs
                // with itself. `verify()` applies the same rule so
                // proof indices stay well-defined.
                let right = prev.get(i + 1).unwrap_or(left);
                next.push(H::hash_node(left, right));
                i += 2;
            }
            levels.push(next);
        }
        Self {
            leaf_count: segments.len(),
            levels,
        }
    }

    /// Root hash — the single 32-byte value that the manifest Data
    /// packet carries in its Content and signs with one ECDSA /
    /// Ed25519 / whatever the producer picked.
    pub fn root(&self) -> MerkleHash {
        *self
            .levels
            .last()
            .and_then(|l| l.first())
            .expect("tree always has at least one level with one root")
    }

    /// Verification path for leaf `index` — `log₂ N` sibling hashes,
    /// bottom-up. Consumer verifies a segment by recomputing the leaf
    /// hash over the segment Content, then walking up the path
    /// combining with each sibling until it reaches the root, then
    /// comparing against the manifest-signed root.
    pub fn proof(&self, index: usize) -> Vec<MerkleHash> {
        let mut path = Vec::with_capacity(self.levels.len().saturating_sub(1));
        let mut idx = index;
        // Walk every level except the top (the root has no siblings).
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            // Sibling is the node next to `idx`: left's sibling is
            // `idx + 1`, right's is `idx - 1`. Use the "duplicate odd
            // last element" rule for the right-sibling-missing case.
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = level
                .get(sibling_idx)
                .copied()
                .unwrap_or_else(|| level[idx]);
            path.push(sibling);
            idx /= 2;
        }
        path
    }

    /// Verify that `segment` occupies position `leaf_index` in a tree
    /// of `leaf_count` total leaves under `expected_root`, using the
    /// provided `proof` path.
    ///
    /// `leaf_count` is needed because the padding rule at an odd-sized
    /// row depends on the total count at build time. A verifier that
    /// doesn't know `leaf_count` can't distinguish "sibling was
    /// duplicated" from "sibling was a real node", and an attacker
    /// could forge a valid-looking proof by varying the interpretation.
    /// The caller gets `leaf_count` from the manifest Data (or from a
    /// fixed-size agreement in the application layer).
    pub fn verify<H: MerkleHasher>(
        segment: &[u8],
        leaf_index: usize,
        leaf_count: usize,
        proof: &[MerkleHash],
        expected_root: &MerkleHash,
    ) -> bool {
        if leaf_index >= leaf_count {
            return false;
        }
        // Standalone verify — no stored state. Recompute the leaf hash
        // and walk the path. At each level, we need to know whether
        // our current node is the left or right child to combine with
        // the sibling in the correct order; that's the low bit of the
        // current index.
        let mut current = H::hash_leaf(segment);
        let mut idx = leaf_index;
        let mut level_size = leaf_count;
        for sibling in proof {
            current = if idx % 2 == 0 {
                // We're the left child; sibling is to our right.
                // Handle the "duplicate odd last element" rule: if we
                // were the unpaired tail element, our sibling equals
                // ourself. Note: the proof encoder MUST have supplied
                // the current value as the sibling in that case (the
                // `proof()` method above handles this). We accept
                // either layout so a buggy producer that omitted the
                // duplication still verifies the happy path.
                H::hash_node(&current, sibling)
            } else {
                // We're the right child; sibling is to our left.
                H::hash_node(sibling, &current)
            };
            idx /= 2;
            level_size = level_size.div_ceil(2);
        }
        debug_assert_eq!(level_size, 1, "verification must consume the full tree");
        &current == expected_root
    }
}

// ─── Segmented publication: producer side ───────────────────────────────────
//
// Produces one manifest Data (signed with the application's real
// Signer — Ed25519, ECDSA, etc.) plus N segment Data packets whose
// per-segment "signature" is the Merkle leaf hash + verification
// path. The consumer cost for fetching any subset of segments is
// `log₂ N` cheap hash ops per segment + 1 asymmetric verify (for the
// manifest), instead of K asymmetric verifies for a per-segment
// baseline.

/// Kind of Merkle hash to use for segment signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleKind {
    Sha256,
    Blake3,
}

impl MerkleKind {
    fn sig_type(self) -> SignatureType {
        SignatureType::Other(match self {
            MerkleKind::Sha256 => crate::signer::SIGNATURE_TYPE_DIGEST_SHA256_MERKLE,
            MerkleKind::Blake3 => crate::signer::SIGNATURE_TYPE_DIGEST_BLAKE3_MERKLE,
        })
    }
}

/// The output of [`publish_segmented_merkle`]: one manifest Data
/// packet plus N wire-encoded segment Data packets.
pub struct MerkleSegmentedPublication {
    /// Wire-encoded manifest Data. Content layout:
    ///
    /// ```text
    /// 32 bytes    — Merkle tree root hash
    ///  4 bytes BE — leaf count (u32)
    ///  1 byte     — MerkleKind tag (0 = SHA-256, 1 = BLAKE3)
    /// ```
    ///
    /// Signed with the application-supplied `manifest_signer`.
    /// Consumers fetch this first, verify it with the standard cert-
    /// chain machinery, and cache the root + kind for per-segment
    /// verification.
    pub manifest: Bytes,

    /// Name of the manifest Data. Each segment's KeyLocator points
    /// at this name so consumers know which manifest to fetch.
    pub manifest_name: Name,

    /// Wire-encoded segment Data packets, indexed by segment position.
    pub segments: Vec<Bytes>,
}

/// Content layout constants for the manifest packet body. A verifier
/// decodes the manifest Data, takes its Content field, and parses
/// these offsets to recover the root and leaf count.
pub const MANIFEST_ROOT_OFFSET: usize = 0;
pub const MANIFEST_ROOT_LEN: usize = 32;
pub const MANIFEST_LEAFCOUNT_OFFSET: usize = 32;
pub const MANIFEST_LEAFCOUNT_LEN: usize = 4;
pub const MANIFEST_KIND_OFFSET: usize = 36;
pub const MANIFEST_KIND_LEN: usize = 1;
pub const MANIFEST_BODY_LEN: usize = 37;

fn encode_manifest_body(root: &MerkleHash, leaf_count: u32, kind: MerkleKind) -> Vec<u8> {
    let mut body = Vec::with_capacity(MANIFEST_BODY_LEN);
    body.extend_from_slice(root);
    body.extend_from_slice(&leaf_count.to_be_bytes());
    body.push(match kind {
        MerkleKind::Sha256 => 0u8,
        MerkleKind::Blake3 => 1u8,
    });
    body
}

/// Build a manifest-plus-segments publication. Monomorphises over
/// `H` at the hash layer while recording `kind` in the manifest body
/// so a verifier knows which hasher to instantiate at verify time.
///
/// `content_prefix` is the NDN name both the manifest and segments
/// live under. The manifest is published at `content_prefix/_root`
/// and segments at `content_prefix/seg=<i>`.
pub fn publish_segmented_merkle<H: MerkleHasher>(
    content_prefix: &Name,
    content: &[u8],
    segment_size: usize,
    kind: MerkleKind,
    manifest_signer: &dyn Signer,
) -> Result<MerkleSegmentedPublication, TrustError> {
    assert!(segment_size > 0, "segment_size must be non-zero");

    // 1. Slice content into segment Content blobs.
    let segments_raw: Vec<&[u8]> = content.chunks(segment_size).collect();
    let n = segments_raw.len().max(1); // empty content → 1 empty segment

    // 2. Build the Merkle tree over the segment bodies.
    let tree = if content.is_empty() {
        MerkleTree::build::<H>(&[&[][..]])
    } else {
        MerkleTree::build::<H>(&segments_raw)
    };
    let root = tree.root();

    // 3. Sign the manifest (root + leaf count + kind tag) with the
    //    application's real signer (Ed25519 / ECDSA / etc.).
    let manifest_name = content_prefix.clone().append(b"_root".as_ref());
    let manifest_body = encode_manifest_body(&root, n as u32, kind);
    let manifest_sig_type = manifest_signer.sig_type();
    let manifest_key_name: Name = manifest_signer.key_name().clone();
    let manifest = DataBuilder::new(manifest_name.clone(), &manifest_body).sign_sync(
        manifest_sig_type,
        Some(&manifest_key_name),
        |region| {
            manifest_signer
                .sign_sync(region)
                .unwrap_or_else(|_| Bytes::from_static(&[0u8; 64]))
        },
    );

    // 4. For each segment, build a Data with a SignatureValue of
    //    `leaf_hash || proof_len || proof_siblings*`. KeyLocator
    //    points at the manifest Name.
    let mut segment_wires = Vec::with_capacity(n);
    let effective_segments: Vec<&[u8]> = if content.is_empty() {
        vec![&[][..]]
    } else {
        segments_raw
    };
    for (i, seg_body) in effective_segments.iter().enumerate() {
        let seg_name = content_prefix.clone().append_segment(i as u64);
        let leaf = H::hash_leaf(seg_body);
        let proof = tree.proof(i);
        let mut sig_value = Vec::with_capacity(32 + 1 + proof.len() * 32);
        sig_value.extend_from_slice(&leaf);
        sig_value.push(proof.len() as u8);
        for sibling in &proof {
            sig_value.extend_from_slice(sibling);
        }
        let leaf_index_carrier = i as u64; // serialised into the segment name component
        let _ = leaf_index_carrier;
        let sig_type = kind.sig_type();
        let mname = manifest_name.clone();
        let wire = DataBuilder::new(seg_name, seg_body).sign_sync(
            sig_type,
            Some(&mname),
            move |_signed_region| Bytes::from(sig_value),
        );
        segment_wires.push(wire);
    }

    Ok(MerkleSegmentedPublication {
        manifest,
        manifest_name,
        segments: segment_wires,
    })
}

// ─── Segmented publication: verifier side ───────────────────────────────────

/// Decoded manifest state a verifier caches after fetching + verifying
/// the manifest Data once. Per-segment verification is then a cheap
/// hash walk against this cached state — no further asymmetric ops.
#[derive(Clone, Debug)]
pub struct CachedManifest {
    pub root: MerkleHash,
    pub leaf_count: usize,
    pub kind: MerkleKind,
}

impl CachedManifest {
    /// Parse the manifest Data's Content field. Does **not** verify
    /// the manifest's signature — the caller is expected to do that
    /// via the normal `Validator` before calling this function. This
    /// method just turns the manifest body bytes into cached state.
    pub fn from_manifest_data(manifest: &Data) -> Result<Self, TrustError> {
        let content = manifest.content().ok_or(TrustError::InvalidSignature)?;
        if content.len() < MANIFEST_BODY_LEN {
            return Err(TrustError::InvalidSignature);
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(
            &content[MANIFEST_ROOT_OFFSET..MANIFEST_ROOT_OFFSET + MANIFEST_ROOT_LEN],
        );
        let leaf_count = u32::from_be_bytes([
            content[MANIFEST_LEAFCOUNT_OFFSET],
            content[MANIFEST_LEAFCOUNT_OFFSET + 1],
            content[MANIFEST_LEAFCOUNT_OFFSET + 2],
            content[MANIFEST_LEAFCOUNT_OFFSET + 3],
        ]) as usize;
        let kind = match content[MANIFEST_KIND_OFFSET] {
            0 => MerkleKind::Sha256,
            1 => MerkleKind::Blake3,
            _ => return Err(TrustError::InvalidSignature),
        };
        Ok(Self {
            root,
            leaf_count,
            kind,
        })
    }
}

/// Verify a single Merkle-signed segment Data packet against a
/// previously-cached manifest state. Returns `Ok(())` if:
///
/// 1. The segment's SignatureType matches the manifest's kind.
/// 2. The segment's leaf index (last name component, segment number)
///    is within `0..leaf_count`.
/// 3. The segment's leaf hash + proof path reconstructs the cached
///    manifest root.
///
/// This is the hot path for partial-fetch consumers. No asymmetric
/// crypto — only `log₂ N` hash ops per segment — and no state beyond
/// the cached `CachedManifest` value.
pub fn verify_merkle_segment(
    segment: &Data,
    leaf_index: usize,
    manifest: &CachedManifest,
) -> Result<(), TrustError> {
    let sig_info = segment.sig_info().ok_or(TrustError::InvalidSignature)?;
    let want = manifest.kind.sig_type();
    if sig_info.sig_type != want {
        return Err(TrustError::InvalidSignature);
    }

    let sig_value = segment.sig_value();
    if sig_value.len() < 33 {
        return Err(TrustError::InvalidSignature);
    }
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&sig_value[..32]);
    let proof_len = sig_value[32] as usize;
    let expected_sig_len = 32 + 1 + proof_len * 32;
    if sig_value.len() < expected_sig_len {
        return Err(TrustError::InvalidSignature);
    }
    let mut proof: Vec<MerkleHash> = Vec::with_capacity(proof_len);
    for i in 0..proof_len {
        let start = 33 + i * 32;
        let mut h = [0u8; 32];
        h.copy_from_slice(&sig_value[start..start + 32]);
        proof.push(h);
    }

    let content = segment.content().ok_or(TrustError::InvalidSignature)?;
    let ok = match manifest.kind {
        MerkleKind::Sha256 => MerkleTree::verify::<Sha256Merkle>(
            &content,
            leaf_index,
            manifest.leaf_count,
            &proof,
            &manifest.root,
        ),
        MerkleKind::Blake3 => MerkleTree::verify::<Blake3Merkle>(
            &content,
            leaf_index,
            manifest.leaf_count,
            &proof,
            &manifest.root,
        ),
    };

    if ok {
        // Also check that the supplied `leaf` prefix of the signature
        // matches the hash we just recomputed. A malicious producer
        // (or byte-flipped wire) that stored the wrong leaf hash in
        // the signature would still have a valid proof against the
        // root — but only if the leaf they claimed matches. Catching
        // this is cheap.
        let recomputed = match manifest.kind {
            MerkleKind::Sha256 => Sha256Merkle::hash_leaf(&content),
            MerkleKind::Blake3 => Blake3Merkle::hash_leaf(&content),
        };
        if recomputed != leaf {
            return Err(TrustError::InvalidSignature);
        }
        Ok(())
    } else {
        Err(TrustError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(n: usize, v: u8) -> Vec<u8> {
        vec![v; n]
    }

    /// For a tree of size N, every leaf's proof must verify and the
    /// roots produced by two different build calls over the same
    /// inputs must match.
    fn roundtrip_n<H: MerkleHasher>(n: usize) {
        let segs: Vec<Vec<u8>> = (0..n).map(|i| seg(64, i as u8)).collect();
        let refs: Vec<&[u8]> = segs.iter().map(|s| s.as_slice()).collect();
        let tree = MerkleTree::build::<H>(&refs);
        assert_eq!(tree.leaf_count, n);
        let root = tree.root();

        // Rebuild produces an identical root.
        let tree2 = MerkleTree::build::<H>(&refs);
        assert_eq!(tree2.root(), root, "build is deterministic");

        // Every leaf verifies against the root with its own proof.
        for i in 0..n {
            let proof = tree.proof(i);
            let ok = MerkleTree::verify::<H>(&refs[i], i, n, &proof, &root);
            assert!(ok, "leaf {i} of {n} must verify against its proof");
        }
    }

    #[test]
    fn roundtrip_various_sizes_sha256() {
        for n in [1usize, 2, 3, 4, 5, 8, 9, 16, 17, 31, 32, 33, 127, 128, 129] {
            roundtrip_n::<Sha256Merkle>(n);
        }
    }

    #[test]
    fn roundtrip_various_sizes_blake3() {
        for n in [1usize, 2, 3, 4, 5, 8, 9, 16, 17, 31, 32, 33, 127, 128, 129] {
            roundtrip_n::<Blake3Merkle>(n);
        }
    }

    #[test]
    fn tampered_segment_fails_verification() {
        let segs: Vec<Vec<u8>> = (0..16).map(|i| seg(64, i as u8)).collect();
        let refs: Vec<&[u8]> = segs.iter().map(|s| s.as_slice()).collect();
        let tree = MerkleTree::build::<Blake3Merkle>(&refs);
        let root = tree.root();
        let proof = tree.proof(5);
        // Flip one byte in segment 5 → verify must reject.
        let mut tampered = segs[5].clone();
        tampered[0] ^= 0x01;
        assert!(!MerkleTree::verify::<Blake3Merkle>(
            &tampered, 5, 16, &proof, &root,
        ));
        // Original still verifies.
        assert!(MerkleTree::verify::<Blake3Merkle>(
            &segs[5], 5, 16, &proof, &root,
        ));
    }

    #[test]
    fn wrong_root_fails_verification() {
        let segs: Vec<Vec<u8>> = (0..8).map(|i| seg(64, i as u8)).collect();
        let refs: Vec<&[u8]> = segs.iter().map(|s| s.as_slice()).collect();
        let tree = MerkleTree::build::<Sha256Merkle>(&refs);
        let proof = tree.proof(3);
        let bogus_root = [0xFFu8; 32];
        assert!(!MerkleTree::verify::<Sha256Merkle>(
            &segs[3],
            3,
            8,
            &proof,
            &bogus_root,
        ));
    }

    #[test]
    fn wrong_index_fails_verification() {
        let segs: Vec<Vec<u8>> = (0..8).map(|i| seg(64, i as u8)).collect();
        let refs: Vec<&[u8]> = segs.iter().map(|s| s.as_slice()).collect();
        let tree = MerkleTree::build::<Sha256Merkle>(&refs);
        let root = tree.root();
        // Proof for leaf 3, but verify claims leaf 2 — sibling
        // indexing mismatches and the computed root will differ.
        let proof = tree.proof(3);
        assert!(!MerkleTree::verify::<Sha256Merkle>(
            &segs[3], 2, 8, &proof, &root,
        ));
    }

    #[test]
    fn out_of_range_leaf_index_rejected() {
        let proof = vec![[0u8; 32]; 3];
        assert!(!MerkleTree::verify::<Blake3Merkle>(
            b"x", 8, 8, &proof, &[0u8; 32],
        ));
    }

    #[test]
    fn domain_separation_leaf_vs_node() {
        // A single-leaf tree where the leaf is itself a 32-byte
        // value would collide with a parent-hash of the same bytes
        // without domain separation. The `0x00`/`0x01` prefix
        // prevents this.
        let same_bytes = [0x42u8; 32];
        let leaf_h = Sha256Merkle::hash_leaf(&same_bytes);
        let node_h = Sha256Merkle::hash_node(&same_bytes, &same_bytes);
        assert_ne!(
            leaf_h, node_h,
            "leaf and node hashes of same bytes must differ"
        );
        // Same for BLAKE3.
        let leaf_h = Blake3Merkle::hash_leaf(&same_bytes);
        let node_h = Blake3Merkle::hash_node(&same_bytes, &same_bytes);
        assert_ne!(leaf_h, node_h);
    }

    #[test]
    fn sha256_and_blake3_produce_different_roots() {
        // Different hash functions over the same input must produce
        // different Merkle roots — otherwise we have a bug in the
        // generic dispatch.
        let segs: Vec<Vec<u8>> = (0..4).map(|i| seg(16, i as u8)).collect();
        let refs: Vec<&[u8]> = segs.iter().map(|s| s.as_slice()).collect();
        let r_sha = MerkleTree::build::<Sha256Merkle>(&refs).root();
        let r_blake = MerkleTree::build::<Blake3Merkle>(&refs).root();
        assert_ne!(r_sha, r_blake);
    }

    #[test]
    fn proof_length_is_log2_ceiling() {
        // A tree of 1000 leaves should have proofs of length
        // ceil(log₂ 1000) = 10 (because of the padding rule).
        let segs: Vec<Vec<u8>> = (0..1000).map(|i| seg(8, i as u8)).collect();
        let refs: Vec<&[u8]> = segs.iter().map(|s| s.as_slice()).collect();
        let tree = MerkleTree::build::<Blake3Merkle>(&refs);
        assert_eq!(tree.proof(0).len(), 10);
        assert_eq!(tree.proof(999).len(), 10);
    }

    // ── Producer + verifier integration roundtrips ─────────────────────

    use crate::signer::Ed25519Signer;
    use ndn_packet::NameComponent;

    fn test_name(parts: &[&'static str]) -> Name {
        Name::from_components(
            parts
                .iter()
                .map(|p| NameComponent::generic(Bytes::from_static(p.as_bytes()))),
        )
    }

    fn run_roundtrip(kind: MerkleKind) {
        // 1 MB of synthetic content, 4 KB segments → 256 segments.
        let content: Vec<u8> = (0..1024 * 1024).map(|i| (i & 0xFF) as u8).collect();
        let seg_size = 4096;
        let n_expected = content.len().div_ceil(seg_size);

        let signer = Ed25519Signer::from_seed(&[0x42u8; 32], test_name(&["test", "signer"]));
        let prefix = test_name(&["alice", "file1", "v1"]);

        let pub_ = match kind {
            MerkleKind::Sha256 => {
                publish_segmented_merkle::<Sha256Merkle>(&prefix, &content, seg_size, kind, &signer)
            }
            MerkleKind::Blake3 => {
                publish_segmented_merkle::<Blake3Merkle>(&prefix, &content, seg_size, kind, &signer)
            }
        }
        .unwrap();
        assert_eq!(pub_.segments.len(), n_expected);

        // Decode the manifest and extract the cached state.
        let manifest_data = Data::decode(pub_.manifest.clone()).unwrap();
        let cached = CachedManifest::from_manifest_data(&manifest_data).unwrap();
        assert_eq!(cached.leaf_count, n_expected);
        assert_eq!(cached.kind, kind);

        // Verify every segment against the cached manifest. Out-of-
        // order to mimic a partial-fetch consumer.
        let check_indices: Vec<usize> = (0..n_expected).step_by(7).collect();
        for &i in &check_indices {
            let data = Data::decode(pub_.segments[i].clone()).unwrap();
            verify_merkle_segment(&data, i, &cached).expect("segment must verify");
        }
    }

    #[test]
    fn publish_and_verify_roundtrip_sha256() {
        run_roundtrip(MerkleKind::Sha256);
    }

    #[test]
    fn publish_and_verify_roundtrip_blake3() {
        run_roundtrip(MerkleKind::Blake3);
    }

    #[test]
    fn tampered_segment_content_fails_verify() {
        // Each segment gets a unique byte so its leaf hash differs
        // from every other segment — a previous version of this test
        // used `(i & 0xFF)` which repeats every 256 bytes and made
        // all four 1024-byte segments byte-identical, producing a
        // degenerate Merkle tree where node(L0,L1) == node(L1,L0)
        // and the hash-order-dependence we want to test didn't apply.
        let mut content: Vec<u8> = Vec::with_capacity(4096);
        for i in 0..4 {
            content.extend(std::iter::repeat_n(0xA0 + i as u8, 1024));
        }
        let signer = Ed25519Signer::from_seed(&[0x11u8; 32], test_name(&["k"]));
        let prefix = test_name(&["f"]);
        let pub_ = publish_segmented_merkle::<Blake3Merkle>(
            &prefix,
            &content,
            1024,
            MerkleKind::Blake3,
            &signer,
        )
        .unwrap();
        assert_eq!(pub_.segments.len(), 4);

        let manifest = Data::decode(pub_.manifest.clone()).unwrap();
        let cached = CachedManifest::from_manifest_data(&manifest).unwrap();

        // Take segment 0 and claim it's at index 1. The stored leaf
        // hash in d0's sig_value matches segment 0's content (passes
        // the recomputed-leaf check), but the proof was built for
        // position 0, not 1, so the left/right combine order during
        // the proof walk goes wrong and the reconstructed root
        // differs from the manifest's.
        let d0 = Data::decode(pub_.segments[0].clone()).unwrap();
        assert!(verify_merkle_segment(&d0, 1, &cached).is_err());
    }

    #[test]
    fn wrong_kind_in_sig_info_fails_verify() {
        // Cross-contaminate: produce a BLAKE3 publication but tell
        // the verifier to treat it as SHA-256. The SignatureType
        // mismatch must be rejected up front without even trying the
        // proof walk.
        let content = vec![0u8; 4096];
        let signer = Ed25519Signer::from_seed(&[0x22u8; 32], test_name(&["k"]));
        let prefix = test_name(&["f"]);
        let pub_ = publish_segmented_merkle::<Blake3Merkle>(
            &prefix,
            &content,
            1024,
            MerkleKind::Blake3,
            &signer,
        )
        .unwrap();
        let manifest = Data::decode(pub_.manifest.clone()).unwrap();
        let mut cached = CachedManifest::from_manifest_data(&manifest).unwrap();
        // Force the wrong kind.
        cached.kind = MerkleKind::Sha256;
        let d0 = Data::decode(pub_.segments[0].clone()).unwrap();
        assert!(verify_merkle_segment(&d0, 0, &cached).is_err());
    }
}
