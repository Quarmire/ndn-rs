//! Merkle-signed segmented Data: producer & consumer benchmarks.
//!
//! Demonstrates the structural advantage of the Merkle-tree approach
//! over per-segment asymmetric signatures, and of BLAKE3 vs SHA-256
//! as the tree hash choice. See
//! `docs/wiki/src/deep-dive/why-blake3.md` for the rationale this
//! bench is designed to quantify.
//!
//! Three producer schemes × two consumer schemes are measured:
//!
//! | scheme                          | producer cost      | consumer (K of N) |
//! |---------------------------------|--------------------|-------------------|
//! | `per-segment-ed25519`           | N Ed25519 signs    | K Ed25519 verifies|
//! | `sha256-merkle + ed25519-root`  | tree + 1 sign      | K × log₂N SHA-256 + 1 ed25519 verify |
//! | `blake3-merkle + ed25519-root`  | tree + 1 sign      | K × log₂N BLAKE3 + 1 ed25519 verify |
//!
//! The per-segment Ed25519 row is the honest baseline: Ed25519 is
//! ndn-rs's internal default and ~2× faster than ECDSA-P256, so we
//! give it the best possible single-signature speed. A clever reader
//! could argue "use batch ECDSA / batch Ed25519 verification to close
//! the gap" — which would win back ~2–3× on the per-segment consumer
//! row — but the Merkle approach still wins by orders of magnitude at
//! interesting N, so we don't implement batching here.
//!
//! Consumer partial-fetch ratio is parameterised at K = N/10 (10% of
//! segments fetched out of order) which is representative of a client
//! resuming a partial download or catching up on a sync snapshot.

use std::time::Duration;

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name, NameComponent, SignatureType};
use ndn_security::merkle::{
    Blake3Merkle, CachedManifest, MerkleKind, Sha256Merkle, publish_segmented_merkle,
    verify_merkle_segment,
};
use ndn_security::signer::Ed25519Signer;
use ndn_security::{Ed25519Verifier, Signer};

// ── Test fixture ────────────────────────────────────────────────────────────

fn comp(s: &'static str) -> NameComponent {
    NameComponent::generic(Bytes::from_static(s.as_bytes()))
}
fn test_name(parts: &[&'static str]) -> Name {
    Name::from_components(parts.iter().map(|p| comp(p)))
}

/// A "file" to segment: `total_bytes` of pseudo-random content so each
/// segment has a distinct leaf hash and the Merkle tree is non-
/// degenerate. Deterministic for reproducible benches.
fn synthetic_file(total_bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; total_bytes];
    let mut state: u64 = 0x9E3779B97F4A7C15;
    for b in out.iter_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (state >> 56) as u8;
    }
    out
}

// ── Per-segment Ed25519 baseline ────────────────────────────────────────────
//
// Today's status quo: sign each segment Data independently with the
// application's Ed25519 key. N asymmetric signs on the producer, K
// asymmetric verifies on the consumer.

fn per_segment_ed25519_produce(
    prefix: &Name,
    content: &[u8],
    seg_size: usize,
    signer: &Ed25519Signer,
) -> Vec<Bytes> {
    let key_name = signer.key_name().clone();
    let mut wires = Vec::with_capacity(content.len().div_ceil(seg_size));
    for (i, seg) in content.chunks(seg_size).enumerate() {
        let seg_name = prefix.clone().append_segment(i as u64);
        let wire = DataBuilder::new(seg_name, seg).sign_sync(
            SignatureType::SignatureEd25519,
            Some(&key_name),
            |region| {
                signer
                    .sign_sync(region)
                    .unwrap_or_else(|_| Bytes::from_static(&[0u8; 64]))
            },
        );
        wires.push(wire);
    }
    wires
}

fn per_segment_ed25519_verify(
    wires: &[Bytes],
    indices: &[usize],
    verifier: &Ed25519Verifier,
    public_key: &[u8; 32],
) {
    for &i in indices {
        let data = Data::decode(wires[i].clone()).expect("decode segment");
        // Use the synchronous verify path — benches don't want async
        // boxing in the measurement loop.
        let outcome = verifier.verify_sync(data.signed_region(), data.sig_value(), public_key);
        debug_assert_eq!(outcome, ndn_security::VerifyOutcome::Valid);
    }
}

// ── Merkle producer / consumer ──────────────────────────────────────────────

fn merkle_produce(
    prefix: &Name,
    content: &[u8],
    seg_size: usize,
    kind: MerkleKind,
    signer: &Ed25519Signer,
) -> (Bytes, Vec<Bytes>) {
    let pub_ = match kind {
        MerkleKind::Sha256 => {
            publish_segmented_merkle::<Sha256Merkle>(prefix, content, seg_size, kind, signer)
        }
        MerkleKind::Blake3 => {
            publish_segmented_merkle::<Blake3Merkle>(prefix, content, seg_size, kind, signer)
        }
    }
    .expect("publish");
    (pub_.manifest, pub_.segments)
}

fn merkle_verify(
    manifest_wire: &Bytes,
    segments: &[Bytes],
    indices: &[usize],
    manifest_verifier: &Ed25519Verifier,
    manifest_public_key: &[u8; 32],
) {
    // Consumer flow: verify manifest once, extract the cached root,
    // then verify each segment against the cached state. The manifest
    // verify is one asymmetric op; the rest are pure hash walks.
    let manifest = Data::decode(manifest_wire.clone()).expect("decode manifest");
    let outcome = manifest_verifier.verify_sync(
        manifest.signed_region(),
        manifest.sig_value(),
        manifest_public_key,
    );
    debug_assert_eq!(outcome, ndn_security::VerifyOutcome::Valid);
    let cached = CachedManifest::from_manifest_data(&manifest).expect("manifest body");

    for &i in indices {
        let data = Data::decode(segments[i].clone()).expect("decode segment");
        verify_merkle_segment(&data, i, &cached).expect("segment must verify");
    }
}

// ── Bench dimensions ────────────────────────────────────────────────────────
//
// File sizes and segment sizes chosen to hit the interesting regimes:
//
//   1 MB  /  4 KB segments → N = 256  — small file, moderate N
//   4 MB  /  4 KB segments → N = 1024 — medium file, N = 1024
//  16 MB  /  8 KB segments → N = 2048 — large file, bigger tree
//
// K (partial fetch count) = N / 10 — 10% of segments out of order.

const BENCH_CASES: &[(usize, usize)] = &[
    (1024 * 1024, 4 * 1024),      // 1 MB / 4 KB → 256 segments
    (4 * 1024 * 1024, 4 * 1024),  // 4 MB / 4 KB → 1024 segments
    (16 * 1024 * 1024, 8 * 1024), // 16 MB / 8 KB → 2048 segments
];

fn pick_partial_indices(n: usize) -> Vec<usize> {
    // Deterministic pseudo-random K/N=10% indices. Using a fixed
    // LCG so the same indices are picked every run for reproducibility.
    let k = (n / 10).max(1);
    let mut state: u64 = 0xCAFEBABE;
    let mut picks = std::collections::BTreeSet::new();
    while picks.len() < k {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        picks.insert((state as usize) % n);
    }
    picks.into_iter().collect()
}

// ── The actual benches ──────────────────────────────────────────────────────

fn bench_merkle_segmented(c: &mut Criterion) {
    let signer = Ed25519Signer::from_seed(&[0x42u8; 32], test_name(&["bench", "signer"]));
    let public_key: [u8; 32] = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
        .verifying_key()
        .to_bytes();
    let verifier = Ed25519Verifier;
    let prefix = test_name(&["bench", "file"]);

    for &(file_size, seg_size) in BENCH_CASES {
        let n = file_size / seg_size;
        let label = format!("{}MB/{}seg", file_size / (1024 * 1024), n);
        let content = synthetic_file(file_size);
        let partial = pick_partial_indices(n);

        // ── Producer row: per-segment Ed25519 ──────────────────────────
        {
            let mut g = c.benchmark_group(format!("merkle/producer/per-segment-ed25519"));
            g.sample_size(10); // large N per iter → fewer samples for wall-time
            g.measurement_time(Duration::from_secs(10));
            g.throughput(Throughput::Bytes(file_size as u64));
            g.bench_with_input(BenchmarkId::from_parameter(&label), &content, |b, c| {
                b.iter(|| per_segment_ed25519_produce(&prefix, c, seg_size, &signer));
            });
            g.finish();
        }

        // ── Producer row: SHA-256 Merkle + 1 Ed25519 root sign ─────────
        {
            let mut g = c.benchmark_group("merkle/producer/sha256-merkle");
            g.sample_size(10);
            g.measurement_time(Duration::from_secs(10));
            g.throughput(Throughput::Bytes(file_size as u64));
            g.bench_with_input(BenchmarkId::from_parameter(&label), &content, |b, c| {
                b.iter(|| merkle_produce(&prefix, c, seg_size, MerkleKind::Sha256, &signer));
            });
            g.finish();
        }

        // ── Producer row: BLAKE3 Merkle + 1 Ed25519 root sign ──────────
        {
            let mut g = c.benchmark_group("merkle/producer/blake3-merkle");
            g.sample_size(10);
            g.measurement_time(Duration::from_secs(10));
            g.throughput(Throughput::Bytes(file_size as u64));
            g.bench_with_input(BenchmarkId::from_parameter(&label), &content, |b, c| {
                b.iter(|| merkle_produce(&prefix, c, seg_size, MerkleKind::Blake3, &signer));
            });
            g.finish();
        }

        // ── Consumer rows: pre-publish once, bench verification only ───
        //
        // The bench setup is not part of the measurement — criterion
        // only times the `|| { ... }` closure body. We publish each
        // scheme once, then in the hot loop we decode + verify the
        // K partial-fetch indices.

        let wires_ed = per_segment_ed25519_produce(&prefix, &content, seg_size, &signer);
        let (manifest_sha, segs_sha) =
            merkle_produce(&prefix, &content, seg_size, MerkleKind::Sha256, &signer);
        let (manifest_blake3, segs_blake3) =
            merkle_produce(&prefix, &content, seg_size, MerkleKind::Blake3, &signer);

        // Per-segment Ed25519 consumer.
        {
            let mut g = c.benchmark_group("merkle/consumer/per-segment-ed25519");
            g.sample_size(20);
            g.throughput(Throughput::Elements(partial.len() as u64));
            g.bench_with_input(BenchmarkId::from_parameter(&label), &(), |b, _| {
                b.iter(|| per_segment_ed25519_verify(&wires_ed, &partial, &verifier, &public_key));
            });
            g.finish();
        }

        // SHA-256 Merkle consumer.
        {
            let mut g = c.benchmark_group("merkle/consumer/sha256-merkle");
            g.sample_size(20);
            g.throughput(Throughput::Elements(partial.len() as u64));
            g.bench_with_input(BenchmarkId::from_parameter(&label), &(), |b, _| {
                b.iter(|| {
                    merkle_verify(&manifest_sha, &segs_sha, &partial, &verifier, &public_key);
                });
            });
            g.finish();
        }

        // BLAKE3 Merkle consumer.
        {
            let mut g = c.benchmark_group("merkle/consumer/blake3-merkle");
            g.sample_size(20);
            g.throughput(Throughput::Elements(partial.len() as u64));
            g.bench_with_input(BenchmarkId::from_parameter(&label), &(), |b, _| {
                b.iter(|| {
                    merkle_verify(
                        &manifest_blake3,
                        &segs_blake3,
                        &partial,
                        &verifier,
                        &public_key,
                    );
                });
            });
            g.finish();
        }
    }
}

criterion_group!(benches, bench_merkle_segmented);
criterion_main!(benches);
