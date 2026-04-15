//! End-to-end Merkle-signed segmented Data throughput through an
//! in-process ForwarderEngine with `InProcFace` pairs.
//!
//! Companion to `crates/engine/ndn-security/benches/merkle_segmented.rs`,
//! which measures producer / consumer costs in isolation with no
//! forwarder in the loop. This bench wires the same three schemes
//! (per-segment Ed25519, SHA-256 Merkle, BLAKE3 Merkle) through a
//! real engine pipeline — TLV decode, PIT, FIB LPM, CS, strategy,
//! dispatch — and asks **how much of the in-process Merkle win
//! survives when every packet pays pipeline cost**.
//!
//! # Why InProcFace, not Unix sockets
//!
//! A real `IpcListener` + `ForwarderClient` setup needs a management
//! handler + security profile wired through the client, which is
//! ~500 lines of reproduced binary plumbing for what is effectively
//! "the same pipeline plus a constant socket-IO cost that every
//! scheme pays identically." `InProcFace` exercises the same engine
//! pipeline on both Interest ingress and Data egress — just without
//! the `read()` / `write()` syscalls, which are ~1–2 µs per direction
//! and would be added to every row equally. The *relative* numbers
//! (Merkle vs per-segment, BLAKE3 vs SHA-256) are what we care about.
//!
//! # Bench dimensions
//!
//! Matches the in-process bench so the two sets of numbers line up:
//! 4 MB file at 4 KB segments (N=1024), 10% partial fetch (K=102),
//! deterministic pseudo-random index set.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_faces::local::{InProcFace, InProcHandle};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, Name, NameComponent, SignatureType};
use ndn_security::merkle::{
    Blake3Merkle, CachedManifest, MerkleKind, Sha256Merkle, publish_segmented_merkle,
    verify_merkle_segment,
};
use ndn_security::signer::Ed25519Signer;
use ndn_security::{Ed25519Verifier, Signer, VerifyOutcome};

// ── Parameters ──────────────────────────────────────────────────────────────

const SEG_SIZE: usize = 4096;
const N_SEGMENTS: usize = 1024;
const FILE_SIZE: usize = SEG_SIZE * N_SEGMENTS;
const PARTIAL_RATIO: usize = 10; // K = N / 10

// ── Fixture: pre-built publications for all three schemes ──────────────────

fn test_name(parts: &[&'static str]) -> Name {
    Name::from_components(
        parts
            .iter()
            .map(|p| NameComponent::generic(Bytes::from_static(p.as_bytes()))),
    )
}

fn synthetic_file(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    let mut state: u64 = 0x9E3779B97F4A7C15;
    for b in out.iter_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (state >> 56) as u8;
    }
    out
}

fn pick_partial_indices(n: usize) -> Vec<usize> {
    let k = (n / PARTIAL_RATIO).max(1);
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

/// Pre-built wires for every scheme. All three schemes put their
/// segment Data packets under `/bench/merkle/seg=<i>` so the engine's
/// FIB entry and the producer's lookup map work for whichever scheme
/// is currently "live". We swap the producer's serving map between
/// bench rows, not between iterations.
struct Publications {
    prefix: Name,
    public_key: [u8; 32],

    per_seg_segments: Vec<Bytes>,

    sha_manifest_wire: Bytes,
    sha_segments: Vec<Bytes>,

    blake_manifest_wire: Bytes,
    blake_segments: Vec<Bytes>,
}

impl Publications {
    fn build() -> Self {
        let prefix = test_name(&["bench", "merkle"]);
        let signer = Ed25519Signer::from_seed(&[0x42u8; 32], test_name(&["bench", "k"]));
        let public_key = signer.public_key_bytes();
        let content = synthetic_file(FILE_SIZE);

        // Per-segment Ed25519 — each segment Data signed independently.
        let per_seg_segments: Vec<Bytes> = content
            .chunks(SEG_SIZE)
            .enumerate()
            .map(|(i, seg)| {
                let name = prefix.clone().append_segment(i as u64);
                let kn = signer.key_name().clone();
                DataBuilder::new(name, seg).sign_sync(
                    SignatureType::SignatureEd25519,
                    Some(&kn),
                    |region| {
                        signer
                            .sign_sync(region)
                            .unwrap_or_else(|_| Bytes::from_static(&[0u8; 64]))
                    },
                )
            })
            .collect();

        let sha = publish_segmented_merkle::<Sha256Merkle>(
            &prefix,
            &content,
            SEG_SIZE,
            MerkleKind::Sha256,
            &signer,
        )
        .expect("sha256 merkle publish");

        let blake = publish_segmented_merkle::<Blake3Merkle>(
            &prefix,
            &content,
            SEG_SIZE,
            MerkleKind::Blake3,
            &signer,
        )
        .expect("blake3 merkle publish");

        Self {
            prefix,
            public_key,
            per_seg_segments,
            sha_manifest_wire: sha.manifest,
            sha_segments: sha.segments,
            blake_manifest_wire: blake.manifest,
            blake_segments: blake.segments,
        }
    }
}

// ── In-process forwarder harness ────────────────────────────────────────────

type ServingMap = Arc<std::sync::RwLock<HashMap<Name, Bytes>>>;

/// A live engine + producer task + consumer handle, built once at
/// the top of `bench_merkle_e2e` and reused across all bench rows.
/// The producer's serving map is shared (via `RwLock`) so the bench
/// can swap wires between schemes without tearing down the engine.
struct Harness {
    runtime: Runtime,
    _engine: ForwarderEngine,
    cancel: CancellationToken,
    consumer: Arc<InProcHandle>,
    producer_serving: ServingMap,
    _producer_task: JoinHandle<()>,
    _shutdown: ShutdownHandle,
}

impl Harness {
    fn build(prefix: &Name) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let cancel = CancellationToken::new();

        let (engine, shutdown, consumer, producer_serving, producer_task) =
            runtime.block_on(async {
                let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
                    .build()
                    .await
                    .expect("engine build");

                // Allocate face IDs and create two InProcFace pairs.
                let producer_fid = engine.faces().alloc_id();
                let consumer_fid = engine.faces().alloc_id();
                let (producer_face, producer_handle) = InProcFace::new(producer_fid, 4096);
                let (consumer_face, consumer_handle) = InProcFace::new(consumer_fid, 4096);

                // Attach both faces to the engine. add_face spawns a
                // per-face reader task that feeds incoming packets
                // into the pipeline.
                engine.add_face(producer_face, cancel.child_token());
                engine.add_face(consumer_face, cancel.child_token());

                // Install a FIB entry /bench/merkle → producer face.
                // `ndn_engine::Fib` (distinct from `ndn_store::Fib`)
                // takes a typed `FaceId` directly via `add_nexthop`,
                // not an `FibEntry::new(...)` — the engine-layer API
                // is three scalars (prefix, face_id, cost).
                engine.fib().add_nexthop(prefix, producer_fid, 0);

                // Shared serving map — swapped between bench rows.
                let serving: ServingMap = Arc::new(std::sync::RwLock::new(HashMap::new()));

                // Long-lived producer task.
                let producer_task = tokio::spawn(producer_serve_loop(
                    producer_handle,
                    Arc::clone(&serving),
                    cancel.child_token(),
                ));

                (
                    engine,
                    shutdown,
                    Arc::new(consumer_handle),
                    serving,
                    producer_task,
                )
            });

        Self {
            runtime,
            _engine: engine,
            cancel,
            consumer,
            producer_serving,
            _producer_task: producer_task,
            _shutdown: shutdown,
        }
    }

    /// Swap the serving map to a new scheme's wires. Also inserts
    /// the manifest wire (if any) so the consumer can fetch it
    /// alongside segments.
    fn install_wires(&self, wires: &[Bytes], manifest: Option<&Bytes>) {
        let mut map = HashMap::with_capacity(wires.len() + 1);
        for w in wires {
            let d = Data::decode(w.clone()).expect("decode segment");
            map.insert(d.name.as_ref().clone(), w.clone());
        }
        if let Some(m) = manifest {
            let d = Data::decode(m.clone()).expect("decode manifest");
            map.insert(d.name.as_ref().clone(), m.clone());
        }
        *self.producer_serving.write().unwrap() = map;
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Producer serve loop: recv Interest, look up by name, send Data.
/// Terminates on cancel.
async fn producer_serve_loop(handle: InProcHandle, serving: ServingMap, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            pkt = handle.recv() => {
                let Some(pkt) = pkt else { return; };
                let Ok(interest) = Interest::decode(pkt) else { continue; };
                let wire = {
                    let map = serving.read().unwrap();
                    map.get(interest.name.as_ref()).cloned()
                };
                if let Some(w) = wire {
                    let _ = handle.send(w).await;
                }
            }
        }
    }
}

// ── Consumer fetch primitive ────────────────────────────────────────────────

/// Pipeline K Interests, then drain K Data responses. Decode each,
/// extract its segment index from the trailing `SegmentNameComponent`
/// (TLV type 0x32, big-endian non-negative integer), and pass it to
/// `verify_fn` along with the Data. We can't correlate by Interest
/// send order because the forwarder pipeline may deliver Data in
/// any order once multiple Interests are in flight — so the segment
/// index has to come from the Data name itself.
async fn consumer_fetch_verify<F>(
    consumer: &InProcHandle,
    prefix: &Name,
    indices: &[usize],
    mut verify_fn: F,
) -> usize
where
    F: FnMut(usize, &Data),
{
    for &i in indices {
        let name = prefix.clone().append_segment(i as u64);
        let interest = InterestBuilder::new(name).build();
        consumer.send(interest).await.expect("interest send");
    }
    let mut verified = 0usize;
    for _ in 0..indices.len() {
        let pkt = consumer.recv().await.expect("data recv");
        let data = Data::decode(pkt).expect("decode data");
        let leaf_index = segment_index_from_name(&data.name)
            .expect("segment Data name must end in a SegmentNameComponent");
        verify_fn(leaf_index, &data);
        verified += 1;
    }
    verified
}

/// Extract the segment index from the last component of a Data name,
/// assuming it's a `SegmentNameComponent` (TLV type 0x32) whose value
/// is a big-endian non-negative integer in 1–8 bytes.
fn segment_index_from_name(name: &Name) -> Option<usize> {
    let last = name.components().last()?;
    // SegmentNameComponent type = 0x32.
    if last.typ != 0x32 {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in last.value.as_ref() {
        acc = (acc << 8) | b as u64;
    }
    Some(acc as usize)
}

// ── The benches ────────────────────────────────────────────────────────────

fn bench_merkle_e2e(c: &mut Criterion) {
    let pubs = Publications::build();
    let harness = Harness::build(&pubs.prefix);
    let verifier = Ed25519Verifier;
    let public_key = pubs.public_key;
    let partial = pick_partial_indices(N_SEGMENTS);

    // For the Merkle rows, fetch the manifest once outside the hot
    // loop and parse it into CachedManifest state. In a real consumer
    // this happens on first-segment arrival; we pre-do it here so the
    // per-iter hot loop only measures the K segment verifies, which
    // is the interesting comparison.
    let sha_cached =
        CachedManifest::from_manifest_data(&Data::decode(pubs.sha_manifest_wire.clone()).unwrap())
            .unwrap();
    let blake_cached = CachedManifest::from_manifest_data(
        &Data::decode(pubs.blake_manifest_wire.clone()).unwrap(),
    )
    .unwrap();

    let label = format!("{}MB/{}seg", FILE_SIZE / (1024 * 1024), N_SEGMENTS);

    // ── Row 1: per-segment Ed25519 ─────────────────────────────────────
    harness.install_wires(&pubs.per_seg_segments, None);
    {
        let mut g = c.benchmark_group("merkle_e2e/per-segment-ed25519");
        g.sample_size(20);
        g.measurement_time(Duration::from_secs(10));
        g.throughput(Throughput::Elements(partial.len() as u64));
        g.bench_with_input(BenchmarkId::from_parameter(&label), &(), |b, _| {
            b.iter(|| {
                harness.runtime.block_on(consumer_fetch_verify(
                    &harness.consumer,
                    &pubs.prefix,
                    &partial,
                    |_i, data| {
                        let outcome = verifier.verify_sync(
                            data.signed_region(),
                            data.sig_value(),
                            &public_key,
                        );
                        debug_assert_eq!(outcome, VerifyOutcome::Valid);
                    },
                ));
            });
        });
        g.finish();
    }

    // ── Row 2: SHA-256 Merkle ──────────────────────────────────────────
    harness.install_wires(&pubs.sha_segments, Some(&pubs.sha_manifest_wire));
    {
        let mut g = c.benchmark_group("merkle_e2e/sha256-merkle");
        g.sample_size(20);
        g.measurement_time(Duration::from_secs(10));
        g.throughput(Throughput::Elements(partial.len() as u64));
        g.bench_with_input(BenchmarkId::from_parameter(&label), &(), |b, _| {
            b.iter(|| {
                harness.runtime.block_on(consumer_fetch_verify(
                    &harness.consumer,
                    &pubs.prefix,
                    &partial,
                    |i, data| {
                        verify_merkle_segment(data, i, &sha_cached).expect("sha verify");
                    },
                ));
            });
        });
        g.finish();
    }

    // ── Row 3: BLAKE3 Merkle ───────────────────────────────────────────
    harness.install_wires(&pubs.blake_segments, Some(&pubs.blake_manifest_wire));
    {
        let mut g = c.benchmark_group("merkle_e2e/blake3-merkle");
        g.sample_size(20);
        g.measurement_time(Duration::from_secs(10));
        g.throughput(Throughput::Elements(partial.len() as u64));
        g.bench_with_input(BenchmarkId::from_parameter(&label), &(), |b, _| {
            b.iter(|| {
                harness.runtime.block_on(consumer_fetch_verify(
                    &harness.consumer,
                    &pubs.prefix,
                    &partial,
                    |i, data| {
                        verify_merkle_segment(data, i, &blake_cached).expect("blake verify");
                    },
                ));
            });
        });
        g.finish();
    }
}

criterion_group!(benches, bench_merkle_e2e);
criterion_main!(benches);
