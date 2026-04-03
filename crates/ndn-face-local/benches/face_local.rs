//! Benchmarks for in-process NDN faces.
//!
//! Three face implementations are compared across latency and unidirectional
//! throughput at packet sizes 64 B, 1 024 B, 8 192 B:
//!
//! | Face | Transport mechanism | Expected tier |
//! |------|--------------------|----|
//! | `AppFace`  | Tokio `mpsc`; zero syscalls | fastest |
//! | `UnixFace` | Unix stream socket + TLV codec | ~2 µs |
//! | `SpscFace` | POSIX SHM ring + parked-flag wakeup | ~125 ns |
//!
//! Run all benchmarks:
//! ```text
//! cargo bench -p ndn-face-local --features spsc-shm
//! ```

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use ndn_face_local::AppFace;
use ndn_transport::{Face, FaceId};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Raw bytes payload for `AppFace` / `SpscFace` (no framing required).
fn make_pkt(size: usize) -> Bytes {
    Bytes::from(vec![0xAA_u8; size])
}

/// NDN TLV-framed packet of approximately `size` bytes for `UnixFace`.
///
/// `UnixFace` uses `TlvCodec` which expects the stream to be a sequence of
/// valid NDN TLV packets.  This function wraps a zero-padded payload in an
/// Interest-type (0x05) TLV envelope so the codec can frame and deframe it.
fn make_tlv_pkt(size: usize) -> Bytes {
    use ndn_tlv::TlvWriter;
    // 1 byte type (0x05) + up to 3 bytes length for sizes ≤ 65535.
    let overhead = if size <= 130 { 2 } else { 3 };
    let payload  = vec![0xAA_u8; size.saturating_sub(overhead)];
    let mut w = TlvWriter::new();
    w.write_tlv(0x05, &payload);
    w.finish()
}

fn current_thread_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ─── AppFace ──────────────────────────────────────────────────────────────────

/// Round-trip latency: one packet handle → face (app→engine), then back.
fn bench_appface_latency(c: &mut Criterion) {
    let rt = current_thread_rt();

    let mut group = c.benchmark_group("appface/latency");
    for &size in &[64_usize, 1_024, 8_192] {
        let pkt = make_pkt(size);
        let (face, handle) = AppFace::new(FaceId(1), 128);

        group.bench_with_input(BenchmarkId::from_parameter(size), &pkt, |b, pkt| {
            b.iter(|| {
                rt.block_on(async {
                    handle.send(pkt.clone()).await.unwrap();
                    face.recv().await.unwrap();
                    face.send(pkt.clone()).await.unwrap();
                    handle.recv().await.unwrap();
                });
            });
        });
    }
    group.finish();
}

/// Unidirectional throughput: burst 1 000 packets handle → face.
fn bench_appface_throughput(c: &mut Criterion) {
    let rt = current_thread_rt();

    const N: u64 = 1_000;
    let mut group = c.benchmark_group("appface/throughput");
    group.throughput(Throughput::Elements(N));

    for &size in &[64_usize, 1_024, 8_192] {
        let pkt = make_pkt(size);
        let (face, handle) = AppFace::new(FaceId(2), N as usize + 64);

        group.bench_with_input(BenchmarkId::from_parameter(size), &pkt, |b, pkt| {
            b.iter(|| {
                rt.block_on(async {
                    for _ in 0..N {
                        handle.send(pkt.clone()).await.unwrap();
                    }
                    for _ in 0..N {
                        face.recv().await.unwrap();
                    }
                });
            });
        });
    }
    group.finish();
}

// ─── UnixFace ─────────────────────────────────────────────────────────────────

/// Round-trip latency over a `UnixStream` socketpair with TLV framing.
///
/// Uses `UnixStream::pair()` (kernel `socketpair(AF_UNIX, SOCK_STREAM, 0)`) so
/// no filesystem socket file is needed.  Establishes the baseline cost for any
/// kernel-mediated face transport on this machine.
fn bench_unix_latency(c: &mut Criterion) {
    #[cfg(unix)]
    {
        use tokio::net::UnixStream;

        let rt = current_thread_rt();
        let mut group = c.benchmark_group("unix/latency");

        for &size in &[64_usize, 1_024, 8_192] {
            let pkt = make_tlv_pkt(size);

            // socketpair(2) — no socket file on disk.
            let (fa, fb) = rt.block_on(async {
                let (s1, s2) = UnixStream::pair().unwrap();
                let fa = ndn_face_local::unix_face_from_stream(FaceId(20), s1, "pair-a");
                let fb = ndn_face_local::unix_face_from_stream(FaceId(21), s2, "pair-b");
                (fa, fb)
            });

            group.bench_with_input(BenchmarkId::from_parameter(size), &pkt, |b, pkt| {
                b.iter(|| {
                    rt.block_on(async {
                        // Use join! so send and recv make cooperative progress.
                        // Sequential would deadlock for packets ≥ the socket
                        // buffer size (8 KiB default on macOS).
                        tokio::join!(
                            async {
                                fa.send(pkt.clone()).await.unwrap();
                                fa.recv().await.unwrap();
                            },
                            async {
                                fb.recv().await.unwrap();
                                fb.send(pkt.clone()).await.unwrap();
                            },
                        );
                    });
                });
            });
        }
        group.finish();
    }

    #[cfg(not(unix))]
    { let _ = c; }
}

/// Unidirectional throughput over a `UnixStream` socketpair.
///
/// `tokio::join!` runs send and recv concurrently so the kernel buffer never
/// fills and blocks the single-threaded executor.
fn bench_unix_throughput(c: &mut Criterion) {
    #[cfg(unix)]
    {
        use tokio::net::UnixStream;

        const N: u64 = 200;
        let rt = current_thread_rt();
        let mut group = c.benchmark_group("unix/throughput");
        group.throughput(Throughput::Elements(N));

        for &size in &[64_usize, 1_024, 8_192] {
            let pkt = make_tlv_pkt(size);

            let (fa, fb) = rt.block_on(async {
                let (s1, s2) = UnixStream::pair().unwrap();
                let fa = ndn_face_local::unix_face_from_stream(FaceId(22), s1, "pair-c");
                let fb = ndn_face_local::unix_face_from_stream(FaceId(23), s2, "pair-d");
                (fa, fb)
            });

            group.bench_with_input(BenchmarkId::from_parameter(size), &pkt, |b, pkt| {
                b.iter(|| {
                    rt.block_on(async {
                        // Concurrent send+recv prevents socket-buffer deadlock.
                        tokio::join!(
                            async {
                                for _ in 0..N {
                                    fa.send(pkt.clone()).await.unwrap();
                                }
                            },
                            async {
                                for _ in 0..N {
                                    fb.recv().await.unwrap();
                                }
                            },
                        );
                    });
                });
            });
        }
        group.finish();
    }

    #[cfg(not(unix))]
    { let _ = c; }
}

// ─── SpscFace ─────────────────────────────────────────────────────────────────

/// Round-trip latency over the SPSC SHM ring.
///
/// Includes two Unix-datagram wakeup round-trips (one per direction), which is
/// why this matches `UnixFace` latency rather than `AppFace`.
fn bench_spsc_latency(c: &mut Criterion) {
    #[cfg(all(unix, feature = "spsc-shm"))]
    {
        use ndn_face_local::shm::spsc::{SpscFace, SpscHandle};

        let rt = current_thread_rt();
        let mut group = c.benchmark_group("spsc/latency");

        for (&size, name) in [64_usize, 1_024, 8_192].iter().zip(["blt0", "blt1", "blt2"]) {
            let pkt = make_pkt(size);
            let (face, handle) = rt.block_on(async {
                let face   = SpscFace::create(FaceId(10), name).unwrap();
                let handle = SpscHandle::connect(name).unwrap();
                (face, handle)
            });

            group.bench_with_input(BenchmarkId::from_parameter(size), &pkt, |b, pkt| {
                b.iter(|| {
                    rt.block_on(async {
                        handle.send(pkt.clone()).await.unwrap();
                        face.recv().await.unwrap();
                        face.send(pkt.clone()).await.unwrap();
                        handle.recv().await.unwrap();
                    });
                });
            });
        }
        group.finish();
    }

    #[cfg(not(all(unix, feature = "spsc-shm")))]
    { let _ = c; }
}

/// Unidirectional throughput over the SPSC SHM ring.
///
/// `BATCH` is kept below the ring capacity (64 slots) so the producer never
/// spins.  One wakeup datagram is sent per packet, which dominates cost.
fn bench_spsc_throughput(c: &mut Criterion) {
    #[cfg(all(unix, feature = "spsc-shm"))]
    {
        use ndn_face_local::shm::spsc::{DEFAULT_CAPACITY, SpscFace, SpscHandle};

        let batch: u64 = (DEFAULT_CAPACITY as u64 / 2).max(1);
        let rt = current_thread_rt();
        let mut group = c.benchmark_group("spsc/throughput");
        group.throughput(Throughput::Elements(batch));

        for (&size, name) in [64_usize, 1_024, 8_192].iter().zip(["bth0", "bth1", "bth2"]) {
            let pkt = make_pkt(size);
            let (face, handle) = rt.block_on(async {
                let face   = SpscFace::create(FaceId(11), name).unwrap();
                let handle = SpscHandle::connect(name).unwrap();
                (face, handle)
            });

            group.bench_with_input(BenchmarkId::from_parameter(size), &pkt, |b, pkt| {
                b.iter(|| {
                    rt.block_on(async {
                        for _ in 0..batch {
                            handle.send(pkt.clone()).await.unwrap();
                        }
                        for _ in 0..batch {
                            face.recv().await.unwrap();
                        }
                    });
                });
            });
        }
        group.finish();
    }

    #[cfg(not(all(unix, feature = "spsc-shm")))]
    { let _ = c; }
}

// ─── Criterion wiring ─────────────────────────────────────────────────────────

criterion_group!(appface_benches, bench_appface_latency, bench_appface_throughput);
criterion_group!(unix_benches,    bench_unix_latency,    bench_unix_throughput);
criterion_group!(spsc_benches,    bench_spsc_latency,    bench_spsc_throughput);
criterion_main!(appface_benches, unix_benches, spsc_benches);
