use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ndn_packet::{Name, NameComponent};
use ndn_security::{
    Blake3DigestVerifier, Blake3KeyedSigner, Blake3KeyedVerifier, Blake3Signer, Certificate,
    Ed25519Signer, Ed25519Verifier, HmacSha256Signer, Signer, TrustSchema, ValidationResult,
    Validator, Verifier,
};
use ndn_tlv::TlvWriter;
use std::sync::Arc;

fn comp(s: &str) -> NameComponent {
    NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))
}

fn name1(c: &str) -> Name {
    Name::from_components([comp(c)])
}

/// Build a minimal signed Data packet: NAME(/data_comp) + SIGINFO + SIGVALUE.
fn build_signed_data(signer: &Ed25519Signer, data_comp: &str, key_comp: &str) -> Bytes {
    let nc = {
        let mut w = TlvWriter::new();
        w.write_tlv(0x08, data_comp.as_bytes());
        w.finish()
    };
    let name_tlv = {
        let mut w = TlvWriter::new();
        w.write_tlv(0x07, &nc);
        w.finish()
    };

    let knc = {
        let mut w = TlvWriter::new();
        w.write_tlv(0x08, key_comp.as_bytes());
        w.finish()
    };
    let kname_tlv = {
        let mut w = TlvWriter::new();
        w.write_tlv(0x07, &knc);
        w.finish()
    };
    let kloc_tlv = {
        let mut w = TlvWriter::new();
        w.write_tlv(0x1c, &kname_tlv);
        w.finish()
    };
    let stype_tlv = {
        let mut w = TlvWriter::new();
        w.write_tlv(0x1b, &[7u8]);
        w.finish()
    };
    let sinfo_inner: Vec<u8> = stype_tlv.iter().chain(kloc_tlv.iter()).copied().collect();
    let sinfo_tlv = {
        let mut w = TlvWriter::new();
        w.write_tlv(0x16, &sinfo_inner);
        w.finish()
    };

    let signed_region: Vec<u8> = name_tlv.iter().chain(sinfo_tlv.iter()).copied().collect();
    let sig = signer.sign_sync(&signed_region).unwrap();

    let sval_tlv = {
        let mut w = TlvWriter::new();
        w.write_tlv(0x17, &sig);
        w.finish()
    };
    let inner: Vec<u8> = signed_region
        .iter()
        .chain(sval_tlv.iter())
        .copied()
        .collect();
    let mut w = TlvWriter::new();
    w.write_tlv(0x06, &inner);
    w.finish()
}

// ── Signing benchmarks ─────────────────────────────────────────────────────

const PAYLOAD_SIZES: &[usize] = &[100, 500, 1000, 2000, 4000, 8000];

fn size_label(size: usize) -> String {
    if size.is_multiple_of(1000) {
        format!("{}KB", size / 1000)
    } else {
        format!("{}B", size)
    }
}

fn make_regions() -> Vec<(String, Vec<u8>)> {
    PAYLOAD_SIZES
        .iter()
        .map(|&n| (size_label(n), vec![0u8; n]))
        .collect()
}

fn bench_signing(c: &mut Criterion) {
    let key_name = name1("key");
    let ed_signer = Ed25519Signer::from_seed(&[1u8; 32], key_name.clone());
    let hmac_signer = HmacSha256Signer::new(&[2u8; 32], key_name.clone());
    let blake3_plain_signer = Blake3Signer::new(key_name.clone());
    let blake3_keyed_signer = Blake3KeyedSigner::new([3u8; 32], key_name);

    let regions = make_regions();

    {
        let mut group = c.benchmark_group("signing/ed25519");
        for (label, region) in &regions {
            group.throughput(Throughput::Bytes(region.len() as u64));
            group.bench_with_input(BenchmarkId::new("sign_sync", label), region, |b, r| {
                b.iter(|| {
                    let sig = ed_signer.sign_sync(r).unwrap();
                    debug_assert_eq!(sig.len(), 64);
                    sig
                });
            });
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("signing/hmac");
        for (label, region) in &regions {
            group.throughput(Throughput::Bytes(region.len() as u64));
            group.bench_with_input(BenchmarkId::new("sign_sync", label), region, |b, r| {
                b.iter(|| {
                    let sig = hmac_signer.sign_sync(r).unwrap();
                    debug_assert_eq!(sig.len(), 32);
                    sig
                });
            });
        }
        group.finish();
    }

    // SHA256 plain digest — DigestSha256 (type 0). No key material.
    //
    // Uses `sha2::Sha256` (rustcrypto), which dispatches to Intel SHA-NI /
    // ARMv8 SHA crypto via the `cpufeatures` crate at runtime when the CPU
    // exposes the extension. This matches the path that the rest of
    // `ndn-security` uses. Earlier iterations of this bench split the group
    // into ring (`-hw`) and sha2 (`-sw`) thinking that would isolate the
    // SHA-NI cost — it doesn't, because both crates use cpufeatures and
    // both end up on the same hardware-accelerated path on any CPU you
    // care about. See `docs/wiki/src/deep-dive/why-blake3.md`.
    {
        use sha2::{Digest, Sha256};
        let mut group = c.benchmark_group("signing/sha256-digest");
        for (label, region) in &regions {
            group.throughput(Throughput::Bytes(region.len() as u64));
            group.bench_with_input(BenchmarkId::new("sign_sync", label), region, |b, r| {
                b.iter(|| {
                    let mut h = Sha256::new();
                    h.update(r);
                    let out = h.finalize();
                    debug_assert_eq!(out.len(), 32);
                    out
                });
            });
        }
        group.finish();
    }

    // BLAKE3 plain digest — analogous to DigestSha256 (type 0).
    {
        let mut group = c.benchmark_group("signing/blake3-plain");
        for (label, region) in &regions {
            group.throughput(Throughput::Bytes(region.len() as u64));
            group.bench_with_input(BenchmarkId::new("sign_sync", label), region, |b, r| {
                b.iter(|| {
                    let sig = blake3_plain_signer.sign_sync(r).unwrap();
                    debug_assert_eq!(sig.len(), 32);
                    sig
                });
            });
        }
        group.finish();
    }

    // BLAKE3 keyed — analogous to HmacWithSha256 (type 4).
    {
        let mut group = c.benchmark_group("signing/blake3-keyed");
        for (label, region) in &regions {
            group.throughput(Throughput::Bytes(region.len() as u64));
            group.bench_with_input(BenchmarkId::new("sign_sync", label), region, |b, r| {
                b.iter(|| {
                    let sig = blake3_keyed_signer.sign_sync(r).unwrap();
                    debug_assert_eq!(sig.len(), 32);
                    sig
                });
            });
        }
        group.finish();
    }
}

// ── Verification benchmark ────────────────────────────────────────────────

fn bench_verification(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let seed = [3u8; 32];
    let ed_signer = Ed25519Signer::from_seed(&seed, name1("key"));
    let public_key = ed_signer.public_key_bytes();
    let ed_verifier = Ed25519Verifier;

    let blake3_plain_signer = Blake3Signer::new(name1("key"));
    let blake3_plain_verifier = Blake3DigestVerifier;

    let blake3_key = [7u8; 32];
    let blake3_keyed_signer = Blake3KeyedSigner::new(blake3_key, name1("key"));
    let blake3_keyed_verifier = Blake3KeyedVerifier;

    // Pre-build regions and pre-sign them once per algorithm.
    let regions = make_regions();
    let presigned: Vec<(String, Vec<u8>, Bytes, Bytes, Bytes)> = regions
        .into_iter()
        .map(|(label, region)| {
            let ed_sig = ed_signer.sign_sync(&region).unwrap();
            let b3_plain_sig = blake3_plain_signer.sign_sync(&region).unwrap();
            let b3_keyed_sig = blake3_keyed_signer.sign_sync(&region).unwrap();
            (label, region, ed_sig, b3_plain_sig, b3_keyed_sig)
        })
        .collect();

    {
        let mut group = c.benchmark_group("verification/ed25519");
        for (label, region, ed_sig, _, _) in &presigned {
            group.throughput(Throughput::Bytes(region.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("verify", label),
                &(region.as_slice(), ed_sig.as_ref()),
                |b, &(r, s)| {
                    b.iter(|| {
                        let outcome = rt.block_on(ed_verifier.verify(r, s, &public_key)).unwrap();
                        debug_assert_eq!(outcome, ndn_security::VerifyOutcome::Valid);
                        outcome
                    });
                },
            );
        }
        group.finish();
    }

    // SHA256 plain-digest verification — re-hash and compare. Same backend
    // as `signing/sha256-digest`; see that group for the rationale on
    // sha2-vs-ring choice.
    {
        use sha2::{Digest, Sha256};
        let mut group = c.benchmark_group("verification/sha256-digest");
        for (label, region, _, _, _) in &presigned {
            let mut h = Sha256::new();
            h.update(region);
            let expected = h.finalize();
            let expected_bytes: Bytes = Bytes::copy_from_slice(expected.as_slice());
            group.throughput(Throughput::Bytes(region.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("verify", label),
                &(region.as_slice(), expected_bytes.as_ref()),
                |b, &(r, s)| {
                    b.iter(|| {
                        let mut h = Sha256::new();
                        h.update(r);
                        let got = h.finalize();
                        debug_assert_eq!(got.as_slice(), s);
                        got
                    });
                },
            );
        }
        group.finish();
    }

    // BLAKE3 plain-digest verification — no key material.
    {
        let mut group = c.benchmark_group("verification/blake3-plain");
        for (label, region, _, b3_plain_sig, _) in &presigned {
            group.throughput(Throughput::Bytes(region.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("verify", label),
                &(region.as_slice(), b3_plain_sig.as_ref()),
                |b, &(r, s)| {
                    b.iter(|| {
                        let outcome = rt
                            .block_on(blake3_plain_verifier.verify(r, s, &[]))
                            .unwrap();
                        debug_assert_eq!(outcome, ndn_security::VerifyOutcome::Valid);
                        outcome
                    });
                },
            );
        }
        group.finish();
    }

    // BLAKE3 keyed verification — 32-byte shared secret as "public_key".
    {
        let mut group = c.benchmark_group("verification/blake3-keyed");
        for (label, region, _, _, b3_keyed_sig) in &presigned {
            group.throughput(Throughput::Bytes(region.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("verify", label),
                &(region.as_slice(), b3_keyed_sig.as_ref()),
                |b, &(r, s)| {
                    b.iter(|| {
                        let outcome = rt
                            .block_on(blake3_keyed_verifier.verify(r, s, &blake3_key))
                            .unwrap();
                        debug_assert_eq!(outcome, ndn_security::VerifyOutcome::Valid);
                        outcome
                    });
                },
            );
        }
        group.finish();
    }
}

// ── Validation benchmarks ─────────────────────────────────────────────────

fn build_validator_with_cert(seed: &[u8; 32]) -> (Validator, Bytes) {
    let key_name = name1("key");
    let signer = Ed25519Signer::from_seed(seed, key_name.clone());
    let public_key = signer.public_key_bytes();
    let wire = build_signed_data(&signer, "data", "key");

    let validator = Validator::new(TrustSchema::accept_all());
    let cert = Certificate {
        name: Arc::new(key_name),
        public_key: Bytes::copy_from_slice(&public_key),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
    };
    validator.cert_cache().insert(cert);
    (validator, wire)
}

fn bench_validation(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("validation");

    // ── schema_mismatch: schema rejects packet before any crypto ──────────
    {
        let signer = Ed25519Signer::from_seed(&[4u8; 32], name1("key"));
        let wire = build_signed_data(&signer, "data", "key");
        let data = ndn_packet::Data::decode(wire).unwrap();
        // Empty schema rejects everything — no crypto ever runs.
        let validator = Validator::new(TrustSchema::new());
        group.bench_function("schema_mismatch", |b| {
            b.iter(|| {
                let result = rt.block_on(validator.validate(&data));
                debug_assert!(matches!(result, ValidationResult::Invalid(_)));
                result
            });
        });
    }

    // ── cert_missing: schema passes but cert not in cache ─────────────────
    {
        let signer = Ed25519Signer::from_seed(&[5u8; 32], name1("key"));
        let wire = build_signed_data(&signer, "data", "key");
        let data = ndn_packet::Data::decode(wire).unwrap();
        // accept_all schema → schema check passes, but no cert → Pending.
        let validator = Validator::new(TrustSchema::accept_all());
        group.bench_function("cert_missing", |b| {
            b.iter(|| {
                let result = rt.block_on(validator.validate(&data));
                debug_assert!(matches!(result, ValidationResult::Pending));
                result
            });
        });
    }

    // ── single_hop: full verification (schema check + cert cache + Ed25519) ─
    {
        let seed = [6u8; 32];
        let (validator, wire) = build_validator_with_cert(&seed);
        let data = ndn_packet::Data::decode(wire).unwrap();
        group.bench_function("single_hop", |b| {
            b.iter(|| {
                let result = rt.block_on(validator.validate(&data));
                debug_assert!(matches!(result, ValidationResult::Valid(_)));
                result
            });
        });
    }

    group.finish();
}

// ── BLAKE3 large-input multi-thread bench ─────────────────────────────────
//
// The per-packet sign/verify benches above compare BLAKE3 against
// hardware-accelerated SHA-256 on inputs the size of an NDN signed
// portion (a few hundred bytes to a few KB). At those sizes BLAKE3
// has no parallelism to extract — it's single-thread vs single-thread,
// and SHA-NI wins. The interesting BLAKE3 win is at multi-MB inputs
// where `Hasher::update_rayon` spreads the work across all cores.
//
// This group benches both sides of `BLAKE3_RAYON_THRESHOLD` so the
// crossover is visible on whatever runner the bench lands on:
//
//   256 KB  — at the threshold, rayon barely wins
//   1 MB    — comfortably above, ~2-4× speedup expected on multi-core
//   4 MB    — fully amortised, near-linear scaling
//
// SHA-256 is included at the same sizes as a control. There is no
// SHA-256 multi-thread variant — it's inherently sequential — so the
// comparison shows the qualitative difference between an algorithm
// that scales with cores and one that does not.
const BLAKE3_LARGE_SIZES: &[usize] = &[256 * 1024, 1024 * 1024, 4 * 1024 * 1024];

fn size_label_bytes(n: usize) -> String {
    if n >= 1024 * 1024 {
        format!("{}MB", n / (1024 * 1024))
    } else if n >= 1024 {
        format!("{}KB", n / 1024)
    } else {
        format!("{}B", n)
    }
}

fn bench_blake3_large(c: &mut Criterion) {
    use sha2::{Digest, Sha256};
    let regions: Vec<(String, Vec<u8>)> = BLAKE3_LARGE_SIZES
        .iter()
        .map(|&n| (size_label_bytes(n), vec![0xA5u8; n]))
        .collect();

    // BLAKE3 single-thread.
    {
        let mut group = c.benchmark_group("large/blake3-single");
        for (label, region) in &regions {
            group.throughput(Throughput::Bytes(region.len() as u64));
            group.bench_with_input(BenchmarkId::new("hash", label), region, |b, r| {
                b.iter(|| blake3::hash(r));
            });
        }
        group.finish();
    }
    // BLAKE3 multi-thread via rayon — the only place BLAKE3 has a
    // structural advantage over SHA-256 on a single buffer.
    {
        let mut group = c.benchmark_group("large/blake3-rayon");
        for (label, region) in &regions {
            group.throughput(Throughput::Bytes(region.len() as u64));
            group.bench_with_input(BenchmarkId::new("hash", label), region, |b, r| {
                b.iter(|| {
                    let mut h = blake3::Hasher::new();
                    h.update_rayon(r);
                    h.finalize()
                });
            });
        }
        group.finish();
    }
    // SHA-256 control. There is no `update_rayon` equivalent — SHA-256
    // cannot be parallelised over a single buffer — so this row is the
    // single-thread ceiling for SHA-256 at large sizes. The interesting
    // comparison is `large/blake3-rayon` vs `large/sha256` on a multi-
    // core runner: BLAKE3 should pull ahead by roughly the core count.
    {
        let mut group = c.benchmark_group("large/sha256");
        for (label, region) in &regions {
            group.throughput(Throughput::Bytes(region.len() as u64));
            group.bench_with_input(BenchmarkId::new("hash", label), region, |b, r| {
                b.iter(|| {
                    let mut h = Sha256::new();
                    h.update(r);
                    h.finalize()
                });
            });
        }
        group.finish();
    }
}

// Note: a one-time `bench_streaming_feasibility` micro-bench used to
// live here, exercising sha2 / blake3 incremental-API overhead and
// post-eviction cold-cache cost across NDN signed-portion sizes
// (256 B, 1 KB, 4 KB, 16 KB) to decide whether to pursue
// hash-during-TLV-decode as an optimisation. The answer was no, and
// the bench is gone — the finding is permanent and lives in
// `docs/wiki/src/deep-dive/why-blake3.md` ("Appendix: streaming hash
// during TLV decode — investigated and rejected").
//
// Short version of why: SHA-256 streaming saves nothing because cache
// locality is already a non-factor at NDN signed-portion sizes, and
// BLAKE3 streaming is *worse* than the current oneshot pattern by ~2×
// at 4 KB+ because feeding BLAKE3 in small chunks defeats its tree-
// mode SIMD parallelism. The current "hash the slice after decode"
// pattern is already optimal.

// ── Ed25519 batch verification ─────────────────────────────────────────────
//
// `ed25519_dalek::verify_batch` combines N verification equations
// into one big check using random coefficients. All-valid batches
// pass in one shot at ~2–3× the speed of N individual verifies;
// any single invalid signature fails the whole batch, and the
// caller then falls back to per-signature verify to find the
// culprit. Useful for forwarder-ingest workloads where almost every
// signature is valid on the happy path.
//
// Bench dimensions: batch sizes 1, 10, 100, 1000 with distinct
// keypairs and per-key messages. The hw-equivalent cost for a
// single sig verify is the `batch/1` row, which also measures the
// setup overhead of `verify_batch` on its own.
fn bench_ed25519_batch(c: &mut Criterion) {
    use ed25519_dalek::{Signer as _, SigningKey};
    use ndn_security::{Ed25519Verifier, ed25519_verify_batch};

    let ed_verifier = Ed25519Verifier;

    const BATCH_SIZES: &[usize] = &[1, 10, 100, 1000];
    for &n in BATCH_SIZES {
        // Set up N keypairs + messages + signatures. We generate
        // distinct 32-byte seeds deterministically so the bench is
        // reproducible across runs.
        let skeys: Vec<SigningKey> = (0..n)
            .map(|i| {
                SigningKey::from_bytes(&{
                    let mut seed = [0u8; 32];
                    seed[0] = (i >> 24) as u8;
                    seed[1] = (i >> 16) as u8;
                    seed[2] = (i >> 8) as u8;
                    seed[3] = i as u8;
                    seed[31] = 0x42; // avoid the all-zero seed
                    seed
                })
            })
            .collect();
        let public_keys: Vec<[u8; 32]> =
            skeys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let messages: Vec<Vec<u8>> = (0..n).map(|i| format!("msg {i}").into_bytes()).collect();
        let signatures: Vec<[u8; 64]> = skeys
            .iter()
            .zip(&messages)
            .map(|(k, m)| k.sign(m).to_bytes())
            .collect();

        // Per-signature verify loop (the baseline). Uses the sync
        // verify path so we don't measure tokio overhead.
        {
            let mut g = c.benchmark_group("verification/ed25519-per-sig-loop");
            g.throughput(Throughput::Elements(n as u64));
            g.bench_with_input(BenchmarkId::from_parameter(n), &(), |b, _| {
                b.iter(|| {
                    for i in 0..n {
                        let outcome =
                            ed_verifier.verify_sync(&messages[i], &signatures[i], &public_keys[i]);
                        debug_assert_eq!(outcome, ndn_security::VerifyOutcome::Valid);
                    }
                });
            });
            g.finish();
        }

        // Batch verify. This is the expected ~2–3× speedup path on
        // homogeneous-valid workloads.
        {
            let mut g = c.benchmark_group("verification/ed25519-batch");
            g.throughput(Throughput::Elements(n as u64));
            let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
            let sig_refs: Vec<&[u8; 64]> = signatures.iter().collect();
            let key_refs: Vec<&[u8; 32]> = public_keys.iter().collect();
            g.bench_with_input(BenchmarkId::from_parameter(n), &(), |b, _| {
                b.iter(|| {
                    let outcome = ed25519_verify_batch(&msg_refs, &sig_refs, &key_refs).unwrap();
                    debug_assert_eq!(outcome, ndn_security::VerifyOutcome::Valid);
                });
            });
            g.finish();
        }
    }
}

criterion_group!(
    benches,
    bench_signing,
    bench_verification,
    bench_validation,
    bench_blake3_large,
    bench_ed25519_batch,
);
criterion_main!(benches);
