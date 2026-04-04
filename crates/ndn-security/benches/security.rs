use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ndn_packet::{Name, NameComponent};
use ndn_security::{
    Certificate, Ed25519Signer, Ed25519Verifier, HmacSha256Signer, Signer, TrustSchema,
    ValidationResult, Validator, Verifier,
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
    let inner: Vec<u8> = signed_region.iter().chain(sval_tlv.iter()).copied().collect();
    let mut w = TlvWriter::new();
    w.write_tlv(0x06, &inner);
    w.finish()
}

// ── Signing benchmarks ─────────────────────────────────────────────────────

fn bench_signing(c: &mut Criterion) {
    let key_name = name1("key");
    let ed_signer = Ed25519Signer::from_seed(&[1u8; 32], key_name.clone());
    let hmac_signer = HmacSha256Signer::new(&[2u8; 32], key_name);

    let region_100 = vec![0u8; 100];
    let region_500 = vec![0u8; 500];

    {
        let mut group = c.benchmark_group("signing/ed25519");
        for (label, region) in [("100B", &region_100), ("500B", &region_500)] {
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
        for (label, region) in [("100B", &region_100), ("500B", &region_500)] {
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
}

// ── Verification benchmark ────────────────────────────────────────────────

fn bench_verification(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let seed = [3u8; 32];
    let signer = Ed25519Signer::from_seed(&seed, name1("key"));
    let public_key = signer.public_key_bytes();
    let verifier = Ed25519Verifier;

    // Pre-sign the region outside the iter closure.
    let region_100 = vec![0u8; 100];
    let region_500 = vec![0u8; 500];
    let sig_100 = signer.sign_sync(&region_100).unwrap();
    let sig_500 = signer.sign_sync(&region_500).unwrap();

    let mut group = c.benchmark_group("verification/ed25519");
    for (label, region, sig) in [
        ("100B", region_100.as_slice(), sig_100.as_ref()),
        ("500B", region_500.as_slice(), sig_500.as_ref()),
    ] {
        group.throughput(Throughput::Bytes(region.len() as u64));
        group.bench_with_input(BenchmarkId::new("verify", label), &(region, sig), |b, &(r, s)| {
            b.iter(|| {
                let outcome = rt.block_on(verifier.verify(r, s, &public_key)).unwrap();
                debug_assert_eq!(outcome, ndn_security::VerifyOutcome::Valid);
                outcome
            });
        });
    }
    group.finish();
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

criterion_group!(benches, bench_signing, bench_verification, bench_validation);
criterion_main!(benches);
