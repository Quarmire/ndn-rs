use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ndn_packet::{Name, NameComponent};
use ndn_tlv::TlvWriter;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn comp(s: &str) -> NameComponent {
    NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))
}

/// Build a name with `n` generic components: a, b, c, ...
fn build_name(n: usize) -> Name {
    let components: Vec<_> = (0..n)
        .map(|i| {
            let label = format!("component{i}");
            comp(&label)
        })
        .collect();
    Name::from_components(components)
}

/// Encode a Name as a full Name TLV (0x07 wrapping component TLVs).
fn encode_name_wire(name: &Name) -> Bytes {
    let mut w = TlvWriter::new();
    let inner: Vec<u8> = name
        .components()
        .iter()
        .flat_map(|c| {
            let mut cw = TlvWriter::new();
            cw.write_tlv(c.typ, &c.value);
            cw.finish()
        })
        .collect();
    w.write_tlv(0x07, &inner);
    Bytes::copy_from_slice(&w.finish())
}

// ── parse (Name::from_str) ────────────────────────────────────────────────

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("name/parse");
    for n in [4usize, 8, 12] {
        let uri: String = (0..n)
            .map(|i| format!("/component{i}"))
            .collect::<Vec<_>>()
            .join("");
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("components", n), &uri, |b, u| {
            b.iter(|| {
                let name: Name = u.parse().unwrap();
                debug_assert_eq!(name.len(), n);
                name
            });
        });
    }
    group.finish();
}

// ── TLV decode (Name::decode from wire bytes) ─────────────────────────────

fn bench_tlv_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("name/tlv_decode");
    for n in [4usize, 8, 12] {
        let name = build_name(n);
        // Name::decode takes the *value* of the outer Name TLV (inner component bytes).
        let inner: Vec<u8> = name
            .components()
            .iter()
            .flat_map(|c| {
                let mut cw = TlvWriter::new();
                cw.write_tlv(c.typ, &c.value);
                cw.finish()
            })
            .collect();
        let wire = Bytes::copy_from_slice(&inner);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("components", n), &wire, |b, w| {
            b.iter(|| {
                let decoded = Name::decode(w.clone()).unwrap();
                debug_assert_eq!(decoded.len(), n);
                decoded
            });
        });
    }
    group.finish();
}

// ── hash ──────────────────────────────────────────────────────────────────

fn bench_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("name/hash");
    for n in [4usize, 8] {
        let name = build_name(n);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("components", n), &name, |b, nm| {
            b.iter(|| {
                let mut hasher = DefaultHasher::new();
                nm.hash(&mut hasher);
                let h = hasher.finish();
                std::hint::black_box(h)
            });
        });
    }
    group.finish();
}

// ── equality ──────────────────────────────────────────────────────────────

fn bench_eq(c: &mut Criterion) {
    let n = 8;
    let name_a = build_name(n);
    let name_b = build_name(n); // equal
    // Name differing at first component
    let mut comps_first = name_a.components().to_vec();
    comps_first[0] = comp("zzz");
    let name_miss_first = Name::from_components(comps_first);
    // Name differing at last component
    let mut comps_last = name_a.components().to_vec();
    comps_last[n - 1] = comp("zzz");
    let name_miss_last = Name::from_components(comps_last);

    let mut group = c.benchmark_group("name/eq");
    group.throughput(Throughput::Elements(1));

    group.bench_function("eq_match", |b| {
        b.iter(|| {
            let result = name_a == name_b;
            debug_assert!(result);
            result
        });
    });

    group.bench_function("eq_miss_first", |b| {
        b.iter(|| {
            let result = name_a == name_miss_first;
            debug_assert!(!result);
            result
        });
    });

    group.bench_function("eq_miss_last", |b| {
        b.iter(|| {
            let result = name_a == name_miss_last;
            debug_assert!(!result);
            result
        });
    });

    group.finish();
}

// ── has_prefix ────────────────────────────────────────────────────────────

fn bench_has_prefix(c: &mut Criterion) {
    let name = build_name(8);
    let mut group = c.benchmark_group("name/has_prefix");
    group.throughput(Throughput::Elements(1));
    for prefix_len in [1usize, 4, 8] {
        let prefix = Name::from_components(name.components()[..prefix_len].to_vec());
        group.bench_with_input(
            BenchmarkId::new("prefix_len", prefix_len),
            &prefix,
            |b, p| {
                b.iter(|| {
                    let result = name.has_prefix(p);
                    debug_assert!(result);
                    result
                });
            },
        );
    }
    group.finish();
}

// ── display ───────────────────────────────────────────────────────────────

fn bench_display(c: &mut Criterion) {
    let mut group = c.benchmark_group("name/display");
    for n in [4usize, 8] {
        let name = build_name(n);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("components", n), &name, |b, nm| {
            b.iter(|| nm.to_string());
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_parse,
    bench_tlv_decode,
    bench_hash,
    bench_eq,
    bench_has_prefix,
    bench_display,
);
criterion_main!(benches);
