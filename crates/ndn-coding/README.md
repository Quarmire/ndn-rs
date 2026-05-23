# ndn-coding

Network coding for NDN — **extension** crate. Phase F1: end-to-end
systematic K-of-N forward error correction over named Data segments.

A producer publishes K source + (N−K) parity Data segments per generation;
a consumer recovers the payload from any K of the N. Every coded segment
is an independently named, signed Data object, so caches, the PIT, and
signature verification are unchanged — the forwarder is never modified.

- Scope: extension (no adopted wire format; RFC 9273 is the nearest anchor).
- Design: `docs/notes/coding-design-2026-05-22.md`.
- Wire spec: `docs/notes/coding-wire-spec-2026-05-22.md`.
- User docs: `docs/coding.md`, wiki `guides/network-coding.md`.

## Endpoint API (feature `endpoint`, default)

```rust
use ndn_coding::{CodedProducer, CodedFetcher, FecPolicy};

let policy = FecPolicy::systematic(8, 12).unwrap();          // K=8, N=12
// Producer: encode one object as a generation, serve its N segments by name.
CodedProducer::new(producer, policy.clone())
    .serve_object("/alice/clip/v=3".parse()?, payload, 1).await?;
// Consumer: fetch K-of-N, over-fetch parity on loss, recover at rank K.
let payload = CodedFetcher::new()
    .fetch(&consumer, "/alice/clip/v=3".parse()?, &policy).await?;
```

`CodedFetcher` pipelines segment Interests over one connection
(`send_raw`/`recv_data`), correlates replies by the FEC index in each
segment's metadata, and pulls parity when a segment times out — adaptive
K-of-N selection, stopping at decoder rank K.

## Modules

| Module | Purpose |
|---|---|
| `policy` | `CodingPolicyTable` — two role-keyed `NameTrie`s, LPM lookup. |
| `metadata` | `FecMetadata` TLV codec; rides at the head of Data `Content`. |
| `field` | GF(2^8) over poly `0x11d`; peasant `mul_add` autovectorises in release; SIMD path behind `feature = "simd"`. |
| `fec` | Systematic K-of-N `Encoder`/`Decoder` (Vandermonde parity + RREF decoder). |
| `segmenter` | `segment_payload` → K source + (N−K) parity Content bodies. |
| `assembler` | `CodedAssembler` — absorb any K of N, recover payload. |
| `endpoint` | `CodedProducer` / `CodedFetcher` (feature `endpoint`). |
| `mgmt` | `CodingMgmtHandler` backing `/localhost/nfd/coding/{set,unset,list}` (wired in `ndn-mgmt`). |
| `config` | TOML `[[coding.policy]]` parser + `populate(&table)`. |

## What does NOT live here

- **F2 (in-network RLNC recoding).** Pending a trust-model doctrine memo
  for authenticating recoded Data the producer never signed. Gated by the
  `f2-recode` feature; not implemented.
- **F3 (COPE-style inter-flow MAC NC).** Belongs in a face/link driver.
- **NDNLP link-FEC** (per-hop byte-fragment FEC for known-lossy faces).
  A separate future `ndn-transport` feature.

## Features

- `endpoint` (default) — `CodedProducer`/`CodedFetcher`; pulls in `ndn-app`.
- `simd` — AVX2/NEON GF(2^8) path (scalar is the reference).
- `f2-recode` — reserved gate for F2; not implemented.

## Targets

The pure FEC core builds for native and `wasm32-unknown-unknown`:

```
cargo build -p ndn-coding --no-default-features                    # core
cargo build -p ndn-coding --no-default-features --target wasm32-unknown-unknown
```

The `endpoint` layer follows `ndn-app`'s target support (native). The
in-browser engine consumes the core directly; no separate wasm shim.

## Tests

`cargo test -p ndn-coding` runs the unit suite plus the
`tests/end_to_end.rs` integration tests (core round-trip and the
`CodedProducer`/`CodedFetcher` round-trip with parity recovery through an
embedded forwarder). `--features simd` adds the SIMD property test.

Witnesses: `testbed/tests/audit/nc0{1,2,3}_*.sh`.

## Microbench

`cargo test -p ndn-coding --release --features simd bench_mul_add --
--ignored --nocapture`

### M-series ARM (aarch64, NEON)

| Path                  | Throughput   | vs peasant |
|-----------------------|--------------|-----------:|
| peasant               | ~10 GiB/s    |       1.0× |
| per-coefficient table | ~3.5 GiB/s   |       0.4× |
| **NEON `vtbl`**       | **~47 GiB/s**|   **~5×**  |

### x86_64 QEMU host (SSSE3, no AVX2)

| Path                  | Throughput   | vs peasant |
|-----------------------|--------------|-----------:|
| peasant               | ~3.8 GiB/s   |       1.0× |
| per-coefficient table | ~1.6 GiB/s   |       0.4× |
| **SSSE3 shuffle**     | **~12.8 GiB/s**|  **~3.3×** |

The dispatched `mul_add` picks the best path at runtime on x86_64
(`AVX2 > SSSE3 > peasant`), and unconditionally NEON on aarch64. Selection
happens once via `is_x86_feature_detected!` and is memoised in a static
function pointer. LLVM autovectorises the peasant inner loop into SIMD
shifts/XORs, so naive log/antilog tables lose to it on every release build
measured; tables remain the right choice for `inv` and `pow`. AVX2 runtime
numbers are pending real bare metal (the QEMU CPU lacks AVX2).
