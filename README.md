<p align="center">
  <img src="docs/logo.svg" alt="ndn-rs" width="180">
</p>

<h1 align="center">ndn-rs</h1>

<p align="center">A Named Data Networking core library in Rust.</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-1800%2B%20%2F%20~25s-brightgreen" alt="tests">
  <img src="https://img.shields.io/badge/wire-property--tested%20%2B%20fuzzed-blue" alt="fuzzed">
  <img src="https://img.shields.io/badge/unsafe-denied%20outside%20OS%20I%2FO-blue" alt="unsafe policy">
  <img src="https://img.shields.io/badge/MSRV-1.90-blue" alt="msrv">
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="license">
</p>

> **Status — AI-authored; verify before you rely on it.** ndn-rs targets the
> real NDN Packet Format v0.3 and NDNLPv2, and the wire layer is now
> property-tested and fuzzed (fuzzing found and fixed a real `Name` URI
> round-trip bug — see [ADR 0005](docs/wiki/src/inside/adr/0005-retire-audit-witness-suite.md)
> and the [conformance matrix](docs/wiki/src/inside/conformance-matrix.md)).
> It is still a young, primarily AI-authored stack: treat it as a capable
> implementation to build on and audit, **not** as a reference implementation
> of NDN. For a reference, use
> [NFD](https://github.com/named-data/NFD),
> [ndn-cxx](https://github.com/named-data/ndn-cxx),
> [NDNts](https://github.com/yoursunny/NDNts),
> [ndnd](https://github.com/named-data/ndnd), or
> [python-ndn](https://github.com/named-data/python-ndn). Known gaps are tracked
> in the [spec-compliance summary](docs/wiki/src/reference/spec-compliance.md).

`ndn-rs` is the **core library**: naming and TLV/packet codecs, data-centric
security (signing, verification, trust schemas, certificates, DID), the
forwarding engine (PIT/FIB/CS, strategies, RIB), standard faces
(UDP/TCP/Unix/Ethernet), dataset sync (SVS/PSync), and the `Consumer`/`Producer`
app API. It depends on nothing else in the ecosystem, and the same code targets
native, `wasm32`, and bare-metal `riscv32` `no_std`.

## Documentation

- **[Using ndn-rs](docs/wiki)** — the wiki's Part I: quickstarts, concepts, and
  guides for writing apps, running the forwarder, and choosing transports.
- **[Inside ndn-rs](docs/wiki/src/inside/README.md)** — the wiki's Part II:
  the contributor book. Architecture tour (with an animated
  [forwarding-pipeline](docs/wiki/src/inside/architecture/forwarding-pipeline.md)
  walkthrough and an interactive [crate graph](docs/wiki/src/inside/architecture/crate-graph.md)),
  cookbooks (add a face / strategy / mgmt module / sync dialect / storage
  backend), the [testing guide](docs/wiki/src/inside/testing.md), the
  [spec conformance matrix](docs/wiki/src/inside/conformance-matrix.md), the
  [cross-repo contract](docs/wiki/src/inside/cross-repo-contract.md), and
  [decision records](docs/wiki/src/inside/adr/README.md).
- **API docs** — `cargo doc --workspace --no-deps --open`.

## The ecosystem

| Repo | What |
|---|---|
| **ndn-rs** | core library (this repo) |
| [ndn-ext](https://github.com/Quarmire/ndn-ext) | extensions: non-standard faces, routing, discovery, strategies, compute, pipes, bindings (wasm/python/FFI) |
| [ndn-fwd](https://github.com/Quarmire/ndn-fwd) | the forwarder binary + CLIs |
| [ndn-dashboard](https://github.com/Quarmire/ndn-dashboard) | operator dashboard (Dioxus) |
| [ndn-mobile](https://github.com/Quarmire/ndn-mobile) | mobile node + FFI for the Android apps |
| [ndn-embedded](https://github.com/Quarmire/ndn-embedded) | `no_std` embedded forwarder |
| [ndn-repo](https://github.com/Quarmire/ndn-repo) | persistent named-data repository daemon |
| [ndn-sim](https://github.com/Quarmire/ndn-sim) | simulator |
| [ndn-anchor](https://github.com/Quarmire/ndn-anchor) | Anchor app (Android/iOS) — presence over NAN + BLE |
| [ndn-ripple](https://github.com/Quarmire/ndn-ripple) | Ripple app (Android) — nearby peers |

The sibling repos depend on `ndn-rs`; the exact API surface they rely on is the
[cross-repo contract](docs/wiki/src/inside/cross-repo-contract.md), which CI
guards with `cargo-semver-checks`.

## Build & test

```bash
cargo build --workspace
cargo nextest run --workspace     # ~1800 tests, ~25s (falls back to cargo test)
cargo clippy --workspace --all-targets
cargo doc --workspace --no-deps
```

The toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml); the
lint policy (including `deny(unsafe_code)` outside the OS-I/O face crates) lives
in [`Cargo.toml`](Cargo.toml) `[workspace.lints]`. See the
[contribution workflow](docs/wiki/src/inside/contributing.md) before opening a
PR. Attribution: [`ATTRIBUTION.md`](ATTRIBUTION.md).
