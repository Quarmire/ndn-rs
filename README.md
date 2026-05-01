# ndn-rs

> **Notice: primarily AI-authored, not yet proven correct.**
>
> This codebase is primarily authored by an AI coding assistant. A
> recent evidence-based audit against the NDN specifications —
> [`docs/notes/spec-compliance-audit-2026-04-20.md`](docs/notes/spec-compliance-audit-2026-04-20.md)
> — found numerous spec-compliance errors, including BLOCKER-tier
> wire-format bugs that any conforming NDN peer would reject.
> Remediation is in progress in the open; see
> [`testbed/EXPECTED_FAILURES.md`](testbed/EXPECTED_FAILURES.md)
> for current known-bad behaviours and the
> [honest spec-compliance summary](docs/wiki/src/reference/spec-compliance.md)
> for what has been verified against the spec.
>
> **Do not use `ndn-rs` as a reference implementation of NDN or
> cite it as one.** Use [NFD](https://github.com/named-data/NFD),
> [ndn-cxx](https://github.com/named-data/ndn-cxx),
> [NDNts](https://github.com/yoursunny/NDNts),
> [ndnd](https://github.com/named-data/ndnd), or
> [python-ndn](https://github.com/named-data/python-ndn).
> `ndn-rs` is developed as an experimental Rust-native NDN stack
> that aspires to become a trusted implementation via packet-
> captured interop evidence under [`testbed/`](testbed/), not
> unilateral claims.

A [Named Data Networking (NDN)](https://named-data.net/) forwarder stack written in Rust (edition 2024). NDN routes packets by name rather than address: consumers express **Interests**; the network routes them toward producers and returns **Data** along the reverse path, caching at every hop.

ndn-rs takes a Rust-idiomatic approach — composable async pipelines with trait-based polymorphism — and targets both standalone forwarder deployments and embedded use within research applications. The engine is a library, not a daemon.

![ndn-rs logo](docs/logo.svg)

**Status:** experimental · primarily AI-authored · under spec-compliance remediation (see notice above) · **[Releases](https://github.com/Quarmire/ndn-rs/releases)** · **[Wiki](https://quarmire.github.io/ndn-rs/wiki/)** · **[Explorer](https://quarmire.github.io/ndn-rs/explorer/)**

---

## Quick Start

```bash
# Build
cargo build --release

# Run the forwarder (default: UDP + TCP listeners on port 6363)
cargo run --release --bin ndn-fwd

# With a config file
cargo run --release --bin ndn-fwd -- -c ndn-fwd.toml
```

Set `RUST_LOG=info` for status output, `RUST_LOG=ndn_engine=trace` to trace individual pipeline stages.

### Management

```bash
# Add a FIB route
ndn-ctl rib register /ndn/example --face 1 --cost 10

# List faces
ndn-ctl faces list

# Content store info
ndn-ctl cs info

# Identity status
ndn-ctl security identity-status
```

`ndn-ctl` speaks the NFD management protocol (TLV over `/localhost/nfd/`), so any NFD-compatible tool works as well.

### Measure throughput

```bash
ndn-iperf server --prefix /bench
ndn-iperf client --prefix /bench --duration 10
```

---

## Documentation

The wiki covers everything from installation to deep dives into each subsystem:

| | |
|--|--|
| **[Getting Started](https://quarmire.github.io/ndn-rs/wiki/getting-started/installation.html)** | Install, first run, config reference |
| **[Architecture](https://quarmire.github.io/ndn-rs/wiki/design/overview.html)** | Pipeline design, crate layers, key data structures |
| **[Deep Dives](https://quarmire.github.io/ndn-rs/wiki/deep-dive/pipeline-walkthrough.html)** | TLV encoding, forwarding pipeline, security, simulation, WASM |
| **[Guides](https://quarmire.github.io/ndn-rs/wiki/guides/implementing-face.html)** | Implementing a Face, Strategy, embedded targets, CLI tools |
| **[Benchmarks](https://quarmire.github.io/ndn-rs/wiki/benchmarks/pipeline-benchmarks.html)** | Pipeline stage costs, forwarder comparison, methodology |
| **[0.1.0 draft release notes](https://quarmire.github.io/ndn-rs/wiki/releases/v0-1-0.html)** | Scope of the upcoming first tagged release (work in progress) |

The [`ARCHITECTURE.md`](ARCHITECTURE.md) file has a crate map and dependency layer diagram for quick offline reference.

---

## Acknowledgments

This project builds on the [Named Data Networking](https://named-data.net/) architecture developed by the NDN research team led by Lixia Zhang at UCLA, with contributions from NIST, University of Memphis, University of Arizona, and others. The protocol specifications, packet format, and forwarding semantics are defined by the NDN team's technical reports and specifications. This implementation aims for compatibility with [NFD](https://github.com/named-data/NFD) and [ndn-cxx](https://github.com/named-data/ndn-cxx) where applicable.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
