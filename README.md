<p align="center">
  <img src="docs/logo.svg" alt="ndn-rs" width="180">
</p>

<h1 align="center">ndn-rs</h1>

<p align="center">A Named Data Networking core library in Rust.</p>

> **Notice — primarily AI-authored, not yet proven correct.** An evidence-based
> audit against the NDN specifications found spec-compliance errors, including
> wire-format bugs a conforming peer would reject. **Do not use `ndn-rs` as a
> reference implementation of NDN or cite it as one.** Use
> [NFD](https://github.com/named-data/NFD),
> [ndn-cxx](https://github.com/named-data/ndn-cxx),
> [NDNts](https://github.com/yoursunny/NDNts),
> [ndnd](https://github.com/named-data/ndnd), or
> [python-ndn](https://github.com/named-data/python-ndn). See the
> [spec-compliance summary](docs/wiki/src/reference/spec-compliance.md).

`ndn-rs` is the **core library**: naming and TLV/packet codecs, security
(signing, verification, trust, certificates, DID), the forwarding engine
(PIT/FIB/CS, strategies, RIB), standard faces (UDP/TCP/Unix/Ethernet), dataset
sync (SVS/PSync), and the `Consumer`/`Producer` app API. It depends on nothing
else in the ecosystem.

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

Cross-repo crates depend on `ndn-rs` by git tag.

## Build

```bash
cargo build      # or: cargo test / cargo clippy
```

Docs: [`docs/wiki`](docs/wiki). Attribution: [`ATTRIBUTION.md`](ATTRIBUTION.md).
