# NDN Forwarder Comparison

A feature comparison of major open-source NDN forwarder implementations,
ordered from features common to all to features found in only one. This page
is reference, not advocacy: cells for other projects reflect what their
upstream documentation states at the time of writing.

## Legend

| Marker | Meaning |
|---|---|
| ✅ | Supported |
| ➖ | Partial, external project, or library-only |
| ❌ | Not supported |

For the **ndn-fwd** column, supported features are further annotated with
release status:

| Marker | Meaning |
|---|---|
| ✅ | Ready for **v0.1.0** — implemented, tested, and in the default build |
| ◐ | **Partial** — feature-gated, incomplete, not integration-tested, or not in default members |
| ○ | **Future** — stub, experimental, or explicitly planned for a later release |

## Table

| Feature | NFD (C++) | NDNd (Go) | NDN-DPDK (C) | ndn-fwd (Rust) |
|---|:---:|:---:|:---:|:---:|
| **── Core NDN protocol ──** |
| TLV Interest / Data (v0.3) | ✅ | ✅ | ✅ | ✅ |
| PIT · CS · FIB | ✅ | ✅ | ✅ | ✅ |
| Nack / NDNLPv2 | ✅ | ✅ | ✅ | ✅ |
| Best-route strategy | ✅ | ✅ | ✅ | ✅ |
| Multicast strategy | ✅ | ✅ | ✅ | ✅ |
| NFD management TLV protocol | ✅ | ✅ | ➖ GraphQL | ✅ |
| **── Common transports ──** |
| UDP · TCP · Unix | ✅ | ✅ | ✅ | ✅ |
| Ethernet (AF_PACKET / L2) | ✅ | ✅ | ✅ | ◐ |
| WebSocket | ✅ | ✅ | ❌ | ✅ |
| WebSocket + TLS listener | ✅ | ✅ | ❌ | ◐ |
| HTTP/3 WebTransport | ❌ | ✅ | ❌ | ❌ |
| **── Strategies ──** |
| ASF (adaptive SRTT) | ✅ | ✅ | ➖ | ✅ |
| Pluggable strategy extension point | ➖ compile-in | ➖ compile-in | ➖ eBPF | ✅ trait |
| Hot-loadable WASM strategies | ❌ | ❌ | ❌ | ◐ |
| **── Content store backends ──** |
| In-memory LRU | ✅ | ✅ | ✅ mempool | ✅ |
| Sharded / parallel CS | ❌ | ❌ | ✅ | ✅ |
| Disk-backed CS | ❌ | ❌ | ❌ | ✅ Fjall |
| **── Routing / sync ──** |
| Static routes | ✅ | ✅ | ✅ | ✅ |
| NLSR (link-state) | ➖ external | ❌ | ➖ external | ➖ external |
| Distance-vector routing | ❌ | ✅ `ndn-dv` | ❌ | ✅ built-in |
| SVS / PSync | ➖ library | ➖ `ndnd/std` | ❌ | ✅ library |
| SWIM neighbour discovery | ❌ | ❌ | ❌ | ✅ |
| **── Performance / hardware ──** |
| Zero-copy packet path | ➖ | ➖ | ✅ DPDK | ✅ `Bytes` |
| Kernel-bypass I/O (DPDK / XDP) | ❌ | ❌ | ✅ | ❌ |
| 100 Gb/s-class throughput | ❌ | ❌ | ✅ | ❌ |
| **── Less common transports ──** |
| Shared-memory SPSC face | ❌ | ❌ | ✅ memif | ✅ `ShmFace` (Unix) |
| Serial / COBS (embedded) | ❌ | ❌ | ❌ | ◐ |
| BLE GATT face | ❌ | ❌ | ❌ | ◐ |
| Wifibroadcast (WFB) face | ❌ | ❌ | ❌ | ○ |
| In-process face | ❌ | ❌ | ❌ | ✅ |
| **── Security ──** |
| ECDSA / RSA / Ed25519 / HMAC | ✅ | ✅ | ➖ | ✅ |
| SHA-256 digest signatures | ✅ | ✅ | ✅ | ✅ |
| BLAKE3 plain + keyed (sig-types 6/7) | ❌ | ❌ | ❌ | ✅ |
| LightVerSec binary trust schema | ➖ library | ✅ `ndnd/std` | ❌ | ✅ |
| NDNCERT 0.3 client | ➖ ndncert | ✅ `certcli` | ❌ | ✅ |
| Compile-time verified-vs-unverified Data type split | ❌ | ❌ | ❌ | ✅ `SafeData` |
| **── Deployment model ──** |
| Standalone daemon | ✅ | ✅ | ✅ | ✅ |
| Forwarder embeddable as library | ❌ | ❌ | ❌ | ✅ |
| Bare-metal `no_std` build | ❌ | ❌ | ❌ | ○ `ndn-embedded` |
| Mobile (Android / iOS) | ➖ NDN-Lite | ❌ | ❌ | ○ `ndn-mobile` |
| WebAssembly / in-browser simulation | ❌ | ❌ | ❌ | ◐ `ndn-wasm` |
| Built-in network simulator | ➖ ndnSIM | ❌ | ❌ | ✅ `ndn-sim` |
| **── Ecosystem / tooling ──** |
| CLI tools (peek/put/ping/etc.) | ✅ ndn-tools | ✅ | ➖ | ✅ |
| Throughput / latency bench suite | ➖ external | ➖ internal | ✅ | ✅ |
| Multi-forwarder compliance testbed | ❌ | ❌ | ❌ | ✅ Docker Compose |
| Desktop GUI management | ❌ | ❌ | ❌ | ◐ Dioxus |
| Python bindings | ➖ separate | ❌ | ❌ | ◐ PyO3 |
| JVM / Swift bindings | ❌ | ❌ | ❌ | ◐ BoltFFI |
| In-network named-function compute | ❌ | ❌ | ❌ | ◐ `ndn-compute` |

## ndn-fwd v0.1.0 status notes

The markers above reflect the state of the `main` branch as the v0.1.0
release is prepared.

**Partial (◐) in v0.1.0:**

- **Ethernet L2**, **WebSocket TLS**, **Serial COBS** — functional but behind
  non-default Cargo features; not exercised by the default CI matrix.
- **BLE GATT face** — implementation present under the `bluetooth` feature
  with a known TODO around macOS TX drain; not yet interop-tested.
- **Hot-loadable WASM strategies** — `ndn-strategy-wasm` exists as a proof of
  concept but is not yet wired into `ndn-engine` as a runtime loader.
- **WebAssembly browser sim** (`ndn-wasm`) — builds for
  `wasm32-unknown-unknown` but not in default workspace members.
- **Dioxus desktop dashboard** — compiles and runs against a live forwarder
  but is not formally release-tested.
- **Python (PyO3) and JVM/Swift (BoltFFI) bindings** — build on a developer
  machine with platform toolchains installed but are not part of default
  members or CI artefacts.
- **`ndn-compute`** — experimental named-function compute runtime; API
  surface is not frozen for v0.1.0.

**Future (○) — post-v0.1.0:**

- **Wifibroadcast (WFB) face** — placeholder crate; `recv` / `send`
  currently return `FaceError::Closed`.
- **`ndn-embedded` bare-metal no_std forwarder** — skeleton exists; MCU
  targets and allocators not yet wired up.
- **`ndn-mobile` Android / iOS forwarder** — requires platform toolchains
  (NDK, Xcode) and is not yet part of any release build.

## Notes on other forwarders

- **NDN-DPDK** is a specialised high-throughput forwarder targeting
  DPDK-capable NICs; absence of WebSocket or a standard-library-style app API
  reflects that focus, not a gap. Strategies are implemented as eBPF programs
  loaded via the DPDK BPF library and executed on the uBPF virtual machine
  (see `container/strategycode/README.md` upstream).
- **NDNd** subsumes the earlier YaNFD project: `ndnd/fw` is the continuation
  of YaNFD, shipped alongside `ndnd/dv` (distance-vector routing),
  `ndnd/std` (Go application library with Light VerSec binary schema
  support), and security tooling (`sec`, `certcli`). Its sample
  `yanfd.config.yml` also exposes an HTTP/3 WebTransport listener.
- **NFD** is the reference implementation; many features listed as
  "➖ external" (NLSR, ndncert, ndn-tools) are maintained as separate
  projects under the `named-data` organisation and are the canonical
  implementations of those features.
- **ndn-fwd** uses the `Face`, `Strategy`, `ContentStore`, `RoutingProtocol`,
  and `DiscoveryProtocol` traits as extension points. The engine itself is a
  library crate (`ndn-engine`); the `ndn-fwd` binary is a thin wrapper around
  it, which enables the embeddable / `no_std` / mobile / WebAssembly build
  targets.
- Rows marked "library" mean the feature exists as an application-level
  library in that project's ecosystem but is not a built-in forwarder
  capability.

## Sources

- NFD: [named-data/NFD](https://github.com/named-data/NFD)
- NDNd (incl. former YaNFD): [named-data/ndnd](https://github.com/named-data/ndnd)
- NDN-DPDK: [usnistgov/ndn-dpdk](https://github.com/usnistgov/ndn-dpdk)
- ndn-fwd: this repository — see [`ARCHITECTURE.md`](https://github.com/Quarmire/ndn-rs/blob/main/ARCHITECTURE.md)
