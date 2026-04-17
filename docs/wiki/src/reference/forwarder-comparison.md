# NDN Forwarder Comparison

A feature comparison of major open-source NDN forwarder implementations.
Cells reflect what upstream documentation states at the time of writing.

## Legend

| Marker | Meaning |
|---|---|
| ✅ | Supported |
| ➖ | Partial or external project |
| ❌ | Not supported |

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
| **── Transports ──** |
| UDP · TCP · Unix | ✅ | ✅ | ✅ | ✅ |
| Ethernet (AF_PACKET / L2) | ✅ | ✅ | ✅ | ➖ |
| WebSocket | ✅ | ✅ | ❌ | ✅ |
| HTTP/3 WebTransport | ❌ | ✅ | ❌ | ❌ |
| **── Strategies ──** |
| ASF (adaptive SRTT) | ✅ | ✅ | ➖ | ✅ |
| Pluggable strategy extension point | ➖ compile-in | ➖ compile-in | ➖ eBPF | ✅ trait |
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
| **── Security ──** |
| ECDSA / RSA / Ed25519 / HMAC | ✅ | ✅ | ➖ | ✅ |
| SHA-256 digest signatures | ✅ | ✅ | ✅ | ✅ |
| BLAKE3 plain + keyed (sig-types 6/7) | ❌ | ❌ | ❌ | ✅ |
| LightVerSec binary trust schema | ➖ library | ✅ `ndnd/std` | ❌ | ✅ |
| NDNCERT 0.3 client | ➖ ndncert | ✅ `certcli` | ❌ | ✅ |
| **── Deployment model ──** |
| Standalone daemon | ✅ | ✅ | ✅ | ✅ |
| Forwarder embeddable as library | ❌ | ❌ | ❌ | ✅ |
| Shared-memory SPSC face | ❌ | ❌ | ✅ memif | ✅ |
| In-process face | ❌ | ❌ | ❌ | ✅ |
| Built-in network simulator | ➖ ndnSIM | ❌ | ❌ | ✅ `ndn-sim` |
| **── Tooling ──** |
| CLI tools (peek/put/ping/etc.) | ✅ ndn-tools | ✅ | ➖ | ✅ |
| Throughput / latency bench suite | ➖ external | ➖ internal | ✅ | ✅ |

## Notes

- **NDN-DPDK** is a specialised high-throughput forwarder targeting
  DPDK-capable NICs; absence of WebSocket or a standard-library-style app API
  reflects that focus, not a gap. Strategies are implemented as eBPF programs
  loaded via the DPDK BPF library.
- **NDNd** subsumes the earlier YaNFD project: `ndnd/fw` is the continuation
  of YaNFD, shipped alongside `ndnd/dv` (distance-vector routing),
  `ndnd/std` (Go application library with Light VerSec binary schema
  support), and security tooling (`sec`, `certcli`).
- **NFD** is the reference implementation; many features listed as
  "➖ external" (NLSR, ndncert, ndn-tools) are maintained as separate
  projects under the `named-data` organisation and are the canonical
  implementations of those features.
- Rows marked "library" mean the feature exists as an application-level
  library in that project's ecosystem but is not a built-in forwarder
  capability.

## Sources

- NFD: [named-data/NFD](https://github.com/named-data/NFD)
- NDNd (incl. former YaNFD): [named-data/ndnd](https://github.com/named-data/ndnd)
- NDN-DPDK: [usnistgov/ndn-dpdk](https://github.com/usnistgov/ndn-dpdk)
- ndn-fwd: this repository
