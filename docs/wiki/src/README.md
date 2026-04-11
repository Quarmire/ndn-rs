# ndn-rs Wiki

**ndn-rs** is a Named Data Networking (NDN) forwarder stack written in Rust. It models NDN as composable data pipelines with trait-based polymorphism, departing from the class hierarchy approach of NFD/ndn-cxx.

## What is NDN?

Named Data Networking is a network architecture where communication is driven by **named data** rather than host addresses. Consumers request data by name (Interest packets), and the network locates and returns the data (Data packets). Every Data packet is cryptographically signed by its producer, enabling in-network caching and security that travels with the data.

## Why ndn-rs?

- **Library, not daemon** -- `ForwarderEngine` embeds in any Rust application
- **Zero-copy pipeline** -- wire-format `Bytes` flow from recv to send without re-encoding
- **Compile-time safety** -- packet ownership through the pipeline prevents use-after-short-circuit; `SafeData` typestate enforces verification
- **Concurrent data structures** -- `DashMap` PIT, `RwLock`-per-node FIB trie, sharded CS
- **Pluggable everything** -- faces, strategies, CS backends, and pipeline stages via traits
- **Embedded to server** -- `no_std` TLV and packet crates run on Cortex-M; same code scales to multi-core routers

## Navigating This Wiki

| Section | For... |
|---------|--------|
| [Getting Started](./getting-started/installation.md) | Building, running, first program |
| [Concepts](./concepts/ndn-overview.md) | NDN fundamentals and ndn-rs data structures |
| [Design](./design/overview.md) | Architecture decisions and comparisons with NFD/ndnd |
| [Deep Dive](./deep-dive/tlv-encoding.md) | Detailed walkthroughs of subsystems |
| [Guides](./guides/implementing-face.md) | How to extend ndn-rs |
| [Benchmarks](./benchmarks/pipeline-benchmarks.md) | Performance data and methodology |
| [Reference](./reference/spec-compliance.md) | Spec compliance, external links |
| [Explorer](../explorer/) | Interactive crate map and pipeline visualizer |

## Crate Map

```
Binaries        ndn-fwd  ndn-tools  ndn-bench
                     |          |          |
Engine/App      ndn-engine  ndn-app  ndn-ipc  ndn-config  ndn-discovery
                     |          |        |
Pipeline        ndn-engine  ndn-strategy  ndn-security
                     |             |
Faces           ndn-faces  ndn-faces  ndn-faces  ndn-faces
                     |              |
Foundation      ndn-store  ndn-transport  ndn-packet  ndn-tlv
                                                         |
Embedded                                           ndn-embedded

Research        ndn-sim  ndn-compute  ndn-sync  ndn-research  ndn-strategy-wasm
```

Dependencies flow strictly downward. `ndn-tlv` and `ndn-packet` compile `no_std`.

```d3graph
{
  "columns": [
    { "label": "Foundation", "nodes": [
        {"id": "ndn-tlv"}, {"id": "ndn-packet"}, {"id": "ndn-store"},
        {"id": "ndn-transport"}, {"id": "ndn-embedded"}
    ]},
    { "label": "Faces", "nodes": [
        {"id": "ndn-faces"}, {"id": "ndn-faces"},
        {"id": "ndn-faces"}, {"id": "ndn-faces"}
    ]},
    { "label": "Pipeline & Strategy", "nodes": [
        {"id": "ndn-engine"}, {"id": "ndn-strategy"}, {"id": "ndn-security"}
    ]},
    { "label": "Engine & App", "nodes": [
        {"id": "ndn-engine"}, {"id": "ndn-app"}, {"id": "ndn-ipc"},
        {"id": "ndn-config"}, {"id": "ndn-discovery"}
    ]},
    { "label": "Binaries", "nodes": [
        {"id": "ndn-fwd"}, {"id": "ndn-tools"}, {"id": "ndn-bench"}
    ]}
  ],
  "satellites": {
    "label": "Research  (depend on engine / app / strategy)",
    "nodes": [
        {"id": "ndn-sim"}, {"id": "ndn-compute"},
        {"id": "ndn-sync"}, {"id": "ndn-strategy-wasm"}
    ]
  },
  "edges": [
    ["ndn-tlv",       "ndn-packet"],
    ["ndn-tlv",       "ndn-embedded"],
    ["ndn-packet",    "ndn-store"],
    ["ndn-packet",    "ndn-transport"],
    ["ndn-transport", "ndn-faces"],
    ["ndn-transport", "ndn-faces"],
    ["ndn-transport", "ndn-faces"],
    ["ndn-transport", "ndn-faces"],
    ["ndn-faces",    "ndn-engine"],
    ["ndn-faces",  "ndn-engine"],
    ["ndn-faces", "ndn-engine"],
    ["ndn-faces",     "ndn-engine"],
    ["ndn-store",       "ndn-engine"],
    ["ndn-engine",    "ndn-strategy"],
    ["ndn-engine",    "ndn-security"],
    ["ndn-strategy",    "ndn-engine"],
    ["ndn-security",    "ndn-engine"],
    ["ndn-engine",    "ndn-ipc"],
    ["ndn-engine",    "ndn-discovery"],
    ["ndn-engine",      "ndn-fwd"],
    ["ndn-engine",      "ndn-tools"],
    ["ndn-engine",      "ndn-bench"],
    ["ndn-app",         "ndn-ipc"],
    ["ndn-app",         "ndn-tools"],
    ["ndn-app",         "ndn-bench"],
    ["ndn-config",      "ndn-fwd"]
  ],
  "satellite_edges": [
    ["ndn-sim",           "ndn-engine"],
    ["ndn-compute",       "ndn-engine"],
    ["ndn-sync",          "ndn-app"],
    ["ndn-strategy-wasm", "ndn-strategy"]
  ]
}
```
