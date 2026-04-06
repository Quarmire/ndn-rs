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
Binaries        ndn-router  ndn-tools  ndn-bench
                     |          |          |
Engine/App      ndn-engine  ndn-app  ndn-ipc  ndn-config  ndn-discovery
                     |          |        |
Pipeline        ndn-pipeline  ndn-strategy  ndn-security
                     |             |
Faces           ndn-face-net  ndn-face-local  ndn-face-serial  ndn-face-l2
                     |              |
Foundation      ndn-store  ndn-transport  ndn-packet  ndn-tlv
                                                         |
Embedded                                           ndn-embedded

Research        ndn-sim  ndn-compute  ndn-sync  ndn-research  ndn-strategy-wasm
```

Dependencies flow strictly downward. `ndn-tlv` and `ndn-packet` compile `no_std`.

```mermaid
flowchart TD
    subgraph Binaries
        router["ndn-router"]
        tools["ndn-tools"]
        bench["ndn-bench"]
    end

    subgraph "Engine & App"
        engine["ndn-engine"]
        app["ndn-app"]
        ipc["ndn-ipc"]
        config["ndn-config"]
        discovery["ndn-discovery"]
    end

    subgraph "Pipeline & Strategy"
        pipeline["ndn-pipeline"]
        strategy["ndn-strategy"]
        security["ndn-security"]
    end

    subgraph Faces
        face_net["ndn-face-net"]
        face_local["ndn-face-local"]
        face_serial["ndn-face-serial"]
        face_l2["ndn-face-l2"]
    end

    subgraph Foundation
        store["ndn-store"]
        transport["ndn-transport"]
        packet["ndn-packet"]
        tlv["ndn-tlv"]
    end

    subgraph Embedded
        embedded["ndn-embedded"]
    end

    subgraph Research
        sim["ndn-sim"]
        compute["ndn-compute"]
        sync_crate["ndn-sync"]
        research["ndn-research"]
        strat_wasm["ndn-strategy-wasm"]
    end

    router --> engine
    tools --> engine
    bench --> engine
    router --> config
    tools --> app
    bench --> app

    engine --> pipeline
    engine --> strategy
    app --> ipc
    ipc --> pipeline
    discovery --> pipeline

    pipeline --> face_net
    pipeline --> face_local
    pipeline --> face_serial
    pipeline --> face_l2
    strategy --> pipeline
    security --> pipeline

    face_net --> transport
    face_local --> transport
    face_serial --> transport
    face_l2 --> transport

    store --> packet
    transport --> packet
    pipeline --> store
    packet --> tlv
    tlv --> embedded

    sim --> engine
    compute --> engine
    sync_crate --> app
    research --> engine
    strat_wasm --> strategy
```
