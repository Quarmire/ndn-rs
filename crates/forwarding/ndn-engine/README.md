# ndn-engine

`ForwarderEngine` wires together all NDN components — pipeline stages, face table, FIB, PIT, CS, strategy table, and routing — into a running forwarder. Built via `EngineBuilder` with a fluent API. Cooperative shutdown is provided by `ShutdownHandle`; per-face counters are exposed through `FaceCounters`.

## Key Types

| Type / Trait | Role |
|---|---|
| `ForwarderEngine` | Running forwarder; owns FIB, PIT, CS, face table, and all Tokio tasks |
| `EngineBuilder` | Fluent builder: add faces, strategies, routing protocols, and CS backend |
| `EngineConfig` | Runtime parameters (CS capacity, pipeline depth, etc.) |
| `Rib` / `RibRoute` | Routing Information Base — receives routes from routing protocols |
| `RoutingManager` | Runs multiple `RoutingProtocol` instances and feeds routes into the RIB |
| `Fib` / `FibEntry` | Forwarding Information Base — name-trie with concurrent longest-prefix match |
| `ComposedStrategy` | Wraps a `Strategy` with a `ContextEnricher` for cross-layer data injection |
| `ShutdownHandle` | Signals cooperative shutdown of all engine tasks |

## Feature Flags

| Flag | Default | Description |
|---|---|---|
| `face-net` | yes | Enables `ndn-face-net` for UDP/TCP/Ethernet face support |

## Usage

```rust
use ndn_engine::{EngineBuilder, EngineConfig};

let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
    .face(udp_face)
    .build()
    .await?;

engine.run().await;
```

Part of the [ndn-rs](../../README.md) workspace.
