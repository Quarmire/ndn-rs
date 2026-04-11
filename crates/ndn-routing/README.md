# ndn-routing

Pluggable routing protocol implementations for the NDN forwarder. Protocols implement the `RoutingProtocol` trait (from `ndn-engine`) and are registered with the engine's `RoutingManager`, which feeds computed routes into the RIB.

## Key Types

| Type / Trait | Role |
|---|---|
| `StaticProtocol` | Installs a fixed set of routes at startup; useful for single-hop topologies and tests |
| `StaticRoute` | A single prefix → face + cost route entry for `StaticProtocol` |
| `DvrProtocol` | Distance Vector Routing — distributed Bellman-Ford over NDN link-local multicast |
| `DvrConfig` | Tuning parameters for DVR (hello interval, hold time, max metric, etc.) |

`DvrProtocol` implements both `RoutingProtocol` (RIB lifecycle) and `DiscoveryProtocol` (packet I/O via the discovery context), so it integrates with `ndn-discovery`'s neighbor table automatically.

## Usage

```rust
use ndn_routing::{StaticProtocol, StaticRoute};
use ndn_engine::EngineBuilder;
use ndn_transport::FaceId;

let (engine, _shutdown) = EngineBuilder::new(Default::default())
    .routing_protocol(StaticProtocol::new(vec![
        StaticRoute { prefix: "/ndn/edu/ucla".parse()?, face_id: FaceId(1), cost: 10 },
    ]))
    .build().await?;
```

Part of the [ndn-rs](../../README.md) workspace.
