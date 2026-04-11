# Routing Protocols

ndn-rs ships two routing algorithms in the `ndn-routing` crate. Both implement the `RoutingProtocol` trait and interact with the engine's RIB through a common handle.

## `StaticProtocol`

Installs a fixed set of routes at startup. Routes are never refreshed or withdrawn (they survive until the protocol is disabled or the engine stops). Useful for:

- Single-hop point-to-point links with known neighbors
- Testing and benchmarking with a fixed topology
- Hybrid deployments where some paths are manually configured

### Configuration

Static routes are declared in TOML under `[[routing.static]]`:

```toml
[[routing.static]]
prefix  = "/ndn/edu/ucla"
face_id = 3
cost    = 10

[[routing.static]]
prefix  = "/ndn/edu/mit"
face_id = 5
cost    = 20
```

### Rust API

```rust
use ndn_routing::{StaticProtocol, StaticRoute};
use ndn_transport::FaceId;

let proto = StaticProtocol::new(vec![
    StaticRoute { prefix: "/ndn/edu/ucla".parse()?, face_id: FaceId(3), cost: 10 },
]);
engine_builder.routing_protocol(proto);
```

## `DvrProtocol` — Distance Vector Routing

Distributed Bellman-Ford over NDN link-local multicast. Each router periodically broadcasts its full routing table as an NDN Interest with AppParams, on the prefix `/ndn/local/dvr/adv`. Neighbors update their tables and re-broadcast.

### Properties

| Property | Value |
|----------|-------|
| Convergence | Bellman-Ford (distributed) |
| Loop prevention | Split horizon |
| Update period | 30 s (configurable at runtime) |
| Route TTL | 90 s (configurable at runtime) |
| Face-down recovery | Immediate route flush |
| Origin value | 127 (`origin::DVR`) |

### Dual registration

DVR acts as both a routing protocol (writes to RIB) and a discovery protocol (sends/receives Interest packets). Both roles must be registered:

```rust
use ndn_routing::DvrProtocol;
use std::sync::Arc;

let dvr = DvrProtocol::new(node_name.clone());
engine_builder
    .discovery(Arc::clone(&dvr) as Arc<dyn DiscoveryProtocol>)
    .routing_protocol(Arc::clone(&dvr));
```

### Runtime configuration

`DvrConfig` fields can be updated live without restarting the router:

```toml
[routing.dvr]
update_interval = "15s"
route_ttl       = "45s"
```

Via management protocol:

```
/localhost/nfd/routing/dvr-status  → read current values
/localhost/nfd/routing/dvr-config  → set (Uri = "update_interval_ms=15000&route_ttl_ms=45000")
```

## `RoutingProtocol` Trait

To add a new routing protocol:

```rust
use ndn_engine::{Rib, RibHandle, RoutingProtocol};
use ndn_transport::FaceId;

pub struct MyProtocol { rib: RibHandle }

impl RoutingProtocol for MyProtocol {
    fn origin(&self) -> u64 { 200 }   // unique value; see origin constants

    fn start(&self, rib: RibHandle) {
        // spawn background task; write routes via rib.insert(...)
    }

    fn stop(&self) {
        // cancel background task; RIB automatically flushes on disable
    }

    fn on_face_down(&self, face_id: FaceId) {
        // optional: withdraw routes via that face immediately
    }
}
```

Register with `EngineBuilder::routing_protocol(my_proto)`.

## See Also

- [Deep Dive: Routing Protocols](../wiki/src/deep-dive/routing-protocols.md) — full architecture, wire format, comparisons
- [Implementing a Routing Protocol](../wiki/src/guides/implementing-routing-protocol.md) — step-by-step developer guide
