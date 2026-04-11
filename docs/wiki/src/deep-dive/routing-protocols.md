# Routing Protocols

ndn-rs separates the **Routing Information Base (RIB)** from the **Forwarding Information Base (FIB)**. Routing protocols compute paths and write them into the RIB; the engine's FIB is derived automatically.

## Architecture

```
  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │  Static      │   │  DVR         │   │  (future)    │
  │  Protocol    │   │  Protocol    │   │  NLSR / …    │
  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
         │ origin=255        │ origin=127        │ origin=128
         └──────────────────┴──────────────────►│
                                                 ▼
                                          ┌──────────────┐
                                          │     RIB      │  per-prefix,
                                          │  (ndn-engine)│  per-face, best-cost
                                          └──────┬───────┘
                                                 │ apply_to_fib()
                                                 ▼
                                          ┌──────────────┐
                                          │     FIB      │  longest-prefix match
                                          └──────────────┘
```

Multiple protocols run concurrently. Each owns routes under a unique **origin** value. The RIB arbitrates: for each prefix, per face_id, it picks the route with the lowest cost (ties broken by lowest origin value) and writes the result to the FIB atomically.

## Route Origins

| Origin | Constant | Protocol |
|--------|----------|----------|
| 0 | `origin::APP` | App-registered via management API |
| 64 | `origin::AUTOREG` | Auto-registration |
| 65 | `origin::CLIENT` | Client auto-registration |
| 66 | `origin::AUTOCONF` | Auto-configuration |
| 127 | `origin::DVR` | Distance Vector Routing (ndn-routing) |
| 128 | `origin::NLSR` | NLSR-compatible routing |
| 129 | `origin::PREFIX_ANN` | Prefix announcements |
| 255 | `origin::STATIC` | Static routes |

## Built-in Protocols (`ndn-routing`)

### `StaticProtocol`

Installs a fixed set of routes at startup and holds them until stopped. Suitable for single-hop links, testing, and hybrid deployments.

```rust
use ndn_routing::{StaticProtocol, StaticRoute};
use ndn_transport::FaceId;

let proto = StaticProtocol::new(vec![
    StaticRoute {
        prefix: "/ndn/edu/ucla".parse()?,
        face_id: FaceId(3),
        cost: 10,
    },
]);
// register with EngineBuilder::routing_protocol(proto)
```

Routes use `origin::STATIC` (255) and `CHILD_INHERIT` flags, so `/ndn/edu/ucla/cs` is also reachable without explicit registration.

### `DvrProtocol`

Distributed Bellman-Ford over NDN link-local multicast. Routes are learned from neighbors and expire if not refreshed (default TTL: 90 s). Features:

- **Split horizon**: routes learned via face F are not re-advertised on face F, preventing two-node loops.
- **Periodic updates** every 30 s.
- **Face-down cleanup**: all routes learned via a downed face are withdrawn immediately.

DVR needs both packet I/O (via discovery context) and RIB write access (via routing handle). It implements **both `DiscoveryProtocol` and `RoutingProtocol`** — register it with both systems:

```rust
use ndn_routing::DvrProtocol;
use ndn_discovery::DiscoveryProtocol;
use std::sync::Arc;

let dvr = DvrProtocol::new(my_node_name.clone());

let engine = EngineBuilder::new()
    .discovery(Arc::clone(&dvr) as Arc<dyn DiscoveryProtocol>)
    .routing_protocol(Arc::clone(&dvr))
    .build()
    .await?;
```

#### DVR Wire Format

Advertisements are sent as NDN Interest packets with AppParams:

```
Interest name:  /ndn/local/dvr/adv
AppParams TLV:
  DVR-UPDATE  (0xD0)
    NODE-NAME (0xD1)  — sender's NDN node name
    ROUTE*    (0xD2)  — zero or more routes
      PREFIX  (0xD3)  — Name TLV
      DVR-COST(0xD4)  — big-endian u32
```

Packets with this name are consumed by `on_inbound` and never reach the forwarding pipeline.

#### Compatibility with ndnd DVR

The ndn-rs DVR is **not interoperable** with ndnd's `dv` module. ndnd uses a fundamentally different architecture:

| | ndn-rs DVR | ndnd DV |
|---|---|---|
| Sync mechanism | Periodic broadcast Interest | SVS v3 state-vector sync |
| Name prefix | `/ndn/local/dvr/adv` | `/localhop/<network>/32=DV/32=ADS/ACT` |
| Advertisement unit | (prefix, cost) | (router, nexthop, cost) |
| Route table | prefix → cost | router → cost, then prefix → router |
| Cost infinity | `u32::MAX` | 16 |
| ECMP | No | Two-best-path |
| Loop prevention | Split horizon | Poison reverse + split horizon |
| Security | None | LightVerSec (Ed25519) |

For testbed interoperability, a future NLSR-compatible protocol (origin 128) is required. The ndn-rs DVR is designed for private, trust-homogeneous networks only.

## `RoutingManager`

The engine owns a `RoutingManager` that controls all running protocols:

```rust
// Start a protocol
engine.routing().enable(Arc::new(my_protocol));

// Stop and flush its routes
engine.routing().disable(origin_value);

// Inspect running protocols
let origins: Vec<u64> = engine.routing().running_origins();
```

Disabling a protocol cancels its background task and synchronously flushes all its RIB routes, recomputing the FIB for affected prefixes. Any routes registered by other protocols for the same prefixes are immediately promoted.

## RIB Details

The RIB stores `RibRoute { face_id, origin, cost, flags, expires_at }` per `(prefix, face_id, origin)` triple. Key invariants:

- **Expiry**: routes with `expires_at` are drained every second by a background task.
- **Face teardown**: `rib.handle_face_down(face_id, fib)` is called automatically when a face goes down, flushing routes via that face and recomputing affected FIB entries.
- **FIB derivation**: for each unique `face_id`, the lowest-cost route across all origins wins. Equal-cost ties break by lowest origin value.

## See Also

- [Implementing a Routing Protocol](../guides/implementing-routing-protocol.md) — developer guide
- [Implementing a Discovery Protocol](../guides/implementing-discovery.md) — for protocols that need packet I/O
- [PIT, FIB, and Content Store](../concepts/pit-fib-cs.md) — forwarding tables overview
