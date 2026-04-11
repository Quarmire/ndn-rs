# ndn-discovery

Pluggable neighbor and service discovery for the NDN forwarder. The `DiscoveryProtocol` trait decouples discovery logic from the engine core; protocols observe face lifecycle events and inbound packets, and mutate engine state exclusively through the narrow `DiscoveryContext` interface. Multiple protocols can run simultaneously via `CompositeDiscovery`.

## Key Types

| Type / Trait | Role |
|---|---|
| `DiscoveryProtocol` | Trait all discovery protocols implement |
| `DiscoveryContext` | Engine-side interface protocols use to modify faces, FIB, neighbor table |
| `HelloProtocol` / `HelloCore` | SWIM/Hello family: heartbeat, direct/indirect probes, capability exchange |
| `UdpNeighborDiscovery` | UDP implementation of the Hello protocol family |
| `HelloState` | Per-neighbor SWIM state machine |
| `NeighborTable` / `NeighborEntry` | Shared neighbor liveness table |
| `SvsServiceDiscovery` | SVS-based epidemic sync for service record distribution |
| `ServiceDiscoveryProtocol` | Publishes and browses service records under `/ndn/local/sd/` |
| `CompositeDiscovery` | Runs multiple `DiscoveryProtocol` instances with non-overlapping prefixes |
| `NoDiscovery` | No-op protocol for standalone or statically configured deployments |
| `BackoffConfig` / `BackoffState` | Exponential backoff with jitter for probe scheduling |

## Usage

```rust
use ndn_discovery::{UdpNeighborDiscovery, DiscoveryConfig, CompositeDiscovery};

let hello = UdpNeighborDiscovery::new(DiscoveryConfig::default());
// Register with the engine builder (via ndn-engine)
```

Part of the [ndn-rs](../../README.md) workspace.
