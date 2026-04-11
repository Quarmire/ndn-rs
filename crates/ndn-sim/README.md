# ndn-sim

In-process NDN network simulation with configurable link properties. Builds
multi-node topologies entirely inside a single Tokio runtime — no processes, no
sockets — making it suitable for unit tests, protocol research, and CI benchmarks.
Unlike Mini-NDN (which wraps real processes via Mininet), simulations here are
deterministic and can run hundreds of nodes in milliseconds.

## Key types

| Type | Description |
|------|-------------|
| `Simulation` | Topology builder: add nodes, connect links, add routes |
| `RunningSimulation` | Handle to a started simulation; access individual engines |
| `NodeId` | Opaque identifier for a simulated node |
| `SimFace` | Channel-backed face with configurable delay, loss, and bandwidth |
| `SimLink` | Connected face pair sharing a set of link properties |
| `LinkConfig` | Delay (ms), loss rate, and bandwidth cap; presets: `lan()`, `wan()` |
| `SimTracer` | Structured event capture for packet-level analysis |
| `SimEvent` / `EventKind` | Individual traced event and its classification |

## Usage

```toml
[dependencies]
ndn-sim = { version = "*" }
```

```rust
use ndn_sim::{Simulation, LinkConfig};
use ndn_engine::builder::EngineConfig;

let mut sim = Simulation::new();
let n1 = sim.add_node(EngineConfig::default());
let n2 = sim.add_node(EngineConfig::default());
sim.link(n1, n2, LinkConfig::lan());
sim.add_route(n1, "/prefix", n2);

let running = sim.start().await?;
// interact with running.engine(n1), running.engine(n2)
running.shutdown().await;
```
