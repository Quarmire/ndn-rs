# ndn-research

Research and measurement extensions for NDN testbeds. Tracks per-flow statistics
via a pipeline observer stage and, on Linux, integrates with nl80211 for Wi-Fi
channel management. Designed for multi-radio experimental deployments where
per-prefix flow telemetry and RF channel control are needed alongside normal
forwarding.

## Key types

| Type | Description |
|------|-------------|
| `FlowTable` | Per-name-prefix flow tracking with throughput and latency statistics |
| `FlowObserverStage` | Pipeline stage that records packet observations into a `FlowTable` |
| `ChannelManager` | Linux-only nl80211 Netlink interface for Wi-Fi channel control (frequency, bandwidth, TX power) |

## Platform notes

`ChannelManager` is compiled only on `target_os = "linux"`. `FlowTable` and
`FlowObserverStage` are cross-platform.

## Usage

```toml
[dependencies]
ndn-research = { version = "*" }
```

```rust
use ndn_research::{FlowTable, FlowObserverStage};
use std::sync::Arc;

let table = Arc::new(FlowTable::new());
let observer = FlowObserverStage::new(Arc::clone(&table));

// Insert observer into the engine's pipeline, then query the table:
let stats = table.stats_for("/ndn/video");
println!("throughput: {} pkt/s", stats.pps);
```
