# ndn-strategy

Forwarding strategy framework for the NDN pipeline. Defines the `Strategy` trait and the supporting context types strategies use to make forwarding decisions. Built-in strategies cover the two most common policies; custom strategies can be composed with `StrategyFilter` wrappers.

## Key Types

| Type / Trait | Role |
|---|---|
| `Strategy` | Core trait: given a `StrategyContext`, return a `ForwardingAction` |
| `StrategyContext` | Immutable view of FIB nexthops, measurements, and cross-layer extension slots |
| `BestRouteStrategy` | Forward to the single lowest-cost nexthop |
| `MulticastStrategy` | Forward to all available nexthops simultaneously |
| `StrategyFilter` | Composable pre/post wrapper around any `Strategy` |
| `RssiFilter` | `StrategyFilter` implementation that gates forwarding on link RSSI quality |
| `MeasurementsTable` | Per-face/prefix EWMA RTT and satisfaction-rate tracking (`DashMap`-backed) |
| `MeasurementsEntry` | Single measurements record for a face/prefix pair |
| `FaceLinkQuality` / `LinkQualitySnapshot` | Cross-layer DTOs carrying transport-layer metrics into the strategy |

## Usage

```rust
use ndn_strategy::BestRouteStrategy;
use ndn_engine::EngineBuilder;

let (engine, _shutdown) = EngineBuilder::new(Default::default())
    .default_strategy(BestRouteStrategy::new())
    .build().await?;
```

Part of the [ndn-rs](../../README.md) workspace.
