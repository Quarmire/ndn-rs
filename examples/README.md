# Examples

Runnable examples demonstrating the ndn-rs strategy system.

## Strategy Examples

| Example | Description | Run |
|---------|-------------|-----|
| [strategy-custom](strategy-custom/) | Write a custom forwarding strategy from scratch | `cargo run -p example-strategy-custom` |
| [strategy-composed](strategy-composed/) | Compose strategies with cross-layer filters | `cargo run -p example-strategy-composed` |
| [cross-layer-enricher](cross-layer-enricher/) | Feed external data (GPS, radio) into strategies | `cargo run -p example-cross-layer-enricher` |
| [wasm-strategy](wasm-strategy/) | Hot-load a WASM strategy module | `cargo run -p example-wasm-strategy` |

## Reading Order

If you're new to ndn-rs strategy development:

1. **strategy-custom** — Start here. Shows the `Strategy` trait, sync fast path, and engine registration.
2. **cross-layer-enricher** — How to feed external data into the strategy layer via `ContextEnricher`.
3. **strategy-composed** — Combine strategies with reusable filters (no base strategy modification).
4. **wasm-strategy** — Hot-load strategies from WASM modules for rapid prototyping.

## Choosing an Approach

| Need | Approach |
|------|----------|
| New forwarding algorithm | Implement `Strategy` trait in Rust |
| Filter/reorder existing decisions | `ComposedStrategy` + `StrategyFilter` |
| Rapid prototyping without recompiling | `WasmStrategy` (WASM module) |
| Routing protocol / topology discovery | External app via AppFace/ShmFace |

See [docs/strategy.md](../docs/strategy.md) for the full architecture guide.
