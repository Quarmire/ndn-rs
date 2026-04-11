# ndn-strategy-wasm

Hot-loadable NDN forwarding strategies compiled to WebAssembly and executed via
`wasmtime`. Each `WasmStrategy` loads a `.wasm` binary at runtime, exposes a host
ABI for FIB lookups and measurements queries, and runs the guest `select_nexthops`
entry point inside a fuel-limited sandbox. New strategies can be deployed without
recompiling or restarting the forwarder.

## Key types

| Type | Description |
|------|-------------|
| `WasmStrategy` | Implements `ndn_strategy::Strategy`; loads a `.wasm` binary and calls the guest ABI |

## Usage

```toml
[dependencies]
ndn-strategy-wasm = { version = "*" }
```

```rust
use ndn_strategy_wasm::WasmStrategy;

// Load a strategy module compiled to WASM
let strategy = WasmStrategy::from_file("strategies/my_strategy.wasm").await?;

// Register with the engine's strategy trie
engine.set_strategy("/ndn/video", Arc::new(strategy));
```

## Writing a strategy module

Implement the `ndn_strategy_abi` guest interface (defined in `src/host.rs`).
The module must export `select_nexthops(interest_ptr, interest_len) -> u64`
and may call host functions for FIB and measurements access. Compile with:

```sh
cargo build --target wasm32-unknown-unknown --release -p my-strategy
```
