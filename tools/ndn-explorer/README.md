# ndn-explorer

Static web SPA for exploring the ndn-rs crate architecture and interactively
simulating the NDN pipeline in a browser. No build step or server required: open
`index.html` directly. The simulation views are powered by the `ndn-wasm` crate
compiled to WebAssembly.

## Views

| View | Description |
|------|-------------|
| Layers | Visual crate layer map: grouped by subsystem with inter-crate links |
| Graph | Interactive dependency graph with zoom/filter |
| Pipeline | Step through Interest/Data pipeline stages with configurable knobs |
| Packets | TLV packet explorer: encode and decode hex-format NDN packets |
| Topology | Multi-node topology simulation with animated per-hop traces |
| Security | Animated signing/verification flow |
| Tour | Guided walkthrough of NDN concepts and ndn-rs architecture |

## Building the WASM module

The pre-built WASM binary is checked in at `wasm/`. To rebuild:

```sh
bash tools/ndn-explorer/build-wasm.sh
# Requires: wasm-pack, Rust wasm32-unknown-unknown target
```

## Usage

```sh
# Open directly (no server needed):
open tools/ndn-explorer/index.html

# Or serve with any static HTTP server:
python3 -m http.server -d tools/ndn-explorer 8000
```
