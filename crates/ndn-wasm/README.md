# ndn-wasm

WebAssembly bindings for in-browser NDN simulation, used by the `ndn-explorer`
static web SPA. Compiled as a `cdylib` / `rlib` targeting `wasm32-unknown-unknown`,
it exposes single-node pipeline simulation, multi-node topology simulation, and
stateless TLV encode/decode to JavaScript via `wasm-bindgen`.

## Key types

| Type / Function | Description |
|-----------------|-------------|
| `WasmPipeline` | Single-node pipeline with configurable FIB, PIT, CS, and strategy |
| `WasmTopology` | Multi-node topology; add routers/consumers/producers, link them, send Interests |
| `load_topology_scenario()` | Load a named pre-built scenario (`linear`, `triangle-cache`, `multipath`, `aggregation`) |
| `tlv_encode_interest()` | Encode an Interest as a hex byte string |
| `tlv_encode_data()` | Encode a Data packet as a hex byte string |
| `tlv_parse_hex()` | Parse hex bytes into a JSON TLV tree |
| `tlv_type_name()` | Human-readable name for a TLV type code |

## Building

```sh
# From the repo root:
wasm-pack build crates/ndn-wasm --target web --out-dir ../../tools/ndn-explorer/wasm
# Or use the helper script:
bash tools/ndn-explorer/build-wasm.sh
```

## Usage

This crate is consumed directly by `tools/ndn-explorer`. The JS API mirrors the
Rust types above; see `tools/ndn-explorer/js/` for usage examples.

```toml
# As a Rust dependency (host-side tests only):
ndn-wasm = { path = "crates/ndn-wasm" }
```
