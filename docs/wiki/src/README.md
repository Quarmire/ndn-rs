# ndn-rs

ndn-rs is a Named Data Networking (NDN) stack in Rust. It ships a
forwarder (`ndn-fwd`), an embeddable engine (`ndn-engine`), and a
Develop-tier umbrella crate (`ndn-rs-prelude`, library name `ndn`)
that an application reaches for to fetch a `Data` by name or serve
one.

The same workspace runs on Linux, macOS, Windows, mobile, and
`wasm32-unknown-unknown`. The engine builds for the browser via
`WasmEngineBuilder`; the dashboard runs the real engine in-page.

Three API tiers separate audience from intent:

- **[Develop](./api/develop.md)** — application authors. The 5-minute
  path: connect a [`Consumer`](./api/develop.md#consumer), call
  [`fetch_object`](./api/develop.md#fetch_object).
- **[Extend](./api/extend.md)** — protocol, strategy, and face
  authors. Implement
  [`Strategy`](./api/extend.md#strategy),
  [`RoutingProtocol`](./api/extend.md#routingprotocol), or
  [`Face`](./api/extend.md#face) without forking the engine.
- **[Instrument](./api/instrument.md)** — researchers and
  measurement tooling. Feature-gated `experimental-instrument`;
  observe every packet, inject a strategy, wire two engines.

## Start here

- New to NDN? → [NDN overview](./concepts/ndn-overview.md).
- Writing your first app? → [Five-minute app](./quickstart/5-minute-app.md).
- Running a node? → [Running the forwarder](./quickstart/running-the-forwarder.md).
- Building a strategy or face? → [Extend tier](./api/extend.md).

The source lives at
[`github.com/Quarmire/ndn-rs`](https://github.com/Quarmire/ndn-rs).
The crate map and pipeline shape are in
[`ARCHITECTURE.md`](https://github.com/Quarmire/ndn-rs/blob/main/ARCHITECTURE.md).
