# ndn-rs

ndn-rs is a Named Data Networking (NDN) stack in Rust. It ships a
forwarder (`ndn-fwd`), an embeddable engine (`ndn-engine`), and a
Develop-tier umbrella crate (`ndn-rs-prelude`, library name `ndn`)
that an application reaches for to fetch a `Data` by name or serve
one.

The first stable boundary is the spec-aligned core plus the tooling
needed to run and verify it. Browser, embedded, mobile, BLE, WebRTC,
in-network compute, network coding, ABE, and dashboard work live in
extension or research scopes unless their individual pages say
otherwise.

The project is primarily AI-authored and still carries known
spec-compliance findings. Do not cite ndn-rs as a reference
implementation of NDN; use the live audit tracker and
[spec-compliance page](./reference/spec-compliance.md) to decide what
has actually been witnessed.

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
- Checking release readiness? → [v0.1.0 boundary](./releases/v0.1.0.md).

The source lives at
[`github.com/Quarmire/ndn-rs`](https://github.com/Quarmire/ndn-rs).
The crate map and pipeline shape are in
[`ARCHITECTURE.md`](https://github.com/Quarmire/ndn-rs/blob/main/ARCHITECTURE.md).
