# Logging

ndn-rs uses the `tracing` crate for structured logging. Binaries
initialise a subscriber; libraries never do. This page covers the
filter syntax, the target taxonomy, and the two observability
options beyond stderr: tokio-console and OpenTelemetry.

## Filter syntax

`tracing-subscriber` reads `EnvFilter` directives. Set via
`RUST_LOG` env var, the `[log]` section in `ndn-fwd.toml`, or
`ndn-ctl log set` at runtime.

```sh
RUST_LOG=info,ndn_engine=debug,ndn_faces::net::udp=trace ndn-fwd
```

| Directive | Effect |
|---|---|
| `info` | All targets at info or above. |
| `ndn_engine=debug` | Engine internals at debug. |
| `ndn_faces=trace` | Every face at trace. |
| `[span_name=value]=debug` | Records with `span_name="value"` at debug. |
| `off` | Silence. |

## Target taxonomy

The Instrument-tier module `ndn_engine::observability::targets`
catalogues the targets the engine and faces use. Stable across v0.1.x.

| Target | What it logs |
|---|---|
| `ndn_engine::pipeline` | Pipeline stage entry/exit, packet dispatch. |
| `ndn_engine::pit` | PIT inserts, satisfies, expiries. |
| `ndn_engine::fib` | FIB inserts and lookups. |
| `ndn_engine::cs` | CS hits, inserts, evictions. |
| `ndn_engine::strategy` | Strategy decisions. |
| `ndn_engine::routing` | Routing protocol events. |
| `ndn_engine::dispatch::outbound` | Outbound packet dispatch. |
| `ndn_faces::*` | Per-face transport events. |
| `ndn_mgmt::*` | Mgmt verb dispatch and replies. |
| `ndn_cert::*` | NDNCERT protocol events. |
| `ndn_discovery::*` | Discovery protocol events. |

The taxonomy is what the dashboard and OpenTelemetry bridge key
off; custom Extend-tier code should use its own crate-rooted target
to stay distinguishable.

## tokio-console

`tokio-console` lets you inspect async task state in real time
(spawn count, busy/idle, polls, wakers).

```sh
RUSTFLAGS="--cfg tokio_unstable" cargo run -p ndn-fwd --features tokio-console
```

In another terminal:

```sh
cargo install tokio-console
tokio-console
```

The forwarder exposes the console listener on `127.0.0.1:6669` by
default. Useful for diagnosing stuck strategies and pipeline
backpressure. See `crates/spec/ndn-engine/Cargo.toml` for the
feature gate.

## OpenTelemetry (NDN-native)

`binaries/tooling/ndn-otel-bridge/` is the OTel bridge. It speaks
NDN to a running forwarder, subscribes to the mgmt notification
streams, and emits OTLP/HTTP-protobuf spans to a collector.

```sh
cargo run -p ndn-otel-bridge -- \
    --forwarder /tmp/ndn-fwd.sock \
    --otlp http://otel-collector:4318
```

The bridge is *NDN-native*: it doesn't read stderr or scrape /metrics.
Project memory `feedback_dioxus_ndn_native` records why.

## TraceContext propagation

NDNLPv2 carries an optional TraceContext field (Phase-3 work). When
present, the strategy stamps it into outbound packets, enabling
cross-router span linkage. The wire inject/extract lives in
`crates/spec/ndn-engine/src/`; downstream forwarders honour and
propagate it.

## Recipes

| You want to… | Filter |
|---|---|
| See every PIT operation | `ndn_engine::pit=trace` |
| Trace one prefix through the pipeline | use a span tag: `info,[forwarding{name=/lab/foo}]=debug` |
| Watch face byte counters | `ndn_engine::dispatch::outbound=debug` |
| Watch strategy decisions | `ndn_engine::strategy=debug` |
| Watch routing updates | `ndn_engine::routing=debug` |
| Watch mgmt verbs in flight | `ndn_mgmt=debug` |

## See also

- `crates/spec/ndn-engine/src/observability/` — target definitions.
- [Performance](./performance.md) — when high log levels hurt
  throughput.
- [ndn-fwd](./ndn-fwd.md) — runtime log filter via mgmt.
