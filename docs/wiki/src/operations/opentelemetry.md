# OpenTelemetry — NDN-native span observability

ndn-fwd ships an OpenTelemetry-compatible distributed-tracing system, but the
default transport is **not** OTLP/gRPC. Spans are published into the NDN
substrate under a configurable prefix; consumers fetch them by Interest. The
practical effect is the same — Jaeger, Tempo, Honeycomb, and Datadog can all
ingest these spans via a sidecar bridge — but the wire under the hood is NDN
Data, not gRPC. The rationale lives in
[`docs/notes/ndn-native-observability-2026-05-20.md`][rationale]; this page is
the operator guide.

[rationale]: ../../../notes/ndn-native-observability-2026-05-20.md

## When to enable

- You want flame-graph timing for the engine pipeline (decode → CS → PIT →
  FIB → strategy → outbound) and to search by attribute (`interest.name`,
  `face.id`, `strategy.name`, …) — same things you'd reach for in Jaeger.
- You're debugging a multi-hop interaction and want one trace stitching every
  forwarder the Interest touched (cross-router; requires
  `propagate_to_peers = true` on every participating router).
- You're tuning strategies, sync protocols, or NDNCERT and want per-decision
  spans with the candidate set, RTT estimate, suppression evidence, etc.

You can leave it off and continue to use the stderr/file/ring logs — the
publisher is opt-in and costs nothing when disabled.

## Configuration

Add an `[observability]` block to your forwarder TOML config:

```toml
[observability]
publish_to_ndn = true                              # install the publisher
ndn_prefix = "/localhost/nfd/observability"        # where spans land
retention = "1h"                                   # CS-style eviction window
max_bytes = 8388608                                # 8 MiB; 0 = default
max_spans = 10000                                  # ring count cap; 0 = default
sample = 0.01                                      # head sampling, 0.0..1.0
propagate_to_peers = false                         # LP TraceContext on egress
otlp_bridge_url = ""                               # informational; see "Bridge"
```

All defaults are conservative — adding the section with `publish_to_ndn = true`
samples 1% of spans, holds the past hour in memory, and does **not** attach
trace context to outbound LP frames (peer propagation reveals usage patterns,
so opt in deliberately).

Restart the forwarder for changes to take effect; the publisher is mounted
during `init_tracing` so the subscriber stack picks it up before the engine
opens its first span.

## Fetching spans

Each completed span lands at:

```
<ndn_prefix>/traces/<trace-id-hex>/spans/<span-id-hex>
```

where `<trace-id-hex>` is the 32-character lowercase hex of the W3C 16-byte
trace identifier and `<span-id-hex>` is the 16-character span identifier. The
Data content is an OTLP `Span` protobuf — byte-identical to what the
official OpenTelemetry SDK produces for the fields ndn-rs populates.

To fetch one by hand:

```sh
ndnpeek --payload "/localhost/nfd/observability/traces/<32-hex>/spans/<16-hex>"
```

The bytes you get back can be fed directly into any OTLP-aware decoder
(`grpcurl`, `otel-cli`, the `opentelemetry-proto` Python module, etc.).

## Bridge to Jaeger / Tempo / Honeycomb

For operators who want the spans in standard OTel tooling, run the
`ndn-otel-bridge` sidecar binary. It expresses Interests under your
observability prefix, decodes the OTLP `Span` protobuf, batches into
`ResourceSpans`, and pushes via OTLP/gRPC to whatever backend you've
configured.

```sh
ndn-otel-bridge \
  --ndn-prefix /localhost/nfd/observability \
  --otlp-endpoint http://localhost:4317
```

> **Status:** the bridge binary is deferred from the Phase-3 prompt
> (`.claude/prompts/observability/phase3-otel-and-trace-id.md` §C status). The
> publisher and OTLP protobuf encoding ship today; the bridge is small (~200
> LOC) and lands in a follow-on. Operators with bridge-shaped needs can write
> a one-off Consumer in Python or Go using the on-wire shape documented
> above.

## Cross-router stitching

When two forwarders both have `propagate_to_peers = true`, the upstream router
attaches a 33-byte `TraceContext` LP TLV (type `0x520`, see
[ndn-rs-tlv-allocations-2026-05-20.md][tlv]) to every egress frame. The
downstream router extracts it on ingress and parents its pipeline span under
the upstream span. The result: a single trace that says "router A spent 0.4ms
in CS lookup, router B spent 1.2ms in NDNCERT validation, hop 3 nack'd with
NoRoute" — one screen, full path.

[tlv]: ../../../notes/ndn-rs-tlv-allocations-2026-05-20.md

When the inbound LP frame lacks `TraceContext` (peer is NFD, ndnd, or has
propagation off), the downstream forwarder synthesises one via
`blake3(Nonce ‖ Name ‖ router-id)[..16]` so every Interest still has an
identifier. Retransmits of the same logical Interest stitch on later hops that
also synthesise — without colluding, both ends compute the same trace ID from
the same `(nonce, name, router-id)` triple.

> **Status:** the LP TraceContext codec is in place
> (`crates/spec/ndn-packet/src/lp/trace_context.rs`); the engine-side
> inject/extract via `TraceContextFeature::on_egress` /
> `on_ingress` lands once the typed `OutboundLpFrame.trace_context` slot
> exists. Until then, `propagate_to_peers = true` is accepted by the config
> parser but is a no-op on the wire. The recent-trace enumeration endpoint
> `/localhost/nfd/observability/traces/recent` is similarly part of the same
> follow-on. See the trace-context design note.

## Sampling guidance

- **`sample = 0.0`** — instrumentation runs but nothing publishes. Use during
  ramp-up to validate the layer is wired without paying for the publisher.
- **`sample = 0.01` (default)** — 1% head sampling, matches OTel community
  defaults. Adequate for SLO dashboards and general visibility.
- **`sample = 0.1`** — 10%. Defensible because the NDN substrate has lower
  per-span cost than OTLP/gRPC push.
- **`sample = 1.0`** — every span. Use only for short debugging sessions; the
  publisher's ring will evict heavily.

The substrate-publish overhead bench
(`testbed/tests/audit/obs_phase3_overhead.sh`) gates the claim that
`publish_to_ndn = true` adds <5% p99 latency at `sample = 0.01`. That bench
harness lands with the bridge binary; until then, treat the overhead claim as
an unverified design target.

## `propagate_to_peers` is a privacy choice

A `TraceContext` LP TLV on every egress frame reveals to peers that this
router is observable, attaches an identifier they can correlate across
flows, and (if they also have observability on) builds a graph of which
prefixes traverse which links. Enable only when you trust the peer set —
intra-org links, single-operator deployments, instrumentation testbeds.
Default off.

## Logs ↔ traces correlation

Every `tracing` log line emitted inside a span includes the span's trace_id /
span_id as `tracing` fields. Pipe the stderr / file output through any tool
that knows OTel correlation and you can pivot from a log line to its full
trace.

## Wire format reference

Span Data is named:

```
<prefix>/traces/<trace-id-hex>/spans/<span-id-hex>
```

Data content (Content TLV value) is the
[OTLP `Span` protobuf][otlp-span] (`opentelemetry/proto/trace/v1/trace.proto`),
v1.3.2 wire format. The encoder is hand-rolled in
`crates/spec/ndn-observability/src/otlp.rs` to avoid a `prost` dep chain; the
wire is byte-identical to what the official SDK produces for the fields
ndn-rs populates (trace_id, span_id, parent_span_id, name, kind, start/end
unix-nano, attributes, status).

[otlp-span]: https://opentelemetry.io/docs/specs/otlp/
