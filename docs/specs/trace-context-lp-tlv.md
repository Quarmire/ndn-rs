# TraceContext LP TLV

> **Status:** ndn-rs-proprietary, experimental TLV range.
> **TLV-TYPE:** `0x520` (NDNLPv2 experimental).
> **Reference impl:** [`crates/ndn-packet/src/lp/trace_context.rs`](../../crates/ndn-packet/src/lp/trace_context.rs).

A per-hop LP header that carries
[W3C trace-context](https://w3c.github.io/trace-context-binary/) plus
a single-hop timestamp, so a forwarder chain can produce coherent
distributed traces without an out-of-band telemetry path.

This spec defines the wire format. Sampling policy, SDK integration,
and bridge behaviour are out of scope; the reference
[OpenTelemetry bridge](../../binaries/tooling/ndn-otel-bridge) consumes
the codec defined here.

## Wire shape

```text
TraceContext = TYPE(0x520) LENGTH(33) VALUE(
    trace_id    [16 bytes, big-endian]
    span_id     [ 8 bytes, big-endian]
    trace_flags [ 1 byte; bit 0 = sampled, bits 1..7 reserved = 0]
    timestamp   [ 8 bytes, big-endian micros since router epoch]
)
```

- **TYPE `0x520`** sits in the NDNLPv2 experimental range
  (≥ `0x500`). The 3-byte varint form (`0xFD 0x05 0x20`) is the only
  legal encoding.
- **LENGTH `33`** fits in the 1-byte varint form.
- **VALUE** is fixed-length 33 bytes. Receivers MUST reject any other
  length as malformed (`TraceContextError::BadLength`).

## Field semantics

| Field | Width | Semantics |
|---|---|---|
| `trace_id` | 16 B | W3C trace ID. Equal-byte semantics; the codec does not interpret the value. |
| `span_id` | 8 B | W3C span ID. Identifies the **current hop's** span; a router that re-emits TraceContext MUST replace this with its own span ID. |
| `trace_flags.sampled` (bit 0) | 1 bit | `1` if the producer of this TraceContext recorded the span. Receivers MAY use this as a hint to record their own span. |
| `trace_flags` (bits 1..7) | 7 bits | Reserved. MUST be `0`. Receivers MUST NOT reject a frame for non-zero reserved bits — forward compatibility. |
| `timestamp` | 8 B | Microseconds since the **originating router's local epoch**. Cross-router absolute time is meaningless; receivers compute single-hop latency by differencing against their own clock. |

## Critical-bit rule

LP TLV-TYPE `0x520` is even and therefore **non-critical** per the
NDNLPv2 critical-bit rule (odd types are critical, even types are
non-critical). Forwarders that do not implement this header MUST
ignore it and forward the packet normally. This guarantees that
adding TraceContext to a packet flow is a unilateral upgrade — no
cooperation from non-tracing peers is required.

## Nonce-derived fallback

When an inbound LP frame arrives without a `TraceContext` TLV, a
receiver MAY synthesise one locally:

```text
fallback_trace_id = BLAKE3(nonce ‖ name_wire ‖ router_id)[..16]
```

- Stable per `(nonce, name, router_id)` triple, so retransmits of the
  same logical Interest stitch on later hops that also use the
  fallback.
- The synthesised context is **internal-only**: when a router
  re-emits TraceContext downstream, it MUST construct a fresh value
  with its own span ID — the fallback never crosses a hop unchanged.

The fallback is optional. Receivers MAY drop frames without
TraceContext from their tracing pipeline; the choice is operator
policy, not part of the wire spec.

## Splice / extract

`TraceContext` rides in the LP frame's optional headers (alongside
`PitToken`, `CongestionMark`, etc.). The reference codec exposes:

- `TraceContext::encode_tlv() -> Bytes` — produce the full TLV.
- `TraceContext::decode_value(&[u8]) -> Result<_, _>` — decode the
  33-byte value without the outer TYPE/LENGTH.
- Splice / extract helpers on already-LP-wrapped wires for
  in-pipeline manipulation.

Forwarders SHOULD splice their own TraceContext on egress without
re-encoding the whole LP frame; the codec keeps the inject/extract
operations zero-copy.

## Interaction with sampling

Sampling decisions happen at three points:

1. **Head sampler** — first hop that mints a TraceContext sets
   `trace_flags.sampled` per its sampling policy.
2. **Mid sampler** — intermediate router MAY override the bit (e.g.
   to drop a long-running trace) when re-emitting; the change MUST
   apply consistently for the lifetime of the trace.
3. **Tail consumer** — the OpenTelemetry bridge (or equivalent) reads
   the bit when deciding whether to export the span.

The wire format does not embed sampler identity; samplers are
out-of-band per the W3C model.

## Implementation status

- **Codec:** complete (`crates/ndn-packet/src/lp/trace_context.rs`).
- **Engine inject/extract:** see `crates/ndn-engine/src/` —
  the strategy stage stamps it on outbound packets when configured.
- **SDK / bridge:** [`binaries/tooling/ndn-otel-bridge`](../../binaries/tooling/ndn-otel-bridge)
  consumes the codec and exports spans through the OpenTelemetry
  collector protocol.

## Backwards compatibility

The codec is versioned implicitly by VALUE length. A future revision
adding fields MUST allocate a new TLV-TYPE or carry the extension in
a sibling LP header — the 33-byte VALUE is fixed.
