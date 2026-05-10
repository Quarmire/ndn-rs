# Browser Demo (Dioxus)

Your first NDN node in the browser.

This walkthrough boots a small Dioxus app that compiles to WebAssembly,
opens a [`BrowserWebTransportFace`] to a local forwarder, and exchanges
real Interest/Data packets — both as a consumer (browser → host) and a
producer (host → browser).

The demo crate lives at `crates/tooling/dioxus-demo/`.

## Three commands

1. **Start the forwarder.**

   ```bash
   docker compose --profile demo -f testbed/docker-compose.yml \
     up dioxus-demo-fwd
   ```

   This boots `ndn-fwd` with a WebTransport listener on `:4433` (self-signed
   loopback cert) and a UDP face on `:6373` for the producer-round-trip
   witness.

2. **Serve the Dioxus app.**

   ```bash
   cd crates/tooling/dioxus-demo
   dx serve --release
   ```

   Open the URL `dx serve` prints (default `http://127.0.0.1:8080/`).

3. **Use it.**

   - The face panel shows `connected` once the WT handshake completes.
   - Type a name in the consumer panel and click **Express Interest**.
     The Data row populates with Name, ContentType, FreshnessPeriod,
     payload size, signature type, and RTT.
   - The producer panel shows the random `/demo/<suffix>` prefix the
     browser registered. Fetch it from the host:

     ```bash
     ndn-tools peek --face-uri udp://127.0.0.1:6373 \
       /demo/<suffix>/counter
     ```

     Each call increments the counter. This is the load-bearing proof
     that the *browser* is producing — not just consuming.

## How it fits together

```
   browser tab (Dioxus, ndn-rs engine + BrowserWebTransportFace)
       │  WebTransport (QUIC datagrams, NDNLPv2)
       ▼
   dioxus-demo-fwd  ──UDP/TCP──▶  ndn-tools peek (host)
```

The face is the same `BrowserWebTransportFace` used by the Phase 3
unit-witness, so the wire framing the browser emits is byte-identical
to what `ndnd`'s HTTP3 transport produces (`SendDatagram` /
`ReceiveDatagram`).

## Witnesses

Two Playwright specs exercise the demo end-to-end:

- `testbed/tests/browser/dioxus_demo_e2e.spec.ts` — consumer side; types
  a name, clicks Express Interest, asserts the Data panel renders.
- `testbed/tests/browser/dioxus_demo_producer.spec.ts` — producer side;
  asserts a host-side `ndn-tools peek` returns a counter that increments
  across two consecutive fetches.

Screenshots land in `testbed/tests/audit/transcripts/`.
