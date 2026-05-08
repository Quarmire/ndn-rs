# WebTransport face — browser client

The `ndn-face-webtransport-wasm` crate produces a `BrowserWebTransportFace`
that an ndn-rs engine running inside a browser tab — or any
`wasm32-unknown-unknown` target — can use to dial out to the server-side
WebTransport listener documented in [webtransport.md](./webtransport.md).

Direction is always outbound. The W3C WebTransport API does not expose an
"accept inbound session" surface in the browser, so this face never
listens. Wire framing matches the server side and NDNts
`@ndn/quic-transport`: one NDN packet per QUIC datagram, NDNLPv2 envelope.

## Build targets

| Target                       | Backend           |
|------------------------------|-------------------|
| `wasm32-unknown-unknown`     | `xwt-web` (`web-sys::WebTransport`) |
| anything else                | `xwt-wtransport` (`quinn` + `wtransport`) |

The native backend is wired in so the crate's loopback unit witness can
drive the same `Face` impl against a Phase 2 listener without spinning up
a real browser.

## From a Rust-to-WASM app

```rust,no_run
use std::sync::Arc;
use ndn_runtime::{Runtime, default_runtime};
use ndn_transport::{Face, FaceId};
use ndn_face_webtransport_wasm::BrowserWebTransportFace;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let runtime = default_runtime();

// `serverCertificateHashes` workflow: pass the SHA-256 digest of the
// server's self-signed DER cert. For production deployments behind a
// real CA, pass an empty slice and the browser uses WebPKI.
let cert_hash: [u8; 32] = [/* sha256(server.der) */ 0; 32];

# #[cfg(target_arch = "wasm32")]
let face = BrowserWebTransportFace::connect(
    FaceId(0),
    "https://router.example.com/ndn",
    &[cert_hash],
    runtime,
).await?;

# #[cfg(target_arch = "wasm32")]
face.send(/* an NDN Interest as Bytes */ bytes::Bytes::new()).await?;
# Ok(()) }
```

The face holds a single pump task that owns the underlying xwt session;
sending and receiving across the `Face` trait both go through `mpsc`
channels so the JS-handle session never has to satisfy `Send + Sync`
itself.

## Why datagrams instead of streams

Same answer as the server side. NDN packets are self-contained TLV
objects, the forwarder retransmits when the strategy decides to, and a
reliable QUIC stream would add head-of-line blocking on the WT layer for
no benefit.

## Witnesses

- Native: `crates/faces/ndn-face-webtransport-wasm/tests/native_xwt_roundtrip.rs`
  — listener + face in-process via xwt-wtransport, audit script
  `testbed/tests/audit/wasm_wt_browser_face.sh`.
- Browser: Playwright spec under `testbed/tests/browser/` (Phase 4
  bundles this into the Dioxus demo end-to-end run).
