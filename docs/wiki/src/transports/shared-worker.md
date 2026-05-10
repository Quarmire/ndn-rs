# SharedWorker Face

The SharedWorker face is a deployment optimization for browser-tier
ndn-rs: instead of one engine instance per tab, **one engine
instance per origin** is shared across every tab the user has open
of that origin. WebTransport sessions, WebRTC peerings, the
Pending Interest Table, and the Content Store are all amortized
across tabs.

Crate: `ndn-face-shared-worker`. Public API:
[`SharedWorkerProxyFace`] (tab side), [`WorkerListener`] +
[`WorkerPortFace`] + [`init_worker_scope`] (worker side).

## When to use

Pick the SharedWorker face when:

- A user typically has more than one tab of your application open
  at once. Without SharedWorker, every tab pays the WebTransport
  or WebRTC + ICE + DTLS handshake tax independently. With it,
  every tab after the first is connection-free.
- You want tab B to benefit from tab A's recent fetches via the
  shared Content Store.
- You want a `did:ndn` enrollment + signing identity that survives
  tab navigation as long as any tab from the origin remains open.

Skip the SharedWorker face when:

- Your application is genuinely single-tab. The extra layer of
  message-passing buys you nothing.
- You need the engine to outlive *all* tabs being closed. The
  SharedWorker dies when its last connected port closes — see
  Lifecycle below.
- Browser support matters more than the optimization. Safari
  shipped buggy SharedWorker support for years; the first cut of
  the witnesses pin to Chromium for that reason.

## Architecture

```
┌─────────── tab A ─────────────┐    ┌────────── SharedWorker ─────────┐
│ app code                      │    │ engine                          │
│      │                        │    │   │                             │
│ SharedWorkerProxyFace ─── port┼────┤  WorkerPortFace (face #1)       │
│      │ (Face trait)           │    │   │                             │
│      │                        │    │  WorkerPortFace (face #2) ──────┼──── tab B
└───────────────────────────────┘    │   │                             │
                                     │  WebTransportFace (upstream) ───┼──── ndn-fwd
                                     │  WebRtcFace (peer) ─────────────┼──── peer X
                                     └─────────────────────────────────┘
```

The SharedWorker face is a face on **both sides** of the port:

- The tab installs a [`SharedWorkerProxyFace`]; from the tab's POV
  it is the only face it ever sees, and Interests/Data flow through
  it to the engine.
- The worker installs a [`WorkerListener`] on its global scope.
  Every tab that opens a port becomes a [`WorkerPortFace`] from
  the engine's POV — i.e. just one more local face.

The wire format on the port is **raw NDN TLV bytes**, one packet
per `MessagePort.postMessage`, transferred as a `Uint8Array` whose
underlying `ArrayBuffer` is moved (zero-copy) via the transfer
list. There is no RPC envelope; the engine on the worker side
already knows how to parse NDN packets, and a tab that ships a
malformed packet through the port gets the same handling as any
other misbehaving face.

## Lifecycle

A `SharedWorker` lives **as long as any connected port exists**.
When the user closes the last tab from your origin, the worker is
killed and the engine state inside it — face table, PIT, Content
Store, WebRTC peerings, signing identity — is gone.

This is the same lifecycle the W3C spec mandates for SharedWorker;
it is not configurable. Two practical consequences:

- Apps that need persistence across the all-tabs-closed gap must
  ship a separate persistence strategy (e.g. an IndexedDB-backed
  PIB that the engine repopulates on startup).
- Browser-side WebRTC peer reuse only amortizes within a single
  worker lifetime. After the worker is killed, the next tab that
  opens has to re-handshake with every peer.

The CLAUDE-md / cross-stack docs use this caveat to position
phase 6 as "browser is a peer per *origin*" — a real UX cliff
drop versus phase 1–5's "browser is a peer per *tab*" — without
overclaiming persistence.

## Why not Service Workers?

Service Workers are activated by `fetch` events; they are
designed to intercept HTTP requests inside a registered scope,
not to host long-lived application state. A Service Worker can
be terminated by the browser between fetches; relying on one to
hold an NDN engine would mean rehydrating the engine on every
fetch event, which defeats the purpose.

SharedWorker is the right tool: its lifecycle is tied to having
at least one connected port, not to fetch traffic, and its
message-passing API is exactly the per-tab face shape this
crate needs.

## Wiring (sketch)

```rust,ignore
// Tab side — pick a stable URL for your worker bootstrap and a
// fixed `name`. Same-origin tabs that pass the same (url, name)
// land on the same worker instance.
let face = SharedWorkerProxyFace::connect(
    FaceId(1),
    "/ndn-engine.worker.js",
    Some("ndn"),
    runtime.clone(),
)?;

// Worker side — call once from the wasm entrypoint.
let listener = init_worker_scope()?;
loop {
    let face = listener.accept_one(runtime.clone()).await?;
    engine.add_face(Box::new(face));
}
```

The `/ndn-engine.worker.js` bootstrap is a thin
`importScripts(...)` shim that loads the wasm-bindgen output of
your worker-side cdylib; `dx serve` produces the bundle, and the
phase-6 demo wires the `?shared-engine=1` URL switch to swap the
in-tab engine for the proxy face.

## Forward compatibility

The face traits both sides expose are the standard
`ndn_transport::Face` shape — every connected tab is just a face
to whatever runs in the worker. Today the dioxus-demo's worker
runs the hand-rolled mini-engine; phase 7 will swap it for the
real `ForwarderEngine`. The face contract on the port does not
change in that handover, so applications wired against
[`SharedWorkerProxyFace`] today survive phase 7 unchanged.
