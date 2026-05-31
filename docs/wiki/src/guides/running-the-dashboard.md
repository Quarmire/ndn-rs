# Running the dashboard

`ndn-dashboard` is a Dioxus web application that talks to a running
forwarder over the TLV management protocol. It speaks no HTTP and
no IP — it speaks NDN to a face it opens against the forwarder.

The dashboard runs in three modes:

| Mode | Engine location | Use |
|---|---|---|
| Local | Embedded in the page (`?engine=local`) | Demo, offline, browser-only research. |
| Remote forwarder | An external `ndn-fwd` | Production operator UI. |
| Multi-forwarder | Switch between forwarders at runtime | Comparing live deployments. |

## Run with an external forwarder

In one terminal:

```sh
cargo run -p ndn-fwd
```

In another:

```sh
cargo run -p ndn-dashboard
```

Open `http://localhost:8080/`. The dashboard opens a face against
the forwarder at `/tmp/ndn-fwd.sock` and starts streaming live
state.

You can point at a different forwarder via the URL:

```text
http://localhost:8080/?forwarder=ws://my-host:9696
```

The selector accepts Unix sockets (when running natively),
WebSocket URLs (for browser-to-forwarder), and WebTransport URLs.

## Run with the in-page engine

Compile the dashboard with the `browser-engine` feature:

```sh
cargo run -p ndn-dashboard --features browser-engine
```

Then visit `http://localhost:8080/?engine=local`. The dashboard
instantiates a `WasmEngineBuilder`-built engine in the page; the
PIT/FIB/CS visible in the dashboard is the engine inside the tab.

Useful for offline demos and for understanding the forwarder's
behaviour without setting one up.

## How it's organized

The sidebar groups every panel under three top-level buckets, separating
the appliance from your identity from what you publish:

- **Engine** — the forwarder you operate: Overview, Strategy, Coding,
  Rate Limit, Routing, Radio, Logs, Fleet, Tools.
- **Identity** — who you are: a **Trust Context** summary (the roots this node
  trusts, its CA, your identities with cert-expiry up front, and where your
  signing key lives on this machine), the detailed Security tabs behind it, and
  Session.
- **Compose** — what you publish: the prefixes a local producer or client
  has registered on the attached engine.

Each bucket collapses independently and shows a live count on its header —
faces for Engine, distinct identities for Identity, published prefixes for
Compose. For a single forwarder with one identity the grouping stays out of
the way; it earns its keep once you attach more than one engine or hold more
than one trust context.

The bar across the top is the **Attach bar**, and it has two independent
axes: the **Engine** you operate (which forwarder, on which socket) and the
identity you're **Acting as**. They're separate on purpose — you can browse
one engine while signing as a given identity, and switch either without
disturbing the other. With one engine and one identity the bar reads as a
single line; the second axis appears only when there's a choice to make.

Selecting a row opens a **detail inspector** on the right. A face shows its
full detail — every counter, URI, scope, link type, MTU, link-service flag
status (local fields, LP reliability, congestion marking), a throughput
sparkline, and the routes that forward through it; a route shows its strategy,
FIB nexthops, and RIB origins/flags/expiration. The inspector is also where you
*act*: change a route's strategy, add or remove a specific nexthop, or click a
nexthop face to jump straight to that face's detail (and back to a route from
the face's "Routes via this face" list). None of that needs to widen the
table. The inspector closes with its ✕, and on narrow screens it becomes a
bottom sheet so the list above it stays visible.

## What the dashboard shows

- **Faces** — every face the forwarder knows, with kind, address,
  byte/packet counters, and lifetime events.
- **FIB** — routes by prefix, with strategy and nexthop list.
- **PIT** — pending Interests, in-records, out-records, scheduled
  retransmissions.
- **Content Store** — entries by name, size, freshness, hit count.
- **Strategy table** — per-prefix strategy choice with override
  controls.
- **Routing** — protocol status (`StaticProtocol`, `NlsrProtocol`,
  `DvProtocol`) with typed state codes.
- **Discovery** — neighbour table from the active discovery protocol.
- **Identities** — `KeyChain` view: identities, keys, certs, policies.

Every panel reads from a single mgmt verb — see
[Management verbs](../reference/mgmt-verbs.md).

## Configuration

Browser → forwarder runs over WebSocket or WebTransport. The
forwarder's `ndn-fwd.toml` must expose one of those listeners:

```toml
[face.ws]
listen = "0.0.0.0:9696"

[face.webtransport]
listen = "0.0.0.0:4443"
cert = "/etc/ndn-fwd/wt.pem"
key  = "/etc/ndn-fwd/wt.key"
```

See [Config reference](../operations/config-reference.md) for every
knob.

## Multi-forwarder runtime profile

The dashboard speaks one wire protocol against multiple forwarder
implementations. The runtime profile selector decides which dialect
of the mgmt protocol to emit (verbs are identical; some optional
fields differ).

```text
http://localhost:8080/?forwarder=ws://other-host:9696&profile=compat
```

Project memory `project_dashboard_multi_forwarder` records the
profile catalogue.

## Security

The dashboard's mgmt operations require authentication. The
forwarder's `[mgmt.auth]` section sets the signing identity that
mgmt commands must carry; the dashboard signs its commands with a
key held by the operator. The flow is in
[NDNCERT setup](./ndncert-setup.md) → "fleet operator key".

For lab use the default config disables auth on `/tmp/ndn-fwd.sock`
because anything with filesystem access already owns the host. Do
not run an open mgmt socket on a network face.

## See also

- `crates/ndn-dashboard/` — implementation.
- [Management verbs](../reference/mgmt-verbs.md) — every verb the
  dashboard issues.
- [ndn-fwd](../operations/ndn-fwd.md) — forwarder ops.
- [Config reference](../operations/config-reference.md) —
  listener configuration.
