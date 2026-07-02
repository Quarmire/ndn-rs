# The crate graph

ndn-rs is a workspace of ~30 library crates. They form a directed acyclic
graph: dependencies flow one way, foundation → forwarding → app. The graph
below is interactive (drag to pan, scroll to zoom).

```d3graph
{
  "columns": [
    { "label": "Foundation (no_std)", "nodes": [
      { "id": "ndn-tlv" },
      { "id": "ndn-foundation-types" },
      { "id": "ndn-packet" },
      { "id": "ndn-crypto-core" },
      { "id": "ndn-signals-core" },
      { "id": "ndn-time" },
      { "id": "ndn-runtime" }
    ]},
    { "label": "Store & transport", "nodes": [
      { "id": "ndn-storage" },
      { "id": "ndn-store" },
      { "id": "ndn-transport" },
      { "id": "ndn-fwd-core" },
      { "id": "ndn-mgmt-wire" }
    ]},
    { "label": "Forwarding & faces", "nodes": [
      { "id": "ndn-strategy" },
      { "id": "ndn-face" },
      { "id": "ndn-discovery-core" },
      { "id": "ndn-engine" }
    ]},
    { "label": "Security", "nodes": [
      { "id": "ndn-security" },
      { "id": "ndn-cert" },
      { "id": "ndn-identity" }
    ]},
    { "label": "App & platform", "nodes": [
      { "id": "ndn-app" },
      { "id": "ndn-mgmt" },
      { "id": "ndn-ipc" },
      { "id": "ndn-config" },
      { "id": "ndn-sync" },
      { "id": "ndn-observability" }
    ]}
  ],
  "edges": [
    ["ndn-packet", "ndn-tlv"],
    ["ndn-packet", "ndn-foundation-types"],
    ["ndn-foundation-types", "ndn-tlv"],
    ["ndn-fwd-core", "ndn-signals-core"],
    ["ndn-store", "ndn-packet"],
    ["ndn-store", "ndn-fwd-core"],
    ["ndn-transport", "ndn-packet"],
    ["ndn-mgmt-wire", "ndn-packet"],
    ["ndn-strategy", "ndn-transport"],
    ["ndn-strategy", "ndn-signals-core"],
    ["ndn-face", "ndn-transport"],
    ["ndn-engine", "ndn-store"],
    ["ndn-engine", "ndn-strategy"],
    ["ndn-engine", "ndn-transport"],
    ["ndn-engine", "ndn-runtime"],
    ["ndn-engine", "ndn-discovery-core"],
    ["ndn-engine", "ndn-security"],
    ["ndn-security", "ndn-packet"],
    ["ndn-cert", "ndn-security"],
    ["ndn-identity", "ndn-cert"],
    ["ndn-app", "ndn-engine"],
    ["ndn-app", "ndn-security"],
    ["ndn-mgmt", "ndn-engine"],
    ["ndn-mgmt", "ndn-mgmt-wire"],
    ["ndn-ipc", "ndn-packet"],
    ["ndn-config", "ndn-mgmt-wire"],
    ["ndn-sync", "ndn-packet"],
    ["ndn-observability", "ndn-transport"]
  ],
  "satellites": {
    "label": "Consumed by sibling repos",
    "nodes": [
      { "id": "ndn-fwd" },
      { "id": "ndn-ext" },
      { "id": "ndn-sim" },
      { "id": "ndn-mobile" },
      { "id": "ndn-embedded" },
      { "id": "ndn-repo" }
    ]
  },
  "satellite_edges": [
    ["ndn-fwd", "ndn-engine"],
    ["ndn-ext", "ndn-engine"],
    ["ndn-sim", "ndn-engine"],
    ["ndn-mobile", "ndn-app"],
    ["ndn-embedded", "ndn-fwd-core"],
    ["ndn-repo", "ndn-sync"]
  ]
}
```

> The diagram is a curated view — it shows the load-bearing edges, not every
> `Cargo.toml` line. The authoritative graph is the manifests; `cargo tree`
> renders it in full.

## Reading the graph

The columns are dependency *layers*, and edges only ever point leftward (toward
foundation). There are no cycles — this is enforced, not just observed: a CI
dependency-direction guard keeps the `spec`-classified crates closed under
dependency, so a new edge that would break the layering fails the build.

## The layers, briefly

- **Foundation** is `no_std`: the TLV codec, packet types, shared name/hash
  primitives, the no-alloc crypto core, the cross-layer signal taxonomy, the
  named-time core (`ndn-time` — uncertainty-bounded samples, the Marzullo
  combiner, measurement provenance; see [ADR 0007](../adr/0007-named-time-crate-boundary.md)),
  and the clock/runtime seam. Everything else builds on these.
- **Store & transport** holds the three forwarding tables (`ndn-store`), the
  pluggable async KV backends (`ndn-storage`), the face/transport abstraction
  and NDNLPv2 link service (`ndn-transport`), the sans-IO forwarding rules
  (`ndn-fwd-core`), and the NFD management wire codec (`ndn-mgmt-wire`).
- **Forwarding & faces** is the strategy framework, the concrete OS faces, the
  discovery trait surface, and `ndn-engine` — the crate that assembles the
  whole forwarding plane.
- **Security** layers certificates and identity lifecycle on top of the
  `ndn-security` core (see the [security model](./security-model.md)).
- **App & platform** is the developer-facing `Node`/`Consumer`/`Producer` API,
  the management dispatcher, IPC, config, the sync protocols, and NDN-native
  observability.

The **satellites** are the sibling repos in `ndn-workspace` that consume
ndn-rs. Which exact items they depend on is the subject of the
[cross-repo contract](../cross-repo-contract.md) — that surface is what
[semver-checks](../contributing.md) protects.

For *why* the foundation is a separate `no_std` layer at all, see
[ADR 0003](../adr/0003-sans-io-seed-crates.md).
