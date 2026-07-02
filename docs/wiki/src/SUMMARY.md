# Summary

[Introduction](./README.md)

# Part I · Using ndn-rs

---

# Start here

- [Why NDN is different](./start/why-ndn-is-different.md)
- [One packet, six depths](./start/one-packet-six-depths.md)
- [Trust, first](./start/trust-first.md)

# Your path

- [App author](./path/app-author.md)
- [Operator](./path/operator.md)
- [Extender](./path/extender.md)
- [Researcher](./path/researcher.md)

# Quickstart

- [Five-minute app](./quickstart/5-minute-app.md)
- [Ten-minute producer](./quickstart/10-minute-producer.md)
- [Running the forwarder](./quickstart/running-the-forwarder.md)

# Concepts

- [NDN overview](./concepts/ndn-overview.md)
- [Interest and Data lifecycle](./concepts/interest-data-lifecycle.md)
- [Identity and keys](./concepts/identity-and-keys.md)
- [Glossary](./concepts/glossary.md)

# Choosing

- [How to read these pages](./choosing/README.md)
- [Confidentiality](./choosing/confidentiality.md)
- [Faces & transports](./choosing/faces-and-transports.md)
- [Routing & discovery](./choosing/routing-and-discovery.md)
- [Reliability & throughput](./choosing/reliability-and-throughput.md)
- [When to use in-network compute](./choosing/in-network-compute.md)

# API

- [The Node cookbook](./api/node-cookbook.md)
- [Develop tier](./api/develop.md)
- [Extend tier](./api/extend.md)
- [Instrument tier](./api/instrument.md)

# Guides

- [Building an application](./guides/building-an-app.md)
- [Writing a strategy](./guides/writing-a-strategy.md)
- [Implementing a face](./guides/implementing-a-face.md)
- [In-network compute](./guides/in-network-compute.md)
- [Network coding (FEC)](./guides/network-coding.md)
- [NDNCERT setup](./guides/ndncert-setup.md)
- [Security pitfalls](./guides/security-pitfalls.md)
- [Running the dashboard](./guides/running-the-dashboard.md)
- [Remote-signer pairing](./guides/remote-signer-pairing.md)
- [Self-hosting](./guides/self-hosting.md)

# Operations

- [ndn-fwd](./operations/ndn-fwd.md)
- [Config reference](./operations/config-reference.md)
- [Logging](./operations/logging.md)
- [Performance](./operations/performance.md)

# Reference

- [Face transports](./reference/face-transports.md)
- [NDN over BLE — GATT profile](./reference/ndn-ble-gatt-profile.md)
- [Management verbs](./reference/mgmt-verbs.md)
- [Trust policies](./reference/trust-policies.md)
- [Dashboard extensions](./reference/dashboard-extensions.md)
- [Spec compliance](./reference/spec-compliance.md)

# Part II · Inside ndn-rs

---

- [Start contributing](./inside/README.md)

# Architecture

- [The layer map](./inside/architecture/layer-map.md)
- [The crate graph](./inside/architecture/crate-graph.md)
- [The forwarding pipeline](./inside/architecture/forwarding-pipeline.md)
- [The security model](./inside/architecture/security-model.md)
- [The determinism seam](./inside/architecture/determinism-seam.md)
- [sans-IO and no_std](./inside/architecture/sans-io-and-no-std.md)

# Cookbooks

- [Add a face transport](./inside/cookbook/add-a-face.md)
- [Add a forwarding strategy](./inside/cookbook/add-a-strategy.md)
- [Add a management module](./inside/cookbook/add-a-mgmt-module.md)
- [Add a sync dialect](./inside/cookbook/add-a-sync-dialect.md)
- [Add a storage backend](./inside/cookbook/add-a-storage-backend.md)

# Working on ndn-rs

- [The testing guide](./inside/testing.md)
- [Spec conformance matrix](./inside/conformance-matrix.md)
- [The cross-repo contract](./inside/cross-repo-contract.md)
- [Contribution workflow](./inside/contributing.md)

# Decision records

- [About ADRs](./inside/adr/README.md)
- [0001 · Real NDN wire format, not a dialect](./inside/adr/0001-real-ndn-wire-format.md)
- [0002 · Type-enforced verification (SafeData)](./inside/adr/0002-type-enforced-verification.md)
- [0003 · sans-IO seed crates for native + embedded](./inside/adr/0003-sans-io-seed-crates.md)
- [0004 · Virtualize the clock for determinism](./inside/adr/0004-virtualize-the-clock.md)
- [0005 · Retire the audit-witness suite for nextest](./inside/adr/0005-retire-audit-witness-suite.md)
- [0006 · The radio foundation boundary](./inside/adr/0006-radio-foundation-boundary.md)
- [0007 · The named-time crate boundary](./inside/adr/0007-named-time-crate-boundary.md)

# Releases

- [v0.1.0](./releases/v0.1.0.md)
