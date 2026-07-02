# Inside ndn-rs

Part I of this book teaches you to *use* ndn-rs — fetch and serve named data,
sign and verify, run a forwarder. Part II is for people who work *on* it:
adding a transport, a strategy, a sync dialect; fixing a bug in the forwarding
plane; or porting the core to a new target.

It assumes you have read at least [Why NDN is different](../start/why-ndn-is-different.md)
and [One packet, six depths](../start/one-packet-six-depths.md) — the mental
model of consumer-driven Interest/Data exchange over a stateful forwarding
plane is load-bearing everywhere below.

## How this part is organised

**[Architecture](./architecture/layer-map.md)** — the shape of the codebase and
why it has that shape. Start with the [layer map](./architecture/layer-map.md)
and the [crate graph](./architecture/crate-graph.md), then read the
[forwarding pipeline](./architecture/forwarding-pipeline.md) walkthrough. The
[security model](./architecture/security-model.md),
[determinism seam](./architecture/determinism-seam.md), and
[sans-IO/no_std](./architecture/sans-io-and-no-std.md) pages each explain one
opinionated design decision that pervades the code.

**[Cookbooks](./cookbook/add-a-face.md)** — task-shaped, copy-adaptable recipes.
Each names the trait you implement, the crate it lives in, and where the
built-in implementations are so you can read a working example.

**[Working on ndn-rs](./testing.md)** — the [testing guide](./testing.md)
(what each layer of the test suite covers and how to run it), the
[spec conformance matrix](./conformance-matrix.md) (spec section ↔ crate ↔
test), the [cross-repo contract](./cross-repo-contract.md) (the API the sibling
repos depend on), and the [contribution workflow](./contributing.md).

**[Decision records](./adr/README.md)** — short, immutable notes explaining
*why* a load-bearing decision was made, so the reasoning outlives the commit
that made it.

## The one-paragraph orientation

ndn-rs is a Rust workspace of ~30 library crates layered
foundation → forwarding → security → app, plus platform and protocol crates
off to the side. The wire layer targets the **real NDN Packet Format v0.3**
and NDNLPv2 (not a private dialect), so it interoperates with NFD, ndn-cxx,
ndnd, and NDNts. The forwarding plane is async (tokio) with sharded lock-free
tables; the security model makes data-centric verification
[compiler-enforced](./architecture/security-model.md); and a
[determinism seam](./architecture/determinism-seam.md) lets the whole engine
run against a virtual clock for reproducible tests and simulation. Two
[sans-IO seed crates](./architecture/sans-io-and-no-std.md) share byte-identical
forwarding and crypto logic between the native engine and a bare-metal
`no_std` build.
