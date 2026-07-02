# The forwarding pipeline

This is the heart of ndn-rs: the path a packet takes from arriving on a face to
being answered, forwarded, or dropped. If you are fixing a forwarding bug or
adding a stage, read this first.

![The forwarding pipeline — an Interest walks decode, Content Store, PIT, and
strategy stages; Data returns along the reverse path the PIT
recorded.](../../images/forwarding-pipeline.svg)

The animation shows the two halves. An **Interest** walks left-to-right through
the ingress stages; a **Data** returns right-to-left along the reverse path the
PIT recorded. The defining property of NDN is visible in the picture: the Data
needs no routing on the way back, because forwarding is *stateful* — the PIT
remembers who asked.

## The three tables

Every NDN forwarder is organised around three tables. In ndn-rs they live in
`ndn-store`:

| Table | Type | What it holds | Keyed by |
|---|---|---|---|
| **Content Store (CS)** | `ContentStore` trait (`LruCs`, `ShardedCs`, `FjallCs`, …) | recently-seen Data, in wire form | name |
| **Pending Interest Table (PIT)** | `Pit` over `DashMap` | Interests awaiting Data, and the faces that want them | `PitToken` (name-hash + discriminator) |
| **Forwarding Information Base (FIB)** | `Fib` over a `NameTrie` | name prefix → next-hop faces + costs | longest-prefix match |

The CS makes any router a cache; the PIT makes the return path free; the FIB is
the routing table. A per-prefix **forwarding strategy** decides *how* to use the
FIB (which next-hops, when to retry, when to give up).

## The ingress path (Interest)

The stages live in `ndn-engine/src/stages/` and are driven in order by the
dispatcher in `ndn-engine/src/dispatcher/`. Reading order for the Interest
path:

1. **Decode** — the raw bytes are parsed. If they are an NDNLPv2 `LpPacket`
   (type `0x64`), the link layer strips fragmentation/PitToken/Nack headers
   first; the inner Interest is decoded lazily (fields are only parsed when
   read, so a CS hit never touches fields it doesn't need).
2. **Content Store** — if the CS holds fresh Data matching the name, it is
   returned immediately and **no further stage runs**. This is the first
   short-circuit.
3. **PIT** — the Interest is looked up by `PitToken`. If an entry already
   exists (someone else asked for this name), the new Interest is *aggregated*:
   its incoming face is added as an in-record and the Interest is **not**
   forwarded again. If it is new, an entry is created. This is where flow
   balance and loop detection (nonce + dead-nonce-list) happen.
4. **Strategy** — a fresh (un-aggregated) Interest is handed to the strategy
   registered for its longest-matching prefix. The strategy reads the FIB entry
   and returns a `ForwardingAction`: forward to some faces, forward after a
   delay, Nack, or suppress. See [Add a forwarding strategy](../cookbook/add-a-strategy.md).
5. **Egress** — chosen next-hops are LP-framed and queued to each face's sender
   task.

## The return path (Data)

1. **PIT match** — the Data's name is matched against pending entries. No match
   → the Data is *unsolicited* and (by default) dropped.
2. **Validate** — on faces that require it, the signature is checked before the
   Data is allowed to propagate. This is where the
   [security model](./security-model.md) becomes load-bearing: a router will
   not forward Data it cannot authenticate on a validating face.
3. **CS insert** — admissible Data is cached (admission policy decides what is
   worth caching; the default admits only Data with a non-zero freshness
   period, matching NFD).
4. **Reverse forward** — the Data is sent to *every* face recorded as an
   in-record on the PIT entry, then the entry is consumed. One Interest, one
   Data, one PIT entry — flow balance.

## Why it is sharded and async, not a single-threaded core

The dispatcher runs the pipeline as tokio tasks over sharded, interior-mutable
tables (`DashMap` for the PIT, per-node `RwLock` in the FIB trie). Interest and
Data for the same name are steered to the same shard so aggregation and
matching stay correct without a global lock. A partitioned data-plane mode
(NDN-DPDK style) hashes the first name components to worker lanes for
throughput. The key invariant that keeps this safe: **stages consume their
`PacketContext`** — every stage variant except "continue" takes the context by
value, so a use-after-handoff is a compile error rather than a data race.

## Where to look in the code

| You want to change… | Start in |
|---|---|
| how a stage behaves | `ndn-engine/src/stages/` |
| how packets are steered to workers | `ndn-engine/src/dispatcher/` |
| the tables themselves | `ndn-store/src/{pit,fib,content_store}.rs` |
| a forwarding decision | `ndn-strategy/src/` and the [cookbook](../cookbook/add-a-strategy.md) |
| the sans-IO forwarding rules shared with embedded | `ndn-fwd-core/src/` |

The pure forwarding *rules* — longest-prefix match, freshness predicates,
conformance checks — live in the `no_std` `ndn-fwd-core` crate so the native
engine and the bare-metal forwarder apply byte-identical logic. See
[sans-IO and no_std](./sans-io-and-no-std.md).
