# In-Network Compute

## Why NDN Enables In-Network Compute

NDN collapses the distinction between *what* you want and *where* you get it. The name `/compute/jpeg-thumb/source=/images/photo.jpg/size=128` simultaneously identifies the result **and** routes the Interest to wherever that computation can be performed.

**Memoization is free**: The first request computes the result, the CS stores it, and subsequent requests are satisfied by the network without involving the compute node. In IP, ten clients calling the same REST endpoint → ten server requests. In NDN, the first computes, the next nine are CS hits.

## Level 1 — Named Results (Already Works)

No engine changes needed. A producer that names outputs with computation parameters embedded in the name already gets CS caching for free:

```
/sensor/room42/temperature/aggregated/window=60s
```

Consumers do not know or care whether Data came from live computation or a cache. This is the most underappreciated form of in-network compute.

## Level 2 — `ComputeFace`

Implements the `Face` trait and registers in the `FaceTable`. The engine FIB routes Interests matching `/compute/*` to it. Internally maintains a `ComputeRegistry` mapping name prefixes to async handler functions:

```rust
pub struct ComputeFace {
    registry: Arc<ComputeRegistry>,
    face_id:  FaceId,
    tx:       mpsc::Sender<RawPacket>,  // back into pipeline
}

pub struct ComputeRegistry {
    handlers: NameTrie<Arc<dyn ComputeHandler>>,
}

pub trait ComputeHandler: Send + Sync {
    async fn compute(&self, interest: &Interest) -> Result<Data>;
}
```

When an Interest arrives at `ComputeFace`, it does a trie lookup, calls the handler, and sends the resulting Data back into the pipeline as if arriving from a remote face. The CS insert stage caches the result. Identical subsequent Interests never reach the handler.

**Versioning**: `/compute/fn/v=2/thumb/…` routes to a different handler than `v=1`. Running multiple versions simultaneously is just multiple FIB entries.

## Level 3 — Aggregation (Wildcard PIT)

The forwarder aggregates data from multiple producers in response to a single Interest. Requires an `AggregationPitEntry`:

```rust
pub struct AggregationEntry {
    upstream: PitToken,
    pending:  HashSet<Name>,   // downstream Interests outstanding
    received: Vec<Data>,       // accumulating results
    combine:  Arc<dyn Fn(Vec<Data>) -> Data + Send + Sync>,
    expiry:   u64,
}
```

A wildcard Interest `/sensor/+/temperature/avg` matches the aggregation strategy, which fans it out to `/sensor/room1/temperature`, `/sensor/room2/temperature`, etc. from a prefix enumeration table. When all pending Interests are satisfied (or timeout), `combine()` runs and the result satisfies the upstream Interest.

Implementable as a pipeline stage plus new strategy type — the existing engine architecture accommodates it without structural changes.

## Level 4 — Computation Fabric (Research Frontier)

Treat a computation as a DAG where each node is a named function and each edge is a named data dependency. Expressing an Interest for the root node causes the network to recursively resolve dependencies by expressing Interests for intermediate nodes. **The network is the scheduler.**

Effectively lazy functional evaluation distributed across a network, with memoization via the CS at every node. Maps onto federated learning naturally:
- `/model/v=5/gradient/shard=3` is computed locally at the shard, cached
- Aggregator expresses Interests for all shards
- Aggregator does not know where shard 3 is located — the FIB routes it there

**Wireless research integration**: The forwarding strategy's routing decisions determine which compute node processes which shard. The strategy already has access to `MeasurementsTable` and `FibEntry`. Adding a `ComputeLoadTable` alongside `MeasurementsTable` — updated by a node monitoring task — gives the strategy everything it needs for compute-aware forwarding without any additional protocol machinery.

## Honest Limitations

**Long-running compute**: A consumer expressing an Interest gets a single Data back. If the computation takes 30 seconds, the Interest lifetime must be 30 seconds or the consumer must re-express periodically. See `docs/ipc.md` for push notification approaches (versioned namespace, `Nack(NotYet, retry_after)`, notification Interest inversion).

**Large intermediate results**: A 100 MB result requires pipelining hundreds of segment Interests, adding latency compared to streaming TCP. The chunked transfer layer handles this correctly but with more complexity.

These are engineering problems with known solutions. The architectural alignment between NDN and in-network compute is strong enough at the edge and in wireless environments where IP-based approaches require fragile service discovery infrastructure.
