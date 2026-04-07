# Browser Simulation with ndn-wasm

## The Question Nobody Thought to Ask

For years the standard answer to "how do I learn NDN?" has been: read the spec, clone NFD, build it, fight with its dependencies, deploy it on two VMs, and send your first Interest packet into the void. If the Data comes back, congratulations — you've run NDN. If it doesn't, you have no idea whether the packet was malformed, the FIB was wrong, or the face just isn't up yet.

The ndn-explorer takes a different approach. What if you could run a real NDN pipeline — with a working FIB trie, a live PIT, an LRU Content Store, and all six forwarding stages — inside a web browser, with no installation required, stepping through each stage's decision in real time?

That's what `ndn-wasm` is. Not a teaching toy that pretends to route packets. An actual simulation of the NDN forwarding pipeline, compiled to WebAssembly, that the ndn-explorer uses to power its animated pipeline traces, topology sandbox, and TLV inspector.

## The Architecture Decision: Reimplement, Don't Port

The honest first idea was to compile the real `ndn-engine` to `wasm32-unknown-unknown`. This runs into a wall almost immediately. The production engine depends on `DashMap` (which uses thread-local state that doesn't exist on WASM), Tokio's `rt-multi-thread` feature (which requires `pthread`), and scattered `tokio::spawn` calls that assume preemptive multitasking. These aren't superficial problems — they go all the way down to how the engine handles concurrent packet processing.

The second idea — and the one that actually works — is to write a purpose-built simulation crate that shares the wire-format libraries (`ndn-tlv`, `ndn-packet`) but reimplements the forwarding data structures using single-threaded primitives that compile cleanly to WASM. No `DashMap`. No background tasks. No mutexes. Just `HashMap`, `Vec`, and deterministic execution.

This trade-off has a cost (more on that later), but it has a significant benefit: the simulation runs synchronously, which makes it *better* for visualization than the real engine would be. The explorer can step through stages one at a time, emit trace events at each decision point, and hand control back to the JavaScript renderer between stages — something that would require substantial instrumentation to achieve with the real async pipeline.

## What `ndn-wasm` Actually Contains

### The FIB Trie

The Forwarding Information Base in `ndn-wasm` is a proper name-component trie, not a string-prefix shortcut. Each node in the trie holds a `HashMap<String, TrieNode>` of its children, indexed by name component. Longest-prefix matching walks the trie one component at a time, tracking the deepest node that has a `next_hop` set, and returns that face ID.

```rust
fn lookup_lpm(&self, name: &[&str]) -> Option<u32> {
    let mut node = &self.root;
    let mut best = node.next_hop;
    for component in name {
        match node.children.get(*component) {
            Some(child) => { node = child; best = best.or(node.next_hop); }
            None => break,
        }
    }
    best
}
```

This is the same algorithm the production FIB uses — just with `HashMap` instead of `Arc<RwLock<TrieNode>>`. In a single-threaded WASM context that's all you need.

The `insert_route()` function creates trie nodes for missing components on the path, so routes like `/ndn/ucla/cs` and `/ndn/mit/csail` live in a shared `/ndn` node with two subtrees. No string interning, no hash collisions from treating the whole name as a key.

### The PIT

The Pending Interest Table tracks outstanding Interests by a composite key `(name, can_be_prefix, must_be_fresh)`. Each entry stores the arrival time, expiry deadline, and nonce set for deduplication. When a second Interest arrives for the same name with the same nonce as a pending entry, it's detected and dropped — loop prevention working exactly as the spec requires.

Expiry is handled via `evict_expired()`, which the pipeline calls before each lookup. This is the simplified version of the production timing wheel: instead of O(1) slot-based expiry, it's a linear scan. For the browser simulation this is fine — the PIT rarely holds more than a few dozen entries at a time.

Aggregation — two different consumers sending the same Interest — is modeled correctly. A second Interest that matches an existing PIT entry records its face as an additional downstream face. When the Data returns, the pipeline dispatches it to all of them.

### The Content Store

The CS is an LRU cache implemented with a `HashMap<String, CsEntry>` for O(1) lookup and a `Vec<String>` that tracks insertion order. When capacity is exceeded, the oldest entry is evicted. Each entry records its freshness period alongside the content, so MustBeFresh Interests only hit entries that are still within their freshness window.

The lookup supports `CanBePrefix`: when the flag is set, the CS scans for any stored name that starts with the requested name's components. This is a linear scan in the WASM implementation (vs. the trie-based scan in the production CS), but it produces correct results.

Hit rate tracking is built in. The CS counts total lookups and hits, so the pipeline stage panel in the explorer can display a live hit rate as you run packets through.

### The Pipeline

This is the heart of `ndn-wasm`. Two pipelines — one for Interest packets, one for Data — each implemented as a sequence of function calls that emit `StageEvent` structs.

**Interest pipeline:**

| Stage | What it checks | What it can do |
|-------|---------------|----------------|
| `TlvDecode` | Parses Name, CanBePrefix, MustBeFresh, Lifetime, Nonce from wire format | Emits decoded fields as trace detail |
| `CsLookup` | Looks up the name in the Content Store | Short-circuits: emits `cache_hit`, returns Data without touching PIT or FIB |
| `PitCheck` | Checks nonce against pending entries; inserts or aggregates | Detects loops; models aggregation |
| `Strategy` | FIB trie lookup; BestRoute / Multicast / Suppress decision | Selects face(s); marks as forwarded or nacked |

**Data pipeline:**

| Stage | What it checks | What it can do |
|-------|---------------|----------------|
| `TlvDecode` | Parses Name, Content, SignatureInfo from wire format | Emits decoded fields |
| `PitMatch` | Finds pending entries whose Interest matches the Data name | Short-circuits if no pending entry (unsolicited Data) |
| `Validation` | Checks the `sig_valid` flag on the packet | Drops invalid Data before it reaches the cache |
| `CsInsert` | Stores the Data in the Content Store | Evicts if over capacity |

Each stage produces a `StageEvent` with a name, verdict (`Continue / Drop / Nack / CacheHit / Forwarded / Satisfied`), the face ID involved, and a JSON detail blob. The explorer's pipeline view collects these events and animates the packet bubble through the stages in sequence.

```rust
pub struct StageEvent {
    pub stage: &'static str,
    pub verdict: Verdict,
    pub face_id: Option<u32>,
    pub detail: serde_json::Value,
}
```

This event stream is what makes the animated pipeline possible. The real async engine emits `tracing` spans — useful for logs, but not structured enough to drive a step-by-step visual without significant extra work. Here, the events are designed from the start to be consumed by a renderer.

### The Topology

Above the individual pipeline, `SimTopology` models a multi-hop network. Nodes hold their own `WasmPipeline` instance (and therefore their own FIB, PIT, and CS). Links connect pairs of nodes, each with a direction-aware face ID. When you call `load_topology_scenario("triangle-caching")`, the topology builds three nodes, wires three links, and calls `propagate_route()` to populate FIB tables.

`propagate_route()` does a BFS from each producer's prefix outward through the topology, installing FIB entries at each hop. It stops at nodes that already have the prefix in their FIB, which prevents redundant writes in looped topologies — though it currently doesn't carry a visited set, so a true cycle in the topology graph would loop. The scenarios that ship with the explorer are all acyclic, so this hasn't been a problem in practice.

### TLV Encoding and Decoding

TLV encoding delegates to the real `ndn-tlv::TlvWriter`, which means the bytes produced by `tlv_encode_interest()` and `tlv_encode_data()` are spec-compliant. You can copy the hex string out of the TLV Inspector, decode it with an independent NDN library, and get the same field values back.

Decoding uses `ndn-packet`'s parser for Interest and Data, then extracts fields into a `WasmTlvNode` tree that JavaScript can walk. Each node carries its type code, decoded type name, byte range in the original buffer, and a human-readable value string.

## Where the Simulation Diverges from Production

Understanding the gaps is as important as understanding what works. `ndn-wasm` is a faithful simulation of NDN semantics, not a production-grade forwarder. Here's exactly where it takes shortcuts:

### Signatures Are a Flag, Not a Calculation

The most visible simplification: when you build a Data packet in the explorer and mark it "invalid", what changes is a boolean `sig_valid` flag, not any bytes in the packet. The `Validation` pipeline stage checks this flag and drops the packet if false.

The wire-format Data packets that `tlv_encode_data()` produces *do* include a `SignatureValue` field — but it's 32 bytes of `0xAA`. There's no ECDSA, no HMAC, no SHA-256. This means a packet produced by the explorer and decoded by a real NDN library will have a syntactically valid but cryptographically meaningless signature. For educational purposes — watching the Validation stage accept or reject a packet — this is sufficient. For anything security-critical, you want the real `ndn-security` crate.

### NDNLPv2 Is Absent

The production forwarder speaks NDNLPv2, the link-layer fragmentation and signaling protocol that carries Interests, Data, and Nacks in a common envelope. `ndn-wasm` skips this entirely. The simulation works at the application-layer PDU level: packets are NDN Interest and Data directly, never wrapped in NDNLPv2 fragments. This means link-layer Nacks (the `NoRoute` / `CongestionMark` signaling that real forwarders exchange) are simulated by directly setting a verdict in the strategy stage, not by constructing and parsing a real NDNLPv2 Nack packet.

### Link Impairments Are Modeled but Ignored in Routing

Every `SimLink` carries `bandwidth_bps` and `loss_rate` fields. The topology UI even lets you set them. But right now they're inert — the routing logic doesn't consult them, packets aren't dropped probabilistically, and bandwidth-delay products aren't reflected in timing. The fields are there because they *should* affect strategy decisions (specifically ASF, which measures per-face RTT and satisfaction rate). Wiring them into the pipeline is the natural next step when ASF strategy is implemented.

### No ASF Strategy

The Adaptive Smoothed RTT-based Forwarding strategy — the production implementation that measures per-face RTT and satisfaction rate and re-ranks faces accordingly — isn't in `ndn-wasm` yet. The simulation offers three strategies: `BestRoute` (first FIB match, single face), `Multicast` (all FIB matches, all faces), and `Suppress` (no forwarding, for dead-end tests). ASF requires a measurements table that persists across packet runs and feeds back into the FIB decision — doable in a single-threaded model, just not implemented yet.

### No CertFetcher

The production Validation stage can trigger a side-channel Interest to fetch a missing certificate before completing signature verification. `ndn-wasm` has no async side channels — the simulation is fully synchronous — so certificate chasing isn't modeled. If you want to show a certificate chain in the explorer, it's currently done by building the chain manually in the scenario definition.

## The Path to Compiling the Real Engine

The three concrete blockers between the real `ndn-engine` and a WASM binary:

**`DashMap`** — `ndn-transport`, `ndn-store`, `ndn-engine`, and `ndn-strategy` all use `DashMap` for concurrent access to the PIT, FIB, face table, and measurements table. `DashMap` uses thread-local storage internally and doesn't compile on `wasm32`. The fix is a feature flag that swaps `DashMap<K, V>` for `Mutex<HashMap<K, V>>` under `target_arch = "wasm32"`. This is semantically correct (WASM is single-threaded) and mechanically straightforward — it's just a lot of call sites to update.

**`rt-multi-thread`** — `ndn-engine` enables Tokio's multi-thread runtime for production use. The multi-thread runtime requires OS threads. The fix is a `wasm` feature that removes `rt-multi-thread` from the Tokio dependency and switches to `current_thread`. The pipeline logic itself is all `async fn` and doesn't depend on parallelism — it would run correctly on a single-threaded executor.

**`tokio::spawn`** — Various places in the engine and faces spawn background tasks using `tokio::spawn`. On WASM, the equivalent is `wasm_bindgen_futures::spawn_local`. Faces also use `tokio::time::sleep` for delays; `gloo_timers` provides the WASM equivalent. This is mostly mechanical substitution, but it requires touching `sim_face.rs` and any face that creates background tasks.

None of these are insurmountable. Together they represent a few days of careful refactoring and a restructured `Cargo.toml` with feature flags. The payoff would be running the real forwarding engine — the exact same binary that runs the production forwarder — in the browser, with the explorer's trace events emitted via the production `tracing` infrastructure rather than `ndn-wasm`'s bespoke `StageEvent` structs.

## Building ndn-wasm

The crate lives in `crates/ndn-wasm/` and is built with `wasm-pack`. From the repository root:

```bash
bash tools/ndn-explorer/build-wasm.sh
```

This runs:

```bash
wasm-pack build crates/ndn-wasm \
  --target web \
  --out-dir tools/ndn-explorer/wasm \
  --out-name ndn_wasm \
  --no-typescript \
  --release
```

The output is four files in `tools/ndn-explorer/wasm/`:
- `ndn_wasm.js` — the ES module loader that wasm-pack generates
- `ndn_wasm_bg.wasm` — the compiled WASM binary
- `ndn_wasm_bg.js` — glue for wasm-bindgen's memory model
- `package.json` — metadata, not needed by the explorer directly

After the build, open `tools/ndn-explorer/index.html` in a browser. The WASM badge in the top-right corner of the nav will switch from `WASM —` to `WASM ✓`, confirming that the Rust simulation is active. If the badge stays grey, open the browser console — the most common cause is a missing WASM file or a CORS error from loading a `file://` URL (use a local dev server instead).

On every push to `main` that touches `crates/ndn-wasm/`, the GitHub Actions wiki workflow rebuilds the WASM binary as part of deploying the GitHub Pages site. The build step runs with `continue-on-error: true`, so a WASM compile failure doesn't block the site deploy — the explorer falls back to its JavaScript simulation until the next successful build.

## Feature Comparison: ndn-wasm vs. Production Engine

| Feature | ndn-wasm | ndn-engine (production) |
|---------|----------|-------------------------|
| FIB: longest-prefix match | ✓ Component trie | ✓ Concurrent Arc<RwLock> trie |
| PIT: aggregation & nonce dedup | ✓ | ✓ DashMap-based |
| CS: LRU, CanBePrefix, MustBeFresh | ✓ | ✓ Pluggable backends |
| Interest pipeline (all 4 stages) | ✓ | ✓ |
| Data pipeline (all 4 stages) | ✓ | ✓ |
| BestRoute strategy | ✓ | ✓ |
| Multicast strategy | ✓ | ✓ |
| ASF strategy | ✗ | ✓ |
| NDNLPv2 (fragmentation, Nack) | ✗ | ✓ |
| Real cryptographic signatures | ✗ Simulated flag | ✓ ECDSA / HMAC / SHA-256 |
| CertFetcher (async cert chain) | ✗ | ✓ |
| Link impairments (loss, delay) | Modeled, not applied | ✓ ndn-sim |
| Multi-hop topology | ✓ BFS route propagation | ✓ SimLink channels |
| TLV wire format (encode/decode) | ✓ Real ndn-tlv | ✓ Same library |
| Structured trace events | ✓ StageEvent (for viz) | ✓ tracing spans |
| Runs in browser | ✓ | ✗ (blocked by DashMap + rt-multi-thread) |
| Thread-safe concurrent access | ✗ Single-threaded | ✓ |

The table tells the story clearly: `ndn-wasm` wins on the things that matter for an interactive educational tool — complete pipeline semantics, real TLV encoding, multi-hop topology — and gives up the things that don't make sense in a single-threaded browser context (thread-safe concurrency) or that are too complex to simulate without the full security stack (real crypto, certificate fetching).

The goal was never to replace the production engine. It was to bring NDN forwarding semantics into a context where a newcomer can click "Run Packet" and watch, step by step, how an Interest finds its way from a consumer to a producer and a Data packet finds its way back.

That part works.
