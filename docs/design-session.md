# NDN Rust Design

**Created:** 3/25/2026 9:38:49  
**Updated:** 3/26/2026 8:57:05  
**Exported:** 3/26/2026 9:04:27  
**Link:** [https://claude.ai/chat/70c2f423-e0f6-41ee-93ba-ae58d4d2c5f5](https://claude.ai/chat/70c2f423-e0f6-41ee-93ba-ae58d4d2c5f5)  

## Prompt:
3/25/2026, 9:41:29 AM

I am trying to design the architecture for a named data networking (NDN) stack written in Rust. However, Rust requires different structuring as it is not an object oriented language like C++ (ndn-cxx, NFD) or Go (ndnd).



## Response:
3/25/2026, 9:42:26 AM

````plaintext
Tool: read_me
````

This is a genuinely interesting design problem — Rust's ownership model, trait system, and lack of inheritance push you toward a fundamentally different architecture than ndn-cxx's class hierarchy or NFD's polymorphic pipeline. Let me sketch out a layered architecture and then we can drill into any part.

The core insight is that Rust wants you to model NDN as **composable data pipelines** with **trait-based polymorphism** rather than class hierarchies. Here's an overview:

````plaintext
Tool: show_widget
````

Here's how the Rust-idiomatic design differs from ndn-cxx at each layer:

**Face abstraction** — instead of an inheritance hierarchy rooted at `ndn::Face`, you define a `Face` trait with async send/recv methods. Each transport is a separate struct implementing that trait. Tokio's async runtime handles all of them uniformly. You'd likely use `Arc<dyn Face + Send + Sync>` at runtime, or monomorphize with generics where possible.

**TLV encoding** — `bytes::Bytes` is the Rust analog to ndn-cxx's `Block`. It's reference-counted and supports zero-copy slicing, which maps well to TLV nested structures. `Name` should be an `Arc<[NameComponent]>` so it's cheaply cloneable across the PIT and FIB without copying.

**Packet pipelines** — this is where Rust diverges most sharply. Instead of NFD's `Algorithm` virtual class chain, you'd use a `Vec<Box<dyn PipelineStage>>` where each stage is a trait object receiving a `PacketContext` and either passing it on or short-circuiting. This gives you the same composability without virtual dispatch overhead on the hot path if you monomorphize for known configurations.

**Forwarding engine** — the PIT maps naturally to a `DashMap<InterestToken, PitEntry>` with a separate timer wheel for expiry. The FIB is a name trie — you'll want a custom trie (or adapt `patricia_tree`) keyed on `Name` components. The content store hides behind a `trait ContentStore` so you can swap implementations (LRU, persistent).

**Async runtime** — the whole thing should run on Tokio. Each face owns a task, the forwarding engine owns a task, and they communicate through `mpsc` channels. This replaces NFD's dispatcher/scheduler.

A few Rust-specific design decisions worth thinking through upfront:

`Name` lifetime and ownership is the trickiest part — names appear in PIT keys, FIB lookups, and packet headers simultaneously. `Arc` sharing is almost certainly the right call over borrowing, since names outlive the packets they arrive in.

The `PipelineStage` trait needs to decide between `async fn` in traits (now stable in Rust 1.75+ via RPITIT) versus `Box<dyn Future>` returns. Async traits with `async_trait` macro work but have allocations per call; native async traits are cleaner now.

Security callbacks (signing, verification) map well to traits, but you'll want to keep them out of the hot path — pre-verify incoming data and cache the result in the `PacketContext`.

Which layer would you like to design in detail? The PIT/FIB data structures, the pipeline stage trait design, or the face abstraction are all meaty problems.



## Prompt:
3/25/2026, 9:49:32 AM

I will get back to these design decisions later.  I first want to address the application API.  ndnd creates an engine that is a single threaded event loop and local client applications connect to using a UNIX socket face.  Would a shared memory face be better?  Also should the Rust engine handle all the FIB and PIT for each application so that the application only has to send data and receive it?



## Response:
3/25/2026, 9:50:34 AM

Two great design questions that are actually related. Let me address both.

**Shared memory vs Unix socket face**

For local IPC, shared memory is significantly faster — you eliminate the kernel crossing on the data path. The tradeoff table looks like this:

| | Unix socket | Shared memory |
|---|---|---|
| Latency | ~2–5 µs | ~200–500 ns |
| Throughput | kernel-limited | memory bandwidth |
| Flow control | built-in | you implement it |
| Process crash handling | clean EOF | need to detect stale state |
| Implementation complexity | low | high |

For NDN specifically, the packet sizes matter. Interests are small (~100–300 bytes) so the Unix socket overhead is proportionally large. Data packets can be up to 8800 bytes (NDN MTU), where the per-call overhead matters less. A shared memory face with a lock-free ring buffer (like `io_uring` style) would meaningfully help Interest round-trip latency, which is the metric that matters most for NDN applications.

A reasonable middle ground: use a **shared memory ring buffer for the data path** (Interest out, Data back) and a **Unix socket as a control channel** (registering prefixes, receiving errors, lifecycle). This is how DPDK and some high-performance message brokers split the planes.

**On who owns the FIB and PIT**

This is the more fundamental question, and there are two real models:

In **ndnd's model** (and NFD's), the forwarder owns everything. Applications are thin — they just express Interests and register prefix handlers. This is clean but means every Interest and Data crosses the IPC boundary twice.

The alternative is a **library forwarder model**, where the engine is a Rust library linked directly into the application, and each application runs its own forwarding logic. This is what `ndn-lite` and some embedded NDN stacks do. Zero IPC cost, but no inter-application forwarding.

For a Rust stack targeting the same use cases as ndnd, the right answer is probably a **hybrid**:

````plaintext
Tool: show_widget
````

**The recommended split:**

The engine owns the global FIB, global PIT, content store, and all external faces — exactly as ndnd does. This is correct because Interest aggregation only works if there's one PIT. If two applications both express the same Interest, the engine collapses them into one outgoing Interest and fans the returning Data back to both. That's fundamental to NDN and can't be split.

What the application *does* own is a **local pending interest table** — a simple map of nonce/name to the `oneshot` channel waiting for the Data. This isn't forwarding logic; it's just dispatch. The application never needs to know about the FIB or global PIT at all. Its API surface is essentially:

```rust
async fn express(&self, interest: Interest) -> Result<Data, NdnError>;
async fn register_prefix(&self, prefix: Name, handler: impl InterestHandler);
```

**On the IPC split:** use shared memory ring buffers for the high-frequency data path (Interests going out, Data coming back), and the Unix socket purely as a control channel for prefix registration, face management, and errors. This gives you the latency wins of shmem without having to implement reliability over it — the control plane stays simple and the data plane stays fast.

One thing worth flagging: signing and verification should stay in the **application process**, not the engine. The engine doesn't and shouldn't know application keys. This also means verification failures are the application's problem, which is semantically correct in trust schema terms.



## Prompt:
3/25/2026, 9:55:46 AM

Let's get back to the pipeline stage trait design.



## Response:
3/25/2026, 9:56:55 AM

Good. This is where Rust forces the most interesting decisions. Let me think through the design space before proposing anything.

The core tension is that a `PipelineStage` needs to:
1. Be **async** (faces are async, crypto is async)
2. Be **composable** at runtime (you want to add/remove stages like a strategy pattern)
3. Carry **mutable context** across stages (the packet, incoming face, PIT tokens, etc.)
4. Support **short-circuiting** (a stage can absorb a packet — CS hit, Nack, etc.)

Those four requirements fight each other in Rust in specific ways. Let me show the design options:

````plaintext
Tool: show_widget
````

**Why Option B with a dyn wrapper is the right call:**

Native `async fn` in traits (stable since 1.75) gives you clean ergonomics and zero allocation when the pipeline is monomorphized — which it will be for the common built-in stages. The object-safety problem only surfaces when you need *runtime-configurable* stages (e.g. loading a strategy plugin at startup). For that, you add one wrapper:

```rust
struct DynStage(Box<dyn Fn(PacketContext) -> BoxFuture<'static, Result<Action>> + Send + Sync>);
```

This pays the allocation cost only for stages that genuinely need dynamic dispatch, not on every hop through the built-in pipeline.

**On `PacketContext` ownership — this is subtle:**

`PacketContext` should be passed **by value** through stages, not by `&mut`. Notice `Action::Continue` *returns* the context back. This means a stage that short-circuits (CS hit → `Action::Satisfy`) simply doesn't return the context at all — Rust's ownership makes this explicit and compiler-enforced. No stage can accidentally use a context after it's been consumed. This is a meaningful improvement over ndn-cxx's approach where context mutation through a raw pipeline is unchecked.

**The `local_tag: AnyMap` field deserves thought:**

NDN-cxx's `TagHost` pattern — where stages attach arbitrary typed tags to packets — maps to an `AnyMap` (via the `anymap` crate or a simple `HashMap<TypeId, Box<dyn Any + Send>>`). This is the escape hatch for stages that need to communicate without coupling. Use it sparingly; prefer explicit fields on `PacketContext` for anything the core pipeline touches on every packet.

**The `Action` enum does the work that `next()` does in middleware chains:**

Rather than passing a `next` closure through each stage (Tower's model), the runner loop drives dispatch:

```rust
async fn run_pipeline(
    stages: &[Box<dyn PipelineStage>],
    mut ctx: PacketContext,
) -> Result<()> {
    for stage in stages {
        match stage.process(ctx).await? {
            Action::Continue(next_ctx) => ctx = next_ctx,
            Action::Send(pkt, face) => return send_to_face(pkt, face).await,
            Action::Satisfy(data) => return satisfy_pit(data).await,
            Action::Drop(reason) => return Ok(log_drop(reason)),
            Action::Nack(reason) => return send_nack(reason).await,
        }
    }
    Ok(())
}
```

This is cleaner than Tower's nested-future model for NDN specifically because NDN pipelines are **linear with early exits**, not middleware stacks with bidirectional flow. You don't need the response to bubble back up through every stage the way HTTP middleware does.

**One remaining question worth deciding now:** should `PacketContext` carry the packet as raw `bytes::Bytes` (decoded on demand by stages that need it) or as a fully decoded `enum IncomingPacket { Interest(Interest), Data(Data), Nack(Nack) }`? The decoded enum is ergonomic but means you pay parse cost upfront. Raw bytes lets the CS hit stage short-circuit before ever decoding. In practice, the Name needs to be parsed for FIB lookup regardless, so a **partially decoded** form — Name parsed, rest lazy — is probably the right balance.

Want to go deeper on any of these: the `PacketContext` fields, the `Action` enum variants, or how the Interest and Data pipelines diverge in their stage sets?



## Prompt:
3/25/2026, 5:13:30 PM

Let's look into PacketContext fields next.



## Response:
3/25/2026, 5:14:39 PM

Good. The fields need to serve all stages across both pipelines without becoming a grab-bag struct. Let me think through what each pipeline stage actually needs to read and write.

````plaintext
Tool: show_widget
````

A few design decisions worth locking in now:

**`name` is hoisted out of `DecodedPacket` and into the top-level struct.** Every stage touches the name — FIB lookup, PIT lookup, CS lookup, dispatch. Keeping it as `Arc<Name>` at the top level means stages clone the arc cheaply rather than pattern-matching into the enum every time. The name is also the one field shared between both pipelines identically.

**`DecodedPacket::Raw` is a real variant, not a fallback.** The TLV decode stage transitions `Raw → Interest/Data/Nack`. Stages before decode (face check, rate limiting) operate on `Raw` and simply pass it through. This makes the decode boundary explicit and means a pass-through forwarding stage — one that just moves packets between faces without caring about content — never pays the decode cost at all.

**`out_faces: SmallVec<FaceId>`** rather than `Vec` — FIB lookup in practice returns one or two faces. `SmallVec<[FaceId; 4]>` keeps this on the stack for the common case. `FaceId` is just a `u32` newtype so the whole thing is 32 bytes inline.

**`pit_token` is `Option<PitToken>` not `PitToken`.** It starts as `None` and the PIT stage writes it. Stages after PIT lookup can assert it is `Some` — if you want to be defensive you add a `debug_assert!` in the dispatch stage. This is better than a sentinel value and makes the pipeline ordering violation visible at runtime in debug builds.

**The two flags deserve a note.** `cs_hit` drives the short-circuit in `Action::Satisfy` — the CS lookup stage sets it and the runner skips the rest of the Interest pipeline. `verified` is set by signature verification in the Data pipeline so the application callback can check it without re-verifying. Both are plain `bool` rather than a bitfield — the struct will be padded anyway and the clarity is worth more than the byte.

**What `tags: AnyMap` is and isn't for.** It is the right home for things like: a congestion marking flag set by a rate-limiter stage, a trust anchor resolved by a validator stage for the application to inspect, or telemetry timestamps added by an instrumentation stage. It is the wrong home for anything the built-in forwarding logic depends on — those get explicit fields. The rule of thumb: if removing a tag would break forwarding, it should be a field; if it enriches the packet for downstream consumers, it belongs in `tags`.

**One open question: `arrival: Instant` vs `arrival: u64` (nanoseconds since epoch).** `Instant` is not `Send` on all platforms and cannot be serialized, which matters if you ever want to log or export pipeline traces. A `u64` nanosecond timestamp from `tokio::time` is more portable. Worth deciding early since it touches every packet.

The complete struct then looks like:

```rust
pub struct PacketContext {
    pub raw_bytes:  Bytes,
    pub face_id:    FaceId,
    pub name:       Arc<Name>,
    pub packet:     DecodedPacket,
    pub pit_token:  Option<PitToken>,
    pub out_faces:  SmallVec<[FaceId; 4]>,
    pub cs_hit:     bool,
    pub verified:   bool,
    pub arrival:    u64,        // ns since Unix epoch
    pub tags:       AnyMap,
}
```

Want to move on to the FIB and PIT data structures next, or dig into how the two pipelines diverge in their stage sets?



## Prompt:
3/25/2026, 6:41:06 PM

Let's move on to the FIB and PIT data structures.



## Response:
3/25/2026, 6:42:22 PM

Good. These are the two most performance-critical structures in the forwarder — every packet touches both of them on the hot path. They have very different access patterns, which drives different design choices.

````plaintext
Tool: show_widget
````

Let me go through the key decisions for each structure.

**FIB — the trie design**

The trie nodes use `HashMap<Component, Arc<RwLock<TrieNode>>>` at each level. The `Arc` lets you hold a reference to a child while releasing the parent lock, which is essential for concurrent longest-prefix match — you walk down the trie taking one read lock at a time, releasing each parent before descending. Without the `Arc` you'd have to hold every ancestor lock for the duration of the walk.

`Component` as the map key needs a careful `Hash` implementation. NDN name components are arbitrary byte strings so you hash the raw bytes, but you also need to handle implicit digest components correctly — two components are equal only if their TLV type *and* value match, not just value.

Longest-prefix match walks to the deepest matching node and returns the last `FibEntry` it saw on the way down. This means every `TrieNode` along a matching path can optionally hold a `FibEntry` — not just the leaves. The walk is:

```rust
fn lpm(&self, name: &Name) -> Option<FibEntry> {
    let mut node = self.root.read();
    let mut best = node.entry.clone();
    for component in name.components() {
        match node.children.get(component) {
            None => break,
            Some(child) => {
                let child = child.read();
                if child.entry.is_some() { best = child.entry.clone(); }
                node = child;  // release parent, hold child
            }
        }
    }
    best
}
```

FIB updates (prefix registration from applications) are rare compared to lookups, so `RwLock` per node is the right call — reads from many Tokio tasks never block each other.

**PIT — the two-level structure**

`DashMap` gives you a sharded concurrent hashmap without a global lock. The key is `(Name, Option<Selector>)` — selectors matter because two Interests for the same name but different `MustBeFresh` or `CanBePrefix` values are distinct PIT entries in NDN semantics.

The split into `InRecord` and `OutRecord` per `PitEntry` is directly from the NDN spec. Each incoming face gets an `InRecord` with its nonce and expiry. Each face the Interest was forwarded on gets an `OutRecord`. When Data arrives, you fan it back to all `InRecord` faces. When a Nack arrives on an `OutRecord` face, you mark that record and potentially re-forward on another face from the FIB.

`nonces_seen: SmallVec<[u32; 4]>` on `PitEntry` is the loop suppression mechanism. When an Interest arrives, you check its nonce against this list. Four slots covers the vast majority of real topologies inline without heap allocation.

**`PitToken` as a `u64` hash**

The alternative is storing a raw pointer or index into the `DashMap`, but both create aliasing and lifetime problems across `await` points in async code. A `u64` hash of `(Name, Selector)` is safe to copy freely across tasks and can be recomputed to look up the entry. The collision probability at realistic PIT sizes (tens of thousands of entries) is negligible. You use it like:

```rust
pub struct PitToken(u64);

impl PitToken {
    pub fn from_interest(name: &Name, selector: Option<&Selector>) -> Self {
        let mut h = FxHasher::default();
        name.hash(&mut h);
        selector.hash(&mut h);
        PitToken(h.finish())
    }
}
```

`FxHasher` rather than `SipHash` here — PIT tokens are not user-controlled inputs so you don't need DoS-resistant hashing, and `FxHasher` is meaningfully faster on short keys.

**The expiry wheel**

Tokio's `sleep` per PIT entry doesn't scale — at 100k concurrent Interests you'd have 100k timer futures. A hierarchical timing wheel (the `timing-wheel` crate, or a hand-rolled one) gives you O(1) insert and expiry firing at 1 ms resolution, which matches NDN's Interest lifetime granularity. The wheel fires a batch of expired tokens; a background task drains the batch and removes them from the `DashMap`.

```rust
// background expiry task
loop {
    let expired = wheel.advance_to(now_ns());
    for token in expired {
        pit.remove(&token);
    }
    tokio::time::sleep(Duration::from_millis(1)).await;
}
```

**One open question worth deciding now:** should `PitEntry` hold `strategy_state: AnyMap` as shown, or should forwarding strategy state live in a separate sidecar map keyed by `PitToken`? The `AnyMap` approach keeps all per-Interest state in one place but couples the PIT struct to the strategy system. A sidecar map keeps the PIT pure but requires a second lookup. Given that not every Interest will have non-trivial strategy state, a sidecar `DashMap<PitToken, StrategyState>` is probably cleaner — the PIT stays a plain data structure.

Want to move on to the content store, or shift to the face abstraction and how faces feed packets into the pipeline?



## Prompt:
3/25/2026, 6:49:37 PM

Let's look at the face abstraction and how faces feed packets into the pipeline.



## Response:
3/25/2026, 6:50:58 PM

Good. The face abstraction is where async Rust really earns its keep — each face is an independent I/O source that needs to feed a shared pipeline without blocking other faces.

````plaintext
Tool: show_widget
````

The central design decision here is the **task topology** — how face I/O tasks relate to the pipeline runner.

**One task per face, one shared pipeline runner**

Each face runs an independent Tokio task whose only job is calling `face.recv().await` in a loop and forwarding raw bytes onto a shared `mpsc` channel. The pipeline runner task drains that channel and spawns a new task per packet via `tokio::spawn`. This gives you three things:

A slow face (high latency remote peer) never stalls other faces — they all push independently onto the channel. A CPU-heavy pipeline stage (signature verification) runs in its own spawned task and doesn't block the runner from dispatching the next packet. And the `mpsc` channel naturally applies backpressure — if the pipeline is saturated, `tx.send().await` will yield the face task, which is exactly what you want.

The `RawPacket` struct that crosses the channel is minimal:

```rust
struct RawPacket {
    bytes:   Bytes,
    face_id: FaceId,
    arrival: u64,    // timestamp taken at recv, before channel enqueue
}
```

Taking the timestamp at recv rather than at pipeline entry matters for Interest lifetime accounting — the clock starts when the packet arrives at the face, not when the pipeline gets around to it.

**The `Face` trait's send and recv split**

`recv` is only ever called from the face's own task — there is exactly one caller. `send` can be called from any pipeline task concurrently, since multiple packets may be forwarded to the same face simultaneously. This asymmetry means `recv` needs no synchronization, but `send` must be `&self` (not `&mut self`) and internally synchronized. For UDP that's trivially true — `UdpSocket::send_to` takes `&self`. For TCP and Unix you need an `Arc<Mutex<WriteHalf>>` internally to serialize concurrent sends on the same stream.

**TCP and Unix framing with `tokio_util::codec`**

UDP is naturally packet-framed but TCP and Unix sockets are byte streams. NDN uses TLV length-prefix framing — the first two bytes of each packet encode the total length. `tokio_util::codec` gives you a `Framed<TcpStream, TlvCodec>` where `TlvCodec` implements `Decoder` by reading the length prefix, buffering until the full packet is available, then yielding a `Bytes`. This keeps the face implementation clean:

```rust
impl Face for TcpFace {
    async fn recv(&self) -> Result<Bytes> {
        self.framed.next().await
            .ok_or(Error::FaceClosed)?
    }
    async fn send(&self, pkt: Bytes) -> Result<()> {
        self.framed.send(pkt).await
    }
}
```

**UDP fragmentation via NDNLPv2**

NDN data packets can reach 8800 bytes but UDP MTU is typically 1500 bytes on Ethernet. NDNLPv2 (the NDN link protocol) handles fragmentation and reassembly at the face layer, below the pipeline. The UDP face wraps a reassembly buffer — incoming fragments are held until the sequence is complete, then the reassembled packet is sent up as a single `Bytes`. Outgoing large packets are split into fragments before `send_to`. This stays entirely inside the UDP face implementation and is invisible to the pipeline.

**`FaceTable` and the send path**

`DashMap<FaceId, Arc<dyn Face>>` is the right structure here for the same reason as the PIT — concurrent reads from many pipeline tasks with occasional writes on face add/remove. A pipeline stage that needs to send clones the `Arc` out of the table, releases the table reference, then calls `face.send().await`. The `Arc` clone keeps the face alive across the await point without holding the table lock during I/O — which would be a deadlock waiting to happen.

Face removal needs care: when a remote peer disconnects, the face task's `recv` returns an error, the task exits, and it should remove itself from the `FaceTable` and notify the PIT to clean up any `OutRecord` entries pointing to that face. A `FaceEvent` channel from each face task back to a face manager task handles this cleanly:

```rust
enum FaceEvent {
    Closed(FaceId),
    Error(FaceId, Error),
}
```

**One remaining question:** should the app face (in-process channel pair) implement the same `Face` trait as network faces, or should it have a separate fast path that bypasses serialization entirely? The uniform trait is cleaner architecturally, but an app face that skips TLV encoding and passes `Arc<DecodedPacket>` directly would save meaningful work on the hot path for local applications. This is the same tradeoff ndnd faces with its Unix socket — worth deciding before you commit the face trait signature.

Want to move on to the content store, the forwarding strategy abstraction, or circle back to any of the earlier structures?



## Prompt:
3/25/2026, 7:00:24 PM

Let's look at the forwarding strategy abstraction.



## Response:
3/25/2026, 7:01:44 PM

Good. The forwarding strategy is the most architecturally interesting component after the pipeline itself — it's the place where NDN's "named data" semantics actually get expressed as routing decisions. It's also where ndn-cxx and NFD's design is most tangled, so Rust gives you a real opportunity to improve on it.

Let me first lay out what a strategy actually needs to decide, then work through the trait design.

````plaintext
Tool: show_widget
````

Here are the key decisions and how they differ from NFD's approach.

**The trait has two required methods, not one per event**

NFD uses a single virtual dispatch per event type — `afterReceiveInterest`, `beforeSatisfyInterest`, `afterReceiveNack` — all as separate overridable methods on a base class. In Rust the cleaner split is two required async methods (`after_receive_interest`, `after_receive_data`) with optional hooks for loop detection, timeout, and Nack handling defaulting to no-ops. Most strategies only care about the forwarding decision, not every event. This keeps simple strategies simple:

```rust
struct BestRouteStrategy;

impl Strategy for BestRouteStrategy {
    fn name(&self) -> &Name { &BEST_ROUTE_NAME }

    async fn after_receive_interest(
        &self, ctx: &mut StrategyContext
    ) -> ForwardingAction {
        let nexthops = ctx.fib_entry.nexthops_excluding(ctx.in_face);
        match nexthops.first() {
            Some((face_id, _cost)) => ForwardingAction::Forward(smallvec![*face_id]),
            None => ForwardingAction::Nack(NackReason::NoRoute),
        }
    }

    async fn after_receive_data(
        &self, ctx: &mut StrategyContext
    ) -> ForwardingAction {
        ForwardingAction::Forward(
            ctx.pit_entry.in_record_faces().collect()
        )
    }
}
```

**`StrategyContext` is a struct of references, not owned data**

The strategy does not own the PIT entry, FIB entry, or face table — it gets immutable references to them through `StrategyContext`. The only thing it owns across calls is its `StrategyState`. This is a deliberate constraint: it prevents a strategy from modifying forwarding tables directly, which in NFD has been a source of subtle bugs where strategies mutate state in ways the pipeline doesn't expect.

The `state: &mut StrategyState` reference is the one mutable field — it is the strategy's scratch pad, keyed by name prefix rather than by PIT token. This matters for adaptive strategies like ASF (Adaptive SRTT-based Forwarding) that need to track RTT measurements and face rankings across many Interests for the same prefix, not just within a single Interest's lifetime.

**`ForwardingAction::ForwardAfter` enables probing**

This is the variant NFD lacks cleanly. Strategies like ASF need to forward on a primary face immediately but probe a secondary face after a delay — if the primary doesn't respond within its measured RTT, forward on the backup too. `ForwardAfter { faces, delay }` tells the pipeline runner to schedule a delayed send via Tokio's timer, without the strategy needing to spawn its own tasks or hold timers internally:

```rust
// in the pipeline runner, after strategy returns ForwardAfter
tokio::spawn(async move {
    tokio::time::sleep(delay).await;
    // re-check PIT — only send if entry still unsatisfied
    if pit.get(&token).map(|e| !e.is_satisfied).unwrap_or(false) {
        face_table.get(&face_id)?.send(pkt).await;
    }
});
```

The re-check before sending is important — the Data may have arrived during the delay window and the Interest is already satisfied.

**`MeasurementsTable` is separate from `StrategyState`**

NFD conflates these into a single `measurements` accessor that returns mutable per-entry state. Separating them in Rust makes the access pattern explicit. `MeasurementsTable` holds read-mostly EWMA statistics (RTT, satisfaction rate per face per prefix) updated by the pipeline on every Data arrival. `StrategyState` holds write-heavy per-strategy scratch data. Keeping them in separate `DashMap` instances means RTT updates don't contend with strategy state reads:

```rust
pub struct MeasurementsEntry {
    pub rtt_per_face:          HashMap<FaceId, EwmaRtt>,
    pub satisfaction_rate:     f32,      // EWMA over last N interests
    pub last_updated:          u64,
}
```

**`StrategyTable` is a second instance of the name trie**

The same longest-prefix match structure as the FIB, but mapping name prefixes to `Arc<dyn Strategy>` instead of nexthops. Using `Arc<dyn Strategy>` here rather than `Box` is deliberate — multiple name prefixes can share the same strategy instance without copying, and the `Arc` clone in the pipeline is cheap.

The pipeline's FIB lookup stage resolves both the `FibEntry` and the `Strategy` in one pass — two trie walks, but both share the same `Name` decomposition so the component iteration happens once. You can even combine them into a single walk that returns both if contention becomes a concern.

**One significant open question: should strategies be able to initiate their own Interests?**

NFD allows strategies to express Interests autonomously — for probing, discovery, or measurement. This is powerful but makes the strategy a full actor rather than a pure decision function, which complicates the ownership model significantly. In Rust the clean answer is to give strategies a `Probe` channel — a `mpsc::Sender<Interest>` they can push onto — which feeds back into the pipeline as if arriving on a synthetic internal face. The strategy stays a decision function; the channel is the controlled escape hatch for autonomous behavior.

Want to dig into how the strategy integrates with the pipeline stage sequence specifically, or move on to the content store?



## Prompt:
3/25/2026, 7:08:53 PM

Let's look at how the strategy integrates with the pipeline stage sequence.



## Response:
3/25/2026, 7:10:18 PM

Good. This is where all the previous design decisions converge — the pipeline stages, `PacketContext`, `ForwardingAction`, and the `StrategyTable` all have to connect cleanly without coupling.

Let me map out both pipelines in full first, then focus on exactly where and how the strategy plugs in.

````plaintext
Tool: show_widget
````

Several things here are worth unpacking carefully.

**The strategy stage is a single `PipelineStage` implementation**

Rather than splitting strategy into a separate hook system like NFD does, it lives as one stage in the sequence — `StrategyStage`. It holds `Arc` references to the shared tables it needs, constructs a `StrategyContext` from the current `PacketContext`, dispatches to the right strategy method based on packet type, and translates the returned `ForwardingAction` back to a pipeline `Action`. This keeps the strategy completely decoupled from the pipeline runner — it never sees `PacketContext` directly, only the curated view in `StrategyContext`.

**The two pipelines share stages 1 and 2 but diverge immediately after**

Both pipelines start with face check and TLV decode — these are identical. After that the Interest pipeline goes CS → PIT → FIB+strategy lookup → strategy call → dispatch, while the Data pipeline goes PIT match → strategy lookup → measurements update → strategy call → CS insert → dispatch. The ordering differences are load-bearing:

CS lookup happens before PIT check on the Interest side because a CS hit lets you skip PIT insertion entirely — you never need to record the Interest if you can satisfy it immediately. On the Data side, CS insert happens after the strategy call but before dispatch, so the cached copy is available for any immediately following Interests for the same name, but the strategy still gets to decide whether to forward the Data at all first.

Measurements update happens before the strategy call on the Data side, not after. This is deliberate — the strategy's `after_receive_data` implementation should be able to read the freshly updated RTT sample to make its forwarding decision. If you updated measurements after the call, an adaptive strategy like ASF would always be working with one sample behind.

**`forwarding_action_to_pipeline_action` is where `ForwardAfter` gets scheduled**

This translation function is the one place in the codebase where Tokio timers are spawned for delayed forwarding. It looks roughly like:

```rust
fn forwarding_action_to_pipeline_action(
    action: ForwardingAction,
    ctx: PacketContext,
    face_table: Arc<FaceTable>,
    pit: Arc<Pit>,
) -> Action {
    match action {
        ForwardingAction::Forward(faces) => {
            Action::Send(ctx, faces)
        }
        ForwardingAction::ForwardAfter { faces, delay } => {
            let token = ctx.pit_token;
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                if pit.get(&token).map(|e| !e.is_satisfied).unwrap_or(false) {
                    for face_id in faces {
                        if let Some(f) = face_table.get(&face_id) {
                            let _ = f.send(ctx.raw_bytes.clone()).await;
                        }
                    }
                }
            });
            Action::Continue(ctx)  // primary forwarding handled separately
        }
        ForwardingAction::Nack(reason) => Action::Nack(reason),
        ForwardingAction::Suppress    => Action::Drop(DropReason::Suppressed),
    }
}
```

The `Action::Continue` return for `ForwardAfter` is the subtle part — the strategy stage returns `Continue` after spawning the delayed task, allowing the pipeline to proceed with the primary forward decision which was already handled by the strategy issuing `Forward` for the primary face alongside `ForwardAfter` for the probe. In practice a strategy doing probing returns both:

```rust
// ASF strategy: forward on best face immediately, probe second face after RTT
ForwardingAction::Forward(smallvec![best_face])
// then separately:
ForwardingAction::ForwardAfter { faces: smallvec![probe_face], delay: measured_rtt }
```

This means `after_receive_interest` may need to return a `Vec<ForwardingAction>` rather than a single action. That is worth reconsidering in the trait signature — returning `SmallVec<[ForwardingAction; 2]>` handles the common case of one action with no allocation, and two actions for the probing case still inline.

**The timeout loop-back is handled outside the pipeline**

The dashed timeout arrow in the diagram on the Interest pipeline side represents the expiry wheel firing — not a pipeline stage calling back into itself. When the wheel fires a `PitToken`, a dedicated expiry handler task calls `strategy.interest_timeout(&mut sctx)` directly, bypassing the full pipeline. The strategy can then return `ForwardingAction::Forward` to retry on another face, or `ForwardingAction::Suppress` to let the entry die. This keeps the pipeline linear while still giving strategies a timeout hook.

**One structural consequence of this design worth noting**

Because `StrategyStage` holds `Arc<StrategyTable>` and strategies are `Arc<dyn Strategy>`, adding or replacing a strategy at runtime is safe — you update the `StrategyTable` trie under a write lock, and in-flight packets using the old strategy finish naturally since they hold their own `Arc` clone. This gives you hot-swappable strategies with no in-flight packet disruption, which NFD achieves only with considerably more machinery.

The content store is the one remaining major structure. Want to go there next, or is there a specific part of the strategy integration you want to dig into further?



## Prompt:
3/25/2026, 7:20:34 PM

Let's look at the content store.



## Response:
3/25/2026, 7:22:09 PM

Good. The content store is the most varied component in terms of implementation options — the right design depends heavily on workload, and Rust's trait system lets you make that variation explicit rather than baking in assumptions.

Let me start with the trait boundary, then work through the implementation options and their tradeoffs.

````plaintext
Tool: show_widget
````

**The trait boundary is deliberately narrow**

Three methods: `get`, `insert`, `evict`. The trait does not expose iteration, statistics, or internal structure — those belong on concrete types. This keeps every implementation substitutable and lets `NullCs` be a genuine zero-cost no-op:

```rust
pub struct NullCs;
impl ContentStore for NullCs {
    async fn get(&self, _: &Interest) -> Option<CsEntry> { None }
    async fn insert(&self, _: &Data, _: CsMeta) -> InsertResult { InsertResult::Skipped }
    async fn evict(&self, _: &Name) -> bool { false }
    fn capacity(&self) -> CsCapacity { CsCapacity::zero() }
}
```

Routers that want to push caching to the application layer can configure `NullCs` and pay nothing on the pipeline hot path.

**`CsEntry` holds wire-format `Bytes`, not a decoded `Data`**

This is the most important implementation decision. Storing the already-encoded wire bytes means a CS hit directly produces the bytes you hand to the face's `send()` — no re-encoding. It also means the CS is independent of your packet type definitions and survives changes to the `Data` struct without migration. The tradeoff is that freshness checks require decoding the `FreshnessPeriod` TLV on insert, which you do once and store as `stale_at`.

**Lookup semantics are where the CS earns its complexity**

`get()` must honour three Interest selectors that affect matching:

`CanBePrefix` is the hard one. When true, any cached Data whose name has the Interest name as a prefix is a valid match — you want the longest matching name. A plain `HashMap<Arc<Name>, CsEntry>` cannot do prefix matching efficiently. The right structure is a **name trie over the CS entries**, parallel to the FIB trie, so prefix lookups are O(name length) rather than O(entries). For the exact-match case (`CanBePrefix=false`) you still want O(1) lookup, so you maintain both a trie and a `HashMap` — the trie for prefix queries, the map for exact queries. Inserts go into both; evictions remove from both.

`MustBeFresh` is a simple timestamp check against `stale_at` on the returned entry. Stale entries are not evicted on a miss — they remain in the cache for consumers that don't set `MustBeFresh`.

**`ShardedCs<C>` reduces contention without duplicating logic**

The plain `LruCs` wraps the `lru` crate's `LruCache` in a `Mutex`. Under high packet rates that mutex becomes a bottleneck. `ShardedCs<C>` is a generic wrapper that shards any `ContentStore` implementation across N independent instances keyed by a hash of the name's first component:

```rust
pub struct ShardedCs<C: ContentStore> {
    shards: Vec<C>,
    shard_count: usize,
}

impl<C: ContentStore> ContentStore for ShardedCs<C> {
    async fn get(&self, interest: &Interest) -> Option<CsEntry> {
        let shard = self.shard_for(&interest.name);
        self.shards[shard].get(interest).await
    }
    // insert and evict similarly
}
```

Sharding by first name component is better than sharding by full name hash for NDN because related content (e.g. `/video/stream/seg/1`, `/video/stream/seg/2`) lands in the same shard, preserving locality for sequential access patterns.

**`PersistentCs` — RocksDB vs redb**

For a router that survives restarts with a warm cache, you need a persistent backend. Two realistic options:

`RocksDB` via the `rocksdb` crate gives you a mature LSM-tree with built-in LRU block cache, compaction, and TTL support. TTL maps directly onto `FreshnessPeriod` — you can configure RocksDB to expire entries automatically. The downside is a large dependency and a C++ FFI boundary.

`redb` is a pure-Rust embedded database with MVCC and a much smaller footprint. It lacks built-in TTL so you manage freshness expiry yourself via the timing wheel. For a Rust-first stack `redb` is the better fit unless you need RocksDB's compaction tuning for very large caches.

Key layout for either backend:

```
key:   [name TLV bytes]          // lexicographic order == name order
value: [wire Data bytes]
cf:    "cs"                       // RocksDB column family
```

Storing name TLV bytes as the key gives you range scans for prefix matching essentially for free — a RocksDB range scan from `/prefix/\x00` to `/prefix/\xFF` returns all Data under that prefix in one iterator pass.

**Capacity bounding by bytes, not entry count**

NDN Data packets range from a hundred bytes for a short response to 8800 bytes for a full MTU packet. Bounding by entry count means a cache full of 8800-byte entries uses 88× more memory than the same count of 100-byte entries. Byte-accurate capacity requires tracking `CsEntry.data.len()` on every insert and eviction. The LRU implementation maintains a running `current_bytes: usize` and evicts the least-recently-used entries until `current_bytes <= capacity_bytes` after each insert.

**Freshness: passive check on `get()` is sufficient for most deployments**

Active expiry via a timing wheel (same structure as the PIT) is worth adding only if your workload has a high proportion of short-lived Data. For typical NDN content — versioned files, sensor readings with moderate freshness periods — passive checking is simpler and correct: stale entries remain in the cache occupying space but are never served to `MustBeFresh` consumers. They get evicted naturally by LRU pressure. If you do add active expiry, the timing wheel fires `evict(name)` on the CS, exactly as it fires PIT entry removal on the PIT.

**One open question worth settling now: should `get()` be `async`?**

For `LruCs` and `ShardedCs` the operation is entirely in-memory and synchronous — making it `async` adds a state machine overhead for no benefit on the hot path. For `PersistentCs` it genuinely needs to be async (disk I/O). The trait forces `async` on all implementations to keep them substitutable. The cost for the in-memory case is negligible since Tokio will inline the no-op future, but it is worth being aware of. An alternative is splitting the trait:

```rust
trait SyncContentStore { fn get(&self, interest: &Interest) -> Option<CsEntry>; }
trait ContentStore: SyncContentStore {
    async fn get_async(&self, interest: &Interest) -> Option<CsEntry> {
        self.get(interest)  // default: delegate to sync
    }
}
```

This lets the pipeline call `get_async()` uniformly while in-memory implementations skip the async machinery. Whether that complexity is worth the hot-path saving depends on how aggressively you profile the CS lookup stage.

That covers all the major structures. Want to look at how the engine assembles these components at startup — the initialization and wiring — or is there another area you want to revisit?



## Prompt:
3/25/2026, 7:33:06 PM

Let's look at how the engine assembles these components at startup.  Does this design combine the engine and NFD or are they still separate?



## Response:
3/25/2026, 7:34:28 PM

Good question to clarify first. The design we've built is **a single unified process** — the engine *is* the forwarder. There is no separation analogous to NFD + ndn-cxx. Let me explain why, then show the assembly.

In the ndn-cxx / NFD world the split exists for a historical reason: ndn-cxx is a client library that applications link against, and NFD is a separate daemon they connect to via Unix socket. The library and daemon were developed independently and the IPC boundary is load-bearing.

In our Rust design that split was consciously collapsed. The `AppFace` using in-process `mpsc` channels *is* the application's connection to the forwarder — there is no Unix socket on the local fast path, no separate daemon process for the forwarding plane. The engine is a library that either runs embedded in a dedicated forwarder binary or links directly into an application that wants self-contained NDN. The Unix socket we discussed earlier is only the *control plane* — prefix registration, face management — not the forwarding data path.

This means the assembly question is really: how does a `ForwarderEngine` struct own and wire all the components we designed?

````plaintext
Tool: show_widget
````

**`ForwarderEngine` owns everything through `Arc`**

Every shared table is wrapped in `Arc` rather than owned directly. This is necessary because the pipeline runner task, per-packet tasks, face tasks, expiry task, and control task all need concurrent access to the same FIB, PIT, CS, and face table. `Arc` gives each task a handle without copying or borrowing across `await` points. The engine struct itself is cheaply cloneable — cloning it gives you another handle to the same running engine, which is how you'd hand the engine to application code that needs to register prefixes or add faces after startup.

**`build()` does five things in order**

First it constructs all the shared tables. Then it builds the pipeline stage sequence — a `Vec<Box<dyn PipelineStage>>` assembled from the configured components, with the strategy stage holding `Arc` clones of the strategy table and measurements table. Then it creates the `mpsc` channel that connects face tasks to the pipeline runner, using `pipeline_channel_cap` from config as the backpressure bound. Then it spawns all the tasks into a `JoinSet`. Finally it returns the `ForwarderEngine` handle and a `ShutdownHandle`.

The pipeline stage sequence is fixed at build time:

```rust
fn build_interest_pipeline(engine: &EngineInner) -> Vec<Box<dyn PipelineStage>> {
    vec![
        Box::new(FaceCheckStage::new(engine.face_table.clone())),
        Box::new(TlvDecodeStage),
        Box::new(CsLookupStage::new(engine.cs.clone())),
        Box::new(PitCheckStage::new(engine.pit.clone())),
        Box::new(StrategyStage::new(
            engine.strategy_table.clone(),
            engine.measurements.clone(),
            engine.face_table.clone(),
        )),
        Box::new(DispatchStage::new(engine.face_table.clone())),
    ]
}
```

Fixing the sequence at build time rather than making it runtime-configurable is a deliberate choice — it means the compiler can inline and optimize the stage dispatch loop for the known concrete types, and it eliminates a whole class of bugs where misconfigured stage ordering causes subtle forwarding failures.

**Shutdown is cooperative via `CancellationToken`**

Every long-running task receives a clone of a `tokio_util::sync::CancellationToken`. Face tasks select between `face.recv()` and `token.cancelled()`. The pipeline runner selects between `rx.recv()` and `token.cancelled()`. When the shutdown handle calls `token.cancel()`, all tasks see the cancellation at their next `await` point, drain what they can, and exit. The `JoinSet` then awaits all of them:

```rust
pub async fn shutdown(self) {
    self.cancel.cancel();
    while let Some(result) = self.tasks.join_next().await {
        if let Err(e) = result {
            tracing::warn!("task panicked during shutdown: {e}");
        }
    }
}
```

Panics in tasks are caught by `JoinSet` and logged rather than propagating — a panicking face task should not bring down the whole forwarder.

**The two usage modes share identical engine code**

The standalone forwarder binary is thin:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = EngineConfig::from_file("ndn-engine.toml")?;
    let (engine, shutdown) = EngineBuilder::new(config)
        .content_store(ShardedCs::new(LruCs::new(64 * 1024 * 1024)))
        .strategy(BestRouteStrategy::new(), Name::root())
        .face(UdpFace::bind("0.0.0.0:6363").await?)
        .face(UnixControlFace::bind("/run/ndn/engine.sock").await?)
        .build()
        .await?;

    tokio::signal::ctrl_c().await?;
    shutdown.shutdown().await;
    Ok(())
}
```

The embedded mode gives the application a direct `AppFace` handle with no IPC:

```rust
let (engine, shutdown) = EngineBuilder::new(config)
    .strategy(BestRouteStrategy::new(), Name::root())
    .build()
    .await?;

// AppFace is an in-process channel pair — zero serialization
let app_face = engine.new_app_face().await?;
app_face.register_prefix("/my/app".parse()?).await?;

// express an Interest
let data = app_face.express(Interest::new("/my/app/data")).await?;
```

`engine.new_app_face()` creates an `mpsc` channel pair, wraps one end as an `AppFace` implementing the `Face` trait, registers it in the `FaceTable`, and spawns its face task — all atomically from the application's perspective.

**One tension worth naming explicitly**

The design we've built is a *library-first* forwarder — the `ForwarderEngine` is a Rust crate that binaries depend on, not a daemon that processes connect to. This is the right call for a Rust-native stack, but it means inter-application forwarding only works when applications either share a process or connect to a standalone forwarder binary via the control socket and a network face. Two separate Rust NDN applications on the same machine that both embed the engine directly will not forward to each other — they each have their own engine instance with no shared state. The standalone binary mode with `AppFace` over shared memory (as we discussed at the start) is the answer for that case.

That completes the full architecture. Want to revisit any component, talk through the crate structure and how to split this into a Rust workspace, or look at something else?



## Prompt:
3/25/2026, 8:57:01 PM

How would logging best be done?



## Response:
3/25/2026, 8:58:16 PM

Good timing to address this — logging touches every component we've designed and the decisions made now affect observability for the lifetime of the project.

Rust's logging ecosystem has a clear answer here: **`tracing`**, not `log`. The distinction matters for an async forwarder specifically.

````plaintext
Tool: show_widget
````

**Why `tracing` and not `log`**

The core problem with `log` in an async forwarder is that log messages have no context. When a thousand packets are in flight simultaneously across dozens of Tokio tasks, a log line saying `"PIT miss"` is useless — you cannot tell which packet, which face, or which name it refers to. `tracing` solves this with *spans* — structured scopes that carry fields across `await` points. Any event emitted inside a span automatically inherits its fields. A PIT miss event inside a `packet` span automatically carries `name`, `face_id`, and `packet_type` without you threading those values through every function call.

**One span per packet is the right granularity**

You create the packet span at pipeline entry — before TLV decode, so before you even know the name. You attach it to the async block via `.instrument(span)`, which means Tokio will re-enter the span every time the task is polled, even across `await` points where other tasks run in between. After TLV decode you add the name field to the span:

```rust
tracing::Span::current().record("name", tracing::field::display(&ctx.name));
```

This is the pattern for fields you cannot know at span creation — declare them with `tracing::field::Empty` upfront and record them once available. This keeps the span honest about what it knew and when.

**The `#[tracing::instrument]` macro on stage methods**

Rather than manually entering spans in every stage, annotate the `process` method:

```rust
impl PipelineStage for PitCheckStage {
    #[tracing::instrument(skip(self, ctx), fields(pit_token))]
    async fn process(&self, ctx: PacketContext) -> Result<Action> {
        // ... lookup
        tracing::Span::current().record("pit_token", token.0);
        tracing::debug!(aggregated = was_aggregated, "PIT check");
        Ok(Action::Continue(ctx))
    }
}
```

`skip(self, ctx)` prevents the macro from trying to `Debug`-format the entire `PacketContext` on every call — you add only the fields you explicitly want. The `fields(pit_token)` declares the field as empty upfront so it can be recorded conditionally.

**The subscriber stack is assembled in `main`, not in the library**

The engine crate itself never calls `tracing_subscriber::fmt::init()` or sets a global subscriber — that is the binary's responsibility. The library only emits events and spans. This is correct library etiquette and means downstream users can compose whatever subscriber stack they need without fighting yours. The standalone forwarder binary sets up the stack:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(true))
        .with(tracing_opentelemetry::layer()
            .with_tracer(otlp_tracer()?))
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    // ...
}
```

`EnvFilter` means operators control verbosity via `RUST_LOG=ndn_engine=info,ndn_engine::pipeline=debug` without recompiling.

**Per-component log levels matter for production**

The pipeline hot path at `debug` level will emit millions of events per second on a busy router — that cannot be on by default. The right production default is `ndn_engine=info` which gives you face lifecycle events, startup configuration, and errors only. `debug` on specific modules is for troubleshooting a live router without restarting. `trace` on `ndn_engine::strategy` is for development — it exposes measurement values and forwarding decisions which are too verbose for any production use.

**Structured fields to emit at each component**

The value of `tracing` is in the fields, not the messages. A few that pay off immediately:

The PIT stage should emit `aggregated: bool` and `pit_entries: usize` (current table size) at debug. The FIB stage should emit `nexthop_count: usize` and `strategy: &str`. The CS stage should emit `hit: bool` and `stale: bool` separately — a stale hit that fails `MustBeFresh` is diagnostically different from a complete miss. The dispatch stage should emit `face_count: usize` and `bytes_sent: usize`. These fields let you build dashboards and alerts directly from traces without post-processing log strings.

**One crate worth knowing: `tracing-futures` is now built into `tracing`**

As of `tracing` 0.1.25 the `.instrument()` extension method is in the main crate via `tracing::Instrument`. You do not need a separate crate. The `opentelemetry` and `tracing-opentelemetry` crates handle the OTLP export if you want distributed tracing across multiple forwarder instances — a span originating on one router can continue on the next hop if you propagate the trace context in NDNLPv2 headers, which is a natural extension once the basic instrumentation is in place.

Want to look at the crate workspace structure next, or move to something else?



## Prompt:
3/25/2026, 9:09:18 PM

I do research with NDN over wireless networks such as modifying links or forwarder settings based on named data flows.  What is the best way to enable this kind of development or is it recommended at all?



## Response:
3/25/2026, 9:10:39 PM

This is a genuinely interesting research use case and the architecture we've built actually supports it quite naturally — better than ndn-cxx/NFD in some ways. Let me think through what you actually need.

Your research workflow is roughly: observe named data flows → make a decision based on name/content/measurement → act on a face, FIB entry, or strategy parameter. That maps onto three distinct extension points in the engine, each with different tradeoffs.

````plaintext
Tool: show_widget
````

The three extension points map onto different research activities. Let me be precise about which to use when, because the wrong choice has real costs.

**Point A — custom strategy: use for per-packet forwarding decisions**

This is the right home for anything that needs to make a forwarding decision based on named data flows. Your strategy gets `MeasurementsTable` access, per-prefix `StrategyState`, and the full `FibEntry` on every packet. For wireless research specifically, you augment the strategy with an `Arc<DashMap<FaceId, LinkMetrics>>` that a separate task populates from nl80211 RSSI readings, MAC-layer retransmission counts, or whatever your wireless interface exposes. The strategy reads that map on every `after_receive_interest` call to rank faces by current link quality rather than static FIB cost.

The `ForwardingAction::ForwardAfter` variant we designed is particularly useful here — you can implement probe-and-fallback natively: forward on the best face immediately, and if the RTT exceeds `2 × measured_rtt` trigger a probe on the backup face. No external controller needed, no separate timer management.

The key constraint: strategy code runs on the packet hot path. Keep it non-blocking, avoid any I/O, and use `try_send` not `send` if you need to push measurements somewhere.

**Point B — custom pipeline stage: use for observation**

This is your research data collection point. A `FlowObserverStage` inserted early in both pipelines with a `try_send` onto a `mpsc` channel is essentially zero cost when the receiver is keeping up — `try_send` on a bounded channel is a single atomic operation. When the receiver falls behind, events are dropped rather than blocking the forwarding pipeline. For research that is almost always the right tradeoff — you can afford to miss a small fraction of events in a log; you cannot afford to slow down forwarding.

The receiver task on the other end of that channel can do anything: write to an InfluxDB time series, emit to a pcap file for Wireshark analysis, compute per-prefix throughput windows, or feed a Python analysis script over a Unix socket. The pipeline never knows or cares.

For wireless network research you would likely want two observer stages — one at the very start of each pipeline (before decode, to capture arrival timing precisely) and one at dispatch (to capture actual forwarding decisions and byte counts). The difference between arrival time and dispatch time is your per-packet pipeline latency, which matters for real-time applications over wireless.

**Point C — management API: use for topology and parameter changes**

This is where your external controller lives — something that reads nl80211 link state, observes named data flow patterns from the observer stage, and then acts: modifying FIB nexthop costs, adding or removing faces, adjusting face parameters like MTU or send timeout, or switching the strategy assigned to a name prefix. Because `ForwarderEngine` exposes its shared tables as `Arc` handles, your controller is just another Tokio task holding those arcs:

```rust
let engine = /* ... build ... */;
let fib = engine.fib();
let faces = engine.faces();

tokio::spawn(async move {
    let mut nl = netlink_wireless::Socket::new().await?;
    loop {
        let event = nl.next_event().await?;
        match event {
            WirelessEvent::LinkDegraded { interface } => {
                let face_id = faces.by_interface(&interface)?;
                // raise cost of this face in FIB so strategy deprioritises it
                fib.update_cost(face_id, Cost::MAX).await;
            }
            WirelessEvent::LinkRestored { interface } => {
                let face_id = faces.by_interface(&interface)?;
                fib.update_cost(face_id, Cost::default()).await;
            }
        }
    }
});
```

This is meaningfully better than NFD's management approach where you'd be making HTTP calls to NFD's management API or shelling out to `nfdc` — here the controller is a typed Rust task with direct access to the engine's data structures, no serialization or IPC boundary involved.

**A practical research architecture combining all three**

For your wireless NDN research the assembly likely looks like this:

```
nl80211 task  ──→  Arc<DashMap<FaceId, LinkMetrics>>  ──→  WirelessStrategy
                                                              (Point A)

pipeline  ──→  FlowObserverStage  ──→  mpsc  ──→  analysis task
                   (Point B)                        ↓
                                              InfluxDB / file / Python

analysis task  ──→  management commands  ──→  Arc<FaceTable>
                        (Point C)              Arc<NameTrie<FibEntry>>
```

The nl80211 task and the analysis task are both just Tokio tasks in the same process. They communicate with the engine through `Arc` handles rather than IPC. Your research loop — observe → decide → act — runs entirely in-process with microsecond latency between observation and action, which is important for wireless where link conditions can change on millisecond timescales.

**One honest caution**

The in-process model is excellent for research but means your experimental code runs in the same address space as the forwarder. A panic in your controller task or observer task will be caught by Tokio's `JoinSet` and logged, but a memory safety bug (which Rust largely prevents) or a deadlock (which Rust does not prevent) could affect forwarding. For production deployment you would want to move the controller to a separate process talking to the management API over a socket. For research, in-process is the right tradeoff — you get much faster iteration on experiments and direct access to all internal state without having to design and version an external API.

The other thing worth flagging: inserting a `FlowObserverStage` at full `debug` verbosity on a 802.11 mesh with many flows will generate a lot of data. Make the observer stage configurable — a `sampling_rate: f32` field that randomly drops events, or a name prefix filter that only observes flows matching your experiment's prefix, prevents the observer from becoming the bottleneck on your research testbed.

Want to look at the crate workspace structure, or is there another aspect of the research workflow to think through?



## Prompt:
3/25/2026, 9:21:42 PM

I also envision NDN being used as an IPC solution because it can unify networking and local processes.  Is this sensible and what changes/improvements would have to be made to the architecture if so?



## Response:
3/25/2026, 9:23:16 PM

This is a sensible vision and actually well-motivated. NDN's name-based decoupling — producers don't need to know consumers, consumers don't need to know locations — is genuinely useful for IPC, not just networking. The same properties that make NDN good for distributed systems (late binding, in-network caching, multicast-by-default) solve real problems in local process communication too.

Let me think through what changes and what stays the same.

**What works already**

The `AppFace` with in-process `mpsc` channels already gives you zero-copy IPC between processes sharing an engine instance. The CS means a producer that ran and exited can still satisfy consumers — the data outlives the producer process, which no traditional IPC mechanism provides. The PIT aggregation means ten processes expressing the same Interest generate one lookup, not ten.

**What needs to change**

The honest answer is that three things need significant rethinking: latency profile, the programming model exposed to IPC consumers, and the trust model for local processes.

````plaintext
Tool: show_widget
````

Let me go through each change in depth.

**Change 1 — shared memory face**

We discussed this briefly at the start and deferred it. For IPC it becomes load-bearing rather than optional. A Unix socket face at 2–5 µs round-trip is acceptable for network-facing IPC but painful for tight process loops — a service handling a thousand requests per second from local clients is spending 2–5 ms/s just on transport. A lock-free SPSC ring buffer in shared memory gets you to 200–500 ns, which is competitive with `pipe(2)` and `eventfd(2)`.

The key design point: `ShmemFace` does not need to TLV-encode `Arc<Name>` when both endpoints are in the same engine process. You can pass the `Arc` pointer directly through the ring buffer — the reference count keeps the name alive. This is a meaningful departure from the `Face` trait's `Bytes`-based interface, which suggests adding a second face trait variant:

```rust
trait LocalFace: Send + Sync + 'static {
    async fn send_packet(&self, pkt: Arc<DecodedPacket>) -> Result<()>;
    async fn recv_packet(&self) -> Result<Arc<DecodedPacket>>;
}
```

The pipeline runner detects `LocalFace` and skips TLV decode entirely — the packet arrives already decoded. This is the fast path that justifies the architecture.

**Change 2 — large data via chunked transfer**

NDN's 8800-byte MTU is a networking constraint, not an IPC constraint. For IPC you want to send megabyte payloads — a video frame, a config blob, a serialized data structure. The right answer is not raising the MTU but implementing chunked transfer as a library layer above the engine, exactly as NDN applications do today with `ndn-cxx`'s `SegmentFetcher`.

The difference for IPC is that chunking should be transparent — the IPC API presents a `send(name, bytes)` / `recv(name) -> Bytes` interface that handles segmentation and reassembly internally. The CS does the right thing automatically: a second consumer fetching the same named payload gets all segments from cache without the producer being involved at all. This is the property that makes NDN genuinely better than a pipe or socket for IPC — the producer can be a batch job that ran once, and any number of consumers can retrieve the result later.

**Change 3 — push notifications**

NDN is pull-only at the wire level, which is the right default but inconvenient for IPC patterns like event streams, sensor feeds, or pub/sub. The clean solution does not require a new protocol — it uses a standing Interest with a very long lifetime:

```rust
// consumer — registers standing subscription
app_face.subscribe("/ipc/sensor/temperature", |data| {
    println!("temp update: {:?}", data);
}).await?;

// producer — satisfies the standing Interest whenever it has new data
loop {
    let reading = sensor.read().await;
    app_face.notify("/ipc/sensor/temperature", reading.encode()).await?;
}
```

Internally `subscribe` expresses a renewable Interest that the engine holds in the PIT indefinitely. When `notify` is called, the engine finds the standing PIT entry and satisfies it immediately — no network round-trip, just a PIT lookup and a channel send. The consumer's callback fires within microseconds of the producer calling `notify`. When the satisfied Interest is consumed, `subscribe` automatically re-expresses it so the next notification is ready.

This is a significant API addition but requires almost no engine changes — it is entirely implemented in the application library layer on top of the existing `AppFace`.

**Change 4 — local trust without cryptographic signatures**

For network NDN, signature verification on every Data packet is correct — you cannot trust the network path. For local IPC between processes on the same machine, signature verification is wasteful and the wrong trust model. The right model is process identity: who connected this face, and what are they allowed to name?

At `AppFace` connection time you capture the connecting process's credentials via `SO_PEERCRED` on the Unix control socket:

```rust
pub struct FaceCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub allowed_prefixes: Vec<Name>,
}
```

The `LocalTrustStage` pipeline stage enforces that Data arriving on a local face only carries names the connecting process is authorized to produce. A process connecting as uid 1000 cannot produce Data under `/system/` — that prefix is reserved for uid 0 services. This replaces the trust schema / signature model for local faces entirely.

Critically, you add a `face_kind` check in the CS insert stage — Data arriving from a local face with `local_scope: true` is not forwarded to remote faces. This prevents a local IPC process from accidentally or maliciously injecting data into the network-facing forwarding plane.

**Change 5 — service registry**

Traditional IPC systems need a service locator — D-Bus has a daemon, Unix sockets have well-known paths, gRPC has a registry. NDN can unify this with the namespace itself. Every service registers its presence by producing Data under `/local/services/<servicename>/info` with a `ServiceDescriptor` payload containing capabilities and version, and `/local/services/<servicename>/alive` with a short freshness period as a heartbeat.

Discovery is just an Interest: express `/local/services` with `CanBePrefix=true` and the CS returns all registered service descriptors. A service that exits has its face closed by the engine, which removes its FIB entries — its heartbeat stops being refreshed and expires from the CS naturally. No separate daemon, no registration protocol, no SPOF.

**What does not change**

The core engine — FIB, PIT, CS, pipeline stages, forwarding strategies — requires no modification for IPC. The packet path is identical. The name trie does not care whether a name is `/edu/ucla/videos/lecture1` or `/local/myapp/request/42`. The CS caches both the same way. The strategy table applies to both.

The workspace structure gains a new crate — `ndn-ipc` — that sits above `ndn-engine` and provides the ergonomic IPC API: `IpcClient`, `IpcServer`, `subscribe`, `notify`, `ChunkedProducer`, `ChunkedConsumer`, `ServiceRegistry`. The engine itself stays clean.

**The honest tension**

NDN's pull model and Interest-Data exchange adds latency and complexity compared to a raw `write(2)` / `read(2)` or a `tokio::sync::mpsc` channel. For processes that know at compile time they will communicate with each other and do not need the NDN properties — persistence, caching, multicast, late binding — a direct channel is simpler and faster. The IPC case for NDN is strongest when you need at least one of: discovery without prior knowledge of the producer, data that outlives the producer, the same data consumed by multiple processes without the producer scaling, or seamless transparency between local and remote — a consumer does not need to know whether its data comes from a local process or a remote host. That last property is the unification argument and it is genuinely compelling for distributed systems research.

Want to look at the workspace and crate structure next, bringing all of this together?



## Prompt:
3/25/2026, 9:31:15 PM

Would you say that NDN enables in-network compute?



## Response:
3/25/2026, 9:32:40 PM

Yes, unambiguously — and it does so more naturally than any IP-based approach. But the claim needs unpacking because "in-network compute" means different things at different layers, and NDN enables some of them architecturally while others require extensions.

Let me work through the spectrum from what NDN gives you today to what becomes possible with deliberate design.

````plaintext
Tool: show_widget
````

**Why NDN is structurally better suited to in-network compute than IP**

The fundamental reason is that IP separates *what* you want from *where* you get it — you need a service locator (DNS, load balancer, service mesh) to bridge the gap. NDN collapses that distinction. The name `/compute/jpeg-thumb/source=/images/photo.jpg/size=128` simultaneously identifies the result *and* routes the Interest to wherever that computation can be performed. The network is the service locator.

This has a second-order consequence that IP cannot replicate: **computed results are first-class named objects that the CS caches**. In IP, if ten clients call the same REST endpoint with the same parameters, the server handles ten requests. In NDN, the first request computes the result, the CS stores it, and the next nine requests are satisfied by the network without involving the compute node at all. Memoization is a free architectural property, not something you bolt on with Redis.

**Level 1 is already working in our engine**

Nothing needs to change. A producer that names its outputs with computation parameters embedded in the name — `/sensor/room42/temperature/aggregated/window=60s` — already gets CS caching of results for free. The consumer does not know or care whether the Data came from a live computation or a cache. This is the most underappreciated form of in-network compute and it requires zero engine modification.

**Level 2 requires one new component: `ComputeFace`**

This is a clean addition to the architecture. `ComputeFace` implements the `Face` trait and registers in the `FaceTable` like any other face. The engine FIB routes Interests matching `/compute/*` to it. Internally it maintains a `ComputeRegistry` mapping name prefixes to async handler functions:

```rust
pub struct ComputeFace {
    registry: Arc<ComputeRegistry>,
    face_id:  FaceId,
    tx:       mpsc::Sender<RawPacket>,  // back into pipeline
}

pub struct ComputeRegistry {
    handlers: NameTrie<Arc<dyn ComputeHandler>>,
}

#[async_trait]
pub trait ComputeHandler: Send + Sync {
    async fn compute(&self, interest: &Interest) -> Result<Data>;
}
```

When an Interest arrives at `ComputeFace`, it does a trie lookup on the name, finds the handler, calls `compute()`, and sends the resulting Data back into the pipeline as if it arrived from a remote face. The pipeline's CS insert stage caches the result. Identical subsequent Interests never reach the handler.

Versioning is natural — `/compute/fn/v=2/thumb/…` routes to a different handler than `/compute/fn/v=1/thumb/…`. Running multiple versions simultaneously is just multiple FIB entries.

**Level 3 requires the most significant engine change: wildcard PIT**

This is where the forwarder itself becomes a compute node — aggregating data from multiple producers in response to a single Interest. The challenge is that the current PIT is keyed on exact name, but aggregation requires the forwarder to express multiple downstream Interests and collect their results before satisfying the upstream Interest.

This requires a new concept: an `AggregationPitEntry` that holds the upstream Interest, tracks a set of downstream Interests it has expressed, and fires a combine function when all downstream Data arrives:

```rust
pub struct AggregationEntry {
    upstream:    PitToken,
    pending:     HashSet<Name>,   // downstream Interests outstanding
    received:    Vec<Data>,       // accumulating results
    combine:     Arc<dyn Fn(Vec<Data>) -> Data + Send + Sync>,
    expiry:      u64,
}
```

The wildcard Interest `/sensor/+/temperature/avg` matches the aggregation strategy, which fans it out to `/sensor/room1/temperature`, `/sensor/room2/temperature`, etc. based on a prefix enumeration table. As Data trickles back, the aggregation entry accumulates results. When all pending Interests are satisfied or timed out, `combine()` runs and the result is returned to the upstream consumer.

This is a meaningful departure from standard NDN semantics but implementable as a pipeline stage plus a new strategy type — the existing engine architecture can accommodate it without structural changes.

**Level 4 is the research frontier — NDN as a computation fabric**

This is where things get genuinely speculative but intellectually compelling. If you treat a computation as a DAG where each node is a named function and each edge is a named data dependency, then expressing an Interest for the root node of that DAG causes the network to recursively resolve dependencies by expressing Interests for intermediate nodes. The network *is* the scheduler.

This is essentially lazy functional evaluation distributed across a network, with memoization via the CS at every node. It maps onto federated learning naturally — `/model/v=5/gradient/shard=3` is computed locally at the shard, cached, and assembled by an aggregator node that expresses Interests for all shards. The aggregator does not need to know where shard 3 is located — the FIB routes it there.

For your wireless research specifically, Level 4 is interesting because the forwarder's routing decisions determine which compute node processes which shard — and your custom strategy can make those decisions based on link quality, node load, and energy budget simultaneously. The strategy already has access to `MeasurementsTable` and `FibEntry`. Adding a `ComputeLoadTable` alongside `MeasurementsTable` — updated by a node monitoring task — gives the strategy everything it needs to do compute-aware forwarding without any additional protocol machinery.

**The honest limitations**

NDN's pull model creates friction for long-running compute. A consumer expressing an Interest gets a single Data back — if the computation takes 30 seconds, the Interest lifetime must be 30 seconds or the consumer must re-express periodically with a progress-checking name. Neither is elegant. Push notifications via standing Interests (as we designed for IPC) help but do not fully resolve this.

Large intermediate results also stress the chunked transfer layer. A computation that produces a 100MB result works correctly but requires the consumer to pipeline hundreds of segment Interests, which adds latency and complexity compared to a streaming TCP connection.

These are real limitations but they are not fundamental blockers — they are engineering problems with known solutions. The architectural alignment between NDN and in-network compute is strong enough that working around them is worthwhile, especially at the edge and in wireless environments where the alternative IP-based approaches require service discovery infrastructure that is fragile precisely where NDN is most robust.

Want to think through how the `ComputeFace` and `ComputeRegistry` would integrate with the engine builder we designed, or explore the aggregation pipeline further?



## Prompt:
3/25/2026, 9:42:29 PM

The fundamental limitation with current wireless and NDN is that a device has to connect to an access point to see other connected devices which defeats its natural discovery.  Is there a good immediate solution to this or does the link layer have to fundamentally change?  Also, what are some natural ways to enable dedicated push-based communication in NDN for applications such as the long-running computations?  I was imagining a hybrid IPv6 scheme over NDN without much thought put into it.



## Response:
3/25/2026, 9:44:07 PM

These are two distinct but related problems. Let me address them separately with precision before showing how they connect.

**On wireless discovery — the link layer does not have to fundamentally change**

The access point problem is real but the solution already exists in 802.11 and is underused: **802.11 ad-hoc mode (IBSS)** and more practically **Wi-Fi Direct (P2P)** and **802.11s mesh**. The issue is not that the link layer lacks the capability — it is that NDN deployments have defaulted to infrastructure mode because that is what devices ship configured for.

The deeper architectural point is that NDN's multicast Interest flooding maps almost perfectly onto 802.11 broadcast frames. In infrastructure mode, broadcast frames go to the AP and stop — the AP does not rebroadcast them to other clients. In ad-hoc or mesh mode, broadcast frames reach all nodes within radio range, which is exactly what NDN prefix discovery needs. NDN over 802.11s is an active research area and the fit is natural.

````plaintext
Tool: show_widget
````

**On wireless discovery — the immediate practical answer**

Your intuition about IPv6 is exactly right, but the framing matters. The solution is not NDN over IPv6 as a unified addressing scheme — it is **IPv6 link-local multicast as a transport underlay for NDN Interest flooding**, which is deployable today without any kernel changes or driver modifications.

IPv6 link-local multicast (`ff02::1`) reaches every node on the same network segment without going through an AP router, even in infrastructure mode — most APs pass link-local multicast between clients because it is required for neighbor discovery. You create a `MulticastUdpFace` that sends NDN packets as UDP payloads to `ff02::1:6363`. Every NDN node on the segment receives them. Interest flooding works. Discovery works. The AP is just a relay, not a gatekeeper.

This is better than ad-hoc mode for most deployments because it does not require reconfiguring the radio — devices stay in infrastructure mode for internet connectivity and simultaneously participate in NDN mesh discovery on the same interface. The dual-mode face strategy we described earlier becomes: try the multicast face first with a short timeout, fall back to the infrastructure face if no local peer responds.

For true multi-hop mesh discovery without any AP, 802.11s is the right answer. Linux supports it natively via `iw` since kernel 3.0. Your Rust engine would add an `MeshFace` that sets the interface to mesh mode and uses the 802.11s path selection protocol to forward NDN Interests beyond one-hop range. This is a research-grade deployment but entirely practical on Linux devices like Raspberry Pis.

**On push-based communication — four approaches, each with a natural fit**

Approach A — standing Interests — is what we designed for IPC and it works well for low-frequency events from a known producer. The limitation is that the PIT entry occupies engine memory for its full lifetime, and if the producer crashes, the consumer hangs until the Interest times out. For long-running compute this timeout problem is significant.

Approach B — versioned namespace — is the most NDN-idiomatic. The producer publishes `/compute/job=abc/status/v=1`, then `/v=2`, then `/v=3` as work progresses. The consumer always expresses an Interest for the next version with `MustBeFresh=true`. Each Interest has a short lifetime — a few seconds — so the consumer is effectively polling but at a rate controlled by Interest retransmission, not a timer. This is clean and robust to producer crashes — the consumer simply stops seeing new versions and can detect staleness. The CS caches each status update so multiple consumers track progress without additional producer load.

Approach C — `Nack(NotYet, retry_after)` — enhances the versioned approach. Rather than the consumer blindly re-expressing after a fixed timeout, the producer's forwarder sends a Nack with a `retry_after` hint in milliseconds. The consumer's engine respects the hint before re-expressing. This eliminates wasted re-expressions during a computation phase that will clearly take longer than the Interest lifetime, without the consumer needing any out-of-band knowledge of the computation's pace. This requires a small engine addition — a `retry_after` field in the Nack TLV and a timer in the consumer's pending Interest table.

Approach D — notification Interest — is the most interesting conceptually and the closest to true push. The producer, when it has something to say, expresses an Interest to a well-known consumer prefix: `/consumer/abc/notify/job=abc/status=complete`. The consumer has registered that prefix and receives the Interest as a notification. It then fetches the actual data via a normal Interest. This inverts the flow — the producer becomes a consumer briefly — but stays entirely within NDN semantics. No new wire protocol needed. This maps cleanly onto your long-running compute case: when training completes, the compute node sends `/client/xyz/ready/job=abc`, the client receives it, and immediately expresses `/compute/train/job=abc/result` to fetch the output.

**On your IPv6 hybrid intuition**

You are onto something real, but I would characterise it differently than "IPv6 over NDN" or "NDN over IPv6". The productive framing is **NDN as the application and routing layer, with IPv6 link-local as one of several possible link-layer transports**, which is exactly how NDN is specified — it is explicitly transport-agnostic.

What your intuition is probably pointing at is the **dual-stack transition problem**: most real deployments will have NDN nodes that also need internet connectivity, and you want them to participate in NDN discovery locally while maintaining IPv6 reachability globally. The architecture for this is:

```
application
     ↓
  NDN engine         (name-based routing, CS, strategy)
     ↓
  face table
   ├── MulticastUdpFace  ff02::1:6363   (local NDN discovery)
   ├── UdpFace           [2001:db8::1]:6363  (remote NDN peer)
   └── AppFace           in-process         (local applications)
```

The IPv6 addresses appear only in the face configuration — they are transport endpoints, not part of the NDN name space. The FIB routes names, not addresses. A consumer expressing `/sensor/room42/temperature` has no idea whether the Data comes from a local device via multicast or a remote node via unicast IPv6 — the engine handles both transparently. This is the unification you were imagining, and it falls directly out of the architecture we already designed without any special IPv6 integration.

The one place where IPv6 and NDN genuinely interact at a deeper level is **NDN name-to-address mapping for bootstrapping** — when a device first joins a network and needs to find other NDN nodes, it cannot yet use NDN to find them because it does not know any face endpoints. This is the classic bootstrapping problem. The clean solution is a link-local mDNS record: `_ndn._udp.local` advertising the node's NDN face endpoint. Devices discover each other via mDNS, establish UDP faces, and from that point NDN handles everything. Your Rust engine would add an `MdnsDiscovery` task at startup that both advertises and listens, creating `UdpFace` instances for each discovered peer and adding a default FIB entry pointing to them.

The combination of IPv6 link-local multicast for flooding and mDNS for unicast peer discovery gives you complete wireless NDN discovery without any AP dependency, without changing the link layer, and without modifying the core engine architecture — it is all face configuration and a small discovery task in the engine builder.



## Prompt:
3/25/2026, 9:53:30 PM

There is a problem however.  Multicast and broadcast often only sends at legacy rates (1 Mbps).  This is a serious limitation for multicast data.  Also, my research is on multi-radio and multi-channel wireless using NDN.  This combination helps overcome multi-hop degradation but requires channel/radio management (both local and remote) and routing packets to the appropriate radio.  I aimed to accomplish this with NDN.  Is this sensible or should these be completely separate matters?



## Response:
3/25/2026, 9:55:14 PM

These are both real and well-known problems, and your instinct to unify them under NDN is not only sensible — it is arguably the most coherent approach available. Let me address the multicast rate problem first since it is a hard constraint, then work through the multi-radio/multi-channel architecture.

**The multicast rate problem**

The 1 Mbps legacy rate issue is a fundamental 802.11 MAC limitation, not an NDN limitation. Multicast and broadcast frames are sent at the lowest mandatory rate to ensure all stations can receive them — the AP or transmitting station has no per-receiver rate knowledge for non-unicast frames. On a modern 802.11ac/ax network this means multicast is sent at 6 Mbps (OFDM minimum) in the best case, often 1 Mbps for true broadcast. This is a serious problem for NDN Interest flooding if Interests are large or frequent, but less serious than it first appears because **Interests are small** — a typical Interest is 100-300 bytes. At 1 Mbps that is under 3 µs of airtime. The real problem is Data, which you would never multicast naively.

The solution has two parts. First, use multicast only for Interest flooding — keep it small and infrequent by suppressing duplicate Interests aggressively in the strategy. Second, deliver Data via **unicast with rate adaptation** — once the Interest has been received and a producer identified, the Data response goes back as a unicast frame to the specific MAC address of the requester, where 802.11 rate adaptation (MCS selection, MIMO) applies normally and you get full link throughput.

````plaintext
Tool: show_widget
````

**On whether channel/radio management should be unified with NDN — yes, and here is the precise argument**

In IP networking, routing and radio management are deliberately separated. The routing layer (OSPF, BGP) knows nothing about radio channels — that is handled by the driver and sometimes by a separate protocol like 802.11k/v/r. This separation made sense when IP routers were wired and radio was an edge concern.

In a multi-radio multi-hop wireless network it breaks down. The routing decision — which next hop to forward to — is inseparable from the radio decision — which channel and which radio to use to reach that hop. They are the same decision made at different timescales. OLSR and similar mesh protocols try to bridge this by leaking radio metrics into routing metrics, but the bridge is always incomplete because the protocols were designed independently.

NDN unifies them naturally because **the name namespace is the coordination medium**. Channel state, neighbor tables, link quality measurements, and radio configuration are all just named data. A node that wants to know the channel load on a neighbor's wlan1 expresses an Interest for `/radio/node=neighbor/wlan1/survey` — the same mechanism it uses for any other data. The forwarding strategy that needs link quality to make a routing decision reads from the same `RadioTable` that the `ChannelManager` task populates via nl80211. There is no protocol boundary to cross.

**The multi-hop degradation problem specifically**

Multi-hop degradation in 802.11 has two causes. The first is the hidden node problem — nodes on different hops cannot hear each other and their transmissions collide at the relay. Multiple radios on different channels directly solve this: one radio per hop, each on a non-overlapping channel, so the relay can receive on channel A and transmit on channel B simultaneously without self-interference. This is standard multi-radio mesh design.

The second cause is the halved throughput problem — a relay node must receive and then retransmit every packet, consuming the channel twice. With multiple radios on dedicated channels this is also resolved since receive and transmit happen on different channels concurrently.

Your NDN architecture handles this by assigning `RadioFace` instances to specific roles — one access face for client-facing Interests and Data, one backhaul face for inter-node forwarding. The `MultiRadioStrategy` makes this explicit: Interests from local applications go out on the access radio; Interests that need multi-hop forwarding go out on the backhaul radio. The FIB contains separate nexthop entries per radio for the same name prefix, and the strategy picks between them based on `RadioTable` metrics.

**The `ChannelManager` task is the critical bridge**

This task runs alongside the engine and does three things. It reads nl80211 survey data and station information continuously via Netlink — channel utilization, per-station RSSI, MCS index, retransmission counts. It publishes this data as named NDN content under `/radio/local/<iface>/state` with short freshness so neighbors can fetch it. And it subscribes to neighbor radio state using standing Interests on `/radio/+/state` so the local `RadioTable` stays current.

When the strategy decides a channel switch would improve throughput for a named flow — say `/video/stream` is performing poorly on channel 6 because a new neighbor appeared — it calls `channel_mgr.switch(face_id, new_channel)` which issues an nl80211 channel switch via Netlink and updates the `RadioTable`. The face stays in the `FaceTable` with the same `FaceId`; only the underlying channel changes. Packets already in flight on the old channel drain naturally.

Remote channel coordination — telling a neighbor to switch its radio — is done by expressing an Interest to `/radio/node=neighbor/wlan1/switch/ch=36`. The neighbor's engine receives it, the `ChannelManager` validates the requester's credentials (prefix authorization from the trust stage), executes the switch, and returns an Ack Data containing the actual switch latency. This is cleaner than any IP-based radio management protocol because the coordination is authenticated, named, cached, and uses the same forwarding infrastructure as data traffic.

**The flow table — binding name prefixes to radio interfaces**

This is the key addition to the strategy that does not exist in standard NDN. A `FlowTable` maps name prefixes to preferred radio faces based on observed flow characteristics:

```rust
pub struct FlowEntry {
    prefix:         Name,
    preferred_face: FaceId,     // which radio
    observed_tput:  f32,        // EWMA bytes/sec
    observed_rtt:   f32,        // EWMA ms
    last_updated:   u64,
}
```

The strategy populates this on every Data arrival — if `/video/stream` consistently arrives faster via the 5 GHz radio than the 2.4 GHz radio, the flow entry records that and subsequent Interests for `/video/stream` are sent directly to the 5 GHz face without consulting the FIB. The FIB is the fallback for names with no flow history; the flow table is the fast path for established flows.

This is analogous to flow-based forwarding in SDN but without a central controller — each node maintains its own flow table based on locally observed NDN traffic, and the forwarding strategy uses it autonomously.

**On the multicast rate problem for Interest flooding specifically**

The practical fix for your multi-radio scenario is to not rely on 802.11 multicast for neighbor discovery at all, and instead use the `ChannelManager`'s neighbor table. When a new node appears in the nl80211 station list, the engine automatically creates a unicast `RadioFace` to it and adds a low-cost FIB entry pointing to it. Interest flooding then goes out as targeted unicast to known neighbors rather than broadcast. This completely bypasses the legacy rate problem — unicast frames use full rate adaptation — and is actually more efficient than broadcast because you do not waste airtime on stations that are not NDN-capable.

The only place you need actual multicast is initial bootstrap — finding the first neighbor when you have no station list yet. For that, one small broadcast Interest at 1 Mbps to announce presence is acceptable; all subsequent traffic is unicast.

**The honest complexity**

The unified architecture is the right design but it is a genuinely hard implementation problem. The nl80211 Netlink interface is complex — the `neli` crate in Rust covers it but the 802.11 survey and channel switch commands require careful handling of kernel version differences. Channel switching causes brief interface unavailability during which PIT entries may time out, requiring the strategy to suppress retransmissions during the switch window. And coordinating channel switches across multiple nodes without a central controller requires a distributed agreement protocol — if node A switches to channel 36 but node B does not, they lose connectivity. The NDN namespace gives you the coordination medium but you still need to design the agreement protocol, which is a research contribution in itself.

That last point is probably the most interesting part of your research agenda — using NDN's named data properties to build a distributed channel coordination protocol that is provably consistent and self-healing. The CS memoization of channel state, the PIT aggregation of concurrent switch requests, and the strategy's access to global measurements via the NDN namespace give you building blocks that IP-based approaches simply do not have.



## Prompt:
3/25/2026, 10:03:22 PM

I thought that Data packets had to travel back over the same exact faces the Interest came through.  This would not allow multicast Interest to return Data over unicast.



## Response:
3/25/2026, 10:04:20 PM

You are absolutely right to catch that. I was imprecise. Let me correct this properly.

**The NDN specification requires Data to follow the reverse path of the Interest exactly.** This is not an implementation choice — it is fundamental to how the PIT works. The PIT records which face an Interest arrived on in the `InRecord`, and Data must be returned on those exact faces. There is no mechanism in standard NDN for Data to arrive on a face that did not forward the corresponding Interest.

The reason this is load-bearing is security and correctness. The PIT entry is the *only* authorization for Data to flow in a given direction. Without it, unsolicited Data would have no place to go and would be dropped — which is the correct behavior. The reverse path property also means a consumer never needs to expose its address or identity to the producer; the Interest carries the reverse path implicitly through the PIT state.

So my earlier statement that "Data response goes back as a unicast frame to the specific MAC address of the requester" was wrong in a subtle but important way. Let me work through what actually happens and what the real options are.

````plaintext
Tool: show_widget
````

**The insight is that face granularity is the design variable**

The legacy rate problem dissolves once you recognise that a multicast face and a per-neighbor unicast face are both valid NDN faces — they just have different scopes. The multicast face is a convenience for bootstrap and flooding. Once you have a neighbor's address, you create a dedicated unicast `UdpFace` to that neighbor and all subsequent traffic — Interest and Data — travels on that face at full rate. The PIT reverse path constraint is fully respected because the Interest arrived on a unicast face and Data returns on the same unicast face.

The `NeighborDiscovery` task is the bridge. It sends one broadcast hello Interest — `/local/hello/nonce=XYZ` — at legacy rate, captures the UDP source address of each responding neighbor's Data, and creates a `UdpFace` per peer. From that point the broadcast face is retired from the data path. New neighbor arrivals trigger a new hello cycle; departures are detected by face timeout when no Data returns on that face's outstanding Interests.

For your multi-radio multi-channel work this is actually cleaner than multicast flooding. Each `RadioFace` to a specific neighbor is tagged with `radio_id`, `channel`, and `band` metadata. The `MultiRadioStrategy` selects among them based on your research criteria — link quality, channel load, flow affinity — and the PIT correctly threads Data back through whichever radio face the winning Interest went out on. Channel switches update the face's metadata in-place without changing the `FaceId`, so the PIT entries remain valid across a channel change.

**The one genuine limitation this exposes**

For truly unknown neighbors — a mobile node entering range with no prior association — you need that initial broadcast. Until the unicast face is established, you are stuck at legacy rate for that exchange. In a mobile scenario this could happen frequently. The mitigation is to make the hello exchange as small as possible: a minimal Interest and a minimal Data containing just the node's unicast endpoint, so the legacy-rate penalty is one or two small frames rather than a full data exchange.



## Prompt:
3/25/2026, 10:07:07 PM

You say unicast UdpFace, but doesn't udp require an IP address?



## Response:
3/25/2026, 10:08:06 PM

Yes, exactly right. I have been sloppy about the layer boundary and you have caught it precisely.

UDP requires an IP address. If we are using `UdpFace { addr: neighbor_ip }` then we have implicitly re-introduced IP as a dependency for NDN neighbor communication — which undermines the whole point of NDN being network-layer independent, and specifically undermines your goal of NDN-native wireless coordination.

Let me think through this carefully at the correct layer of abstraction.

````plaintext
Tool: show_widget
````

**`EtherFace` over `AF_PACKET` is the correct abstraction**

NDN has an IANA-assigned Ethertype — `0x8624` — specifically for carrying NDN packets directly over Ethernet frames with no IP or UDP involvement. An `AF_PACKET` raw socket in Linux lets you send and receive these frames directly, identified only by MAC address. This is how NDN was always intended to run at the link layer and it resolves every issue cleanly:

Discovery uses a broadcast frame to `ff:ff:ff:ff:ff:ff`. The kernel's `AF_PACKET` `recvfrom` returns the source MAC of each responding neighbor. You create one `EtherFace` per `(peer_mac, interface)` pair — no IP address ever appears. Subsequent Interests go out as unicast Ethernet frames to the peer's MAC address. The 802.11 MAC layer sees a normal unicast frame and applies full rate adaptation. Data returns on the same `EtherFace` — the PIT reverse path constraint is satisfied because the face identity is the `(peer_mac, iface)` tuple, not an IP endpoint.

For your multi-radio work this is exactly the right model. A node reachable on both wlan0 and wlan1 gets two separate `EtherFace` entries in the `FaceTable` — `(mac=A, iface=wlan0, radio=0, ch=6)` and `(mac=A, iface=wlan1, radio=1, ch=36)`. The FIB can have nexthop entries for both with different costs. The `MultiRadioStrategy` selects between them based on your research criteria and the PIT correctly threads everything through the chosen face.

**The one place where IP remains useful**

For connectivity beyond the local wireless segment — reaching NDN nodes on other networks, or the internet-facing side of your research testbed — `UdpFace` over IP is still appropriate. The architecture naturally supports both: `EtherFace` for local wireless peer-to-peer communication with no IP dependency, `UdpFace` for tunnelled NDN over existing IP infrastructure where you do not control the link layer. The FIB and strategy treat them identically — they are both just faces with different `FaceKind` metadata.

The `AF_PACKET` implementation in Rust uses the `nix` crate for the socket syscalls and wraps the file descriptor in a Tokio `AsyncFd` for non-blocking operation, fitting cleanly into the async face task model we designed earlier.



## Prompt:
3/25/2026, 10:11:31 PM

I have seen that EtherFaces have generally worse throughput than UdpFaces.  Why is this so?  Also, wouldn't a named-based MAC layer be better than MAC addresses for NDN?



## Response:
3/25/2026, 10:12:55 PM

Both observations are sharp and get at real limitations in how NDN has been deployed so far.

**Why EtherFace has worse throughput than UdpFace in practice**

The answer is not what most people expect. It is not the raw socket overhead — that is minimal. There are four real causes:

````plaintext
Tool: show_widget
````

**On EtherFace throughput**

The dominant cause in practice is the per-syscall cost. A standard `AF_PACKET` `recvfrom` call delivers one frame per syscall. At 1500-byte frames and 10 Gbps that is roughly 830,000 frames per second — and 830,000 syscalls per second, each crossing the user/kernel boundary. UDP avoids this through Generic Receive Offload (GRO) which coalesces multiple packets in the kernel before delivering them, and through `recvmmsg` which batches multiple receives into one syscall.

The fix is `PACKET_RX_RING` — a memory-mapped ring buffer that the kernel fills directly and userspace polls without syscalls. This is what `tcpdump` uses internally for high-rate capture and it largely closes the throughput gap. The Rust implementation wraps the mmap'd region in a safe struct and polls it in the face task loop rather than calling `recvfrom`. Combined with `PACKET_TX_RING` for transmit batching, a well-tuned `EtherFace` should approach UDP throughput on the same hardware.

The MTU difference is real but manageable for NDN specifically. NDN Data packets are already bounded at 8800 bytes by the NDNLPv2 MTU, so they require fragmentation regardless of whether you use Ethernet or UDP. The NDNLPv2 fragmentation layer sits above the face and handles this identically in both cases. Jumbo frames only help if you can guarantee end-to-end jumbo support, which you cannot in a heterogeneous wireless mesh.

**On named MAC — your intuition is correct and important**

A named MAC layer is not just better for NDN — it is arguably the natural completion of NDN's design. The current situation where NDN names route at the network layer but MAC addresses route at the link layer creates an impedance mismatch that causes real problems: ARP/NDP traffic, MAC-layer mobility failures, and the address resolution overhead we discussed.

The key insight is that in NDN a "next hop" is conceptually a name prefix served by a neighboring node, not a hardware address. MAC addresses are an implementation detail of how frames get to that neighbor — they should be invisible above the face layer.

**The 802.11 firmware constraint is the hard limit**

The 802.11 MAC sublayer — ACK frames, RTS/CTS collision avoidance, block ACK aggregation, rate adaptation — all operate on MAC addresses internally in the firmware or driver. You cannot replace this from userspace without custom firmware (OpenWRT with modifications) or SDR hardware. This means a fully named MAC layer requires either custom 802.11 firmware or a clean separation where names are used above the 802.11 sublayer and MAC addresses remain as an internal transport handle below it.

The practical architecture that is achievable today without custom firmware is a `NamedEtherFace` with a local name-to-MAC resolution table:

```rust
pub struct NamedEtherFace {
    node_name:    Name,           // this neighbor's NDN node name
    mac:          MacAddr,        // resolved once at first contact
    iface:        String,
    radio_meta:   RadioFaceMetadata,
    socket:       Arc<PacketRing>, // PACKET_RX_RING / TX_RING
}
```

The MAC address is resolved once during neighbor discovery — the hello Interest response carries the neighbor's node name, and the face is created with both. Above the face layer everything is names. The FIB contains entries like `(/neighbor/nodeB, face_id=7)` not `(/neighbor/nodeB, mac=aa:bb:cc:dd:ee:ff)`. The MAC is encapsulated inside the face implementation and never surfaces to the strategy, PIT, or FIB.

**What this enables for your research specifically**

The three properties in the diagram — link-layer anycast, no ARP, and mobility — are each directly relevant to multi-radio multi-channel NDN.

Link-layer anycast means a frame addressed to `/prefix/service` can be received and responded to by any node within radio range that serves that prefix. In a multi-hop mesh this means you do not need to know which specific node has the data — you express the Interest by name and the nearest serving node responds. This is NDN's fundamental property expressed all the way down to the link layer.

No ARP matters for channel switching. In the current model, switching a radio to a new channel invalidates MAC-layer neighbor associations and may trigger ARP timeouts. With named faces the face identity is the node name, not the MAC or channel. A channel switch updates the face's internal MAC handle if needed but the face itself — and therefore the FIB entry, PIT entries, and strategy state — remains stable. Your channel manager can switch radios without disrupting the NDN forwarding state above it.

Mobility is the most significant property for wireless research. A mobile node that moves between access points or mesh segments changes its MAC-visible address in infrastructure mode and may change its radio interface entirely. With named faces the mobile node's name is stable — `/node/device123` — and only the internal MAC resolution needs updating when it moves. The FIB entry on neighboring nodes points to the name, not the MAC, so mobility is handled entirely within the face layer without touching routing state. This is a genuine architectural advantage over anything IP-based, where mobility requires either tunnelling (Mobile IP) or re-convergence (routing protocol update).

**The longer-term answer**

A proper named MAC layer requires changes at the 802.11 association and frame exchange level — replacing MAC address fields in management frames with name TLVs, and modifying the association protocol so nodes advertise name prefixes rather than just capabilities. This is firmware-level work beyond what any userspace NDN stack can do today, but it is a coherent research direction. The intermediate architecture we have described — named faces with internal MAC resolution — gives you the naming properties at the NDN layer while remaining compatible with unmodified 802.11 hardware, and provides a natural migration path toward a deeper named MAC implementation when the hardware permits it.



## Prompt:
3/25/2026, 10:21:39 PM

So we still have to handle MAC address resolution underneath?



## Response:
3/25/2026, 10:22:44 PM

Yes, but the resolution problem is actually much simpler than ARP/NDP, and NDN solves it more elegantly than IP does. Let me be precise about what needs resolving and what does not.

**What ARP/NDP actually does and why NDN does not need most of it**

ARP exists because IP addresses and MAC addresses are independently assigned with no structural relationship. Given an IP address you have no way to derive the MAC — you must ask. The question "who has 192.168.1.5?" is a broadcast query that exists purely to bridge two flat namespaces that were designed independently.

NDN eliminates this problem at the conceptual level. You never need to resolve a name to a MAC address globally — you only need to know which directly adjacent neighbor to send a frame to next. That is a strictly local, one-hop question. And because NDN's hello mechanism already exchanges node names at first contact, the name-to-MAC binding is established as a side effect of neighbor discovery with no additional protocol machinery.

````plaintext
Tool: show_widget
````

**The fundamental difference from ARP**

ARP must resolve MAC addresses for arbitrary IP destinations across an entire subnet because IP addresses and MAC addresses have no structural relationship and either can change independently. It is an ongoing, subnet-wide, O(N²) coordination problem.

NDN's resolution problem is structurally smaller in three ways. First, it is strictly one-hop — you only need the MAC of your directly adjacent neighbors, never of distant nodes. Second, it is established once at first contact as a side effect of the hello exchange, not triggered on every new destination. Third, the binding is keyed on a node name that is stable across radio changes, so mobility does not invalidate it — you update the MAC inside the `NeighborEntry` and nothing above the face layer knows or cares.

**The MAC is an internal implementation detail of `EtherFace.send()`**

This is the key architectural point. The MAC address never surfaces to the FIB, PIT, strategy, or any pipeline stage. The FIB contains `(/node/B/prefix, face_id=7)`. The strategy returns `ForwardingAction::Forward(face_id=7)`. The dispatch stage calls `face_table.get(7).send(bytes)`. Inside that `send()` implementation the `EtherFace` writes the stored `peer_mac` into the Ethernet frame header. That is the only place the MAC appears.

```rust
impl Face for NamedEtherFace {
    async fn send(&self, pkt: Bytes) -> Result<()> {
        let frame = EtherFrame {
            dst:       self.peer_mac,      // only place MAC is used
            src:       self.local_mac,
            ethertype: NDN_ETHERTYPE,
            payload:   pkt,
        };
        self.ring.send(frame).await
    }
}
```

Everything above this call is pure NDN names. The MAC is as invisible as a TCP sequence number is to an HTTP application.

**For your multi-radio work specifically**

The `NeighborEntry` for a single neighbor holds a `Vec` of radio bindings — one per interface on which that neighbor is reachable. Each binding has its own `FaceId` in the `FaceTable` and its own MAC address if the neighbor's radios have different MACs (which they will if they are separate physical interfaces). The `MultiRadioStrategy` selects among `FaceId`s based on your research criteria. The MAC resolution for each selected face is already done and cached. There is no per-packet address resolution cost on the forwarding hot path — the MAC was resolved once during hello and is stored inside the face struct permanently.

The resolution overhead in steady state is genuinely zero. The only time MAC resolution work happens is when a new neighbor is discovered, when a neighbor's MAC changes due to mobility, or when a neighbor's hello refresh lapses and it must be rediscovered. All three of these are rare events handled by the `NeighborDiscovery` background task, completely off the forwarding hot path.



## Prompt:
3/25/2026, 10:27:54 PM

I am still concerned about the performance loss when packets go from one radio to another because the engine sits in between as opposed to bridging two interfaces using ip tools.



## Response:
3/25/2026, 10:29:06 PM

This is a legitimate and important concern. You are identifying a real architectural cost. Let me be precise about what that cost actually is before discussing solutions.

**The exact cost of engine-in-the-middle**

When a packet arrives on wlan0 and needs to go out on wlan1, the path through the engine is:

````plaintext
Tool: show_widget
````

**The comparison with a kernel bridge is not quite fair — but the concern is still valid**

A kernel bridge forwards blindly. It pays ~1–2 µs per packet but does no useful work beyond moving frames. The NDN engine pays ~10–50 µs but performs PIT aggregation, CS lookup, strategy decisions, and interest suppression — work that meaningfully reduces total network traffic. On a multi-hop wireless mesh where bandwidth is the scarce resource, doing more work per packet to reduce total packets is often the right tradeoff.

That said, the overhead is real and for your multi-radio research where you are specifically studying forwarding performance, it matters. There are three answers at different levels.

**Answer 1 — userspace forwarding cache**

The first packet for a new name takes the full pipeline. The pipeline exit populates a `ForwardingCache` entry mapping `(in_face, name_hash) → out_faces`. Subsequent packets matching that entry skip all pipeline stages and go directly to dispatch. The cache is invalidated when the PIT entry expires. This is the same principle as Linux's connection tracking fast path and gets you to ~1–2 µs for established flows in userspace.

**Answer 2 — XDP for kernel-level bypass**

eXpress Data Path (XDP) lets you attach an eBPF program to a network interface that runs in the kernel driver context, before the packet is even handed to the kernel network stack. An XDP program for NDN would parse just enough of the TLV to extract a name hash, look it up in a BPF map that the engine maintains, and call `XDP_REDIRECT` to forward directly to the output interface — all without the packet ever reaching userspace. This gets you to ~200 ns, genuinely comparable to a kernel bridge.

The engine manages the BPF map — inserting entries when PIT entries are established, removing them on expiry or strategy change. The Rust `aya` crate handles eBPF program loading and map access cleanly without leaving the Rust ecosystem:

```rust
// engine side — updating the XDP forwarding map
pub struct XdpForwardingMap {
    map: aya::maps::HashMap<NameHash, XdpForwardEntry>,
}

impl XdpForwardingMap {
    pub fn insert(&mut self, name: &Name, in_ifindex: u32, out_ifindex: u32) {
        let hash = name.fast_hash();
        self.map.insert(hash, XdpForwardEntry { in_ifindex, out_ifindex }, 0);
    }
    pub fn remove(&mut self, name: &Name) {
        self.map.remove(&name.fast_hash());
    }
}
```

The XDP program itself is a small eBPF program — parse NDN ethertype, hash the name TLV, lookup in map, redirect or pass. Unknown flows fall through to XDP_PASS and the engine handles them normally. This gives you the best of both worlds: kernel-speed forwarding for established flows, full NDN intelligence for new flows and cache misses.

**Answer 3 — rethink when engine-in-the-middle is actually necessary**

For your multi-radio research specifically, there is a meaningful distinction between two forwarding scenarios. The first is inter-radio forwarding of transit traffic — packets from a remote source passing through your node to a remote destination, where your node is purely a relay. The second is locally-originating or locally-terminating traffic where your node is a producer or consumer.

For pure transit traffic the XDP path is correct — the engine established the forwarding state when the first Interest was processed, and subsequent Data packets on that flow can be forwarded at kernel speed. For locally-terminating traffic the full pipeline is necessary and its latency is appropriate since it is doing real application-layer work.

The three-tier model in the diagram captures this: new flows and local traffic always go through the full pipeline; established transit flows get promoted first to the userspace cache and then to the XDP fast path as the flow matures. Promotion is triggered by the pipeline itself — after N packets on the same `(in_face, name)` pair, the pipeline stage writes the XDP map entry and subsequent packets bypass it entirely.

**For your research on multi-radio channel management**

There is one additional consideration. Your research involves changing channel assignments, which invalidates forwarding state. When a channel switch happens on wlan0, all XDP map entries for faces on wlan0 must be flushed and re-established after the switch completes. The `ChannelManager` task handles this: before issuing the nl80211 channel switch it calls `xdp_map.flush_interface(ifindex)`, the switch executes, the interface comes back up, and new flows re-establish through the full pipeline and repopulate the map. This is a brief forwarding interruption — the duration of the channel switch itself, typically 10–50 ms for 802.11 — after which the fast path is restored automatically.

This interaction between channel management and the XDP fast path is actually an interesting research question in itself. How long does it take for the fast path to re-warm after a channel switch? What is the traffic cost of the re-establishment period? Does pre-populating the XDP map before the switch based on predicted flow continuity reduce that cost? These are questions your architecture is uniquely positioned to measure precisely because the engine controls both the channel switch and the forwarding state.



## Prompt:
3/25/2026, 10:34:05 PM

The problem is that last I checked, XDP did not support wireless interfaces.



## Response:
3/25/2026, 10:35:17 PM

You are absolutely right, and this is a well-known and frustrating limitation. XDP support requires the network driver to implement the `ndo_xdp_xmit` callback, and virtually no 802.11 drivers do. The reasons are architectural — 802.11 has per-station queuing, power save buffering, rate adaptation, and QoS queues that sit between the driver and the hardware, and XDP's model of "redirect frame directly to hardware ring" does not map onto that stack cleanly. This is not a temporary gap that will be filled soon — it reflects a genuine mismatch between XDP's assumptions and 802.11's complexity.

So we need to think about what fast-path options actually exist for wireless. Let me work through the realistic ones honestly.

````plaintext
Tool: show_widget
````

**tc eBPF is the realistic kernel fast path for wireless**

Traffic Control (tc) hooks via `cls_bpf` run at a different point in the kernel stack than XDP — after the driver has processed the frame rather than inside the driver. This means they work on mac80211 interfaces. The `bpf_redirect()` helper in a tc ingress program can forward a frame to another interface, including another wireless interface, without it ever reaching a socket or userspace. The `aya` crate supports tc eBPF with the same map management API as XDP, so the engine-side code changes minimally.

The catch is that `bpf_redirect` between two wireless interfaces in tc context does work but has been historically unreliable on some drivers — it is worth testing on your specific hardware. On ath9k and ath10k it has been reported working. On drivers using the newer wifi7 stack the situation may differ.

**But the honest answer is that 802.11 itself sets the floor**

The numbers in the diagram matter. A single 802.11 hop at 54 Mbps takes 300–500 µs minimum due to DIFS backoff, transmission time, and ACK. Your engine overhead of 10–50 µs is 3–15% of that total. Saving 10 µs with tc eBPF saves you 2–3% of total hop latency. On an 802.11ac or 802.11ax link at higher MCS rates the transmission time shrinks but the DIFS/backoff floor does not — the engine overhead becomes proportionally larger, but the absolute forwarding latency is still dominated by the MAC layer.

The engine overhead becomes the actual bottleneck in two specific situations. The first is very high packet rate with small packets — Interests are 100–300 bytes and at 10,000 Interests per second the engine pipeline at 50 µs per packet would need 500 ms of CPU time per second, which is clearly unsustainable. The userspace forwarding cache solves this without needing any kernel changes — known flows skip the pipeline entirely and cost only a hash lookup and an `AF_PACKET` send, getting you to roughly 50,000–100,000 packets per second on a modern core. The second situation is embedded hardware with a single CPU core shared between the engine and the radio driver interrupt handler — here cache efficiency and minimising pipeline work per packet matters more than fast-path latency.

**For your multi-radio research specifically**

The most useful framing is probably not "how do I match kernel bridge performance" but rather "what is the forwarding overhead relative to what I gain from NDN-aware forwarding decisions." Your research involves selecting between multiple radios based on channel conditions and flow characteristics — that decision requires exactly the information the engine pipeline gathers. A kernel bridge cannot make that decision at all. The question is whether the overhead of making that decision in userspace is acceptable given the wireless hop latency it sits within, and for most wireless scenarios the answer is yes.

The place to invest optimisation effort is the userspace forwarding cache — making it lock-free using a `DashMap` with atomic updates, ensuring the cache check is the very first thing the pipeline runner does before any other stage, and tuning the `AF_PACKET` ring buffer sizes for your expected packet rates. That combination should get you within a factor of two of kernel bridge throughput while retaining full NDN forwarding intelligence, which is a reasonable tradeoff for research hardware.



## Prompt:
3/25/2026, 10:39:20 PM

I also want to incorporate compatibility with projects like wfb-ng.  Is this a sensible investment of effort?



## Response:
3/25/2026, 10:40:31 PM

This is a genuinely interesting compatibility target and worth thinking through carefully because wfb-ng represents a fundamentally different physical layer model than anything we have discussed so far.

**What wfb-ng actually is**

WFB-NG (Wifibroadcast Next Generation) is not a standard 802.11 stack. It uses 802.11 monitor mode with raw frame injection to implement a **unidirectional broadcast link** with FEC (Forward Error Correction) over the physical layer, deliberately discarding the 802.11 MAC entirely — no association, no ACK, no CSMA/CA backoff, no rate adaptation handshake. It was designed for FPV drone video links where you want maximum range and tolerance for packet loss at the cost of giving up bidirectional acknowledgement. The key properties are:

````plaintext
Tool: show_widget
````

**The fundamental tension**

NDN's Interest-Data exchange assumes a bidirectional path — Interest goes out, Data comes back on the same face. wfb-ng is inherently unidirectional. These are not compatible without a deliberate architectural accommodation. The question is whether that accommodation is clean or hacky.

It turns out to be clean, because the asymmetric link model is not unusual in networking — satellite links, VSAT, some LTE configurations all have asymmetric uplink/downlink paths. The accommodation is a `FacePairTable` that tells the dispatch stage "when Data needs to return on face X, actually send it on face Y." This is a small, well-contained engine change — perhaps 50 lines of code — and it does not disturb any other component.

**The more natural use of wfb-ng with NDN**

The Interest-Data exchange model works but requires two radios in the asymmetric configuration. The more natural fit is using wfb-ng as a **named data broadcast layer** where the producer continuously pushes named segments and the CS does the work. The drone broadcasts `/drone/video/seg=N` continuously on the downlink. Ground stations receive whatever they can, and the CS buffers it. If a segment is missed, the consumer re-expresses an Interest which goes up the uplink — but most segments are satisfied locally from the CS without any uplink traffic. The FEC in wfb-ng and the retransmission in NDN are complementary — FEC handles burst loss at the physical layer, NDN Interest retransmission handles anything FEC could not recover.

**The engine change needed — `FacePairTable`**

The dispatch stage currently sends Data back on whatever face the PIT InRecord points to. For wfb-ng you need one additional lookup:

```rust
// in dispatch stage, before sending Data
let send_face_id = self.face_pairs
    .get_tx_for_rx(ctx.pit_token.in_face)
    .unwrap_or(ctx.pit_token.in_face);  // fall through for normal faces
face_table.get(send_face_id)?.send(data).await;
```

Normal faces return `None` from `get_tx_for_rx` and behave identically to today. `WfbFacePair` registers its rx face id mapped to its tx face id. The rest of the engine is untouched.

**Where it gets genuinely interesting for your research**

wfb-ng over multiple radios and channels — which is exactly your research focus — opens up some compelling scenarios. A node with one radio in monitor mode receiving on multiple channels simultaneously (using channel hopping or multiple radios) and another radio injecting responses creates a multi-channel asymmetric mesh where NDN names route across links that have no MAC-layer addressing whatsoever. The FIB routes names, the strategy selects which wfb downlink to inject on, and the CS absorbs the inherent lossiness of broadcast physical layers. This is a genuinely novel configuration that no existing NDN implementation supports and that your Rust engine architecture can accommodate with the face pairing extension plus the multi-radio strategy work we already designed.

**On the engineering investment**

The `WfbFace` implementation itself requires interfacing with the wfb-ng packet format, which is documented and stable, plus raw socket injection using `PACKET_TX_RING` for the transmit side and monitor mode capture for the receive side. The wfb-ng FEC is available as a C library with a clean API that you can call via Rust FFI or reimplement in Rust — there are partial Rust implementations of Reed-Solomon already available. The `FacePairTable` engine change is small. Total implementation effort is probably two to four weeks for a solid initial implementation, which is a reasonable investment if long-range asymmetric wireless is part of your research scope.



## Prompt:
3/25/2026, 10:46:08 PM

How about NDN over serial or bluetooth.  I am sure there are uses for those links.



## Response:
3/25/2026, 10:47:41 PM

Yes, both are sensible and the use cases are distinct enough to be worth thinking through separately. The good news is that the `Face` trait abstraction we designed handles both cleanly — they are just new `Face` implementations. No engine changes needed at all.

**Serial first — the use cases are compelling**

Serial links (UART, RS-232, RS-485, USB CDC) are the dominant communication medium for embedded systems, sensors, microcontrollers, and industrial equipment. An NDN serial face would connect things like Arduino/STM32 sensor nodes, GPS receivers, industrial PLCs, and radio modems (LoRa, 433 MHz, satellite modems like RockBLOCK) into an NDN mesh without any IP stack on the embedded side.

````plaintext
Tool: show_widget
````

**Serial is the simpler implementation**

The `tokio-serial` crate wraps platform serial ports as async `AsyncRead + AsyncWrite` streams, which fits directly into the same `tokio_util::codec` framing pattern we designed for TCP faces. The only serial-specific decision is framing.

COBS is the right choice for embedded sensor links because it gives you reliable frame resynchronisation after line noise or corruption. A length-prefix frame that gets corrupted loses sync until the next connection reset. A COBS frame is delimited by `0x00` bytes which never appear in the encoded payload — after corruption you wait for the next `0x00` and resync immediately. For industrial RS-485 environments with electrical noise this matters. The `cobs` crate in Rust handles encoding and decoding.

For LoRa radio modems connected over UART the serial face is particularly useful. A LoRa modem like the RFM95 or RAK811 presents as a UART device accepting AT commands. You send it an NDN packet framed over COBS, it transmits over LoRa, the remote modem receives it and outputs it over its UART to the remote engine. You get kilometre-range NDN links with no IP anywhere. The bandwidth is low — LoRa at SF7 gives you about 5.5 kbps — but NDN's Interest-Data model is well suited to low-bandwidth links because Interest aggregation and CS caching minimise retransmissions naturally.

RS-485 is interesting for a different reason. It is a multi-drop bus — up to 32 devices on a single twisted pair, half-duplex. NDN's broadcast-and-respond model maps onto RS-485 naturally: an Interest broadcast on the bus reaches all nodes, the node that has the named data responds. This is essentially how Modbus works but with names instead of register addresses and with CS caching instead of stateless polling. For industrial sensor networks this is a genuine improvement over Modbus — a PLC reading `/factory/line1/temperature` gets a cached response if that data was recently read by anything else on the bus, halving bus traffic in dense polling scenarios.

**Bluetooth Classic reuses SerialFace**

Bluetooth Classic's RFCOMM profile presents as a serial stream — on Linux it appears as `/dev/rfcommN` after pairing. Your `SerialFace` implementation works without modification. The `bluer` crate handles RFCOMM connection management in async Rust. Throughput up to 3 Mbps makes it suitable for carrying full NDN Data packets including video segments. Latency of 20–40 ms is coarser than WiFi but acceptable for most NDN applications given that NDN Interest lifetime is typically 4 seconds.

**BLE requires a distinct face implementation**

BLE is fundamentally different from Classic Bluetooth despite sharing the name. The connection interval — the period between radio wakeups — is the dominant parameter. At the minimum 7.5 ms interval you get reasonable latency but poor battery life. At a 1-second interval you get excellent battery life but Interest lifetime must be set accordingly — a 4-second default Interest lifetime survives 4 connection interval misses, which is usually sufficient.

The right BLE profile for NDN is **L2CAP Connection-Oriented Channels (CoC)** rather than GATT NUS (Nordic UART Service). L2CAP CoC gives you a proper bidirectional stream channel with negotiated MTU up to 65535 bytes, avoiding the 20-byte GATT characteristic limit and the overhead of GATT notifications. The negotiated ATT MTU in practice lands around 247 bytes on most modern BLE stacks, which fits NDN Interests comfortably and requires NDNLPv2 fragmentation for Data packets.

The `btleplug` crate provides cross-platform BLE in Rust but its L2CAP CoC support is limited — Linux via `bluer` is more complete for the server side. For your research hardware (likely Linux-based) `bluer` is the right dependency.

**The CS interaction with BLE sleep cycles is genuinely useful**

When a BLE peripheral sleeps between connection intervals, it cannot receive Interests. In a standard request-response protocol this means the client must retry or wait. In NDN the CS handles this gracefully — if the peripheral has recently broadcast its sensor data and the forwarder cached it, the consumer gets a CS hit immediately without the peripheral waking at all. The peripheral's producer only needs to push fresh data once per freshness period, and any number of consumers can read it from cache. For battery-powered sensors this is a meaningful efficiency gain over any IP-based approach.

**The phone gateway use case is worth highlighting**

A BLE face on a Linux NDN node connecting to a smartphone creates a path from the NDN mesh to cellular networks without any IP configuration on the NDN side. The phone runs a small NDN gateway application that bridges BLE NDN packets to UDP NDN packets over LTE. From the engine's perspective this is just two faces — a `BleFace` and a `UdpFace` — and the FIB routes names across them. A sensor node in the field with no WiFi coverage can reach an NDN repository over the internet via BLE to phone to LTE, with the phone's NDN gateway handling the transport translation transparently.

**Implementation priority**

For your wireless research the order of priority is probably: `SerialFace` first since it is straightforward and immediately useful for connecting sensor hardware and radio modems, Bluetooth Classic second since it reuses `SerialFace` almost entirely, and BLE third since it requires the most platform-specific work but enables the most interesting constrained device scenarios. All three fit cleanly into the face abstraction with no engine changes, which is exactly the extensibility the architecture was designed to provide.



## Prompt:
3/26/2026, 8:02:55 AM

Now, help me understand how Rust can handle TLV decoding effectively.



## Response:
3/26/2026, 8:04:33 AM

Good. TLV decoding is one of the places where Rust's type system earns its keep most clearly — you can make invalid packet states unrepresentable and push all error handling to the decode boundary, so everything above it works with guaranteed-valid types.

Let me start with the wire format, then work through the design options and their tradeoffs.

**NDN TLV wire format recap**

Every NDN element is a Type-Length-Value triple where both Type and Length are variable-width encoded using a scheme borrowed from BER but simplified:

````plaintext
Tool: show_widget
````

**The core primitive: `read_varu64`**

Everything in TLV decoding reduces to reading variable-width unsigned integers. The function above is branchless for the common case — values below 253 (which covers all standard NDN type codes and most lengths) take one byte and one match arm. The `try_into()` calls on byte slices are infallible if the slice has the right length, and the compiler knows this from the match structure, so they compile to direct load instructions with no bounds check overhead.

This function is the hot path. Every TLV element requires two calls to it — one for Type, one for Length. A typical NDN Interest has around 15–20 TLV elements, so a single packet decode costs roughly 30–40 calls. Keeping this function small enough to inline is important.

**`TlvReader` over `bytes::Bytes` — the zero-copy design**

The key insight is that `bytes::Bytes` supports `slice()` which returns a new `Bytes` sharing the same underlying allocation — it increments an atomic reference count and returns a view, with no `memcpy`. This means a `TlvReader` can hand out sub-slices of the original packet buffer to decoded fields without copying anything. A `Name` component, a signature value, a content field — all are `Bytes` slices pointing into the original receive buffer.

This matters for the CS specifically. A `CsEntry` storing `data: Bytes` is storing a reference-counted view of the receive buffer, not a copy. If the buffer lives long enough — which it will, since the `Arc` in `Bytes` keeps it alive — cache hits serve packets directly from the original allocation. The memory cost of the CS is proportional to the actual data size, not doubled by copying.

**Partial decode with `OnceLock` — pay only for what you use**

This is the design decision that has the most impact on pipeline performance. Consider the CS lookup stage: it needs the `Name` and the `MustBeFresh` flag. It does not need the nonce, the forwarding hint, the application parameters, or the signature. If you fully decode the Interest upfront, you pay for all of those fields even on a CS hit that short-circuits the pipeline before any stage needs them.

`OnceLock<T>` is Rust's standard library primitive for lazy initialisation — it stores an `Option<T>` internally and provides `get_or_init(f)` which calls `f` once and caches the result. Using it for lazily-decoded fields means the decode cost is paid exactly once, the first time a stage accesses the field, and not at all if no stage reaches that point:

```rust
impl PartialInterest {
    pub fn nonce(&self) -> Result<u32> {
        self.nonce.get_or_try_init(|| {
            decode_nonce(&self.raw)
        }).copied()
    }
}
```

The CS stage accesses `name` and `selectors.must_be_fresh` — both decoded. On a CS hit the packet is satisfied and the pipeline exits. The nonce, lifetime, and forwarding hint `OnceLock` fields are never initialised. Their decode cost is zero.

**Name decoding deserves special attention**

`Name` is the most frequently accessed field and the most expensive to decode — it is a sequence of TLV-encoded components, each of which is itself a Type-Length-Value. A typical name has 4–8 components. The decoded `Name` needs to be `Arc<Name>` so it can be shared cheaply across the PIT key, FIB lookup, CS key, and strategy context without copying.

The component representation matters for FIB trie performance. Each component is a `(type: u64, value: Bytes)` pair where type distinguishes generic components from versioned components, sequence number components, implicit digest components, and so on. Storing components as `SmallVec<[NameComponent; 8]>` keeps names with 8 or fewer components entirely on the stack during decode before they are moved into the `Arc`:

```rust
pub struct Name {
    components: SmallVec<[NameComponent; 8]>,
}

pub struct NameComponent {
    typ:   u64,
    value: Bytes,   // zero-copy slice of original packet buffer
}
```

The `Bytes` in each `NameComponent` slices into the original receive buffer — no copying of component values even for long names.

**Error handling — the `TlvError` type**

The decoder should distinguish several error cases that have different recovery strategies:

```rust
pub enum TlvError {
    UnexpectedEof,              // packet truncated — drop silently
    UnknownCriticalType(u64),   // NDN spec: drop if critical bit set
    InvalidLength { typ: u64, expected: usize, got: usize },
    InvalidUtf8 { typ: u64 },   // for URI components
    NonceMissing,               // malformed Interest
    DuplicateField(u64),        // same TLV type appeared twice
}
```

The NDN spec has a specific rule about unknown TLV types: if the type number is odd (critical bit set) and unknown, the packet must be dropped. If the type is even (non-critical) and unknown, it must be silently skipped. Your decoder handles this in the `TlvReader::skip_unknown` method:

```rust
fn skip_unknown(&mut self, typ: u64) -> Result<(), TlvError> {
    if typ & 1 == 1 {
        Err(TlvError::UnknownCriticalType(typ))
    } else {
        let len = self.read_length()?;
        self.pos += len;  // skip non-critical unknown field
        Ok(())
    }
}
```

This is important for forward compatibility — new NDN spec versions add non-critical TLV types and old implementations must handle them gracefully.

**Encoding — the symmetric problem**

Encoding is simpler than decoding because you control the output. The key design decision is whether to encode into a pre-allocated `BytesMut` or to compute the size first and allocate exactly. For NDN the second approach is better because TLV lengths are variable-width and you cannot know the encoded length until you know the value. The pattern is a two-pass encoder or a `BytesMut` that grows:

```rust
pub struct TlvWriter {
    buf: BytesMut,
}

impl TlvWriter {
    pub fn write_tlv(&mut self, typ: u64, value: &[u8]) {
        self.write_varu64(typ);
        self.write_varu64(value.len() as u64);
        self.buf.extend_from_slice(value);
    }

    pub fn write_nested<F>(&mut self, typ: u64, f: F)
    where F: FnOnce(&mut TlvWriter) {
        let start = self.buf.len();
        self.write_varu64(typ);
        let len_pos = self.buf.len();
        self.buf.extend_from_slice(&[0u8; 4]); // placeholder for length
        f(self);
        let value_len = self.buf.len() - len_pos - 4;
        // backfill length — if it fits in 1 byte, shift the buffer
        // this is the awkward part of nested TLV encoding
    }
}
```

The awkward part of nested TLV encoding is that outer lengths depend on inner content. `write_nested` handles this by reserving length space, encoding the inner content, then backfilling. If the inner content is small enough that the length fits in 1 byte instead of 4, you shift the buffer. This is the one place where a two-pass approach — compute size tree first, then encode — is cleaner at the cost of two traversals.

**The `nom` vs hand-rolled question**

`nom` and `winnow` are excellent for protocol parsers where you have many different packet formats and want compositional combinators. For NDN TLV specifically, the format is simple enough and performance-sensitive enough that hand-rolled is the right choice for the engine core. The `varu64` decoder and `TlvReader` are maybe 200 lines of code — not enough complexity to justify a parser combinator framework on the hot path. Where `winnow` does add value is for the less performance-critical parts: parsing NDN URI strings (`/foo/bar/%AB`), configuration file formats, and management protocol messages. Use the right tool for each context.

Want to go deeper on Name encoding and the canonical ordering rules, or move to how the decoded types map onto the `PacketContext` fields we designed earlier?



## Prompt:
3/26/2026, 8:21:05 AM

Let's see how Rust handles NDN's security architecture.



## Response:
3/26/2026, 8:22:53 AM

Good. NDN's security architecture is more deeply integrated than IP security — signatures are on the data itself, not on the channel, which means security travels with the content regardless of how it is forwarded or cached. This has significant implications for how you structure the Rust types.

**The core NDN security model**

In NDN every Data packet is signed by its producer. The signature covers the Name, MetaInfo, Content, and SignatureInfo fields — not the wire encoding of the outer packet. Trust is in the data, not the path. This means a CS hit from an untrusted forwarder is as secure as a fresh response from the producer, which is what makes NDN caching safe in adversarial environments.

````plaintext
Tool: show_widget
````

Now let me work through the implementation decisions in depth.

**The signed region is contiguous — verify without copy**

The most important implementation fact is that NDN's signed region — Name, MetaInfo, Content, SignatureInfo — is contiguous in the wire encoding. The SignatureValue TLV comes at the end and is explicitly excluded. This means verification takes a slice directly into the `bytes::Bytes` receive buffer:

```rust
impl Data {
    pub fn signed_region(&self) -> &[u8] {
        // signed region starts at byte 2 (after outer Data TLV header)
        // ends just before SignatureValue TLV
        &self.raw[self.signed_start..self.signed_end]
    }

    pub fn sig_value(&self) -> &[u8] {
        &self.raw[self.sig_value_start..self.sig_value_end]
    }
}
```

Both are zero-copy slices. The crypto library receives `&[u8]` references into the original packet buffer. No intermediate allocation anywhere on the verification path.

**Concrete implementations using `ring` and `ed25519-dalek`**

The `ring` crate covers RSA, ECDSA P-256, HMAC-SHA256, and SHA256 digest — all the standard NDN signature types — with excellent performance and a sound API. `ed25519-dalek` covers Ed25519 which is the most appropriate choice for new NDN deployments given its small key size, fast verification, and resistance to implementation errors:

```rust
pub struct Ed25519Signer {
    signing_key:  ed25519_dalek::SigningKey,
    key_name:     Name,
    cert_name:    Name,
}

impl Signer for Ed25519Signer {
    fn sig_type(&self) -> SignatureType {
        SignatureType::SignatureEd25519
    }

    fn key_locator(&self) -> Option<&Name> {
        Some(&self.cert_name)
    }

    async fn sign(&self, region: &[u8]) -> Result<Bytes> {
        use ed25519_dalek::Signer;
        let sig = self.signing_key.sign(region);
        Ok(Bytes::copy_from_slice(sig.to_bytes().as_ref()))
    }
}

pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    async fn verify(
        &self, region: &[u8], sig: &[u8], key: &[u8],
    ) -> Result<VerifyOutcome> {
        use ed25519_dalek::Verifier;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(
            key.try_into().map_err(|_| TrustError::InvalidKey)?
        )?;
        let sig = ed25519_dalek::Signature::from_bytes(
            sig.try_into().map_err(|_| TrustError::InvalidSignature)?
        );
        match vk.verify(region, &sig) {
            Ok(()) => Ok(VerifyOutcome::Valid),
            Err(_) => Ok(VerifyOutcome::Invalid),
        }
    }
}
```

Note that `verify` returns `Ok(VerifyOutcome::Invalid)` rather than `Err` for a bad signature — a verification failure is an expected outcome, not a programming error. Only genuinely unexpected conditions (malformed key, wrong key length) return `Err`.

**The trust schema — name pattern matching with variable capture**

The trust schema is the part that makes NDN security semantically meaningful rather than just cryptographically sound. A valid signature by a known key is not sufficient — the key must also be authorised to sign names matching the data's name, according to a policy that captures namespace structure.

The pattern matching needs variable capture — the rule `/sensor/<node>/<type>` signed by `/sensor/<node>/KEY/<id>` requires that the `<node>` captured from the data name matches the `<node>` captured from the key name. In Rust this maps naturally to a pattern type with named capture groups:

```rust
pub enum PatternComponent {
    Literal(NameComponent),          // exact match
    Capture(Arc<str>),               // named capture — binds a variable
    MultiCapture(Arc<str>),          // matches one or more components
}

pub struct NamePattern(Vec<PatternComponent>);

impl NamePattern {
    pub fn matches(
        &self,
        name: &Name,
        bindings: &mut HashMap<Arc<str>, NameComponent>,
    ) -> bool {
        // walk pattern and name simultaneously
        // Capture binds to single component, MultiCapture to remainder
        // check bindings are consistent across data and key patterns
    }
}
```

Schema evaluation checks both the data pattern and the key pattern against their respective names, then verifies that all captured variables with the same name bound to the same value. This is the mechanism that prevents a sensor node from signing data for a different sensor node, even if both use valid keys under the same namespace.

**Certificate cache — NDN fetches certs as named data**

This is where NDN's architecture becomes elegant. Certificates are just signed Data packets with names like `/sensor/node1/KEY/abc123/self/%FD001`. Fetching a certificate is just expressing an Interest. The certificate cache is therefore backed by the engine's own CS:

```rust
pub struct CertCache {
    app_face: Arc<AppFace>,           // to express cert-fetch Interests
    local:    DashMap<Name, Certificate>,  // hot cache, avoids CS round-trip
    max_age:  Duration,
}

impl CertCache {
    pub async fn get_or_fetch(&self, key_name: &Name) -> Result<Certificate> {
        if let Some(cert) = self.local.get(key_name) {
            return Ok(cert.clone());
        }
        // fetch via NDN — CS may satisfy this locally
        let data = self.app_face
            .express(Interest::new(key_name.clone()))
            .await?;
        let cert = Certificate::decode(&data)?;
        self.local.insert(key_name.clone(), cert.clone());
        Ok(cert)
    }
}
```

The first time a certificate is needed it is fetched via a normal NDN Interest — which may be satisfied by the CS if the cert was recently fetched by anyone else on the same node. Subsequent accesses hit the local `DashMap`. This means certificate validation does not require any out-of-band PKI infrastructure — everything travels over NDN.

**The validation pipeline — where this sits in the engine**

Validation is an application-layer concern, not a forwarder concern. The engine's pipeline does not validate signatures on transit Data — it cannot, because it does not have the application's trust schema or key store. What the engine does is set the `verified: bool` flag in `PacketContext` to `false` for all incoming Data, and the application library's `AppFace` runs validation before delivering Data to the application callback:

```rust
// in AppFace — application side, not engine pipeline
async fn deliver(&self, data: Data, ctx: &PacketContext) -> Result<()> {
    if self.config.verify_incoming {
        match self.validator.validate(&data).await? {
            ValidationResult::Valid   => {},
            ValidationResult::Invalid => return Err(TrustError::InvalidData),
            ValidationResult::Pending => {
                // cert chain not yet resolved — queue for async completion
                self.pending_validation.push((data, ctx.pit_token));
                return Ok(());
            }
        }
    }
    self.deliver_validated(data).await
}
```

The `ValidationResult::Pending` case handles the situation where certificate fetching is in progress — the Data is held in a pending queue until the cert Interest resolves. This is important for cold starts when no certs are cached.

**The `ValidationResult::Pending` state and the async certificate chain**

Certificate chains can be arbitrarily deep in NDN — a data cert signed by an intermediate cert signed by a root cert. Each step requires fetching the signing cert via an Interest, which may itself trigger another fetch. This is naturally modelled as a recursive async function with a depth limit:

```rust
async fn validate_chain(
    &self,
    cert: &Certificate,
    depth: usize,
) -> Result<ValidationResult> {
    if depth > self.config.max_chain_depth {
        return Err(TrustError::ChainTooDeep);
    }
    // is this cert a trust anchor we already accept?
    if self.trust_anchors.contains(cert.name()) {
        return Ok(ValidationResult::Valid);
    }
    // fetch the cert that signed this cert
    let issuer_name = cert.sig_info.key_locator()?;
    let issuer = self.cert_cache.get_or_fetch(issuer_name).await?;
    // verify this cert's signature against issuer's key
    self.verifier.verify(
        cert.signed_region(),
        cert.sig_value(),
        issuer.public_key(),
    ).await?;
    // recurse up the chain
    self.validate_chain(&issuer, depth + 1).await
}
```

Tokio handles the async recursion correctly. The depth limit prevents infinite loops from malformed or adversarial certificate chains.

**SafeData — making verified status part of the type**

This is where Rust's type system enables something not possible in ndn-cxx. A `Data` packet and a verified `Data` packet are different types at compile time:

```rust
pub struct Data {
    // raw decoded data — not yet verified
    name:      Arc<Name>,
    content:   Bytes,
    sig_info:  SignatureInfo,
    sig_value: Bytes,
}

pub struct SafeData {
    // proof that validation succeeded — cannot be constructed except by Validator
    inner:      Data,
    trust_path: TrustPath,   // chain of cert names that validated this
    verified_at: u64,
}

// Validator::validate returns SafeData, not Data
// Application callbacks receive SafeData — cannot accidentally use unverified data
```

Any function that requires verified data takes `&SafeData` — the compiler enforces that unverified `Data` cannot be passed where verified data is required. This is a meaningful safety guarantee that the ndn-cxx `shared_ptr<Data>` model cannot express.

**For your wireless research — when to skip verification**

For the local trust model we designed for IPC and local process communication, the `LocalTrustStage` pipeline stage bypasses crypto verification entirely for faces with verified credentials. The `SafeData` wrapper can be constructed directly from a `Data` arriving on a trusted local face by a privileged constructor:

```rust
impl SafeData {
    // only constructable by Validator or trusted local path
    pub(crate) fn from_local_trusted(data: Data, face_creds: &FaceCredentials) -> Self {
        SafeData {
            inner: data,
            trust_path: TrustPath::LocalFace(face_creds.uid),
            verified_at: now_ns(),
        }
    }
}
```

The `pub(crate)` visibility ensures only code within the engine crate can construct `SafeData` without going through the full validator — application code cannot bypass verification accidentally or maliciously.

**Key storage — the `KeyChain` abstraction**

The final piece is where private keys live. For research hardware the simplest approach is file-based storage using the `pkcs8` crate for serialisation. For production or higher-security deployments you want TPM or HSM backing:

```rust
pub trait KeyStore: Send + Sync {
    async fn get_signer(&self, key_name: &Name) -> Result<Arc<dyn Signer>>;
    async fn generate_key(&self, name: Name, algo: KeyAlgorithm) -> Result<Name>;
    async fn delete_key(&self, key_name: &Name) -> Result<()>;
}

pub struct FileKeyStore { path: PathBuf }   // development
pub struct TpmKeyStore  { handle: TpmCtx }  // production
pub struct MemKeyStore  { keys: DashMap<Name, Arc<dyn Signer>> }  // testing
```

The `KeyChain` struct composes a `KeyStore` with a `CertCache` and a `TrustSchema` into the complete security subsystem that applications configure once at startup and pass to their `AppFace`.

Want to look at how the security subsystem integrates with the application API, or move on to the crate workspace structure that ties all of this together?



## Prompt:
3/26/2026, 8:34:05 AM

Let's check out if iceoryx2 is a good fit for the shared memory local faces or whether there is a better approach.



## Response:
3/26/2026, 8:35:36 AM

Good timing to look at this carefully. iceoryx2 is a serious piece of engineering and the question of fit is more nuanced than it first appears.

**What iceoryx2 actually is**

iceoryx2 is a zero-copy inter-process communication middleware based on a publish-subscribe model with shared memory as the transport. It originated from the automotive industry (AUTOSAR Adaptive) where deterministic latency and zero-copy semantics are requirements, not nice-to-haves. The Rust rewrite is a first-class citizen, not a binding.

````plaintext
Tool: show_widget
````

**The core mismatch — pub-sub vs request-response**

iceoryx2's model is publish-subscribe: a publisher writes to a topic, any number of subscribers receive it. NDN's Interest-Data model is fundamentally request-response: a consumer expresses a specific Interest, and only Data matching that Interest is delivered back to that consumer via the PIT reverse path. These are structurally different.

For the Data delivery direction — engine to application — iceoryx2 maps well. The engine is the publisher, the application is the subscriber. Multiple applications subscribing to the same name prefix all receive the same Data from the same shared memory segment with no copies. This is the zero-copy fan-out that makes iceoryx2 compelling.

For the Interest direction — application to engine — pub-sub is awkward. The application needs to send a specific Interest and receive back specifically the matching Data, not any Data published on a topic. You need request-response correlation, which iceoryx2 supports via its request-response API (added in more recent versions) but it is less mature than its pub-sub path.

**The variable-size problem is real but manageable**

iceoryx2's zero-copy guarantee depends on pre-allocated fixed-size slots in the shared memory segment. NDN packets are variable size — Interests range from 50 to 500 bytes, Data from 100 to 8800 bytes. The `loan_slice_uninit` API allows variable-size payloads but requires a maximum size at service creation time.

The practical solution is two separate iceoryx2 services with different max sizes:

```rust
// at engine startup
let interest_service = node
    .service_builder(&ServiceName::new("ndn/interests")?)
    .publish_subscribe::<[u8]>()
    .max_slice_len(512)        // covers all realistic Interests
    .create()?;

let data_service = node
    .service_builder(&ServiceName::new("ndn/data")?)
    .publish_subscribe::<[u8]>()
    .max_slice_len(9000)       // NDN MTU + headroom
    .create()?;
```

The internal fragmentation cost — allocating 9000 bytes for a 200-byte Data packet — is real but only matters if you have many concurrent pending Data deliveries. For typical NDN application patterns where the CS absorbs most traffic, the number of in-flight Data deliveries is small.

**The zero-copy loan pattern for large Data**

For video frames or large sensor buffers this is where iceoryx2 genuinely shines. The engine writes directly into the shared memory slot without copying:

```rust
// engine dispatch stage — Data delivery to local application
async fn deliver_to_app(
    &self,
    data: &Data,
    publisher: &Publisher<[u8]>,
) -> Result<()> {
    let wire = data.raw.as_ref();
    let mut sample = publisher.loan_slice_uninit(wire.len())?;
    // write directly into shared memory — no intermediate buffer
    sample.payload_mut().copy_from_slice(wire);
    let sample = unsafe { sample.assume_init() };
    sample.send()?;
    Ok(())
}
```

The application receives a `SampleMut` that is a direct reference into the shared memory segment. It reads the NDN TLV, decodes what it needs, and drops the sample — the slot is returned to the pool. No copy from engine to application at any point.

For large Data this is a meaningful win. A 8800-byte video segment copied via Unix socket costs one kernel crossing plus two memcpys — roughly 8–10 µs for the copy alone. Via iceoryx2 the engine writes once into shared memory and the application reads from the same physical pages — the copy cost is essentially zero.

**The hand-rolled SPSC alternative**

A hand-rolled single-producer single-consumer ring buffer over `mmap` is the alternative that gives you maximum control. The implementation is maybe 300 lines of Rust using atomics for the head and tail pointers:

```rust
struct ShmemRing {
    header: *mut RingHeader,   // mmap'd region start
    data:   *mut u8,           // packet data region
    capacity: usize,
}

#[repr(C)]
struct RingHeader {
    head:     AtomicUsize,     // written by consumer
    tail:     AtomicUsize,     // written by producer
    capacity: usize,
    _pad:     [u8; 40],        // keep head and tail on separate cache lines
}
```

The advantage over iceoryx2 is that you control the slot layout — you can store the NDN TLV length prefix in the slot header and pack packets tightly without the fixed-size slot waste. The disadvantage is that you implement flow control, crash detection, and process cleanup yourself. If the consumer process dies with the producer still writing, you need to detect this via the consumer's PID in the ring header and clean up the shared memory.

**The honest recommendation**

For your research use case the right answer depends on what you are optimising for.

If you are building infrastructure that other researchers will use and you want robustness and low implementation risk, use **iceoryx2 for the Data path and tokio mpsc for the Interest path**. iceoryx2 handles the hard problems — memory management, crash recovery, service discovery — and its 100–200 ns latency is excellent. The variable-size friction is manageable with the two-service approach.

If you are optimising for the absolute minimum latency on the Data path for your own research experiments — measuring forwarding performance, characterising the overhead of different strategies — a **hand-rolled SPSC ring buffer** gives you sub-100 ns and full visibility into every aspect of the path. You know exactly what is happening and can instrument it precisely.

If the applications sharing the engine are in the **same process** — which is the embedded use case and your IPC research scenario — **tokio mpsc with `Arc<DecodedPacket>`** is the right answer. No shared memory setup, no cross-process complexity, and passing an `Arc` clone costs one atomic increment — roughly 10–20 ns. The `Arc` keeps the packet alive in the engine's allocation until all consumers drop their reference. This is genuinely zero-copy in the sense that the bytes are never duplicated — just reference-counted.

The three-tier model that emerges is:

```
same process:      tokio mpsc + Arc<DecodedPacket>   — ~20 ns
cross-process:     iceoryx2 Data + mpsc Interest     — ~150 ns  
cross-process      hand-rolled SPSC ring             — ~80 ns
high-performance:  (research / benchmarking only)
```

For the standalone forwarder binary that external applications connect to, iceoryx2 is the right default. For the embedded research node where everything runs in one process, mpsc with Arc is simpler and faster. The `AppFace` trait abstraction means you can swap between these without changing any application code — the face implementation changes but the API the application sees does not.

Want to look at the crate workspace structure now that we have all the major components designed, or is there another area to explore first?



## Prompt:
3/26/2026, 8:46:06 AM

Just an observation: it seems that if we use SPSC, the engine is essentially becoming an iceoryx2 alternative, right?  Let's get on to crate workspace structure now.



## Response:
3/26/2026, 8:47:58 AM

That observation is exactly right. A hand-rolled SPSC ring buffer with service discovery, crash detection, flow control, and zero-copy semantics is iceoryx2 — you would be reimplementing it with NDN names as the service namespace. The NDN CS would even serve as a natural persistence layer that iceoryx2 lacks. It is an interesting direction but you would be building middleware, not an NDN stack. iceoryx2 for cross-process and mpsc for in-process is the right boundary to draw.

On to the workspace.

````plaintext
Tool: show_widget
````

The workspace has five layers. Each layer only depends on layers below it — no upward dependencies. This is the constraint that keeps the graph acyclic and prevents the core types from pulling in engine or face dependencies.

**Layer 0 — binaries**

These are thin. `ndn-router` is essentially `EngineBuilder` configuration read from a TOML file plus signal handling. `ndn-tools` provides the research and debugging CLI — `ndn-peek /name` to fetch named data, `ndn-put /name file` to publish, `ndn-ls /prefix` to enumerate, `ndn-ping /name` for RTT measurement. `ndn-bench` drives controlled throughput and latency experiments against a running engine. All three depend on `ndn-app` and `ndn-engine` but nothing in the core layers depends on them.

**Layer 1 — application and engine**

`ndn-app` is what external code imports. It exposes `AppFace`, `express()`, `produce()`, `subscribe()`, `ChunkedConsumer`, `ChunkedProducer`, and `ServiceRegistry`. It depends on `ndn-engine` internally but hides the engine's internals — an application author never imports `ndn-engine` directly. This is important for API stability: `ndn-engine`'s internals can change without breaking application code.

`ndn-ipc` builds on `ndn-app` with the higher-level IPC patterns — `IpcServer` for processes that want to expose a named service, `IpcClient` for consumers, and the `ServiceRegistry` that maps service names to name prefixes. It adds the `iceoryx2` dependency only here, not in any lower crate.

`ndn-engine` owns `ForwarderEngine`, `EngineBuilder`, and the task topology. It depends on the pipeline, store, and transport layers but not on any face implementations directly — faces are registered at runtime through `EngineBuilder`.

**Layer 2 — pipeline, strategy, security**

`ndn-pipeline` defines the `PipelineStage` trait, `PacketContext`, `Action`, and `ForwardingAction`. It is the interface that both the engine and all stage implementations depend on. Keeping it separate from `ndn-engine` means custom stage crates can depend on `ndn-pipeline` without pulling in the full engine.

`ndn-strategy` implements the built-in strategies — `BestRouteStrategy`, `MulticastStrategy`, `AsfStrategy`, and `MultiRadioStrategy`. A researcher writing a custom strategy depends only on `ndn-pipeline` and `ndn-packet`, not on the engine itself. This is the clean extension point we discussed for your wireless research.

`ndn-security` owns the `Signer`, `Verifier`, `TrustSchema`, `Validator`, `CertCache`, and `KeyStore` traits and their implementations. It depends on `ndn-packet` for the `Data` type and on `ring` and `ed25519-dalek` for crypto. The engine optionally depends on it — security is not mandatory for a forwarder.

**Layer 3 — faces**

Splitting faces into four crates reflects real dependency differences. `ndn-face-net` pulls in tokio's net features. `ndn-face-local` pulls in `iceoryx2` or platform Unix socket APIs. `ndn-face-serial` pulls in `tokio-serial` and `cobs`. `ndn-face-l2` pulls in `neli` for nl80211 Netlink, the wfb-ng FFI, and `bluer` for Bluetooth. None of these dependencies belong in the engine itself — a router that only uses UDP faces should not compile iceoryx2 or tokio-serial.

All four depend on `ndn-transport`, which defines the `Face` trait, `FaceId`, `FaceTable`, and `RawPacket`. This is the only thing the engine needs to know about faces.

**Layer 4 — data structures**

`ndn-tlv` is the foundation — `TlvReader`, `TlvWriter`, `varu64`, COBS framing. No NDN-specific types, just encoding primitives. It has minimal dependencies: `bytes` and nothing else.

`ndn-packet` defines `Name`, `NameComponent`, `Interest`, `Data`, `Nack`, `SignatureInfo`, `MetaInfo` — all the decoded packet types. It depends on `ndn-tlv` for decoding and `bytes` for zero-copy storage. This is the crate that embedded NDN applications on microcontrollers would import — it has no async dependency, no tokio, no engine.

`ndn-store` defines `NameTrie<V>`, `Pit`, and the `ContentStore` trait plus the `LruCs`, `SegmentedLruCs`, and `ShardedCs<C>` implementations. It depends on `ndn-packet` for `Name` and on `dashmap`, `smallvec`, and `lru`.

`ndn-transport` defines the `Face` trait and `FaceTable`. It depends on `ndn-packet` and `bytes`. It is the thinnest crate in the workspace — maybe 200 lines — but its position in the graph makes it the right home for the `Face` trait rather than putting it in `ndn-engine` where it would create a circular dependency with face crates.

**Layer 5 — research extensions**

`ndn-research` contains `FlowObserverStage`, the `RadioTable`, nl80211 integration via `neli`, and any measurement infrastructure specific to research. It depends on `ndn-pipeline` and `ndn-face-l2` but is not depended on by anything in the core stack. A production deployment compiles without it.

`ndn-compute` contains `ComputeFace`, `ComputeRegistry`, and `ChunkedProducer` for compute result segmentation.

`ndn-sync` implements dataset synchronisation protocols — SVS (State Vector Sync) and PSync — which are the NDN equivalents of distributed pub-sub. These are application-layer protocols built on top of `ndn-app`.

**The workspace dependency file**

Declaring shared dependencies at the workspace level with `[workspace.dependencies]` means every crate in the workspace uses the same version of `bytes`, `tokio`, `tracing`, `dashmap`, and `smallvec`. Version conflicts between workspace crates are impossible. Individual crates inherit versions with:

```toml
# in crates/ndn-packet/Cargo.toml
[dependencies]
bytes    = { workspace = true }
smallvec = { workspace = true, features = ["union"] }
```

Feature flags matter here. `tokio = { version = "1", features = ["full"] }` in the workspace pulls full tokio into every crate. Better to declare it minimal at the workspace level and let individual crates enable features:

```toml
# workspace
tokio = { version = "1", default-features = false }

# ndn-engine/Cargo.toml
tokio = { workspace = true, features = ["rt-multi-thread", "sync", "time"] }

# ndn-face-net/Cargo.toml
tokio = { workspace = true, features = ["net"] }

# ndn-packet/Cargo.toml — no tokio at all
```

This keeps `ndn-packet` and `ndn-tlv` dependency-free enough to compile on embedded targets like Cortex-M with `no_std` — which is a real use case for the sensor node side of your wireless research. Adding `#![no_std]` to `ndn-tlv` and `ndn-packet` with `alloc` feature gating is a small amount of work that opens up the entire embedded NDN space.

The directory layout on disk follows the crate graph directly:

```
ndn-rs/
├── Cargo.toml                 # workspace root
├── crates/
│   ├── ndn-tlv/
│   ├── ndn-packet/
│   ├── ndn-transport/
│   ├── ndn-store/
│   ├── ndn-pipeline/
│   ├── ndn-strategy/
│   ├── ndn-security/
│   ├── ndn-engine/
│   ├── ndn-app/
│   ├── ndn-ipc/
│   ├── ndn-face-net/
│   ├── ndn-face-local/
│   ├── ndn-face-serial/
│   ├── ndn-face-l2/
│   ├── ndn-compute/
│   ├── ndn-sync/
│   └── ndn-research/
└── binaries/
    ├── ndn-router/
    ├── ndn-tools/
    └── ndn-bench/
```

One last structural note: `ndn-tlv` and `ndn-packet` are the crates most likely to be useful to the broader NDN community independently of your engine — someone building an NDN application in Rust should be able to import just those two and get full packet encoding and decoding without pulling in a forwarder. Designing them with that use case in mind from the start is worth the small extra care.



## Prompt:
3/26/2026, 8:56:29 AM

How do you recommend me turn this design into code, i.e., claude code, in this chat, some other tool?



## Response:
3/26/2026, 8:57:05 AM

Good question to think through carefully because the answer depends on what phase of development you are in and what you want to optimise for.

**The honest assessment of each option**

**In this chat** is the wrong tool for implementation. I can write correct individual functions and data structures, but I have no persistent memory of what I wrote three responses ago. You would end up with code fragments that are internally consistent but do not compose — the `TlvReader` I write now will not match the `PacketContext` I wrote earlier unless you manually reconcile them. For a workspace of this complexity that is a recipe for subtle inconsistencies that are hard to debug.

**Claude Code** is the right tool for this project, but with a specific workflow. It maintains context across the entire workspace, can read and edit multiple files in one operation, runs `cargo check` and `cargo test` inline, and sees the actual compiler errors rather than guessing at them. For a Rust workspace with this many interacting traits — `Face`, `PipelineStage`, `ContentStore`, `Strategy`, `Signer` — the compiler is your primary design validation tool and you need something that can talk to it directly.

**The recommended approach — phased with Claude Code**

Do not try to implement the whole design at once. The crate graph gives you a natural build order where each layer compiles independently before the next:

```
Phase 1:  ndn-tlv          — varu64, TlvReader, TlvWriter, COBS
          ndn-packet        — Name, Interest, Data, Nack
          (cargo test passes before moving on)

Phase 2:  ndn-transport     — Face trait, FaceId, FaceTable, RawPacket
          ndn-store         — NameTrie, Pit, ContentStore trait, LruCs

Phase 3:  ndn-pipeline      — PipelineStage, PacketContext, Action
          ndn-strategy      — BestRouteStrategy, MulticastStrategy

Phase 4:  ndn-engine        — ForwarderEngine, EngineBuilder, task topology
          ndn-face-net      — UdpFace, TcpFace

Phase 5:  ndn-security      — Signer, Verifier, TrustSchema, Validator
          ndn-app           — AppFace, express(), produce()

Phase 6+: remaining crates
```

Each phase should reach a state where `cargo test` passes and the public API is stable before you start the next phase. Changing `Name` after `NameTrie` and `Pit` depend on it is expensive.

**How to work with Claude Code effectively on this**

Start each Claude Code session with a context document — a short markdown file in the repo root called `DESIGN.md` that summarises the key architectural decisions we made. Claude Code reads files before writing code, so giving it the design decisions upfront prevents it from making choices that contradict the architecture. Key things to include:

```markdown
# NDN-RS Design Decisions

- PacketContext passes by value through pipeline stages
- Name is Arc<Name> shared across PIT, FIB, CS
- Face trait has async send(&self) and recv(&self)
- PIT uses DashMap keyed by (Name, Option<Selector>)
- TlvReader operates zero-copy over bytes::Bytes
- Strategies return ForwardingAction not pipeline Action directly
- SafeData is only constructable by Validator
```

Then ask Claude Code to implement one crate at a time, starting with the test suite. Writing tests first gives Claude Code a concrete target and catches design issues before they propagate. For `ndn-tlv` for example:

```
"Implement ndn-tlv. Start with the test suite covering:
- varu64 round-trip for all four encoding widths
- TlvReader correctly slices nested TLVs zero-copy
- COBS encode/decode round-trip including zero bytes in payload
- Error cases: UnexpectedEof, UnknownCriticalType
Then implement to pass the tests."
```

**One specific recommendation for the wireless and research components**

For `ndn-face-l2` and `ndn-research` — the nl80211 integration, ChannelManager, and MultiRadioStrategy — prototype these separately from the main workspace first as a small standalone binary that just reads nl80211 survey data and prints it. The Netlink interface is complex and platform-specific and you do not want debugging it to block progress on the core stack. Once you have a working nl80211 reader, integrating it into `ndn-face-l2` is straightforward.

**The practical starting point**

Create the workspace skeleton first — all the `Cargo.toml` files with correct dependency declarations but empty `src/lib.rs` files. Verify `cargo build` succeeds on the empty workspace. Then start filling in `ndn-tlv` with Claude Code. Having the full workspace skeleton in place from the start means Claude Code can see the intended structure and write code that fits into it correctly rather than writing self-contained modules that need restructuring later.

One final note: keep this conversation exportable. The design decisions we made — particularly around `PacketContext` ownership, the `ForwardingAction` enum variants, `EtherFace` vs `UdpFace`, the `FacePairTable` for wfb-ng, the three-tier IPC model — are not written down anywhere except here. Export this conversation to markdown and commit it to the repo as `docs/design-session.md` before you start coding. Claude Code can then reference it when you ask why a particular design choice was made.





---
Powered by [Claude Exporter](https://www.ai-chat-exporter.net)