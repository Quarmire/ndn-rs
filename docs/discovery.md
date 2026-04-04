# Neighbor Discovery and Service Discovery

## Two Distinct Problems

Neighbor discovery and service discovery are often conflated but they solve different problems at different scopes.

**Neighbor discovery** answers: "Who are my directly-connected link-layer peers?" It operates at the link scope and produces MAC↔name bindings and face table entries. Without it, the forwarding plane has no faces to use.

**Service discovery** answers: "Who in the network can serve prefix `/ndn/edu/ucla/cs/...`?" It operates at the routing scope and produces FIB entries. In IP networks this requires a separate mechanism (DNS-SD, mDNS, Consul). In NDN it is largely subsumed by routing — when a producer registers a prefix with its local router and the routing protocol distributes that reachability information, consumers express Interests and the FIB delivers them. There is no separate "lookup" step.

What NDN still needs that routing cannot provide is **link-local bootstrap**: the layer-2 plumbing that makes routing possible in the first place. That is the primary focus of this document.

---

## Should Discovery Live in the Engine?

The current NDN research practice runs NFD, NLSR, and ndnsd as separate daemons. That design was shaped by academic context: each team owns their component, interoperability with other implementations matters, and the target platform is a general-purpose Linux machine.

For `ndn-rs`, a different tradeoff applies. The forwarding plane is genuinely unaffected by *how* the face table and FIB get populated — only that they are populated correctly and promptly. This is the clean interface boundary. What the engine *must* know about is the outcome of discovery (face up/down, FIB entry added/removed), not the mechanism.

**Arguments against baking a specific protocol into the engine core:**

- *Protocol evolution*: hello formats, timer algorithms, and state machines will change. Every change requires touching the forwarding plane.
- *Embedded targets*: `ndn-embedded` runs on bare-metal MCUs and cannot run any discovery protocol at all. Baked-in code ships dead weight to resource-constrained devices.
- *Multi-protocol composition*: a campus router might need both link-local neighbor discovery and NLSR simultaneously. One hardcoded protocol cannot serve both.
- *Testing*: forwarding correctness tests should not require a running discovery protocol.

**Arguments against a fully separate process:**

- *Latency*: mobile nodes switching channels at 100 ms granularity cannot afford the IPC round-trip through the management socket for every face creation event.
- *Internal access*: discovery needs to atomically create a face and add a FIB entry. Doing this across a process boundary introduces TOCTOU windows.
- *Deployment simplicity*: a single binary is far easier to operate on small devices.

**The right answer**: a **trait object that runs inside the engine process**, called at well-defined lifecycle hooks, with access to the engine's internals through a controlled interface. Not baked in — injected at construction time. This is exactly the pattern the `Strategy` system uses and it is the right model here.

```text
┌─────────────────────────────────────────────────────────────┐
│  ndn-engine                                                  │
│                                                             │
│  Forwarding plane (FIB / PIT / CS / pipeline)              │
│       ↑  ↓  face create/remove, FIB add/remove             │
│  DiscoveryContext  ◄──────── controlled interface           │
│       ↑                                                     │
│  dyn DiscoveryProtocol  ◄──── injected at startup          │
│  (EtherND, NLSR adapter, MdnsDiscovery, NoDiscovery, ...)  │
└─────────────────────────────────────────────────────────────┘
```

The engine calls discovery hooks. Discovery calls back through `DiscoveryContext`. Neither knows the other's internals. Swap implementations by injecting a different trait object at engine construction time.

---

## Trait Definitions

### `DiscoveryProtocol`

```rust
/// A discovery protocol implementation.
///
/// Injected into the engine at construction time. The engine calls
/// these hooks at face lifecycle events and on inbound packets that
/// may be discovery traffic. The protocol drives face creation and
/// FIB population through `DiscoveryContext`.
///
/// Implementations must be `Send + Sync + 'static` so the engine can
/// hold them behind `Arc<dyn DiscoveryProtocol>` and call hooks from
/// multiple Tokio tasks.
pub trait DiscoveryProtocol: Send + Sync + 'static {
    /// A new face has been added to the face table. The implementation
    /// may start hello traffic on this face or begin listening.
    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext);

    /// A face has been removed. Clean up any state tied to this face.
    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext);

    /// A packet arrived on `incoming_face`. The implementation may
    /// inspect it and return `true` if it consumed the packet (so the
    /// forwarding pipeline does not also process it), or `false` to let
    /// it pass through normally.
    ///
    /// This hook is called before the TLV decoder, so `raw` is always
    /// the unmodified wire bytes.
    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> bool;

    /// Called on a periodic tick. Interval is determined by the engine
    /// configuration (`DiscoveryConfig::tick_interval`). Implementations
    /// drive their own timer state here.
    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext);
}
```

### `DiscoveryContext`

```rust
/// Engine capabilities exposed to discovery implementations.
///
/// The interface is intentionally narrow. Discovery code cannot read
/// the PIT, CS, or strategy state — only create/remove faces and
/// FIB entries, send packets, and schedule work.
pub trait DiscoveryContext: Send + Sync {
    /// Create a face and register it with the face table.
    /// Returns the assigned `FaceId`.
    fn add_face(&self, face: Box<dyn Face>) -> FaceId;

    /// Remove a face. Associated PIT in-records are reaped by the engine.
    fn remove_face(&self, face_id: FaceId);

    /// Add a FIB entry routing `prefix` toward `nexthop`.
    fn add_fib_entry(&self, prefix: &Name, nexthop: FaceId, cost: u32);

    /// Remove a FIB entry. No-op if not present.
    fn remove_fib_entry(&self, prefix: &Name, nexthop: FaceId);

    /// Transmit a raw packet on a specific face, bypassing the pipeline.
    /// Used to send hello Interests and announcement Data.
    fn send_on(&self, face_id: FaceId, pkt: Bytes);

    /// Current engine time (monotonic, used for expiry calculations).
    fn now(&self) -> Instant;
}
```

---

## Hello Strategies

Periodic hello at a fixed interval is the worst-case approach: it wastes bandwidth at idle, reacts slowly to topology changes, and causes synchronization storms in dense networks when many nodes start at the same time. Discovery implementations should compose from the following strategy primitives, not hardcode timers.

### Exponential Backoff with Jitter

The baseline improvement over fixed-interval. Start at a fast rate (100 ms) when a face first comes up — the neighbor table is empty and must be populated quickly. Back off exponentially (200 ms → 400 ms → 800 ms → ... → 30 s) once the neighbor is stable. Apply ±25% random jitter to each interval to desynchronize nodes that started at the same time. Reset to the fast rate on any topology event (face down, route withdrawal, forwarding failure).

This is the correct choice for most deployments that need a simple periodic mechanism.

### Event-Driven / Triggered

No timer in the steady state. Send a hello only when:

- A face comes up for the first time.
- A packet arrives from an unknown source MAC (reactive: "someone is out there — who are you?").
- A forwarding failure occurs: Nack received, no FIB match for an expressed Interest.
- A neighbor's liveness deadline expires.

This is significantly lower overhead for low-traffic networks and battery-powered nodes. The trade-off is slightly higher latency for first discovery after a quiet period.

### Passive Neighbor Detection

Zero-overhead discovery for mesh networks where traffic flows continuously. The multicast face receives packets addressed to the NDN multicast group that were not solicited by this node. Extract the source MAC from the incoming `sockaddr_ll`. If the sender is not in the neighbor table, issue a targeted unicast hello to that MAC only. No broadcast timer; no unsolicited traffic.

This is composable with any other strategy: run passive detection continuously and fall back to triggered hellos when passive detection has been quiet for a configurable interval.

### Demand-Driven (most NDN-native)

Instead of pushing hello broadcasts, express Interests:

```
/ndn/local/neighbors          → "who is directly reachable from me?"
/ndn/local/prefixes/<name>    → "what prefixes does this node serve?"
```

Responses are cached in the content store. A node that already has a fresh `/ndn/local/neighbors` entry will not ask again until it expires. This composition with the CS is something IP neighbor discovery cannot do. For deployments where neighbors are stable (home networks, static office infrastructure), this virtually eliminates hello traffic after the initial discovery.

### Composite Strategy

Multiple hello strategies can run simultaneously on different face types. A router might use passive detection on Ethernet (high traffic, zero overhead), exponential backoff on WiFi (moderate traffic, managed overhead), and static configuration on a serial UART face (no discovery at all). The `CompositeDiscovery` implementation holds a `Vec<Box<dyn HelloStrategy>>` and routes lifecycle events to each.

---

## `NoDiscovery` — A First-Class Implementation

Static configuration is valid and important for embedded deployments, data center deployments, and any environment where the topology is known in advance. `NoDiscovery` is not a degenerate case — it is the right choice when the topology is fixed.

```rust
pub struct NoDiscovery;

impl DiscoveryProtocol for NoDiscovery {
    fn on_face_up(&self, _: FaceId, _: &dyn DiscoveryContext) {}
    fn on_face_down(&self, _: FaceId, _: &dyn DiscoveryContext) {}
    fn on_inbound(&self, _: &Bytes, _: FaceId, _: &dyn DiscoveryContext) -> bool { false }
    fn on_tick(&self, _: Instant, _: &dyn DiscoveryContext) {}
}
```

On embedded targets (`ndn-embedded`), `NoDiscovery` is the only option. The `DiscoveryProtocol` trait is not part of `ndn-embedded` at all — the forwarder's FIB is populated at startup via `Fib::add_route` calls and never changes.

---

## Deployment Profiles and Tuning Knobs

Discovery configuration should be expressed as a **named profile** with individual field overrides, not a flat list of magic numbers. The profile captures the intent; overrides capture site-specific adjustments.

```rust
pub enum DiscoveryProfile {
    /// No discovery. FIB and faces are configured statically.
    Static,
    /// Link-local LAN (home, small office). Low traffic, stable topology.
    Lan,
    /// Campus or enterprise network. Mix of stable and dynamic peers.
    Campus,
    /// Mobile / vehicular. Topology changes at human-movement timescales.
    Mobile,
    /// High-mobility (drones, V2X). Sub-second topology changes.
    HighMobility,
    /// Asymmetric unidirectional link (Wifibroadcast, satellite downlink).
    /// Hello protocol not applicable; liveness via link-quality metrics only.
    Asymmetric,
    Custom(DiscoveryConfig),
}

pub struct DiscoveryConfig {
    /// Hello mechanism to use on Ethernet / WiFi faces.
    pub hello_strategy: HelloStrategyKind,
    /// Initial hello interval before backoff kicks in.
    pub hello_interval_base: Duration,
    /// Maximum hello interval after full backoff.
    pub hello_interval_max: Duration,
    /// Jitter as a fraction of the current interval (0.0–0.5).
    pub hello_jitter: f32,
    /// Declare a neighbor dead after this many missed hellos.
    pub liveness_miss_count: u32,
    /// How to announce local prefixes: inline in hello Data, or separate Interest.
    pub prefix_announcement: PrefixAnnouncementMode,
    /// Whether to auto-create unicast faces when a new neighbor is discovered.
    pub auto_create_faces: bool,
    /// Tick interval passed to `on_tick`. Smaller = finer timer resolution.
    pub tick_interval: Duration,
}
```

Reference values for the built-in profiles:

| Parameter | Static | Lan | Campus | Mobile | HighMobility |
|---|---|---|---|---|---|
| Hello strategy | None | Backoff+jitter | Backoff+jitter | Triggered | Triggered+passive |
| Base interval | — | 5 s | 30 s | 200 ms | 50 ms |
| Max interval | — | 60 s | 300 s | 2 s | 500 ms |
| Jitter | — | ±25% | ±10% | ±15% | ±10% |
| Liveness miss | — | 3 | 3 | 5 | 3 |
| Prefix announce | Static | In hello | NLSR LSA | In hello | In hello |
| Auto-create faces | No | Yes | Yes | Yes | Yes |

---

## Source MAC on Incoming Packets: The Link-Layer Prerequisite

No discovery implementation can function until the face layer surfaces the sender's MAC address on received packets. This is the foundational piece.

When `MulticastEtherFace::recv()` calls `try_pop_rx()`, the TPACKET_V2 ring buffer frame includes a `sockaddr_ll` structure at a fixed offset before the payload. That structure contains `sll_addr[8]` — the source MAC of the sending node. Currently the implementation discards it and returns only the payload bytes.

`MulticastEtherFace` is the discovery face. Every hello packet arrives on it from an unknown peer. Without the source MAC, the discovery layer knows the sender's NDN name (carried in the hello Data) but has no MAC to direct unicast traffic to — making it impossible to create a `NamedEtherFace` for the peer.

The fix is a new method on `MulticastEtherFace`:

```rust
/// Receive a packet and the source MAC of the sender.
/// Used by the discovery layer to create unicast faces for new neighbors.
pub async fn recv_with_source(&self) -> Result<(Bytes, MacAddr), FaceError>;
```

The base `Face::recv()` implementation continues to return only `Bytes`, satisfying the pipeline interface. The discovery layer uses `recv_with_source()` through a type-specific reference, not via the trait. The MAC never appears in the forwarding plane.

---

## Neighbor Discovery State Machine

A minimal but correct neighbor discovery protocol for Ethernet links:

```text
                     face_up
                        │
                        ▼
              ┌──────────────────┐
              │    PROBING       │ ── hello Interest broadcast (fast)
              └──────────────────┘
                 │           │
           hello Data     timeout (max_probes exceeded)
           received           │
                 │            ▼
                 │     ┌──────────────┐
                 │     │   ABSENT     │ ── stop sending, mark face inactive
                 │     └──────────────┘
                 ▼
        ┌──────────────────┐
        │   ESTABLISHED    │ ── hello interval backed off to steady rate
        └──────────────────┘
              │       │
         liveness   hello
         timeout    received → reset timer, stay ESTABLISHED
              │
              ▼
        ┌──────────────────┐
        │   STALE          │ ── resume fast hellos (re-probe)
        └──────────────────┘
              │         │
           response   timeout
           received       │
              │           ▼
        ESTABLISHED    ABSENT → remove face + FIB entries
```

Key transitions:

- `PROBING → ESTABLISHED`: hello Data received. Extract peer NDN name. Create unicast `NamedEtherFace` via `DiscoveryContext::add_face`. Add FIB entries for announced prefixes via `DiscoveryContext::add_fib_entry`.
- `ESTABLISHED → STALE`: liveness deadline missed. Resume fast hellos without removing the face yet — transient losses are common on wireless links.
- `STALE → ABSENT`: max re-probe count exceeded. Remove the face and all associated FIB entries. The pipeline's PIT reaper handles in-flight Interest entries.
- `ABSENT → PROBING`: external trigger (link-quality improvement, operator command) or a passive-detection event (packet overheard from this MAC).

---

## Hello Packet Format

Hello messages use standard NDN Interest/Data:

```
Interest:  /ndn/local/hello/<nonce-u32>
           CanBePrefix = false
           MustBeFresh = true
           Lifetime    = hello_interval × 2 (so the responder can reliably reply)

Data:      /ndn/local/hello/<nonce-u32>
           Content = HelloPayload (NDN TLV)
           FreshnessPeriod = hello_interval × 2
```

`HelloPayload` TLV content:

```
HelloPayload ::= NODE-NAME TLV
                 (SERVED-PREFIX TLV)*
                 CAPABILITIES TLV?

NODE-NAME      ::= 0x01 length Name
SERVED-PREFIX  ::= 0x02 length Name
CAPABILITIES   ::= 0x03 length (FLAG-BYTE*)
```

Capabilities flags (advisory, not enforced): fragmentation support, content store present, security validation enabled.

The nonce in the Interest name ensures uniqueness and prevents CS caching of stale hellos. The responder echoes the nonce in the Data name so the requester can match the response to its outstanding hello.

---

## Service Discovery

In NDN, producer registration (telling the local router "I produce `/ndn/sensor/temp`") is already handled by `Producer::connect` in `ndn-app`, which calls `register_prefix` over the IPC channel. Route distribution from there is a routing-layer concern (static FIB config or NLSR).

The only genuinely new piece is **browsability**: discovering what prefixes are available in the local link scope without knowing the names in advance. This is analogous to DNS-SD service browsing.

The approach that requires no new infrastructure: producers publish a registration record at a well-known name:

```
/ndn/local/services/<prefix-hash>/<node-name>/v=<timestamp>
```

Content is a compact record: the full prefix name, capabilities metadata, and a freshness period matching the registration lifetime. Any node discovers available services by expressing a prefix Interest for `/ndn/local/services/`. The content store caches results; no separate registry daemon is needed.

This is deliberately minimal. Complex service registry semantics (health checks, load balancing, capability queries) belong at the application layer, not in the router. The router's job is to forward named packets.

---

## Module Structure

```
crates/ndn-discovery/
  Cargo.toml
  src/
    lib.rs              — DiscoveryProtocol trait, DiscoveryContext trait
    config.rs           — DiscoveryConfig, DiscoveryProfile, HelloStrategyKind
    no_discovery.rs     — NoDiscovery (static config, embedded, zero overhead)
    ether_nd.rs         — EtherNeighborDiscovery: state machine + neighbor table
    strategy/
      mod.rs            — HelloStrategy trait
      backoff.rs        — exponential backoff with jitter
      reactive.rs       — event-driven / triggered
      passive.rs        — passive overhearing from multicast face
      composite.rs      — run multiple strategies simultaneously
    hello.rs            — HelloPayload TLV encoder/decoder
    neighbor_table.rs   — NeighborEntry, NeighborTable, expiry
    prefix_announce.rs  — /ndn/local/services/ publisher and browser
```

The `ndn-engine` crate gains a single new field:

```rust
pub struct Engine {
    // ... existing fields ...
    discovery: Arc<dyn DiscoveryProtocol>,
}
```

And calls three hooks from the face task and packet dispatcher:

```rust
// In the face task, on each received packet:
if self.discovery.on_inbound(&raw, face_id, &ctx) {
    continue; // consumed by discovery
}
// otherwise enqueue for forwarding pipeline

// In FaceTable when a face is registered or removed:
self.discovery.on_face_up(face_id, &ctx);
self.discovery.on_face_down(face_id, &ctx);

// In a periodic timer task (interval = DiscoveryConfig::tick_interval):
self.discovery.on_tick(Instant::now(), &ctx);
```

---

## Relation to Other Components

- **`ndn-face-wireless`**: provides `NamedEtherFace`, `MulticastEtherFace`, and the MAC extraction prerequisite (`recv_with_source`). Discovery uses these face types but does not own them.
- **`ndn-strategy`**: independent. Discovery populates the FIB; strategy decides what to do with FIB entries when forwarding.
- **`ndn-embedded`**: uses `NoDiscovery` exclusively. The `ndn-discovery` crate is not a dependency of `ndn-embedded`.
- **`ndn-config`**: `DiscoveryProfile` and `DiscoveryConfig` are serializable and included in the router configuration file. The management interface can update the active profile at runtime by calling `DiscoveryProtocol::on_config_change` (future extension).
- **`wireless.md`**: covers the multi-radio and channel management concerns that run alongside discovery. Discovery creates faces; channel management selects which face to use for a given packet.

---

## Implementation Order

The following sequence respects the dependency graph:

1. **Source MAC extraction** — `MulticastEtherFace::recv_with_source()` in `ndn-face-wireless`. Prerequisite for everything else.
2. **`ndn-discovery` crate scaffold** — traits, config, `NoDiscovery`. Engine integration hooks.
3. **`NeighborTable`** — neighbor state machine, expiry.
4. **`HelloStrategy` trait + `BackoffStrategy`** — the baseline hello mechanism.
5. **`EtherNeighborDiscovery`** — wires the multicast face, state machine, and backoff strategy together.
6. **`ReactiveStrategy` and `PassiveStrategy`** — alternative hello strategies.
7. **`CompositeDiscovery`** — multi-strategy composition.
8. **`prefix_announce`** — `/ndn/local/services/` publisher/browser.
