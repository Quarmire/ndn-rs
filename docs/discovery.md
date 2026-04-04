# Neighbor Discovery and Service Discovery

## Three Layers

Discovery in an NDN network operates at three distinct scopes that must not be
conflated:

1. **Link-local neighbor discovery** — "Who are my directly-connected peers?"
   Produces MAC↔name bindings and face table entries. Operates within a single
   broadcast domain. Without this, the forwarding plane has no faces.

2. **Service discovery** — "What prefixes are available locally?" Produces FIB
   entries for locally-reachable producers. Operates within an administrative
   scope (link, site, or network). In pure NDN this is largely subsumed by
   routing, but browsability — knowing what exists without prior knowledge —
   requires a small additional mechanism.

3. **Network-wide state dissemination** — "What is the global topology and
   reachability?" Produces long-lived FIB entries for multi-hop paths. Operated
   by routing protocols (NLSR, link-state, or gossip-based). This layer does
   not belong in the discovery crate; it is its own separate concern.

These layers depend on each other in order: Layer 3 builds on top of Layer 2
routes, which builds on top of Layer 1 faces. The `ndn-discovery` crate covers
Layers 1 and 2. Layer 3 is NLSR or equivalent.

---

## Two Distinct Problems Within Layer 1 and 2

**Neighbor discovery** answers: "Who are my directly-connected link-layer
peers?" It produces MAC↔name bindings and face table entries. Without it, the
forwarding plane has no faces to use.

**Service discovery** answers: "Who in the network can serve prefix
`/ndn/edu/ucla/cs/...`?" It produces FIB entries. In IP networks this requires
a separate mechanism (DNS-SD, mDNS, Consul). In NDN it is largely subsumed by
routing — when a producer registers a prefix with its local router and the
routing protocol distributes that reachability, consumers simply express
Interests. There is no separate lookup step.

What NDN still needs that routing cannot provide is **link-local bootstrap**: the
layer-2 plumbing that makes routing possible in the first place.

---

## Should Discovery Live in the Engine?

The current NDN research practice runs NFD, NLSR, and ndnsd as separate
daemons. That design was shaped by academic context: each team owns their
component, interoperability with other implementations matters, and the target
platform is a general-purpose Linux machine.

For `ndn-rs` the tradeoff is different. The forwarding plane is genuinely
unaffected by *how* the face table and FIB get populated — only that they are
populated correctly and promptly. This is the clean interface boundary.

**Arguments against baking a specific protocol into the engine core:**

- *Protocol evolution*: hello formats, timer algorithms, and state machines
  will change. Baked-in code couples those changes to the forwarding plane.
- *Embedded targets*: `ndn-embedded` cannot run any discovery protocol at all.
  Baked-in code ships dead weight to MCUs.
- *Multi-protocol composition*: a campus router might need both link-local ND
  and NLSR simultaneously. One hardcoded protocol cannot serve both.
- *Testing*: forwarding correctness tests should not require a running
  discovery protocol.

**Arguments against a fully separate process:**

- *Latency*: mobile nodes switching channels at 100 ms granularity cannot
  afford IPC round-trips for every face creation event.
- *Atomicity*: discovery needs to atomically create a face and add a FIB
  entry. Doing this across a process boundary introduces TOCTOU windows.
- *Deployment simplicity*: a single binary is far easier to operate on small
  devices.

**The right answer**: a **trait object injected into the engine at construction
time**, called at well-defined lifecycle hooks, with access to engine internals
through a narrow controlled interface. Not baked in. Not a separate process.
This is exactly the pattern the `Strategy` system uses.

```text
┌──────────────────────────────────────────────────────────────┐
│  ndn-engine                                                   │
│                                                              │
│  Forwarding plane (FIB / PIT / CS / pipeline)               │
│       ↑  ↓  face create/remove, FIB add/remove              │
│  DiscoveryContext  ◄──────── narrow controlled interface     │
│       ↑  (also holds NeighborTable — see below)             │
│  dyn DiscoveryProtocol  ◄──── injected at startup           │
│  (EtherND, NLSR adapter, CompositeDiscovery, NoDiscovery)   │
└──────────────────────────────────────────────────────────────┘
```

The engine calls discovery hooks. Discovery calls back through
`DiscoveryContext`. Neither knows the other's internals. Swap implementations
by injecting a different trait object at construction time.

---

## Trait Definitions

### `DiscoveryProtocol`

```rust
/// A discovery protocol implementation injected into the engine.
///
/// The engine calls these hooks at face lifecycle events and on inbound
/// packets that may be discovery traffic. The protocol drives face
/// creation and FIB population through `DiscoveryContext`.
pub trait DiscoveryProtocol: Send + Sync + 'static {
    /// Name prefixes this protocol owns.
    ///
    /// `CompositeDiscovery` enforces at construction time that no two
    /// protocols claim overlapping prefixes. Ownership controls which
    /// protocol receives `on_inbound` for a given packet and which
    /// protocol's FIB entries are removed when it shuts down.
    fn claimed_prefixes(&self) -> &[Name];

    /// Stable identifier for this protocol instance.
    ///
    /// Used to tag FIB entries so they can be removed without affecting
    /// entries added by other protocols.
    fn protocol_id(&self) -> ProtocolId;

    /// A new face has been added to the face table.
    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext);

    /// A face has been removed. Clean up any state tied to this face.
    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext);

    /// A packet arrived on `incoming_face`.
    ///
    /// Called before the TLV decoder. Return `true` to consume the
    /// packet (forwarding pipeline will not see it), `false` to pass
    /// it through. `CompositeDiscovery` routes by prefix match before
    /// calling this; a protocol should only ever see packets under its
    /// `claimed_prefixes`.
    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> bool;

    /// Periodic tick. Interval set by `DiscoveryConfig::tick_interval`.
    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext);
}

/// Opaque protocol identifier for FIB entry ownership tracking.
pub type ProtocolId = u32;
```

### `DiscoveryContext`

```rust
/// Engine capabilities exposed to discovery implementations.
///
/// Intentionally narrow: discovery code cannot read the PIT, CS, or
/// strategy state. It can only manage faces and FIB entries, access
/// the shared neighbor table, send packets, and read the clock.
pub trait DiscoveryContext: Send + Sync {
    // ── Face management ─────────────────────────────────────────────

    /// Create a face and register it. Returns the assigned `FaceId`.
    ///
    /// Before calling this, check `face_for_peer` to avoid duplicates
    /// when multiple protocols discover the same neighbor.
    fn add_face(&self, face: Box<dyn Face>) -> FaceId;

    /// Remove a face. Associated PIT in-records are reaped by the engine.
    fn remove_face(&self, face_id: FaceId);

    /// Look up an existing unicast face for a given MAC + interface.
    ///
    /// Returns `Some(face_id)` if a `NamedEtherFace` for this peer
    /// already exists. Protocols must check this before calling
    /// `add_face` to avoid creating duplicate faces.
    fn face_for_peer(&self, mac: &MacAddr, iface: &str) -> Option<FaceId>;

    // ── FIB management ──────────────────────────────────────────────

    /// Add a FIB entry owned by `owner`.
    ///
    /// The `owner` tag is stored alongside the entry. When a protocol
    /// shuts down or a neighbor is removed, only entries with that
    /// owner tag are affected — entries from other protocols survive.
    fn add_fib_entry(
        &self,
        prefix: &Name,
        nexthop: FaceId,
        cost: u32,
        owner: ProtocolId,
    );

    /// Remove a specific FIB entry. Only removes the entry if it
    /// matches both the nexthop and owner.
    fn remove_fib_entry(&self, prefix: &Name, nexthop: FaceId, owner: ProtocolId);

    /// Remove all FIB entries owned by `owner`.
    ///
    /// Called when a neighbor is declared ABSENT or a protocol shuts
    /// down, without disturbing entries from other protocols.
    fn remove_fib_entries_by_owner(&self, owner: ProtocolId);

    // ── Neighbor table ──────────────────────────────────────────────

    /// Read access to the shared neighbor table.
    ///
    /// The neighbor table is owned by the engine (via DiscoveryContext),
    /// not by any individual DiscoveryProtocol. This means the table
    /// survives a protocol swap and is visible to all composite members.
    fn neighbors(&self) -> &dyn NeighborTableView;

    /// Update a neighbor entry (insert, refresh, or mark state change).
    fn update_neighbor(&self, update: NeighborUpdate);

    // ── Packet transmission ─────────────────────────────────────────

    /// Transmit a raw NDN packet on a specific face, bypassing the
    /// forwarding pipeline. Used for hello Interests and probes.
    fn send_on(&self, face_id: FaceId, pkt: Bytes);

    // ── Time ────────────────────────────────────────────────────────

    fn now(&self) -> Instant;
}
```

---

## Namespace Isolation

When multiple discovery protocols run simultaneously, they must not interfere
with each other's packet streams, CS entries, or FIB state. Three mechanisms
enforce this.

### Reserved Namespace Tree

All discovery and local management traffic lives under `/ndn/local/`, which is
**never forwarded beyond the local link**. The engine enforces this as a
forwarding scope constraint — any outbound Interest or Data under
`/ndn/local/` is dropped at the face boundary if the outbound face is not
local. This mirrors IPv6 link-local address semantics (`fe80::/10`).

Sub-namespaces are assigned to protocol functions:

```
/ndn/local/nd/hello/         — neighbor discovery hello Interest/Data
/ndn/local/nd/probe/direct/  — SWIM direct liveness probe
/ndn/local/nd/probe/via/     — SWIM indirect liveness probe
/ndn/local/nd/peers/         — demand-driven neighbor queries
/ndn/local/sd/services/      — service discovery records
/ndn/local/sd/updates/       — service discovery SVS sync group
/ndn/local/routing/lsa/      — link-state advertisements (NLSR adapter)
/ndn/local/routing/prefix/   — prefix announcements
/ndn/local/mgmt/             — management protocol (existing)
```

Third-party or experimental protocols must use a versioned sub-namespace that
includes an owner identifier:

```
/ndn/local/x/<owner-name>/v=<version>/...
```

### Protocol Declaration

Each `DiscoveryProtocol` implementation declares the prefixes it claims via
`claimed_prefixes()`. This declaration is used at two points:

1. **Construction-time conflict check** in `CompositeDiscovery` — two protocols
   may not claim overlapping prefixes (neither may be a prefix of the other).
2. **Packet routing** in `CompositeDiscovery::on_inbound` — packets are routed
   to the protocol whose claimed prefix matches the Interest or Data name,
   rather than using first-claim or try-each semantics.

```rust
// Good: disjoint prefixes
ether_nd.claimed_prefixes()     == ["/ndn/local/nd/"]
service_disc.claimed_prefixes() == ["/ndn/local/sd/"]

// Conflict: one is a prefix of the other
proto_a.claimed_prefixes() == ["/ndn/local/"]
proto_b.claimed_prefixes() == ["/ndn/local/nd/"]  // ERROR at add() time
```

### FIB Entry Ownership

A protocol that removes FIB entries when a neighbor goes down must not
accidentally remove entries installed by a different protocol for the same
prefix. Every `add_fib_entry` call carries a `ProtocolId`; every removal
specifies the same owner. `remove_fib_entries_by_owner` removes only entries
tagged with that ID, leaving entries from other protocols intact.

### `CompositeDiscovery` Design

`CompositeDiscovery` is the composition wrapper. It holds multiple
`DiscoveryProtocol` implementations and enforces the isolation rules above.

```rust
pub struct CompositeDiscovery {
    members: Vec<CompositeEntry>,
}

struct CompositeEntry {
    prefixes: Vec<Name>,
    protocol: Box<dyn DiscoveryProtocol>,
}

impl CompositeDiscovery {
    /// Add a protocol. Fails if its claimed prefixes overlap with any
    /// already-registered protocol.
    pub fn add(
        &mut self,
        p: Box<dyn DiscoveryProtocol>,
    ) -> Result<(), NamespaceConflict> {
        let claimed = p.claimed_prefixes().to_vec();
        for entry in &self.members {
            for new in &claimed {
                for existing in &entry.prefixes {
                    if new.is_prefix_of(existing) || existing.is_prefix_of(new) {
                        return Err(NamespaceConflict {
                            existing: existing.clone(),
                            conflicting: new.clone(),
                        });
                    }
                }
            }
        }
        self.members.push(CompositeEntry { prefixes: claimed, protocol: p });
        Ok(())
    }
}

impl DiscoveryProtocol for CompositeDiscovery {
    fn on_inbound(
        &self,
        raw: &Bytes,
        face_id: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        // Route by prefix match — O(members × prefixes), both small.
        // Do not use first-claim semantics: that requires calling each
        // protocol in turn and stops only on the first true, which means
        // a mismatch in one protocol still invokes the next at full cost.
        if let Some(name) = peek_name(raw) {
            for entry in &self.members {
                if entry.prefixes.iter().any(|p| p.is_prefix_of(&name)) {
                    return entry.protocol.on_inbound(raw, face_id, ctx);
                }
            }
        }
        false
    }

    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        for entry in &self.members {
            entry.protocol.on_face_up(face_id, ctx);
        }
    }

    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        for entry in &self.members {
            entry.protocol.on_face_down(face_id, ctx);
        }
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        for entry in &self.members {
            entry.protocol.on_tick(now, ctx);
        }
    }

    fn claimed_prefixes(&self) -> &[Name] { &[] }
    fn protocol_id(&self) -> ProtocolId { 0 }
}
```

**Face deduplication** is handled in `DiscoveryContext::face_for_peer`. Before
any `add_face` call, a protocol checks whether a `NamedEtherFace` for the
given `(mac, iface)` pair already exists. If so it reuses the existing
`FaceId` instead of creating a duplicate. This coordination is in the context,
not each protocol — individual protocols need not be aware of each other.

---

## In-Flight Neighbor State and NeighborTable Ownership

**In-flight neighbor state** is the per-peer runtime data that lives at any
given instant:

- **Neighbor table entries**: for each known peer, current state
  (`PROBING / ESTABLISHED / STALE / ABSENT`), associated face IDs, the NDN
  name from the last hello, and last-seen timestamp.
- **Outstanding hello nonces**: nonces of Interests that were sent but have
  not received a Data response. If the protocol is replaced while a hello is
  in flight, the response arrives and the new implementation has no record
  of the nonce — the response is discarded and the peer will time out.
- **Per-neighbor backoff state**: the *current* hello interval for each peer,
  which may be far from the configured base after exponential backoff. If lost,
  that peer's interval resets to base and briefly floods the link before
  backing off again.
- **Miss counters**: consecutive unanswered hellos toward each peer. If a peer
  is at miss count 2/3 when state is replaced, it resets to 0/3 — delaying
  face removal during an actual outage.
- **Link quality measurements**: per-peer RSSI, loss rate, and RTT. Used to
  adaptively tune hello rates. These take time to accumulate.

**The problem**: if the engine replaces the `Arc<dyn DiscoveryProtocol>` when
a configuration update changes the hello strategy, all of this state is lost.
For a stable home LAN this is merely annoying — the protocol restarts and
re-discovers neighbors within seconds. For a mobile node at 100 ms hello
intervals this causes visible forwarding disruption: miss counters reset, faces
are retained or removed at wrong times, backoff timers restart from base.

**The solution**: `NeighborTable` is owned by the engine via `DiscoveryContext`,
not inside the `DiscoveryProtocol` implementation. The protocol reads and
writes the table through `ctx.neighbors()` and `ctx.update_neighbor()`, but
does not own the storage. When the engine replaces the protocol implementation,
the neighbor table survives intact. The new implementation reads the existing
entries — peer names, states, face IDs — and reconstructs its timer state from
them rather than starting cold. Per-neighbor backoff can be re-initialized from
`last_seen` timestamps already in the table.

This is the one meaningful structural change from the initial design: the
module structure section below reflects the corrected ownership.

---

## Hello Strategies

Periodic hello at a fixed interval is the worst-case approach: it wastes
bandwidth at idle, reacts slowly to topology changes, and causes
synchronization storms in dense networks when many nodes start simultaneously.
Discovery implementations should compose from the following strategy primitives.

### Exponential Backoff with Jitter

The baseline improvement over fixed-interval. Start fast (100 ms) when a face
first comes up — the neighbor table is empty and must be populated quickly.
Back off exponentially (200 ms → 400 ms → ... → 30 s) once the neighbor is
stable. Apply ±25% random jitter to desynchronize nodes that started together.
Reset to fast on any topology event (face down, route withdrawal, forwarding
failure). This is the correct choice for most deployments that need a simple
periodic mechanism.

### Event-Driven / Triggered

No timer in the steady state. Send a hello only when:

- A face comes up for the first time.
- A packet arrives from an unknown source MAC ("someone is there — who are you?").
- A forwarding failure occurs: Nack received or no FIB match.
- A neighbor's liveness deadline expires.

Significantly lower overhead for low-traffic and battery-powered nodes. The
trade-off is slightly higher latency for first discovery after a quiet period.

### Passive Neighbor Detection

Zero-overhead discovery for mesh networks where traffic flows continuously.
The multicast face receives packets not solicited by this node. Extract the
source MAC from `sockaddr_ll`. If the sender is absent from the neighbor table,
issue a targeted unicast hello only to that MAC. No broadcast timer; no
unsolicited traffic. Composable with any other strategy: run passive detection
continuously and fall back to triggered hellos when passive detection has been
quiet for a configurable interval.

### Demand-Driven (most NDN-native)

Express Interests for neighbor information instead of broadcasting hellos:

```
/ndn/local/nd/peers                → "who is directly reachable?"
/ndn/local/nd/peers/<node-name>    → "is this specific node still there?"
```

Responses are cached in the content store. A node that has a fresh
`/ndn/local/nd/peers` answer will not re-ask until it expires. This
composition with the CS is something IP neighbor discovery cannot do — no
re-querying until the freshness period expires, regardless of how many nodes
ask.

### SWIM-Style Indirect Probing

Simple hello timeout is unreliable in lossy wireless environments: a single
lost hello packet causes a false positive failure detection that removes the
face and disrupts active forwarding. SWIM (Scalable Weakly-consistent
Infection-style Membership) addresses this by distinguishing direct loss from
actual node failure via indirect probing:

1. Node A sends a direct probe to node B:
   `Interest: /ndn/local/nd/probe/direct/<B-name>/<nonce>`

2. If no response within `probe_timeout`, A asks K intermediaries to probe B
   on its behalf:
   `Interest: /ndn/local/nd/probe/via/<C-name>/<B-name>/<nonce>`

3. Only if none of the K indirect probes succeed does A declare B failed.

In NDN this is especially natural: the indirect probe Interest is forwarded via
the normal FIB toward C, C forwards it to B, and B's response Data follows the
reverse Interest path. The PIT handles the rendezvous. No special routing is
needed. K = 3 intermediaries reduces false-positive failure detection by a
factor of `(packet-loss-rate)^K` — with 10% link loss, indirect probing with
K=3 reduces false positives from 10% to 0.1%.

Gossip piggybacking: SWIM packs membership change notifications (new neighbors,
failed neighbors) into the payload of every probe and probe-ack. This uses
spare capacity in existing traffic to propagate state changes without any
additional messages. The NDN equivalent: carry `NeighborDiff` TLV content in
hello Data responses.

---

## Gossip Protocols and Epidemic Dissemination

Gossip protocols are the right tool for **network-wide state dissemination**
(Layer 3), but they also have significant contributions to Layers 1 and 2. This
section covers where gossip fits, why it composes naturally with NDN, and which
specific protocols are most relevant.

### Why Gossip Fits NDN Naturally

IP-based gossip protocols typically use UDP push: node A selects random peer B
and sends its state. NDN is pull-based by design, which makes push gossip an
awkward fit. However, **pull gossip maps directly to Interest/Data**, and NDN
provides three properties that make gossip dramatically more efficient here
than in IP:

1. **Content store deduplication**: a gossip state record, once fetched, is
   cached. The Nth node to ask for the same record gets a cache hit, not a
   network fetch. In IP, every peer independently fetches from the origin.

2. **PIT aggregation**: N nodes expressing the same gossip Interest before the
   first response arrives produce one network fetch (the PIT collapses them).
   The response satisfies all N waiting consumers simultaneously.

3. **Named data is self-identifying**: a gossip record at
   `/ndn/local/nd/gossip/<node-name>/<seq>` is unambiguously identified by
   its name. There is no need for sequence number negotiation outside the
   Interest name itself.

### SVS as the Gossip Substrate

State Vector Sync (`ndn-sync`, already in the codebase) is precisely a gossip
protocol adapted for NDN. Each node maintains a state vector:
`{ nodeA: seq=5, nodeB: seq=3, nodeC: seq=7, ... }`. When a node publishes
new data it increments its sequence. Nodes exchange state vectors and
express Interests only for entries they are missing. Convergence is O(log N)
rounds.

For discovery, SVS can disseminate:

- **Neighbor table state**: "I see neighbors X, Y, Z with these face states."
  Other nodes aggregate this to build a multi-hop topology view without
  running a full link-state protocol.
- **Service records**: producers publish under the SVS sync group; all members
  receive updates without polling.
- **Link quality metrics**: RSSI, loss rate, RTT per link — shared network-wide
  for smarter multi-path strategies.

The service discovery `/ndn/local/sd/updates/` prefix is the SVS sync group
for service record changes. Any node that wants push notifications joins the
group. Nodes that only need occasional browsability use pull via
`/ndn/local/sd/services/`. Both mechanisms work simultaneously with no
conflict.

### Epidemic Broadcast and Convergence

Epidemic broadcast (sometimes called rumor spreading) works by having each
newly-informed node forward the message to K randomly chosen peers. The
network becomes fully informed in O(log N) rounds.

In NDN, epidemic broadcast happens without explicit implementation: when a
node publishes new data under a prefix that many nodes are interested in, PIT
aggregation and CS caching handle the epidemic spread automatically. A node
that wants to receive topology updates expresses a long-lived prefix Interest
(`CanBePrefix=true`) for `/ndn/local/nd/gossip/`. Any node that publishes
under that prefix satisfies it.

For time-sensitive events (topology change, face failure), the strategy can
temporarily increase gossip fanout: instead of the normal backoff interval,
trigger K immediate unsolicited announcements to different peers. This
provides fast convergence for critical events while steady-state traffic
remains low. Convergence time for emergency gossip with K=5 fanout on a
100-node network is approximately 3–4 rounds.

### CRDTs for Distributed Neighbor State

When gossip delivers updates out of order or in parallel (the normal case),
the neighbor table must merge them correctly without a central coordinator.
Conflict-free Replicated Data Types (CRDTs) provide merge semantics that are
correct by construction:

- **LWW-Map** (Last-Write-Wins Map): each neighbor entry carries a logical
  timestamp. The entry with the higher timestamp wins on conflict. Correct
  for most neighbor table updates where the latest information is authoritative.

- **OR-Set** (Observed-Remove Set): tracks additions and removals with unique
  tags. Prevents zombie entries: a node that is removed and then re-added is
  correctly treated as a new entry, not as the removal being undone. Important
  when nodes leave and rejoin the network.

Neither of these requires implementing a CRDT library. The neighbor table
state machine (PROBING → ESTABLISHED → STALE → ABSENT) already provides
the necessary merge logic: a state transition to ESTABLISHED can only happen
after observing a hello response, not from a gossip message alone. Gossip
provides background state; direct observation provides authoritative state.

### HyParView and PLUMTREE

For large networks (hundreds to thousands of nodes), random gossip becomes
inefficient. HyParView + PLUMTREE is the research state-of-the-art for
scalable epidemic broadcast:

- **HyParView**: each node maintains a *partial view* of K active peers and
  a larger passive view. The active view forms a connected overlay; the passive
  view is a fallback. In NDN, the active view maps to the current set of
  NamedEtherFace / UdpFace entries; the passive view maps to known-but-unused
  entries in the neighbor table.

- **PLUMTREE**: uses a spanning tree (derived from HyParView) for fast
  broadcast of new messages (O(N) messages total), and falls back to lazy
  gossip when tree nodes fail. In NDN, the spanning tree corresponds to the
  primary FIB structure; lazy repair corresponds to demand-driven Interest
  expressions to fill in missing sequence numbers.

This is relevant for `ndn-rs` as the network scales. At small scale (< 50
nodes), simpler gossip via SVS is sufficient. At large scale, PLUMTREE-style
tree broadcast reduces overhead significantly. Both can be implemented as
`DiscoveryProtocol` implementations without changing the trait interface.

### What Gossip Does Not Replace

Gossip provides eventual consistency, not immediate consistency. It cannot
replace:

- **Direct hello liveness detection**: only the direct probe path confirms
  that a specific neighbor is alive right now.
- **Cryptographic verification**: gossip propagates state but does not
  authenticate it. Signatures on gossip Data packets ensure authenticity;
  the validator pipeline handles this.
- **Ordered delivery**: gossip does not guarantee message ordering. The
  neighbor table state machine must be robust to out-of-order state
  transitions.

---

## `NoDiscovery` — A First-Class Implementation

Static configuration is valid and important for embedded deployments, data
center deployments, and any environment where the topology is known in advance.
`NoDiscovery` is not a degenerate case — it is the right choice when the
topology is fixed.

```rust
pub struct NoDiscovery;

impl DiscoveryProtocol for NoDiscovery {
    fn claimed_prefixes(&self) -> &[Name] { &[] }
    fn protocol_id(&self) -> ProtocolId { 0 }
    fn on_face_up(&self, _: FaceId, _: &dyn DiscoveryContext) {}
    fn on_face_down(&self, _: FaceId, _: &dyn DiscoveryContext) {}
    fn on_inbound(&self, _: &Bytes, _: FaceId, _: &dyn DiscoveryContext) -> bool { false }
    fn on_tick(&self, _: Instant, _: &dyn DiscoveryContext) {}
}
```

On embedded targets (`ndn-embedded`), `NoDiscovery` is the only option. The
`DiscoveryProtocol` trait is not part of `ndn-embedded` at all — the
forwarder's FIB is populated at startup via `Fib::add_route` and never changes.

---

## Deployment Profiles and Tuning Knobs

Configuration is expressed as a named profile with individual field overrides.
The profile captures the intent; overrides capture site-specific adjustments.

```rust
pub enum DiscoveryProfile {
    /// No discovery. FIB and faces configured statically.
    Static,
    /// Link-local LAN (home, small office). Low traffic, stable topology.
    Lan,
    /// Campus or enterprise. Mix of stable and dynamic peers.
    Campus,
    /// Mobile / vehicular. Topology changes at human-movement timescales.
    Mobile,
    /// High-mobility (drones, V2X). Sub-second topology changes.
    HighMobility,
    /// Asymmetric unidirectional link (Wifibroadcast, satellite downlink).
    /// Hello protocol not applicable; liveness via link-quality only.
    Asymmetric,
    Custom(DiscoveryConfig),
}

pub struct DiscoveryConfig {
    pub hello_strategy: HelloStrategyKind,    // Backoff | Triggered | Passive | Swim | Gossip
    pub hello_interval_base: Duration,
    pub hello_interval_max: Duration,
    pub hello_jitter: f32,                    // fraction of current interval, 0.0–0.5
    pub liveness_miss_count: u32,
    pub swim_indirect_fanout: u32,            // K for SWIM indirect probing; 0 = disabled
    pub gossip_fanout: u32,                   // K for emergency gossip broadcast; 0 = disabled
    pub prefix_announcement: PrefixAnnouncementMode,
    pub auto_create_faces: bool,
    pub tick_interval: Duration,
}
```

Reference values for built-in profiles:

| Parameter | Static | Lan | Campus | Mobile | HighMobility |
|---|---|---|---|---|---|
| Hello strategy | None | Backoff+jitter | Backoff+jitter | Triggered+SWIM | Triggered+passive+SWIM |
| Base interval | — | 5 s | 30 s | 200 ms | 50 ms |
| Max interval | — | 60 s | 300 s | 2 s | 500 ms |
| Jitter | — | ±25% | ±10% | ±15% | ±10% |
| Liveness miss | — | 3 | 3 | 5 | 3 |
| SWIM fanout K | — | 0 | 3 | 3 | 5 |
| Gossip fanout K | — | 0 | 3 | 5 | 5 |
| Prefix announce | Static | In hello | NLSR LSA | In hello | In hello |
| Auto-create faces | No | Yes | Yes | Yes | Yes |

---

## Source MAC on Incoming Packets: The Link-Layer Prerequisite

No discovery implementation can function until the face layer surfaces the
sender's MAC address on received packets.

When `MulticastEtherFace::recv()` calls `try_pop_rx()`, the TPACKET_V2 ring
buffer frame includes a `sockaddr_ll` structure at a fixed offset before the
payload. That structure contains `sll_addr[8]` — the source MAC of the sender.
Currently the implementation discards it.

`MulticastEtherFace` is the discovery face. Every hello arrives on it from an
unknown peer. Without the source MAC, the discovery layer knows the sender's
NDN name (from the hello Data content) but has no MAC to direct unicast traffic
to — making it impossible to create a `NamedEtherFace` for the peer.

The fix is a new method alongside the existing `Face::recv()`:

```rust
/// Receive a packet and the source MAC of the sender.
/// Used by the discovery layer to create unicast faces for new neighbors.
/// The base Face::recv() continues to return only Bytes for the pipeline.
pub async fn recv_with_source(&self) -> Result<(Bytes, MacAddr), FaceError>;
```

The MAC never appears in the forwarding plane. The discovery layer uses
`recv_with_source()` through a type-specific reference, not via the `Face`
trait.

---

## Neighbor Discovery State Machine

```text
                     face_up
                        │
                        ▼
              ┌──────────────────┐
              │    PROBING       │ ── hello Interest broadcast (fast rate)
              └──────────────────┘
                 │           │
           hello Data     timeout (max_probes exceeded)
           received           │
                 │            ▼
                 │     ┌──────────────┐
                 │     │   ABSENT     │ ── stop sending, face inactive
                 │     └──────────────┘
                 ▼             ▲
        ┌──────────────────┐   │ timeout (max re-probe exceeded)
        │   ESTABLISHED    │   │
        └──────────────────┘   │
              │       │        │
         liveness   hello      │
         timeout   received    │
              │   (reset timer,│
              │   stay here)   │
              ▼                │
        ┌──────────────────┐   │
        │     STALE        │ ──┘ resume fast hellos (re-probe)
        └──────────────────┘
```

Key transitions:

- `PROBING → ESTABLISHED`: hello Data received. Extract peer NDN name and
  announced prefixes. Check `ctx.face_for_peer(mac, iface)` before calling
  `ctx.add_face()`. Add FIB entries via `ctx.add_fib_entry(prefix, face_id,
  cost, self.protocol_id())`. Write neighbor entry via `ctx.update_neighbor()`.
- `ESTABLISHED → STALE`: liveness deadline missed. Resume fast hellos without
  removing the face — transient losses are common on wireless.
- `STALE → ABSENT`: max re-probe count exceeded. Call
  `ctx.remove_fib_entries_by_owner(self.protocol_id())`. Call
  `ctx.remove_face(face_id)`. Update neighbor state to ABSENT.
- `ABSENT → PROBING`: passive detection event (packet overheard from this MAC),
  external operator command, or link-quality improvement signal.

---

## Hello Packet Format

Hello messages use standard NDN Interest/Data so they are handled by the normal
forwarding pipeline, suppressed by PIT deduplication, and debuggable with
standard NDN tools.

```
Interest:  /ndn/local/nd/hello/<nonce-u32>
           CanBePrefix = false
           MustBeFresh = true
           Lifetime    = hello_interval × 2

Data:      /ndn/local/nd/hello/<nonce-u32>
           Content = HelloPayload (NDN TLV)
           FreshnessPeriod = hello_interval × 2
```

`HelloPayload` TLV:

```
HelloPayload  ::= NODE-NAME TLV
                  (SERVED-PREFIX TLV)*
                  CAPABILITIES TLV?
                  (NEIGHBOR-DIFF TLV)*   ← SWIM gossip piggyback

NODE-NAME     ::= 0x01 length Name
SERVED-PREFIX ::= 0x02 length Name
CAPABILITIES  ::= 0x03 length FLAG-BYTE*
NEIGHBOR-DIFF ::= 0x04 length (ADD-ENTRY | REMOVE-ENTRY)*
ADD-ENTRY     ::= 0x05 length Name
REMOVE-ENTRY  ::= 0x06 length Name
```

Capabilities flags (advisory, not enforced): fragmentation support, CS
present, security validation enabled, SVS capable.

The nonce in the Interest name ensures uniqueness and prevents CS caching of
stale hellos. The `NEIGHBOR-DIFF` entries carry SWIM-style gossip piggybacked
on existing hello traffic at zero additional message cost.

---

## Service Discovery

Producer registration — telling the local router "I produce `/ndn/sensor/temp`"
— is already handled by `Producer::connect` in `ndn-app`, which calls
`register_prefix` over the IPC channel. Route distribution is a routing-layer
concern (static FIB config or NLSR).

The only genuinely new piece is **browsability**: discovering what prefixes are
available without knowing them in advance. The approach that requires no new
infrastructure: producers publish a record at a well-known name:

```
/ndn/local/sd/services/<prefix-hash>/<node-name>/v=<timestamp>
```

Content is a compact TLV record: the full prefix name, capabilities metadata,
and a freshness period matching the registration lifetime. Any node discovers
services by expressing a prefix Interest for `/ndn/local/sd/services/`. The CS
caches results; no registry daemon is required.

### Evolution Path

The minimal design is intentionally thin. Each extension is additive and
backward-compatible:

**Richer metadata** — the content TLV payload grows without changing the naming
convention. v1 consumers ignore fields they do not understand. SLA hints,
security requirements, load metrics, and geographic scope belong here.

**Versioned naming** — when a breaking metadata change is needed, the version
appears in the name:
```
/ndn/local/sd/v=2/services/<prefix-hash>/<node-name>/v=<timestamp>
```
v1 and v2 can coexist during a transition period; producers publish under both;
consumers express the version they understand.

**Scope hierarchy** — link-local is sufficient for single-hop discovery. Wider
scopes use different prefixes, with forwarding policy controlling propagation:
```
/ndn/local/sd/services/    — link-local only (not forwarded beyond this link)
/ndn/site/sd/services/     — distributed by NLSR within a site
/ndn/global/sd/services/   — federated global registry (different operational model)
```
The protocol is identical at each scope; only which faces forward which
prefixes changes.

**Push notifications via SVS** — producers publish update events to the sync
group at `/ndn/local/sd/updates/`. Consumers that need real-time notification
when a new producer appears join the group. Pull via `/ndn/local/sd/services/`
continues to work for consumers that only need occasional browsability. Both
mechanisms coexist without conflict because `ndn-sync` SVS is already in the
codebase.

**Capability filtering** — filtering by properties should remain client-side.
The moment you add server-side filter semantics, you have built a queryable
database. That belongs at the application layer, not in the router. If
structured queries are genuinely needed, that is a separate NDN application
that runs as a producer on a known prefix.

**Security evolution** proceeds independently:
1. No signing (now): accept any record; suitable for closed deployments.
2. Self-certified names: the producer's NDN name is derived from its public
   key, so the name itself authenticates the record.
3. Site CA signed: records signed by a site certificate authority, verified
   before acting on them.
4. Trust-on-first-use: accept unsigned records but require the operator to
   explicitly promote producers to a trust list.

Each level is a validation policy configured in the engine; none requires a
protocol change.

### Engine Tuning for Service Discovery

Several existing engine subsystems interact with service discovery and need
configurable behavior:

**Content store budget and eviction priority.** Service records are thin
(< 1 KB), frequently accessed, and trivially re-fetchable from a local
producer. They should not compete with application data for CS capacity. Two
knobs:
- `service_record_cs_budget`: maximum CS entries allocated to
  `/ndn/local/sd/services/`. Prevents a noisy producer from evicting real
  cached data.
- Eviction priority: service records are evicted before user data when the CS
  is under pressure. The `ShardedCs` backend naturally achieves this by
  routing the services prefix to a dedicated smaller shard.

**FIB auto-population.** When a service record is received, the engine can
automatically add a FIB entry for the announced prefix. This is useful for
edge routers that act as default forwarders, but undesirable for end-node
clients that should not receive arbitrary FIB entries from the network.

```rust
pub struct ServiceDiscoveryConfig {
    /// Automatically add FIB entries when service records are received.
    pub auto_populate_fib: bool,
    /// Only auto-populate from link-local scope (not site/global).
    pub auto_populate_scope: DiscoveryScope,
    /// Route cost assigned to auto-populated FIB entries.
    /// Should be higher (worse) than manually configured routes.
    pub auto_fib_cost: u32,
    /// How long an auto-populated entry lives without refresh.
    /// Expressed as a multiple of the record's FreshnessPeriod.
    pub auto_fib_ttl_multiplier: f32,
    /// Whitelist of name prefixes the engine will auto-populate from.
    /// Empty = accept any prefix.
    pub auto_populate_prefix_filter: Vec<Name>,
    /// Maximum service records per scope prefix.
    pub max_records_per_scope: usize,
    /// Max registrations per producer per time window (rate limiting).
    pub max_registrations_per_producer: u32,
    pub max_registrations_window: Duration,
    /// Whether to relay service records received from peers.
    /// Relevant for multi-hop networks without NLSR.
    pub relay_records: bool,
    /// Validation policy for incoming service records.
    pub validation: ServiceValidationPolicy,
}

pub enum ServiceValidationPolicy {
    Skip,       // No validation; fast; suitable for closed networks
    WarnOnly,   // Log unsigned/unverified records but act on them
    Required,   // Drop unsigned records; only auto-populate from verified
}
```

**Rate limiting** is enforced in the `on_inbound` hook before records reach
the CS or trigger FIB updates. A misbehaving producer that floods registrations
is rate-limited per-producer per time window before the engine processes them.

**Validation** plugs into the existing `ValidationStage` pipeline. Service
records are standard NDN Data packets; the same signature verification path
applies. The `ServiceValidationPolicy` determines what to do with the result
before auto-populating the FIB — not whether to validate (the pipeline always
validates if configured), but whether to act on unverified records.

**Interest suppression** for browsing works automatically: `CanBePrefix=true`
Interests for `/ndn/local/sd/services/` are deduplicated by the PIT. Multiple
consumers asking for the same service catalog within the PIT entry lifetime
produce one network fetch. No additional tuning is needed; the correct behavior
is already the default.

---

## Module Structure

```
crates/ndn-discovery/
  Cargo.toml
  src/
    lib.rs
      — DiscoveryProtocol trait (with claimed_prefixes, protocol_id)
      — DiscoveryContext trait (with NeighborTable, face_for_peer,
        add_fib_entry with owner, remove_fib_entries_by_owner)
      — ProtocolId type alias
    config.rs
      — DiscoveryConfig, DiscoveryProfile, HelloStrategyKind
      — ServiceDiscoveryConfig, ServiceValidationPolicy
    no_discovery.rs
      — NoDiscovery
    composite.rs
      — CompositeDiscovery, NamespaceConflict
      — peek_name() helper (fast TLV name extraction without full decode)
    neighbor_table.rs
      — NeighborEntry, NeighborState, NeighborUpdate
      — NeighborTableView trait (read-only access)
      — NeighborTableImpl (owned by engine, accessed via DiscoveryContext)
    ether_nd.rs
      — EtherNeighborDiscovery: state machine wired to multicast face
    strategy/
      mod.rs           — HelloStrategy trait
      backoff.rs       — exponential backoff with jitter
      reactive.rs      — event-driven / triggered
      passive.rs       — passive MAC overhearing
      swim.rs          — SWIM direct + indirect probing
      composite.rs     — run multiple hello strategies simultaneously
    gossip/
      mod.rs           — GossipStrategy trait
      svs_gossip.rs    — SVS-backed network-wide state dissemination
      epidemic.rs      — emergency fanout for topology change events
    hello.rs           — HelloPayload TLV encoder/decoder (with NEIGHBOR-DIFF)
    probe.rs           — ProbePayload TLV encoder/decoder
    prefix_announce.rs — /ndn/local/sd/services/ publisher and browser
    scope.rs           — /ndn/local/ scope enforcement helpers
```

The `ndn-engine` crate gains one field and four call sites:

```rust
pub struct Engine {
    // ... existing fields ...
    discovery: Arc<dyn DiscoveryProtocol>,
    neighbor_table: Arc<NeighborTableImpl>,  // owned here, exposed via DiscoveryContext
}
```

```rust
// Face task — before enqueuing for pipeline:
if engine.discovery.on_inbound(&raw, face_id, &ctx) {
    continue;
}

// FaceTable — on face registration and removal:
engine.discovery.on_face_up(face_id, &ctx);
engine.discovery.on_face_down(face_id, &ctx);

// Periodic timer task (interval = DiscoveryConfig::tick_interval):
engine.discovery.on_tick(Instant::now(), &ctx);
```

---

## Relation to Other Components

- **`ndn-face-l2`**: provides `NamedEtherFace`, `MulticastEtherFace`,
  and the `recv_with_source()` MAC extraction method. Discovery uses these
  face types but does not own them.
- **`ndn-sync`**: SVS is the gossip substrate for service record push
  notifications and network-wide state dissemination. `ndn-discovery` depends
  on `ndn-sync` for those features.
- **`ndn-strategy`**: independent. Discovery populates the FIB; strategy
  decides what to do with FIB entries when forwarding.
- **`ndn-pipeline`**: the `ValidationStage` is reused for service record
  signature verification. No new pipeline stage is needed.
- **`ndn-embedded`**: uses `NoDiscovery` exclusively. `ndn-discovery` is not
  a dependency of `ndn-embedded`.
- **`ndn-config`**: `DiscoveryProfile`, `DiscoveryConfig`, and
  `ServiceDiscoveryConfig` are serializable and included in the router config
  file. Config updates replace the protocol implementation; the `NeighborTable`
  (owned by the engine) survives the swap.
- **`wireless.md`**: covers multi-radio and channel management. Discovery
  creates faces; channel management selects which face to use per packet.

---

## Implementation Order

1. **Source MAC extraction** — `MulticastEtherFace::recv_with_source()` in
   `ndn-face-l2`. Prerequisite for everything.
2. **`ndn-discovery` crate scaffold** — `DiscoveryProtocol` trait,
   `DiscoveryContext` trait, `ProtocolId`, `NoDiscovery`. Engine integration
   hooks and `neighbor_table.rs` owned by engine.
3. **`BackoffStrategy`** — exponential backoff with jitter. Baseline hello
   mechanism.
4. **`EtherNeighborDiscovery`** — wires multicast face, state machine, backoff
   strategy, and hello TLV encoder/decoder.
5. **`CompositeDiscovery`** — namespace conflict checking, prefix-based
   routing, face deduplication via `face_for_peer`.
6. **`ReactiveStrategy` and `PassiveStrategy`** — alternative hello strategies.
7. **`SwimStrategy`** — direct and indirect probing. NEIGHBOR-DIFF piggyback
   in HelloPayload.
8. **`prefix_announce`** — `/ndn/local/sd/services/` publisher and browser.
9. **`SvsGossipStrategy`** — SVS-backed push notifications for service records.
10. **`EpidemicStrategy`** — emergency fanout on topology change events.
