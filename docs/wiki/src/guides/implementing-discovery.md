# Implementing a Discovery Protocol

This guide walks through writing a custom discovery protocol for ndn-rs. Discovery protocols run inside the engine — they observe face lifecycle events and inbound packets, and they mutate engine state (faces, FIB routes, the neighbor table) through a narrow context interface.

## The DiscoveryProtocol Trait

The trait lives in `ndn-discovery` (`crates/engine/ndn-discovery/src/protocol.rs`):

```rust
pub trait DiscoveryProtocol: Send + Sync + 'static {
    fn protocol_id(&self) -> ProtocolId;
    fn claimed_prefixes(&self) -> &[Name];

    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext);
    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext);

    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool;

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext);

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(100)
    }
}
```

Key points:

- **`protocol_id()`** returns a `ProtocolId(&'static str)` — a short ASCII tag like `"swim"` or `"beacon"`. Used to label FIB routes so they can be bulk-removed when the protocol shuts down.
- **`claimed_prefixes()`** declares which NDN name prefixes this protocol owns. `CompositeDiscovery` checks at construction time that no two protocols overlap. All discovery traffic lives under `/ndn/local/`.
- **`on_inbound()`** is called for every raw packet **before** it enters the forwarding pipeline. Return `true` to consume the packet (preventing forwarding); return `false` to let it pass through. This is how hello packets and probes are intercepted without polluting the forwarding plane.
- **`on_tick()`** is called periodically at `tick_interval`. Use it to send hellos, check timeouts, rotate probes, and gossip state.
- Protocols **cannot** hold mutable references to engine internals. All mutations go through `DiscoveryContext`.

## The DiscoveryContext Interface

`DiscoveryContext` is the boundary between your protocol and the engine. It gives you everything you need without exposing engine internals:

```rust
pub trait DiscoveryContext: Send + Sync {
    // Face management
    fn alloc_face_id(&self) -> FaceId;
    fn add_face(&self, face: Arc<dyn ErasedFace>) -> FaceId;
    fn remove_face(&self, face_id: FaceId);

    // FIB management (routes are tagged with your ProtocolId)
    fn add_fib_entry(&self, prefix: &Name, nexthop: FaceId, cost: u32, owner: ProtocolId);
    fn remove_fib_entry(&self, prefix: &Name, nexthop: FaceId, owner: ProtocolId);
    fn remove_fib_entries_by_owner(&self, owner: ProtocolId);

    // Neighbor table
    fn neighbors(&self) -> Arc<dyn NeighborTableView>;
    fn update_neighbor(&self, update: NeighborUpdate);

    // Direct packet send (bypasses pipeline)
    fn send_on(&self, face_id: FaceId, pkt: Bytes);

    fn now(&self) -> Instant;
}
```

All FIB routes you install should carry your `ProtocolId` as the owner. The engine calls `remove_fib_entries_by_owner` when the protocol shuts down, cleaning up all routes in one call regardless of how many prefixes you registered.

## Designing Your Protocol's Packet Format

Discovery protocols communicate using NDN Interest and Data packets, just like any other NDN traffic. The difference is that discovery packets are intercepted in `on_inbound` before they reach the pipeline, and they are sent directly via `ctx.send_on()` rather than through a `Consumer`.

### Choosing prefixes

All discovery traffic must live under `/ndn/local/` — this prefix is link-local scoped and never forwarded off the local subnet. Choose sub-prefixes that are specific to your protocol:

```
/ndn/local/nd/hello         neighbor discovery hellos
/ndn/local/nd/probe/direct  SWIM direct probes
/ndn/local/nd/probe/via     SWIM indirect probes
/ndn/local/sd/register      service registration
/ndn/local/sd/query         service lookup
```

### Intercepting packets

In `on_inbound`, check whether the raw packet belongs to your protocol by inspecting its NDN name prefix before full decoding:

```rust
fn on_inbound(
    &self,
    raw: &Bytes,
    incoming_face: FaceId,
    meta: &InboundMeta,
    ctx: &dyn DiscoveryContext,
) -> bool {
    // Fast path: check if this looks like one of our packets.
    // Decode only what you need to route it internally.
    let Ok(interest) = Interest::decode(raw.clone()) else {
        return false;
    };

    if interest.name().has_prefix(&self.hello_prefix) {
        self.handle_hello(interest, incoming_face, meta, ctx);
        return true;  // consumed — do not forward
    }

    false  // not ours — let the pipeline handle it
}
```

Returning `true` prevents the packet from entering the forwarding pipeline. Only return `true` for packets your protocol actually handles.

## Example: A Simple Beacon Protocol

Here is a minimal but complete protocol that periodically broadcasts a beacon Interest on every known face, and tracks which peers respond.

### State

```rust
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_discovery::{
    DiscoveryContext, DiscoveryProtocol, InboundMeta,
    NeighborEntry, NeighborState, NeighborUpdate, ProtocolId,
};
use ndn_packet::{Name, encode::InterestBuilder};
use ndn_transport::FaceId;

pub struct BeaconProtocol {
    node_name: Name,
    beacon_prefix: Name,
    hello_interval: Duration,
    state: Mutex<BeaconState>,
}

struct BeaconState {
    known_faces: Vec<FaceId>,
    last_hello: Option<Instant>,
    // peer name → last-seen time
    peers: HashMap<Name, Instant>,
}

impl BeaconProtocol {
    pub fn new(node_name: Name) -> Self {
        Self {
            beacon_prefix: "/ndn/local/beacon".parse().unwrap(),
            node_name,
            hello_interval: Duration::from_secs(1),
            state: Mutex::new(BeaconState {
                known_faces: Vec::new(),
                last_hello: None,
                peers: HashMap::new(),
            }),
        }
    }
}
```

### Implementing the trait

```rust
impl DiscoveryProtocol for BeaconProtocol {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId("beacon")
    }

    fn claimed_prefixes(&self) -> &[Name] {
        std::slice::from_ref(&self.beacon_prefix)
    }

    fn on_face_up(&self, face_id: FaceId, _ctx: &dyn DiscoveryContext) {
        self.state.lock().unwrap().known_faces.push(face_id);
    }

    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        let mut s = self.state.lock().unwrap();
        s.known_faces.retain(|&id| id != face_id);
    }

    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        _meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let Ok(interest) = ndn_packet::Interest::decode(raw.clone()) else {
            return false;
        };

        if !interest.name().has_prefix(&self.beacon_prefix) {
            return false;
        }

        // Extract the sender name from the Interest name:
        // /ndn/local/beacon/<sender-name-uri>/<nonce>
        let components: Vec<_> = interest.name().components().collect();
        if components.len() < 4 {
            return false;
        }

        // The third component onwards (after /ndn/local/beacon) is the sender name.
        // In a real implementation you would encode this properly in the payload.
        let sender_name: Name = "/ndn/example/peer".parse().unwrap(); // placeholder

        // Update neighbor table.
        ctx.update_neighbor(NeighborUpdate::SetState {
            name: sender_name.clone(),
            state: NeighborState::Established { last_seen: ctx.now() },
        });

        // If this is a new peer, install a FIB route and record it.
        {
            let mut s = self.state.lock().unwrap();
            if !s.peers.contains_key(&sender_name) {
                ctx.add_fib_entry(
                    &sender_name,
                    incoming_face,
                    10,
                    self.protocol_id(),
                );
                ctx.update_neighbor(NeighborUpdate::Upsert(
                    NeighborEntry::new(sender_name.clone()),
                ));
            }
            s.peers.insert(sender_name, ctx.now());
        }

        true  // consumed
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        let (should_send, faces) = {
            let mut s = self.state.lock().unwrap();
            let due = s.last_hello
                .map(|t| now.duration_since(t) >= self.hello_interval)
                .unwrap_or(true);
            if due {
                s.last_hello = Some(now);
            }
            (due, s.known_faces.clone())
        };

        if !should_send {
            return;
        }

        // Build a beacon Interest: /ndn/local/beacon/<my-name>/<nonce>
        let beacon_name: Name = format!(
            "/ndn/local/beacon/{}/{}",
            self.node_name,
            rand::random::<u32>()
        ).parse().unwrap();

        let wire = InterestBuilder::new(beacon_name)
            .lifetime(Duration::from_millis(500))
            .build();

        // Broadcast on every known face.
        for face_id in faces {
            ctx.send_on(face_id, wire.clone());
        }

        // Evict peers not seen in 3× the hello interval.
        let deadline = now - self.hello_interval * 3;
        let mut s = self.state.lock().unwrap();
        let stale: Vec<_> = s.peers
            .iter()
            .filter(|(_, &t)| t < deadline)
            .map(|(n, _)| n.clone())
            .collect();
        for name in stale {
            s.peers.remove(&name);
            ctx.remove_fib_entries_by_owner(self.protocol_id());
            ctx.update_neighbor(NeighborUpdate::Remove(name));
        }
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(100)
    }
}
```

### Registering with the engine

```rust
use ndn_engine::{EngineBuilder, EngineConfig};

let node_name: Name = "/ndn/site/mynode".parse()?;
let beacon = BeaconProtocol::new(node_name);

let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
    .discovery(beacon)
    .build()
    .await?;
```

If you want to run two protocols simultaneously, wrap them in `CompositeDiscovery`:

```rust
use ndn_discovery::CompositeDiscovery;

let discovery = CompositeDiscovery::new()
    .add(UdpNeighborDiscovery::new(config)?)
    .add(MyServiceDiscovery::new());

let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
    .discovery(discovery)
    .build()
    .await?;
```

`CompositeDiscovery` checks at construction time that no two protocols claim overlapping prefixes and routes inbound packets to the correct protocol based on name prefix match.

## Testing Your Protocol in Isolation

Because `DiscoveryProtocol` only interacts with the engine through `DiscoveryContext`, you can test it without a running engine by implementing a stub context:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use ndn_discovery::{NeighborTable, NeighborTableView};

    struct StubCtx {
        fib: Mutex<Vec<(Name, FaceId)>>,
        neighbors: Arc<NeighborTable>,
    }

    impl StubCtx {
        fn new() -> Self {
            Self {
                fib: Mutex::new(Vec::new()),
                neighbors: NeighborTable::new(),
            }
        }
    }

    impl DiscoveryContext for StubCtx {
        fn alloc_face_id(&self) -> FaceId { FaceId(99) }
        fn add_face(&self, _: Arc<dyn ndn_transport::ErasedFace>) -> FaceId { FaceId(99) }
        fn remove_face(&self, _: FaceId) {}
        fn add_fib_entry(&self, prefix: &Name, nexthop: FaceId, _cost: u32, _owner: ProtocolId) {
            self.fib.lock().unwrap().push((prefix.clone(), nexthop));
        }
        fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
        fn remove_fib_entries_by_owner(&self, _: ProtocolId) {
            self.fib.lock().unwrap().clear();
        }
        fn neighbors(&self) -> Arc<dyn NeighborTableView> { self.neighbors.clone() }
        fn update_neighbor(&self, update: NeighborUpdate) {
            self.neighbors.apply(update);
        }
        fn send_on(&self, _: FaceId, _: Bytes) {}
        fn now(&self) -> Instant { Instant::now() }
    }

    #[test]
    fn face_up_registers_face() {
        let protocol = BeaconProtocol::new("/ndn/test/node".parse().unwrap());
        let ctx = StubCtx::new();
        protocol.on_face_up(FaceId(1), &ctx);
        assert!(protocol.state.lock().unwrap().known_faces.contains(&FaceId(1)));
    }

    #[test]
    fn face_down_removes_face() {
        let protocol = BeaconProtocol::new("/ndn/test/node".parse().unwrap());
        let ctx = StubCtx::new();
        protocol.on_face_up(FaceId(1), &ctx);
        protocol.on_face_down(FaceId(1), &ctx);
        assert!(!protocol.state.lock().unwrap().known_faces.contains(&FaceId(1)));
    }
}
```

## Design Checklist

Before shipping a discovery protocol:

- [ ] `claimed_prefixes()` covers every name prefix the protocol sends or listens for
- [ ] All FIB entries are installed with your `ProtocolId` so they clean up automatically on shutdown
- [ ] `on_inbound` returns `false` for packets that don't belong to your protocol
- [ ] `on_tick` checks elapsed time before sending — never assumes it is called exactly at `tick_interval`
- [ ] State mutations happen inside `Mutex` — `on_inbound` and `on_tick` may be called from different tasks
- [ ] You handle the case where `on_face_down` fires before any `on_inbound` for that face
- [ ] The protocol has at least a stub test that verifies the context interactions without a running engine
