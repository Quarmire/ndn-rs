# Implementing a Routing Protocol

This guide walks through writing a custom routing protocol for ndn-rs. Routing protocols manage routes in the engine's RIB (Routing Information Base), which is then used to derive the FIB.

## Overview

A routing protocol is a Tokio background task that:
1. Runs until cancelled
2. Installs routes via `RoutingHandle::rib`
3. Calls `rib.apply_to_fib()` after each mutation

The `RoutingProtocol` trait in `ndn_engine`:

```rust
pub trait RoutingProtocol: Send + Sync + 'static {
    /// Unique origin value for this protocol's routes.
    fn origin(&self) -> u64;

    /// Start as a Tokio background task.
    ///
    /// Runs until `cancel` is cancelled. Use `handle.rib` to install/remove
    /// routes and `handle.rib.apply_to_fib(&prefix, &handle.fib)` to push
    /// changes into the FIB.
    fn start(&self, handle: RoutingHandle, cancel: CancellationToken) -> JoinHandle<()>;
}
```

The `RoutingHandle` provides:
- `handle.rib` — write routes
- `handle.fib` — needed for `rib.apply_to_fib()`
- `handle.faces` — enumerate active faces
- `handle.neighbors` — read neighbor table (discovered peers)

## Minimal example: periodic beacon

```rust
use ndn_engine::{RibRoute, RoutingHandle, RoutingProtocol};
use ndn_transport::FaceId;
use ndn_packet::Name;
use ndn_config::control_parameters::origin;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

struct BeaconProtocol {
    prefix: Name,
    face_id: FaceId,
}

impl RoutingProtocol for BeaconProtocol {
    fn origin(&self) -> u64 {
        origin::AUTOCONF  // 66 — pick an appropriate value
    }

    fn start(&self, handle: RoutingHandle, cancel: CancellationToken) -> JoinHandle<()> {
        let prefix = self.prefix.clone();
        let face_id = self.face_id;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        handle.rib.add(&prefix, RibRoute {
                            face_id,
                            origin: origin::AUTOCONF,
                            cost: 1,
                            flags: ndn_config::control_parameters::route_flags::CHILD_INHERIT,
                            expires_at: Some(std::time::Instant::now()
                                + std::time::Duration::from_secs(120)),
                        });
                        handle.rib.apply_to_fib(&prefix, &handle.fib);
                    }
                    _ = cancel.cancelled() => break,
                }
            }
        })
    }
}
```

## Choosing an origin value

Use a value from `ndn_config::control_parameters::origin` that matches your protocol's role:

| Value | Constant | When to use |
|-------|----------|-------------|
| 0–63 | `APP`, `AUTOREG`, `CLIENT` | Application-managed routes |
| 64–126 | `AUTOCONF`…custom | Auto-configuration, custom protocols |
| 127 | `DVR` | Distance vector routing |
| 128 | `NLSR` | Link-state routing, NLSR-compatible |
| 255 | `STATIC` | Permanent static routes |

Lower origin values win tie-breaks when multiple protocols register the same prefix via the same face at the same cost.

## The dual-protocol pattern (packet I/O)

Some routing algorithms — like DVR — need to send and receive NDN packets (route advertisements). The `RoutingProtocol` trait doesn't provide packet I/O; that's the `DiscoveryProtocol` domain. The solution is to implement **both traits** on the same struct, sharing state via `Arc<Inner>`.

```
┌─────────────────────────────┐
│   DiscoveryProtocol impl    │ ← on_inbound() receives route adverts
│   (registered with engine   │ ← on_tick() sends route adverts
│    discovery system)        │
│                             │
│   RoutingProtocol impl      │ ← start() stores RoutingHandle in OnceLock
│   (registered with          │ ← on_inbound() writes to rib via stored handle
│    RoutingManager)          │
└─────────────────────────────┘
```

The `DvrProtocol` in `crates/ndn-routing/src/protocols/dvr.rs` is the reference implementation.

### Pattern skeleton

```rust
use std::sync::{Arc, OnceLock};

struct MyInner {
    // Routing handle — populated by RoutingProtocol::start()
    routing: OnceLock<ndn_engine::RoutingHandle>,
    // Protocol state
    // ...
}

#[derive(Clone)]
pub struct MyProtocol {
    inner: Arc<MyInner>,
}

impl DiscoveryProtocol for MyProtocol {
    // ...
    fn on_inbound(&self, raw: &Bytes, face: FaceId, _meta: &InboundMeta, _ctx: &dyn DiscoveryContext) -> bool {
        let Some(handle) = self.inner.routing.get() else {
            return false; // not yet started
        };
        // decode `raw`, update handle.rib, call handle.rib.apply_to_fib(...)
        true
    }
}

impl RoutingProtocol for MyProtocol {
    fn origin(&self) -> u64 { MY_ORIGIN }

    fn start(&self, handle: ndn_engine::RoutingHandle, cancel: CancellationToken) -> JoinHandle<()> {
        let _ = self.inner.routing.set(handle); // bridge the two systems
        tokio::spawn(async move { cancel.cancelled().await })
    }
}
```

Register both with the engine builder:

```rust
let proto = Arc::new(MyProtocol::new(node_name));
let engine = EngineBuilder::new()
    .discovery(Arc::clone(&proto) as Arc<dyn DiscoveryProtocol>)
    .routing_protocol(Arc::clone(&proto))
    .build().await?;
```

## RIB API reference

```rust
// Install or update a route.
rib.add(&prefix, RibRoute { face_id, origin, cost, flags, expires_at });

// Remove a specific (face_id, origin) route.
rib.remove(&prefix, face_id, origin);

// Remove all routes via face_id for this prefix.
rib.remove_nexthop(&prefix, face_id);

// Remove all routes registered by this origin (across all prefixes).
// Returns affected prefixes; call apply_to_fib for each.
let affected = rib.flush_origin(my_origin);
for prefix in affected {
    rib.apply_to_fib(&prefix, &fib);
}

// Push computed best nexthops into the FIB.
// Always call this after add/remove to keep the FIB in sync.
rib.apply_to_fib(&prefix, &fib);
```

`RibRoute` fields:

| Field | Type | Notes |
|-------|------|-------|
| `face_id` | `FaceId` | Outgoing face |
| `origin` | `u64` | Your protocol's origin value |
| `cost` | `u32` | Route cost (lower preferred) |
| `flags` | `u64` | `CHILD_INHERIT` (1), `CAPTURE` (2) |
| `expires_at` | `Option<Instant>` | `None` = permanent |

Use `CHILD_INHERIT` so that `/ndn/edu/ucla/cs` is automatically covered by a route for `/ndn/edu/ucla`.

## Testing your protocol

The simplest test strategy: build an engine with your protocol, register a prefix, and verify it appears in the FIB.

```rust
#[tokio::test]
async fn test_static_route_appears_in_fib() {
    use ndn_engine::EngineBuilder;
    use ndn_routing::{StaticProtocol, StaticRoute};

    let engine = EngineBuilder::new()
        .routing_protocol(StaticProtocol::new(vec![
            StaticRoute {
                prefix: "/ndn/test".parse().unwrap(),
                face_id: FaceId(1),
                cost: 10,
            },
        ]))
        .build()
        .await
        .unwrap();

    // Give the task a moment to install routes.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let fib = engine.fib();
    assert!(fib.lookup(&"/ndn/test/sub".parse().unwrap()).is_some());
}
```

For protocols with packet I/O, consider using `ndn-sim` to create a simulated network topology and verify routes converge correctly.

## Adding to `ndn-routing`

To add a new protocol to the `ndn-routing` crate:

1. Create `crates/ndn-routing/src/protocols/your_protocol.rs`
2. Implement `RoutingProtocol` (and `DiscoveryProtocol` if needed)
3. Add `pub mod your_protocol;` to `crates/ndn-routing/src/protocols/mod.rs`
4. Add `pub use protocols::your_protocol::YourProtocol;` to `crates/ndn-routing/src/lib.rs`

See `protocols/static.rs` for a minimal example and `protocols/dvr.rs` for the full dual-protocol pattern.
