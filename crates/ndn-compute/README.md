# ndn-compute

In-network computation for NDN: routes Interests to registered compute handlers and
injects the resulting Data packets back into the forwarder pipeline. This enables
Named Function Networking (NFN) patterns where computation is co-located with the
router and results are cached in the Content Store like any other Data object.

## Key types

| Type | Description |
|------|-------------|
| `ComputeFace` | Virtual face that bridges the NDN pipeline to registered handlers |
| `ComputeRegistry` | Maps name prefixes to `ComputeHandler` instances |
| `ComputeHandler` | Trait for user-defined compute functions; receives an `Interest`, returns `Data` |

## Usage

```toml
[dependencies]
ndn-compute = { version = "*" }
```

```rust
use ndn_compute::{ComputeRegistry, ComputeHandler, ComputeFace};

struct EchoHandler;

#[async_trait::async_trait]
impl ComputeHandler for EchoHandler {
    async fn handle(&self, interest: Interest) -> Option<Data> {
        Some(Data::new(interest.name().clone(), b"pong"))
    }
}

let mut registry = ComputeRegistry::new();
registry.register("/compute/echo", EchoHandler);
let face = ComputeFace::new(registry);
// Register `face` with the engine like any other face.
```
