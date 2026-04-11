# ndn-pipeline

Fixed-stage packet processing pipeline for the ndn-rs forwarder. Every NDN packet flows through a sequence of `PipelineStage` trait objects; each stage receives `PacketContext` by value and returns an `Action` that drives dispatch. The stages are fixed at build time so the compiler can optimize the hot path.

## Key Types

| Type | Role |
|------|------|
| `PipelineStage` | Trait implemented by each processing step (FaceCheck, CsLookup, PitCheck, etc.) |
| `PacketContext` | Per-packet state (raw bytes, decoded packet, face, PIT token, metadata map) passed by value through stages |
| `DecodedPacket` | Lazily-decoded `Interest` or `Data` extracted from `PacketContext` |
| `Action` | Enum controlling packet fate: `Continue`, `Send`, `Satisfy`, `Drop`, `Nack` |
| `ForwardingAction` | Strategy-level decision: `Forward`, `ForwardAfter`, `Nack`, `Suppress` |
| `DropReason` / `NackReason` | Structured reasons attached to `Drop` and `Nack` actions |
| `BoxedStage` | Type-erased `Box<dyn PipelineStage>` for runtime pipeline assembly |
| `AnyMap` | Re-exported from `ndn-transport`; holds per-packet extension data |

## Feature Flags

None. All dependencies (`ndn-packet`, `ndn-transport`, `ndn-store`) are unconditional.

## Usage

```rust
use ndn_pipeline::{PipelineStage, PacketContext, Action};

struct CsLookupStage { /* cs handle */ }

impl PipelineStage for CsLookupStage {
    fn process(&self, ctx: PacketContext) -> Action {
        // return Action::Satisfy(...) on cache hit, Action::Continue otherwise
        Action::Continue(ctx)
    }
}
```

**Interest pipeline:** FaceCheck → TlvDecode → CsLookup → PitCheck → Strategy → Dispatch

**Data pipeline:** FaceCheck → TlvDecode → PitMatch → Strategy → MeasurementsUpdate → CsInsert → Dispatch

Part of the [ndn-rs](../../README.md) workspace.
