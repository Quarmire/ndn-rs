# NDN-RS Architecture Overview

## Design Philosophy

This stack treats NDN as **composable data pipelines** with **trait-based polymorphism** rather than class hierarchies. Key departures from ndn-cxx/NFD:

- No separate daemon process — `ForwarderEngine` is a library crate, not a service
- `AppFace` uses in-process `mpsc` channels as the local fast path; no Unix socket on the data path
- `PacketContext` passes **by value** through pipeline stages — ownership makes short-circuits compiler-enforced
- Security is application-layer; the forwarder does not validate signatures on transit Data
- Custom strategies, stages, and faces plug in via traits without modifying the engine

## Unified Engine Model

Unlike NFD + ndn-cxx, there is no IPC boundary between the forwarder and the application API:

```
same-process applications → AppFace (mpsc, ~20 ns)
cross-process applications → iceoryx2 Data + mpsc Interest (~150 ns)
remote peers             → UdpFace / EtherFace / TcpFace
```

Inter-application forwarding requires either a shared process or a standalone `ndn-router` binary that external applications connect to via `AppFace` over shared memory.

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Packet ownership through pipeline | by value | Compiler enforces no-use-after-short-circuit |
| Name sharing | `Arc<Name>` | Shared across PIT key, FIB lookup, CS key without copy |
| PIT structure | `DashMap<(Name, Option<Selector>), PitEntry>` | Per-shard locking, no global hot lock |
| FIB structure | `NameTrie` with `Arc<RwLock<TrieNode>>` per node | LPM with concurrent read, rare writes |
| CS storage | wire-format `Bytes` | CS hit → direct `face.send()`, no re-encoding |
| Strategy return type | `SmallVec<[ForwardingAction; 2]>` | Inline probing (primary + ForwardAfter), no alloc |
| Security | `SafeData` newtype | Verified status encoded in the type, not a flag |
| Async trait dyn-compat | `BoxFuture<'a, T>` for `Signer`/`Verifier` | Enables `dyn Signer` storage |
| Arrival timestamp | `u64` ns since epoch | `Instant` is not `Send` on all platforms |

## Crate Layer Graph

```
Layer 0 (binaries)
  ndn-router   ndn-tools   ndn-bench

Layer 1 (application & engine)
  ndn-app      ndn-ipc     ndn-engine

Layer 2 (pipeline, strategy, security)
  ndn-pipeline   ndn-strategy   ndn-security

Layer 3 (faces)
  ndn-face-net   ndn-face-local   ndn-face-serial   ndn-face-wireless

Layer 4 (data structures & transport)
  ndn-store    ndn-transport

Layer 5 (foundation)
  ndn-packet   ndn-tlv

Layer 6 (research extensions, optional)
  ndn-research   ndn-compute   ndn-sync
```

Dependencies flow strictly downward. `ndn-packet` and `ndn-tlv` have no async dependency and can compile `no_std` (with `alloc`) for embedded sensor nodes.

## Task Topology

```
face_task (one per Face)
   │  RawPacket { bytes, face_id, arrival }
   ▼
pipeline_runner_task
   │  tokio::spawn per packet
   ▼
per-packet pipeline task → [ stage₁ → stage₂ → ... → dispatch ]
                                                          │
                                               face_table.get(id).send(bytes)
expiry_task
   └─ drains expired PIT entries every 1 ms
```

Face tasks push onto a bounded `mpsc` channel (`pipeline_channel_cap` from `EngineConfig`). Backpressure on a slow pipeline yields the face task naturally.

## Phased Build Order

```
Phase 1: ndn-tlv, ndn-packet
Phase 2: ndn-transport, ndn-store
Phase 3: ndn-pipeline, ndn-strategy
Phase 4: ndn-engine, ndn-face-net
Phase 5: ndn-security, ndn-app
Phase 6: face crates, research extensions, binaries
```

Each phase should reach `cargo test` passing before proceeding. `Name`, `Face`, and `PipelineStage` trait signatures must be stable before dependent crates are implemented.
