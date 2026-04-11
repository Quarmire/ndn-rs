# docs/

Design documentation for the ndn-rs implementation. For the user-facing wiki see `docs/wiki/`.

## Reference Docs

| File | Contents |
|------|----------|
| [`architecture.md`](architecture.md) | Design philosophy, key decisions, task topology |
| [`tlv-encoding.md`](tlv-encoding.md) | varu64, TlvReader, partial decode, COBS framing |
| [`packet-types.md`](packet-types.md) | Name, Interest, Data, PacketContext, lazy decode |
| [`pipeline.md`](pipeline.md) | PipelineStage, Action, Interest/Data stage sequences |
| [`forwarding-tables.md`](forwarding-tables.md) | FIB, PIT, Content Store implementations |
| [`faces.md`](faces.md) | Face trait, task topology, all face types |
| [`engine.md`](engine.md) | ForwarderEngine, EngineBuilder, tracing setup |
| [`strategy.md`](strategy.md) | Strategy trait, BestRoute, measurements table |
| [`security.md`](security.md) | Signing, trust schema, SafeData, validator chain |
| [`ipc.md`](ipc.md) | Transport tiers, chunked transfer, service registry |
| [`discovery.md`](discovery.md) | SWIM neighbor discovery, epidemic gossip, service records |
| [`wireless.md`](wireless.md) | Multi-radio architecture, nl80211, wfb-ng |
| [`compute.md`](compute.md) | In-network compute levels and ComputeFace |
| [`simulation.md`](simulation.md) | SimFace, SimLink, topology builder, event tracer |
| [`spsc-shm-spec.md`](spsc-shm-spec.md) | Shared-memory ring buffer wire format |

## Protocol Specs

| File | Contents |
|------|----------|
| [`protocols/ndn-ft-protocol.md`](protocols/ndn-ft-protocol.md) | NDN Forwarding Table protocol |
| [`protocols/routing.md`](protocols/routing.md) | DVR routing algorithm and static routes |

## Unimplemented / Gaps

| File | Contents |
|------|----------|
| [`unimplemented.md`](unimplemented.md) | Known unimplemented features and TODO items |
| [`did-ndn-spec.md`](did-ndn-spec.md) | DID-over-NDN specification draft |

## Archive

| File | Contents |
|------|----------|
| [`archive/design-session.md`](archive/design-session.md) | Original design transcript (historical reference) |
