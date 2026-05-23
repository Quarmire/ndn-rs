# ndn-compute

In-network computation for NDN: route Interests to named functions and inject
the resulting Data back into the forwarder pipeline, where it caches in the
Content Store and aggregates in the PIT like any other Data object.

The crate is layered — reach for a richer type only when you need more:

| Tier | Entry point | Use |
|------|-------------|-----|
| 0 | `ComputeHandler` | raw `&Interest -> Data` |
| 1 | `ComputeService::function` / `ComputeClient::call` | typed args/result, no `Data`/`FaceId` plumbing |
| 2 | `ComputeService::executor_function` + `ComputeExecutor` | sandboxed/native bytes→bytes kernels (`WasmExecutor` behind `wasm-exec`) |
| 3 | `ComputeService::job` + `ComputeClient::call_job` | long-running jobs via thunks |
| — | `ComputeService::function_ref` + `ComputeContext` | pull a parameter *by name* (NFN-style dereference) |
| — | `ComputeService::function_reflexive` | pull params over the reflexive reverse path (RICE §8) |
| — | `ComputeService::function_reflexive_authenticated` | as above, but validate the signed params before computing |
| — | `ComputeService::function_reflexive_sealed` | as above, but params are encrypted over the reverse path (`sealed-params`) |
| — | `ComputeService::function_reflexive_secure` | authenticated **and** encrypted reflexive params (the secure default) |
| — | `ComputeService::register` | bridge an arbitrary `ComputeHandler` |

Determinism is explicit, not a flag:

- **transparent** functions (`function`) — the result is fully determined by the
  invocation name, so it is cached and concurrent identical calls coalesce in
  the PIT into a single execution.
- **opaque** functions (`opaque_function`) — the client adds an unpredictable
  nonce name component, so results never alias and are never served stale. This
  matches the engine's PIT doctrine, which strips the
  `ParametersSha256DigestComponent` and so cannot use it to distinguish two
  calls.

See the design note (`docs/notes/compute-design-2026-05-21.md`) and the
cross-implementation wire spec (`docs/notes/compute-wire-spec-2026-05-21.md`).

## Example

```rust,ignore
use ndn_compute::{ComputeService, ComputeClient};

// Attach to a running engine; this allocates the synthetic compute face.
let compute = ComputeService::attach(&engine);

// A transparent function: result cached, repeat calls coalesce.
compute.function("/calc/add", |(a, b): (i64, i64)| async move { Ok(a + b) });

// Consumer side:
let sum: i64 = ComputeClient::new(consumer).call("/calc/add", (2, 3)).await?;
assert_eq!(sum, 5);
```

## Status

`extension` scope — pragmatic engineering, no adopted community spec (NFN is
research; RICE is an individual ICNRG draft). The wire spec in `docs/notes` is
author-led. Inputs too large for the name can be pulled *by reference* with
`function_ref` (the handler fetches a parameter name; NFN-style dereference) or,
when the consumer holds no routable prefix, with `function_reflexive` — RICE §8
reflexive forwarding, where the node Interests params back along the reverse
path. The engine reflexive-forwarding support it builds on is described in
`docs/notes/reflexive-forwarding-engine-2026-05-21.md`.
`function_reflexive_authenticated` adds RICE's authorization leg — the node
validates the consumer's signed params against a `Validator` before computing.
`function_reflexive_sealed` (`sealed-params` feature) adds confidentiality — an
X25519/AES-256-GCM sealed box so the params travel encrypted over the reverse
path. `function_reflexive_secure` combines both — validated *and* encrypted —
which also defeats MITM of the key exchange (the signature covers the sealed
blob); it is the recommended default when the path is untrusted.
