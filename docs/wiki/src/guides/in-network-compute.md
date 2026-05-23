# In-network compute

In-network compute lets a forwarder answer an Interest with *computed*
Data instead of stored Data. A named function runs at the node, and its
result is injected back into the pipeline — so it caches in the Content
Store and aggregates in the PIT exactly like fetched content.

The API lives in `ndn-compute` (`crates/ndn-compute`). It is
layered: reach for a richer entry point only when you need it.

| Tier | Entry point | Use |
|------|-------------|-----|
| 0 | `ComputeHandler` | raw `&Interest -> Data` |
| 1 | `ComputeService::function` / `ComputeClient::call` | typed Rust args and results |
| 2 | `ComputeService::executor_function` / `ComputeExecutor` | sandboxed or native bytes→bytes kernels |
| 3 | `ComputeService::job` / `ComputeClient::call_job` | long-running jobs via thunks |

## Attaching to an engine

`ComputeService::attach` allocates a synthetic compute face on a running
engine. Each registration wires a FIB route for the function prefix to
that face.

```rust,ignore
use ndn_compute::{ComputeService, ComputeClient};

let compute = ComputeService::attach(&engine);

// A typed function: result cached, identical calls coalesce.
compute.function("/calc/add", |(a, b): (i64, i64)| async move { Ok(a + b) });

// Consumer side:
let mut client = ComputeClient::new(consumer);
let sum: i64 = client.call("/calc/add", (2, 3)).await?;
assert_eq!(sum, 5);
```

Arguments are framed into the name components after the prefix and the
result into the Data content, using the `ComputeArgs` / `ComputeValue`
codec. Implement those traits for your own types when the built-in
scalar and byte framings are not enough.

## Determinism: transparent vs. opaque

Whether a result may be cached is a property of the *name*, not a flag.

- A **transparent** function (`function`) is fully determined by its
  invocation name. The result carries a freshness period, so it caches
  and concurrent identical calls collapse into one execution.
- An **opaque** function (`opaque_function`) may return a different
  value each call. The client appends an unpredictable nonce component
  and requests a fresh result, so calls never alias.

Opaque calls must distinguish themselves with a name component, never
with the `ApplicationParameters` digest — the forwarder strips that
digest before keying the PIT and Content Store (see [Interest and Data
lifecycle](../concepts/interest-data-lifecycle.md)), so two otherwise
identical opaque calls would collapse onto one entry.

```rust,ignore
compute.opaque_function("/rng/u64", |_: ()| async move { Ok(rand_u64()) });
let n: u64 = client.call_opaque("/rng/u64", ()).await?;
```

## Sandboxed kernels

`ComputeExecutor` is the backend seam: a plain `Fn(&[u8]) -> Result<Bytes>`,
or a `WasmExecutor` loaded from a `.wasm` module, both plug in behind the
same trait. Build with the `wasm-exec` feature to pull in the wasmtime
backend.

```rust,ignore
use ndn_compute::WasmExecutor;

let kernel = WasmExecutor::from_file("thumbnail.wasm", /* fuel */ 5_000_000)?;
compute.executor_function("/img/thumbnail", kernel);
```

Each invocation runs in a fresh sandbox with a fuel budget; a runaway
guest traps instead of hanging the node. The guest exports `compute`
plus `memory` and imports three host functions (`input_len`,
`read_input`, `write_output`). An executor's input rides one name
component, so executor-backed functions stay transparent.

## Long-running jobs

When a computation cannot finish within roughly one round trip, register
it as a `job`. The invocation Interest returns a **thunk** — a small Data
object naming where the result will appear, plus a completion estimate —
and the computation runs in the background. The client polls the thunk
name until the result is ready.

```rust,ignore
use std::time::Duration;

compute.job("/render/scene", Duration::from_millis(500), |scene_id: u64| async move {
    Ok(render(scene_id))
});

let pixels: Vec<u8> = client
    .call_job("/render/scene", 7u64, Duration::from_millis(200), Duration::from_secs(30))
    .await?;
```

`call_job` runs the whole handshake: fetch the invocation name, read the
thunk, then poll. Identical arguments map to the same thunk, so several
clients waiting on the same job share one execution.

## Pulling parameters by reference

When an input is too large to put in the name, register the function with
`function_ref` and take the parameter's *name* as the argument. The handler
receives a `ComputeContext` and fetches the value itself:

```rust,ignore
compute.function_ref("/sum", |param: String, ctx| async move {
    let bytes = ctx.fetch(param.parse::<ndn_packet::Name>().unwrap()).await?;
    Ok(bytes.iter().map(|&b| b as u64).sum::<u64>())
});
```

The referenced name must be routable to a producer — the consumer publishes the
parameter under a name and the compute node fetches it.

When the consumer holds no routable name, use `function_reflexive` instead: the
invocation Interest carries an unpredictable reflexive name, and the node
Interests the parameters back along the reverse path the Interest arrived on, so
the consumer answers without registering any prefix. This relies on the
forwarders on the path supporting reflexive forwarding.

## Testing

The in-process engine is the testing fixture — drive a `ComputeClient`
over an `InProcFace` handle and assert the result. The crate's
`tests/end_to_end.rs` shows the pattern for every tier, including
caching, coalescing, the WASM round trip, and the job handshake.

## See also

- [Develop tier](../api/develop.md) — the `Consumer` / `Producer`
  surface the compute client builds on.
- [Interest and Data lifecycle](../concepts/interest-data-lifecycle.md) —
  PIT aggregation and Content Store admission, which compute results
  ride on.
