# Performance

This page covers the knobs that move the forwarder's throughput
and latency under load, and the diagnostics to spot which one is
biting you.

The pipeline shape (PacketContext by value, DashMap PIT,
`bytes::Bytes` zero-copy, no global lock on the hot path) is in
`ARCHITECTURE.md`. This page is operational, not architectural.

## Throughput knobs

| Knob | Where | Effect |
|---|---|---|
| `[engine] pipeline_threads` | `ndn-fwd.toml` | 0 (auto) / 1 (inline) / N. Inline is lowest-latency; N is highest-throughput. |
| `[engine] pipeline_channel_cap` | `ndn-fwd.toml` | Inter-task channel depth. Raise if you see "channel full, packet dropped". |
| `[cs] variant` | `ndn-fwd.toml` | `sharded-lru` cuts lock contention at high concurrency. |
| `[cs] capacity_mb` | `ndn-fwd.toml` | Bigger cache → more hits → less producer round-trip. |
| Log filter | `RUST_LOG` / `[log] filter` | `debug`/`trace` is expensive on hot paths. Run production at `info`. |
| Face MTU / fragmentation | `[[face]] mtu` | Larger MTU = fewer NDNLPv2 fragments. |
| UDP socket buffers | (automatic) | UDP faces request 4 MiB receive / 1 MiB send on bind (kernel-clamped to `net.core.{r,w}mem_max`), reducing drops under bursty load. |

## Latency knobs

| Knob | Effect |
|---|---|
| `pipeline_threads = 1` | No inter-task hop on the hot path. |
| `tracing` filter `off` on hot targets | Removes per-packet log work. |
| `[cs] admission_policy = "default"` | Only PIT-satisfying Data goes into CS (cache is hot for actual traffic). |
| Strategy choice | `BestRouteStrategy` is single-nexthop; `MulticastStrategy` fans out (higher load). |

## Diagnostic recipes

### Where is time going?

Run with `tokio-console`:

```sh
RUSTFLAGS="--cfg tokio_unstable" cargo run -p ndn-fwd --features tokio-console
```

Look for tasks with high busy ratios and long poll times. Pipeline
worker tasks are named; strategies expose their own spans.

### Is the channel full?

Set `RUST_LOG=ndn_engine::pipeline=warn` and watch for
"channel full, packet dropped". If frequent: raise
`pipeline_channel_cap` or add `pipeline_threads`.

### Is the PIT churning?

`ndn-ctl cs info` shows PIT churn indirectly via expiry counts.
For raw counts, instrument-tier `engine.pit().len()` over time, or
read the mgmt notification stream `pit-events`.

### Is the CS missing?

`ndn-ctl cs info` reports `hits` and `misses`. Hit ratio under
20% on a workload that ought to repeat → capacity too small or
admission policy excluding traffic.

## Benchmarks

In-tree benchmarks live under `binaries/tooling/ndn-bench/`.
Wasm-target and native-target numbers are tracked internally;
rerun the benchmarks to refresh.

For your own workload, capture before/after with `ndn-bench` and
compare. Single numbers in isolation are not informative; the
shape of the curve under varying concurrency is.

## Project-memory pointers

- `feedback_face_id_provenance` — the `face_id` provenance hazard
  cost a 170× throughput regression. Code touching face IDs in the
  hot path should re-read it.
- `feedback_face_id_no_recycle` — face IDs are monotonic; never
  recycle. Closes ABA hazards in caches keyed by face ID.
- `feedback_pre_push_ci_checks` — full CI run before push catches
  performance-regressing clippy lints.

## See also

- [ndn-fwd](./ndn-fwd.md) — runtime ops and the mgmt verbs that
  expose counters.
- [Logging](./logging.md) — observe what the pipeline is doing.
- [Config reference](./config-reference.md) — every knob with its
  default.
- `binaries/tooling/ndn-bench/` — workload generator.
