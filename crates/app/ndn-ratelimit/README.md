# ndn-ratelimit

Admission-control rate limiting for the ndn-rs forwarder.

- Scope: `extension`.
-

## Targets

Native and `wasm32-unknown-unknown` both build clean. `governor`
and `dashmap` carry wasm-compatible code at their default feature
sets; no extra gating required.

```
cargo build -p ndn-ratelimit
cargo build -p ndn-ratelimit --target wasm32-unknown-unknown
```

`WasmEngineBuilder::with_rate_limit_hook(Some(hook))` wires the
same `EngineRateLimitHook` into the in-browser engine.

## Status — Phase A + B landed

| Module | Status | Purpose |
|---|---|---|
| `bucket` | **implemented** | `TokenBucket` wrapping `governor` (GCRA). Interest-PPS + Data-BPS in one cell. |
| `policy` | **implemented** | Sparse `(face × prefix × direction)` cells in a `DashMap`; LPM walk on lookup; bounded capacity. |
| `mgmt`   | **implemented** | Typed `RateLimitMgmtHandler` + `RateLimitMgmtBackend` impl for `ndn-mgmt` dispatch. |
| `config` | **implemented** | TOML `[rate-limit] [[policy]]` loader with validation. |
| `stage`  | **implemented** | `EngineRateLimitHook` implements `ndn_engine::RateLimitHook`. |

**Engine integration.** `EngineBuilder::with_rate_limit_hook(Some(hook))`
plumbs the policy table into the dispatcher. Inbound packets are
charged after `TlvDecodeStage`; outbound on Send + Satisfy. Hook
absent ⇒ one untaken branch per packet.

**Mgmt integration.** `/localhost/nfd/rate-limit/{set,unset,list}`
wired in `ndn-mgmt`. `MgmtHandles.rate_limit_handler: Option<Arc<dyn
RateLimitMgmtBackend>>` — default `None` ⇒ STATUS 404 from the
module.

Tests:
- 24 unit + 2 integration in `ndn-ratelimit`.
- 6 wire-protocol tests in `ndn-mgmt::rate_limit_tests`.
- 1 round-trip test in `ndn-config` for the ControlParameters
  fields.

End-to-end witness (`inbound_pps_burst_caps_floods`): spins up an
embedded `ForwarderEngine`, installs a 5-PPS / burst-5 inbound
policy on face 1 + prefix `/test/rl`, sends 25 Interests, asserts
that the rate limit engages (some permits, some denials, neither
empty nor full).

## Microbench

`cargo test -p ndn-ratelimit --release bench_bucket -- --ignored --nocapture`

| Bucket primitive | Throughput |
|---|---:|
| `try_consume(1, 0)` (Interest, single thread) | **~250 M ops/s** (4 ns/op) |

Well below any plausible Interest rate — the per-packet overhead of
checking a bucket on the hot path is statistically free relative
to TLV decode + signature work.

## Phase B (next)

- `RateLimitInStage` (pre-decode and post-decode variants) and
  `RateLimitOutStage` as `PipelineStage` impls in this crate.
- Engine builder registers the stages and threads
  `SharedPolicyTable` through.
- `ndn-mgmt` gains a `RateLimitHandler` trait + `handle_rate_limit`
  function dispatched under `/localhost/nfd/rate-limit/{set,unset,list}`,
  mirroring the FEC wiring landed in commit `9b78479`.
- End-to-end integration test: lossy-link witness equivalent to
  `nc02_flood.sh` per the design memo §11.
