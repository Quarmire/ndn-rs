# Link Service Composition

The `LinkService` trait owns the framing and per-LP-frame policy half of a
face — NFD's `GenericLinkService` factored into a Rust trait. The forwarder
holds an `Arc<dyn LinkService>` paired with an `Arc<dyn ErasedTransport>`
inside each `Face`; the pair is the abstraction every other crate (engine,
mgmt, ndn-ctl) consumes.

This page is the implementation-side reference: trait shape, the feature
composition model, the two state machines that drive Tier-3 dataplane
behaviour, and the lifecycle of an option flip from `faces/update` to the
wire. The operator-side companion is
[the faces operator guide](../operations/faces.md).

## The two-half model

```rust
pub struct Face {
    pub transport:    Arc<dyn ErasedTransport>,
    pub link_service: Arc<dyn LinkService>,
}
```

- **`Transport`** ships raw bytes over the underlying medium. UDP socket,
  TCP stream, Shm ring, in-process mpsc, Ethernet frame source, WebTransport
  datagram. Carries the runtime knobs that belong to the medium —
  `send_mtu`, `set_send_mtu`, `set_persistency`.
- **`LinkService`** owns NDNLPv2 framing, reliability, congestion-mark
  policy, IncomingFaceId stamping, TraceContext propagation. Carries the
  per-feature pipeline and the typed `apply` seam.

Mirrors NFD's `Face = Transport + LinkService` split at
`~/Documents/Dev/NFD/daemon/face/face.hpp:41-101`. The split is observable
through the public API: `LinkService` is the object-safe trait everywhere
the engine touches; `Transport` is the inner-trait. Both have an erased
counterpart (`ErasedTransport`) so the face table holds `Arc<dyn>` slots
without generic-parameter explosion.

## Two impls ship

| LinkService              | Where it goes                                  | LP-encodes |
| ---                      | ---                                            | ---        |
| `PassthroughLinkService` | Local-scope faces (App, Shm, InProc, Internal, Unix, Management, WebSocket, WebRtc, WebTransport). | No |
| `LpLinkService`          | Non-local faces (Udp, Tcp, Ethernet, Serial, Bluetooth, Multicast). | Yes |

`PassthroughLinkService` is **not** "the composer with an empty feature
list". Local-scope IPC has a different shape — in-process source-face
tagging via `Transport::send_bytes_with_source`, no LP framing — and
forcing it through the feature pipeline costs perf for no win.

## The `LinkServiceFeature` trait

Every per-LP-frame policy is a feature. Features are object-safe by
construction (no generics, no RPIT); the composer holds them as
`Vec<Arc<dyn LinkServiceFeature>>` and iterates in registration order.

```rust
pub trait LinkServiceFeature: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    fn on_egress(&self, _frame: &mut OutboundLpFrame, _ctx: &EgressCtx) {}
    fn on_ingress(&self, _frame: &InboundLpFrame, _ctx: &IngressCtx) {}
    fn tick(&self, _ctx: &TickCtx) -> Option<Duration> { None }
}
```

Hooks have default no-op bodies so a feature that only owns wire-format
state (like the codec-only `TraceContextFeature` at Tier 1) needs zero
boilerplate. Hook ordering in the composer:

```
transport.recv_bytes_with_addr()
     │
     ▼
InboundLpFrame (typed slots)
     │
     ├──► feature[0].on_ingress
     ├──► feature[1].on_ingress
     ├──► …  (in registration order)
     ▼
engine pipeline (decode, PIT, …)

engine pipeline → LpLinkService::send(packet)
     │
     ▼
fragment / LP-wrap → OutboundLpFrame
     │
     ├──► feature[0].on_egress
     ├──► feature[1].on_egress
     ├──► …
     ▼
transport.send_bytes
```

Source: `crates/spec/ndn-transport/src/link_service/feature.rs`.

## The default eight-feature pipeline

`LpLinkService::new()` registers eight features for every non-local face.
Order matters — features run in this sequence on every frame:

| #   | Feature                  | Owns                                                  |
| --- | ---                      | ---                                                   |
| 1   | `FragmentationFeature`   | LP fragmentation policy (framework — not user-mutable). |
| 2   | `ReassemblyFeature`      | LP reassembly buffers on ingress.                     |
| 3   | `LocalFieldsFeature`     | Gate for `IncomingFaceId` egress stamping.            |
| 4   | `IncomingFaceIdFeature`  | Stamps source face id on outbound LP frames when bit on. |
| 5   | `NackFeature`            | Nack-on-ingress recognition + Nack-on-egress passthrough. |
| 6   | `TraceContextFeature`    | LP `TraceContext` TLV codec (Phase-3 OTel hook).      |
| 7   | `ReliabilityFeature`     | NDNLPv2 reliability state machine — Tier 3.           |
| 8   | `CongestionMarkingFeature` | CoDel egress marking — Tier 3.                      |

Features 1..=6 are inert at registration time; flipping a feature ON happens
via `LpLinkService::apply` (see below). The exact registration order lives
in `crates/spec/ndn-transport/src/link_service/features/mod.rs`.

## The typed `apply` seam

`LinkService::apply` takes a typed `FaceOption` enum and flips runtime state
without rebuilding the LinkService. This is how the management surface
turns reliability on a live face, raises the CoDel threshold, or refuses
options that don't fit the transport:

```rust
pub trait LinkService {
    fn apply(&self, opt: FaceOption) -> Result<(), FaceOptionError> { ... }
    fn snapshot(&self) -> FaceOptions { ... }
}
```

`FaceOption` (non-exhaustive):

| Variant                           | Effect on `LpLinkService`                    | Phase    |
| ---                               | ---                                          | ---      |
| `LocalFields(bool)`               | FaceState bit; consulted by IncomingFaceId. | Tier 2/3 |
| `LpReliability(bool)`             | Flips `ReliabilityFeature::enabled`.        | Tier 3   |
| `CongestionMarking(bool)`         | Flips `CongestionMarkingFeature::enabled`.  | Tier 3   |
| `BaseCongestionMarkingInterval(d)` | Sets CoDel base interval.                  | Tier 3   |
| `DefaultCongestionThreshold(t)`   | Sets CoDel threshold.                       | Tier 3   |
| `EffectiveMtu(Option<u64>)`       | Returns `NotSupportedByTransport` (route via Transport instead). | Tier 2 |
| `Persistency(FacePersistency)`    | Same — route via Transport.                 | Tier 2   |

`FaceOptionError` has three operator-visible variants that map 1:1 to the
HTTP-idiom status codes the management module returns:

| Variant                        | Status | Meaning                                                 |
| ---                            | ---    | ---                                                     |
| `NotSupportedByTransport`      | 503    | This face's transport/LinkService has no story for this option. |
| `Immutable`                    | 409    | The option exists but is baked at create time.          |
| `OutOfRange`                   | 400    | Value above transport hard max, negative duration, etc. |

The two impls take different paths:

- `PassthroughLinkService::apply` inherits the default `NotSupportedByTransport`
  for every option — local-scope faces don't run the LP pipeline, so
  none of the LP-bound options apply.
- `LpLinkService::apply` (`link_service/mod.rs:344-365`) routes the three
  LP-flag-bit variants and the two CoDel-param variants to typed handles on
  the matching features; everything else errors `NotSupportedByTransport`.

The typed handles live alongside the trait-erased Vec in `LpLinkService`,
so `apply` flips the feature directly without a `dyn`-cast or name lookup.

## The reliability state machine

`ReliabilityFeature` wraps the synchronous `LpReliability` state machine
from `crates/spec/ndn-transport/src/reliability.rs`. The state machine
implements NDNLPv2 per-hop reliability with four RTO strategies:

- **`RtoStrategy::Rfc6298`** — EWMA with Karn's algorithm; conservative
  default for unknown links.
- **`RtoStrategy::Quic`** — RFC 9002; lower initial RTO (333 ms vs 1 s),
  tighter granularity — better for short flows.
- **`RtoStrategy::MinRtt { margin_us }`** — minimum observed RTT plus a
  configurable margin; aggressive, best for stable low-jitter links.
- **`RtoStrategy::Fixed { rto_us }`** — constant RTO, no adaptation;
  ideal for local Unix / Shm faces where RTT is known and stable.

This is **richer** than NFD's single fixed-RTO scheme
(`lp-reliability.cpp:73-83`) and the design choice was deliberate — see
design doc Q2.

The Tier-3 feature wraps the state machine behind hooks:

```rust
impl LinkServiceFeature for ReliabilityFeature {
    fn on_egress(&self, frame: &mut OutboundLpFrame, _ctx: &EgressCtx) {
        if !self.is_enabled() || !frame.is_lp_wrapped { return; }
        self.state.lock().unwrap().on_send_track(&frame.wire);
    }
    fn on_ingress(&self, frame: &InboundLpFrame, _ctx: &IngressCtx) {
        if !self.is_enabled() { return; }
        self.state.lock().unwrap().on_receive(&frame.wire);
    }
}
```

`on_send_track` is a side-effect-only tracking variant — the composer has
already LP-wrapped the frame by the time the feature runs, so we record
the wire verbatim rather than re-encoding through `on_send`. Documented as
a known non-canonical retx path until the composer routes through the
state machine directly; the engine's per-face tick loop that pumps
`take_retransmissions` onto `FaceState.send_tx` is the follow-up.

Counters surfaced on `faces/list`:

- `n_lp_resent_packets` — retransmissions emitted by `take_retransmissions`.
- `rto_micros` — current RTO from the wrapped state machine's estimator.

## The CoDel marking state machine

`CongestionMarkingFeature` reads the egress queue depth via an
engine-injected closure (`queue_depth_fn`), runs a CoDel-style above-threshold
timer, and splices an LP `CongestionMark` TLV (0x0340) into the wire when
the timer has elapsed:

```rust
fn should_mark_now(&self, depth: u64, now: Instant) -> bool {
    if depth < self.def_cong_threshold { /* reset timer */ return false; }
    match self.above_threshold_since.lock().unwrap() {
        None       => { /* start timer */ false }
        Some(t0) if now - t0 >= self.base_cong_interval => {
            /* reset timer to now */ true
        }
        Some(_) => false,
    }
}
```

- Below threshold → no mark, clear timer.
- First sample above threshold → start timer; do **not** mark this frame
  (NFD CoDel waits one interval before the first mark).
- Above threshold for one full `base_cong_interval` → mark next frame;
  reset timer to "now" (we mark again only after another full interval).

The two CoDel parameters live on the feature:

- `base_cong_interval` — minimum spacing between successive marks
  (NFD-default `100 ms`).
- `def_cong_threshold` — queue depth at or above which the above-threshold
  timer starts (NFD-default `64 KiB`, reinterpreted in queue items when
  the depth closure returns item counts).

Source: `crates/spec/ndn-transport/src/link_service/features/congestion_marking.rs`.

## The lifecycle of an option flip

Operator runs `ndn-ctl face update 259 --flags 0x2 --mask 0x2` to turn on
`LpReliability`. The full chain:

1. `ndn-ctl` builds an Interest at `/localhost/nfd/faces/update` with
   `ControlParameters{ face_id: 259, flags: Some(2), mask: Some(2) }`.
2. The router's mgmt dispatcher decodes the Interest, runs auth, and calls
   `faces_update(params, source_face, engine)`.
3. The handler decomposes `flags`+`mask` into one
   `FaceOption::LpReliability(true)` and calls
   `target.link_service.apply(opt)`.
4. `LpLinkService::apply` routes to `self.reliability_feature.set_enabled(true)`.
5. The next outbound LP frame on this face hits
   `ReliabilityFeature::on_egress`, which sees the feature enabled and
   tracks the wire bytes for retransmission.
6. The handler returns `(ControlResponse::ok, vec![])` — no `MtuChanged`
   or `OptionRefused` event because nothing failed and no MTU changed.
7. The dispatch wrapper publishes any events from the vec onto
   `/localhost/nfd/faces/notifications`.

On failure — say the same command against a Shm face — step 4 returns
`Err(NotSupportedByTransport { option: "lp-reliability" })`. The handler
emits `FaceEvent::OptionRefused { face_id, option: "flags:lp-reliability",
reason: "transport-not-eligible" }` and returns
`ControlResponse::error(503, "field=flags:lp-reliability reason=transport-not-eligible")`.
The dispatch wrapper publishes the event so subscribers see the refusal
in real time.

## Cross-references

- `crates/spec/ndn-transport/src/link_service/` — the trait, the composer,
  the eight features.
- `crates/spec/ndn-transport/src/reliability.rs` — the state machine.
- `crates/spec/ndn-mgmt/src/modules/faces.rs` — the management surface
  consuming `apply`, `snapshot`, and the feature counters.
- `docs/notes/face-system-design-2026-05-20.md` — the design doc that
  drove this work (every decision recorded with rationale).
- `docs/notes/ndn-rs-tlv-allocations-2026-05-20.md` — TLV codes for every
  extension TLV on the wire.

## What's deferred

Per the design doc Tier 4 / 5 boundary, four follow-ups remain:

- The engine tick loop that pumps `ReliabilityFeature::take_retransmissions`
  onto `FaceState.send_tx`. Tier 3 ships the feature + counter; the per-face
  tick task is the wiring follow-up.
- `EngineBuilder` injecting `set_queue_depth_fn` from each face's send_tx
  capacity into the matching `CongestionMarkingFeature`. The closure
  defaults to "depth = 0" until then; production wiring lands next.
- `--detailed`, `--scheme`, `--remote`, `--local`, `--watch` filter flags on
  `ndn-ctl face list`. Tier 4 ships the renderer for the rich shape; the
  CLI flags are queued.
- Phase-3 OTel sampler. Tier 4 ships the `face_otel_overhead.sh` scaffold
  and the OFF baseline Criterion bench; Phase-3 populates the "feature ON"
  datapoint.
