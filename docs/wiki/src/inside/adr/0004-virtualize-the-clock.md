# 0004 · Virtualize the clock behind a runtime seam for determinism

**Status:** Accepted

## Context

A forwarder is full of time: PIT entries expire, nonces age out of the
dead-nonce list, strategies retry after delays, faces time out, sync suppresses
on jittered timers. When every one of these reads the system clock directly,
the engine's behaviour is non-deterministic — tests that exercise timeouts are
flaky, and a multi-node simulation cannot be replayed. "Sleep and hope"
appears in the tests, and CI pays for it in both wall-clock and trust.

## Decision

Route **every** engine time read through a single seam: the `Now` trait in
`ndn-runtime`, which distinguishes monotonic `now()` (deadlines, expiry) from
wall-clock `unix_nanos()` (timestamps on the wire). The native `TokioRuntime`
reads the real clock; a virtual runtime overrides `now()` to return logical
time driven by an `AtomicU64`, so a test or simulator can advance time
explicitly and deterministically.

The forwarding path threads a packet's **arrival timestamp** (`ctx.arrival`)
instead of re-reading the clock at each stage, so all of a packet's
time-derived decisions are anchored to one consistent instant. Background tasks
take an injected `now`.

## Consequences

- **Positive:** timeout-dependent behaviour is testable without sleeping — the
  test advances logical time and asserts. This is why the full suite runs in
  ~25 seconds.
- **Positive:** `ndn-sim` runs the *real* `ForwarderEngine` against a virtual
  clock, so a simulated multi-node run is deterministic and replayable — the
  simulator is not a separate mock of the forwarder.
- **Positive:** on wasm32 the same seam swaps in a `web-time` clock, so the
  engine builds and runs in the browser.
- **Cost:** contributors must resist reaching for `SystemTime::now()` /
  `Instant::now()` directly in engine code; the correct source is
  `runtime.now()` or `ctx.arrival`. Direct clock reads in the forwarding path
  are a review red flag.

## Alternatives considered

- **Mock the clock only in tests** (e.g. inject a fake in test builds).
  Rejected: it leaves production code reading the real clock, so the *engine*
  isn't deterministic — only the test harness is — and the simulator can't
  reuse it.
- **A global test clock.** Rejected: global mutable time breaks parallel test
  execution, which is exactly what nextest relies on for speed.

## Status note

The seam is in place across the forwarding path, background tasks, the
Nack-path out-records, and the discovery clock. A small number of
`FaceState`-timestamp reads in the engine were the last direct clock reads and
are being routed through the seam; see the polish work in the A+ series.
