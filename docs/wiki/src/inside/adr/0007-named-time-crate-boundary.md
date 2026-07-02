# 0007 · The named-time crate boundary

**Status:** Accepted

## Context

Named-time is a non-standard ndn-rs extension: a subsystem that carries
*trusted, uncertainty-bounded time* over the same faces, security model, and
cognitive control pattern as the rest of the stack (the design lives in the
`named-time` document). Building it raised four boundary questions that a
future contributor would otherwise have to reverse-engineer from the code.

## Decision

**1. The pure core is a `no_std` crate; concrete sources are a separate
extension.** `ndn-time` (`[scope] = spec`, `no_std`, no-alloc) holds the
taxonomy and the math: `TimeInterval`, `ClockCapability`/`Holdover`,
`Measured`/`MeasurementProvenance`, `LinkStamp`/`ClockDomainId`/`LatchPoint`,
the Marzullo combiner, and the soft→hard ratchet. `ndn-time-sources`
(`[scope] = extension`, in ndn-ext) will hold the I/O backends (GNSS/RTC/NTP
shims, the peer-derived source). This mirrors the existing
`ndn-signals-core` / `ndn-signal-sources` split, and it means the entire
protocol core is unit-testable with a simulated clock and runs on a
microcontroller.

**2. The stamp types live in `ndn-time`, not `ndn-frame-io`.** The design sketch
was in tension here — it said "`ndn-time` owns `ClockDomainId`" *and* "the stamp
types land in `ndn-frame-io`." The resolution follows from the layers:
`ndn-time` must be `no_std`, but `ndn-frame-io` is `std`+tokio (raw sockets,
async `FrameIo`). The only valid dependency direction is therefore
`ndn-frame-io → ndn-time`. So `LinkStamp`/`ClockDomainId`/`LatchPoint` are
defined in `ndn-time`, and when Cut 1 lands, `ndn-frame-io` gains a dependency
on `ndn-time` and `CapturedFrame` gets an `Option<LinkStamp>` field — the stamp
*type* here, the *field* there. Both crates are `spec`, so the dependency
respects the dep-direction guard.

**3. Provenance is a type, not a convention (principle P6).** A measurement is a
`Measured<T>` carrying both its noise (`sigma_ns`) and its adversary exposure
(`MeasurementProvenance`: distance-bounded? replay-protected? authenticated?).
This is the named-time analogue of `SafeData` (ADR 0002): just as unvalidated
data cannot reach forwarding, an unbounded/unauthenticated/replayable
measurement cannot be treated by the combiner as equal to a
bounded/authenticated/fresh one. Admission (`provenance::admits`) reasons over
the exposure as a lattice with **threat-diversity** (distinct keys for Sybil,
distinct paths or a real distance bound for relay), never a checkmark count.

**4. Marzullo is robustness; the trust schema is admission.** The combiner
rejects a *minority* of false tickers but is defeated by a fabricated majority,
so it must never be the security boundary. Admission — which keys may speak for
time — happens upstream in the LVS trust schema (`ndn-security`); the combiner
assumes its inputs are already admitted. The crate documents and *tests* this
boundary (a test asserts a fabricated majority wins Marzullo, precisely so the
property can't be silently regressed into a false sense of safety).

## Consequences

- **Positive:** the whole time core is pure, `no_std`, no-alloc, and hardware-
  free — 38 tests including property tests, and it compiles for riscv32
  `no_std`. The security-critical logic (provenance lattice, ratchet
  fail-closed/append-only) is unit-testable without a radio.
- **Positive:** the boundary with the radio foundation (ADR 0006) is clean:
  `LinkStamp` is one more `CapturedFrame` optional hint, and it carries an
  explicit clock domain so cross-domain stamps are never silently subtracted.
- **Cost:** Cut 1 (`CapturedFrame.stamp`) is a *breaking* change to a
  cross-repo type — the sibling repos that construct `CapturedFrame`
  (monitor-wifi's `FrameIo` impls, ndn-sim) must be updated in lockstep, and
  `cargo-semver-checks` + `build_all.sh` will flag it. It is therefore a
  separate, deliberately-sequenced step, not folded into the core crate.
- **Cost:** `ndn-frame-io` depending on `ndn-time` reads slightly
  "backwards" (a low-level L2 crate depending on a time crate). It is
  acceptable because `ndn-time` is a tiny `no_std` primitives-and-math crate
  with no I/O, consumed by `ndn-frame-io` only for the stamp *vocabulary*.

## Alternatives considered

- **Put the stamp types in `ndn-frame-io`.** Rejected: it would force `ndn-time`
  to depend on a `std`+tokio crate, breaking its `no_std` guarantee and its
  embedded target — the opposite of the layering the stack is built on.
- **Fold provenance into `sigma` as a single "quality" scalar.** Rejected: it
  collapses distinct threat exposures (relay vs Sybil vs replay) whose failure
  modes differ, which is exactly the mistake ("signed = trusted") the threat
  model exists to prevent.
- **One `ndn-time` crate that also does the I/O.** Rejected: it would drag
  `std`/async into the pure core and make the combiner and ratchet un-testable
  on a microcontroller, against the sans-IO seed-crate pattern (ADR 0003).
