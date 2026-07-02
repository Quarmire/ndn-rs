# 0006 · The radio foundation boundary

**Status:** Accepted

## Context

The named-data radio work spans many crates: `ndn-frame-io` (the L2 frame I/O
substrate), `ndn-signals-core` (the cross-layer signal plane), a userspace
Wi-Fi driver that implements four USB chipsets, a Wi-Fi Aware (NAN) stack, a
cognitive rate/power planner, a discrete-event radio simulator, and — coming —
a trusted-time protocol and non-RF bearers (IR, optical/VLC). Without a written
boundary, each leaf crate has to guess what belongs in the shared substrate
versus its own code, and the substrate's closed types (the `FrameFormat` enum)
become a per-consumer bolt-on point (`Raw80211` was the second such addition).

The codebase already made the core commitment — `ndn-frame-io`'s own header
says "backend-agnostic link-layer frame I/O; device-specific drivers live with
their face crate and implement `FrameIo` against this surface" — but the
principle wasn't stated as a boundary contract. This ADR makes it one.

## Decision

**Hardware specificity lives in exactly two places: backend implementations
below a trait, and honest numbers advertised through capability descriptors.
Everything above consumes the numbers, never the hardware.**

Concretely, the boundary is:

| The foundation (`ndn-frame-io`, `ndn-signals-core`) owns | Leaf crates own |
|---|---|
| The `FrameIo` device trait (async inject/recv) | The backend `impl FrameIo` per device (chipset registers, USB rings, RXWI parse) |
| radiotap parse + TX-header build | Chipset-specific init, TXAGC/EDCCA calibration |
| The `FrameFormat` set + the `Raw80211` passthrough escape hatch | Frame *internals* above the substrate (e.g. NAN management-frame bodies) |
| The single-stream 20 MHz MCS→rate table (`mcs_for_rssi`, `mcs_phy_rate_bps`) | Calibrated/MIMO/wide-channel rate models, *if ever needed*, as their own thing |
| The signal taxonomy (`SignalView`/`SignalStore`, `LinkSignals`, units) | Concrete signal sources (GNSS, RTC, sensors) pushing into a `SignalStore` |
| `CapturedFrame`'s optional-hint shape (addr, group, rssi, mcs, …) | Interpretation of those hints for a specific protocol |

Two rules make the boundary hold:

1. **Extend by escape hatch, not by enum growth.** A new medium or
   management-frame protocol uses `Raw80211` (substrate prepends radiotap and
   injects the frame verbatim; the consumer owns the whole frame) rather than
   adding a `FrameFormat` variant. New variants are reserved for genuinely new
   *body framing* the substrate must build/parse itself.
2. **Capabilities are advertised numbers, not feature flags.** A backend that
   can stamp receive time to ±100 ns, or transmit with bounded delay, says so
   through a descriptor with an honest number; generic logic upstream (rate
   selection, and — see below — time combining) reads the number and adapts.
   This is how "dynamically adaptive to capabilities" is realized without the
   protocol ever naming a chipset feature like TSFT or EDCCA-ignore.

## Consequences

- **Positive:** the Wi-Fi work is the *first implementation* of each seam, not a
  load-bearing assumption. ndn-sim already proves this — it consumes the rate
  table and drives `FrameIo` on the determinism seam without forking the
  substrate; the four chipset drivers each implement one trait.
- **Positive:** leaf authors have a decision rule ("own your frame internals
  above `Raw80211`; advertise your hardware's numbers; don't touch the core
  enum"), so the substrate stops accreting per-consumer variants.
- **Positive:** it de-risks the incoming trusted-time and non-RF-bearer work.
  A per-frame **timing observation belongs on `CapturedFrame` as one more
  optional hint** — a stamp carrying its value, an explicit *clock-domain id*
  (a TSF counter, a PHC, `CLOCK_MONOTONIC`, and a PIO cycle counter are
  different timelines — a stamp without a domain is a bug generator), a latch
  point, and an honest precision. That follows the exact `Option<hint>` pattern
  `rssi_dbm`/`mcs_index` already use. The *protocol* logic (time combining,
  false-ticker rejection, ranging) then lives in a bearer-agnostic crate that
  consumes stamps by precision, not by medium.
- **Cost:** the capability-descriptor discipline requires shaping each new trait
  against **at least three genuinely different backends** before it is frozen
  (e.g. hardware TSF stamp, software fallback stamp, PIO cycle stamp) — a trait
  shaped around one backend is that backend's API in a costume.
- **Cost:** the escape hatch can be over-used. `Raw80211` is correct when the
  consumer owns the whole frame; it is a smell if a consumer uses it to avoid
  contributing framing the substrate *should* own for reuse.

## Alternatives considered

- **A `FrameFormat` variant per medium/protocol.** Rejected: it makes the core
  enum a shared mutable bottleneck every consumer must PR into, and couples the
  substrate's release cadence to every leaf protocol.
- **A lowest-common-denominator frame API with no capability descriptors.**
  Rejected: it would erase exactly the hardware advantages (hardware timestamps,
  bounded-delay TX, CSI) that the radio work exists to exploit. The point is to
  *surface* capability, honestly, not to hide it.
