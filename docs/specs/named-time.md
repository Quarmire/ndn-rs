> **STATUS: HISTORICAL / SUPERSEDED (banner added 2026-08-21).** This design doc
> predates the implementation. The crates it proposes now exist: `ndn-time`
> (ndn-rs/crates/core), plus `ndn-time-sources`/`ndn-timekeeper`/`ndn-time-driver`
> (ndn-ext/crates/time). The crate boundary is recorded in ADR 0007
> (docs/wiki/src/inside/adr/0007-named-time-crate-boundary.md), which is the
> authoritative record. Rescued from the workspace root during the 2026-08-21
> state audit; kept for design rationale only.

# Named-time — a trusted time protocol for `ndn-rs` — *design / extension*

> **Non-standard extension.** Nothing here is an NDN community spec. It is the
> time-synchronization counterpart to `named-radio`: a subsystem that carries
> *trusted, uncertainty-bounded time* over the same faces, the same security
> model, and the same cognitive control pattern as the rest of the stack.
> Proposed crates: `ndn-time` (`[scope] = "spec"`, pure/`no_std` core) and
> `ndn-time-sources` (`[scope] = "extension"`, concrete backends) — mirroring the
> `ndn-signals-core` / `ndn-signal-sources` split.

> **Revision note (post-design-session).** This replaces an earlier draft. Three
> things changed materially: (1) the design is now **bearer-agnostic** — the
> Wi-Fi-specific mechanisms are the *first implementations* of a small set of
> traits (§4), not the architecture; (2) the security section is split into what
> the model actually *gives* (§9) and a real **threat model** naming the three
> still-open problems (§10) — because "signed" does **not** mean "true," and the
> earlier draft over-claimed that it did; (3) precision figures are stated as
> **targets pending the on-air measurement (G1)**, never as results.

This closes the line on the named-radio status board — *"Time-sync +
coordination-announcement (FHSS prerequisites): designed, not built"* — and fills
the frontier sketch that wanted *"sync rides traffic + a CCLF-elected
`/localhop/time/anchor`."*

---

## 1. The problem, and the gripe

Existing time protocols treat the network as host-centric and time as a side
service you reach out to: NTP/PTP point a client at a *server address* and trust
whatever comes back from it. Two consequences:

1. **You phone an IP NTP server even when a better clock is next to you.** A node
   with a GPS fix one hop away is invisible to `ntpd` unless someone statically
   configured it as a peer. The addressing model can't see "the best clock in
   radio range."
2. **Security is bolted on.** NTP's NTS and PTP's Annex P are late, optional, and
   orthogonal to how the rest of the system trusts anything. Time is treated
   casually — an unauthenticated reply steers your clock — right up until it is
   critical (a cert expiry, a replay window, a TSCH slot boundary, a forensic
   timestamp), at which point the casual treatment is the vulnerability.

NDN solves the first problem for *data*: you ask for a **name**, not an address,
and the nearest copy answers. It solves *part* of the second: nothing is consumed
unless it is signed and passes a trust schema. **Named-time is the observation
that time is just data**, so the naming solution applies directly and the
security solution applies *as far as it goes* — which, as §9–§10 make precise, is
further than NTP but not as far as the slogan "apply the security model to time"
implies on its own. Signing defeats forgery; it does nothing about delay, replay,
or relay, and those are exactly the attacks that move a clock.

A clock reading becomes a named, signed Data packet. Consuming it runs the
existing `Validator`, yields a `SafeData`, and is therefore — by the type system,
at compile time — impossible to act on unvalidated. The "nearest good clock
answers" behaviour falls out of NDN forwarding plus a self-election. That is the
foundation; the adversary model (§10) is what turns it into *trusted* time.

---

## 2. Core principles (the load-bearing decisions)

**(P1) Time is named, signed Data; consuming it yields `SafeData` — necessary,
not sufficient.** A time claim is published under a name and signed; the consumer
validates it against an LVS trust schema pinning *which keys may speak for time in
which namespace*. The `SafeData` newtype means unvalidated time can never reach
the discipline loop. This buys authenticity and integrity — the packet is from who
it says and was not altered. It does **not** buy truth of the *measurement*: an
authentic signed sample can still have been delayed, replayed, or relayed. P1 is
the floor the rest of the security design stands on, not the whole building (§10).

**(P2) Uncertainty is first-class. A reading is an interval, never a point.**
Every value travels as `(wall_estimate, ±uncertainty)` — NTP root-dispersion
promoted to a required field. "I don't know the time well enough" is
representable, which is what makes the system safe under degradation *and* under
attack: a node with huge uncertainty is *correctly* distrusted rather than
silently wrong. Consumers read the interval and decide whether it is tight enough.

**(P3) Monotonic time and wall-clock time are different, and the monotonic clock
carries security load.** `ndn-signals-core` already splits a monotonic
`updated_ms` (staleness, ordering — cannot regress) from `NodeSignals.clock_ms`
(wall-clock estimate, `0 = unknown`). Named-time formalises it and — this is new
relative to the earlier draft — makes the monotonic floor do *adversarial* work:

- **Monotonic** is trusted unconditionally, needs no network, and underwrites
  ordering/replay/skew/election **and** a floor of enforcement (§10) that must
  hold even when the wall-clock plane is jammed into high uncertainty.
- **Wall-clock** is a *belief with uncertainty*, established progressively, and
  may be unknown at boot.

**(P4) Agreement ≠ traceability.** A GPS-less swarm does not need UTC; it needs to
*agree*. Named-time can deliver a self-consistent **ensemble** timescale — µs-
coherent internally, not UTC-traceable — and, separately, a traceable scale when a
reference is present. The two are distinguished on the wire so nobody mistakes
"we all agree" for "this is UTC."

**(P5) Capabilities are heterogeneous and self-describing.** A GPS-disciplined
OCXO, a phone RTC, an ESP32 RC oscillator, and a WAN NTP uplink are wildly
different clocks, described by a `ClockCapability` (§5) the way `RadioCapability`
describes radios and `LinkProfile` gives each face a prior. Capability is
learnable data, not static config.

**(P6) Verification is a type — and that extends to the adversary, not just the
noise.** `SafeData` already encodes "validated" as a type rather than a
convention. Named-time carries the same discipline into *measurements*: a sample
is a typed, provenance-carrying value that states not only how noisy it is
(`±`) but how exposed it is to an active adversary (distance-bounded? replay-
protected? from an authenticated domain peer?). The combiner then *cannot* treat
an unbounded, unauthenticated, replayable measurement as equal to a bounded,
authenticated, fresh one — the type forbids it, exactly as `SafeData` forbids
unvalidated data reaching forwarding. This is the "fifth cut" of §4 and the
mechanism that makes the threat model (§10) expressible in code rather than prose.

---

## 3. Why the monitor-mode Wi-Fi work matters (directly — as the first backend)

Time-transfer accuracy is bounded by **how precisely you can timestamp a packet**
and **how known/symmetric the path delay is**. The monitor-mode face is strong on
the first for three reasons — and it is the *first implementation* of the
bearer-agnostic seams in §4, not a special case the protocol knows about.

**(a) Hardware RX timestamps via radiotap TSFT.** A captured 802.11 frame's
radiotap header carries the **TSFT** — the 64-bit MAC Timing Synchronization
Function counter, ~1 µs resolution, latched *in the NIC* at reception. That is a
hardware timestamp of the class that makes hardware-PTP NICs accurate, on ~$60
commodity dongles. It removes the dominant software error (host scheduler, USB/IRQ
latency, network stack) because the stamp precedes all of it. *Caveat, corrected
from the earlier draft:* the latch-to-antenna offset is **not constant** across
MCS and bandwidth, so it must be modelled as a function of the PHY parameters, and
where a frame's configuration falls outside what has been calibrated the face must
**widen its reported precision** rather than emit a confident-but-wrong stamp
(§4, §17). This is the precision wireless tier *if the on-air number (G1) bears it
out* — a target, not a result.

**(b) Connectionless broadcast is the ideal distribution topology.** The face is
`LinkType::AdHoc`: one injected frame is heard by *every* monitor receiver at
once — the one-to-many shape time distribution wants — and it enables
**common-view** (§7): N receivers hearing the *same* event cancel the
transmitter's clock error out of their inter-receiver offset, synchronising to
each other through a beacon none of them trusts as a clock. Note carefully what
this does and does not remove: it removes the *transmitter's* clock error and the
*common* path; it does **not** remove a wormhole/relay attacker who re-radiates the
event to a distant receiver (§10, T1). "No on-path relay to delay" was an
over-claim in the earlier draft.

**(c) Per-frame rate control already lives there.** The cognitive plane picks MCS
per frame; a beacon rides a fixed-rate, FEC-protected slot (`with_fixed_mcs` /
`with_link_fec`) so airtime — and thus modelled delay — is computable. And the
userspace driver (`LibUsbRtl88xxBackend` / `Mt7612uBackend`) gives determinism the
kernel can't: `set_edcca_ignore` suppresses CSMA backoff variance on owned
spectrum, single-MPDU injection makes airtime exact, and owning the RXWI parse
puts the stamp immediately off bulk-IN. These are *how this backend earns the
numbers it advertises* (§4); the protocol never names them.

---

## 4. The bearer-agnostic substrate — four cuts, plus a fifth

The Wi-Fi mechanisms above are one backend. The protocol is defined against a
small set of traits so that IR/optical, UWB, wired, BLE, LoRa, and future radios
are *implementations*, not rewrites. The governing rule: **hardware specificity
lives in exactly two places — backend implementations below the trait, and honest
numbers advertised through descriptors.** The generic core reads the numbers and
adapts; it never speaks TSFT or EDCCA. `precision_ns` (and now provenance) is the
universal currency. This matches a commitment the codebase already made — 
`ndn-frame-io`'s `FrameIo` is backend-agnostic across four chipsets, its rate
table is a shared source of truth, and `CapturedFrame` is already an
optional-hints struct — so most of these cuts are *in-pattern additions*, not new
machinery.

**Cut 1 — `LinkStamp` (nearly free; the A2 item, generalised).** `CapturedFrame`
gains one optional field:

```rust
pub struct LinkStamp {
    pub raw: u64,               // counter value as latched
    pub domain: ClockDomainId,  // WHICH counter — the single most load-bearing field
    pub precision_ns: u32,      // honest ± of this stamp
    pub latch: LatchPoint,      // PhyPreamble | MacDone | HostRecv — where in the pipe
}
// CapturedFrame { …, pub stamp: Option<LinkStamp> }
```

Filled by TSFT on monitor-wifi (`MacDone`, ~1 µs), `SO_TIMESTAMPING` on
Ethernet/`AfPacketBackend`, the RXWI on the RTL backend, an on-chip counter on
ESP32, cycle-deterministic PIO stamps on an optical face (ns-class — *better* than
TSFT), and a plain software stamp with honestly fat `precision_ns` on BLE. **Clock
domains must be explicit**: a TSF counter, a PHC, `CLOCK_MONOTONIC`, and a PIO
cycle counter are different timelines, and a stamp without a `domain` is a
bug generator. `ndn-time` owns `ClockDomainId` and the cross-domain mapping
(offset+rate per domain pair, learned from paired samples) — which is Linux PHC/PTP
practice generalised, and reuses the discipline loop's skew estimator (§8).

**Cut 2 — `TxDiscipline` (capability, not register).** What the protocol needs from
the transmit path is a *promise*, not a chipset feature:

```rust
pub enum TxDiscipline {
    BestEffort,                            // kernel wifi; congested anything
    PromptBounded { max_delay_ns: u64 },   // EDCCA-ignore delivers this on owned spectrum
    ScheduledAt   { granularity_ns: u64 }, // PIO optical; future hardware scheduled-TX
}
```

Beacon slots, the URLLC lane, and TSCH-by-name *ask for* a discipline and read its
number; EDCCA-ignore is merely how the monitor-wifi backend delivers
`PromptBounded`. When scheduled-TX hardware appears, nothing above the trait
changes.

**Cut 3 — `ChannelObs` (positioning, bearer-agnostic).** The estimator never sees a
CSI matrix. It sees typed observations, each with a source and an uncertainty:

```rust
pub enum ChannelObs {
    Range   { m: f64, sigma_m: f64 },
    Bearing { az: f64, el: f64, sigma_rad: f64 },
    Doppler { hz: f64, sigma_hz: f64 },
}
```

Wi-Fi CSI yields range (forgiving) and bearing (fragile — per-antenna phase
calibration drifts with temperature; this is why 802.11az took years, so `sigma`
on bearing must reflect that); UWB yields range directly (~10 cm); a camera
watching modulated LEDs yields bearing directly (cm-class angle); M1 timestamps
yield coarse range. The coupled estimator (§14) consumes `ChannelObs` +
`TimeSample` and is thereby agnostic — the literal realisation of "layer
capabilities as needed."

**Cut 4 — `EventId` (makes common-view generic).** M3's only real requirement is
"these receivers heard the *same* physical event." Tag stamps with an `EventId`
(frame digest + channel + coarse time window) and common-view runs over any
broadcast medium: an optical cone, a LoRa chirp, an ambient AP beacon via SDR. The
Wi-Fi frame becomes one instance of a stampable shared event.

**Cut 5 — `MeasurementProvenance` (P6; the security cut).** The four cuts carry
`precision_ns` — *how noisy*. None carries *how trustworthy against an active
adversary*. A measurement is therefore a typed value that also states its exposure:

```rust
pub struct Measured<T> {
    pub value: T,
    pub sigma: f64,                 // noise
    pub prov:  MeasurementProvenance // adversary exposure — a small lattice, not a score
}

pub struct MeasurementProvenance {
    pub distance_bounded: bool,   // is there a PHY upper bound on physical distance? (T1)
    pub replay_protected: bool,   // fresh nonce/seq bound to this exchange? (T3)
    pub authenticity: Authenticity // Unauthenticated | AuthenticatedDomainPeer(KeyId)
}
```

These are **not independent booleans to OR into a score** — their *failure modes
differ*, so the combiner reasons over a small lattice: an authenticated-but-not-
distance-bounded measurement is exposed to a compromised/relayed domain peer that
an unauthenticated-but-distance-bounded one is not, and vice-versa. The combiner
must know *which* threat each measurement is exposed to, not count green
checkmarks. This slots into the ADR-0006 principle (descriptors carry honest
numbers) by adding an honest *adversary* number beside the honest *noise* number,
and it is what earns the phrase "apply the security model to time."

**Discipline: the rule of three.** Shape each trait against at least three real
implementations before freezing it — TSFT (µs, hardware, `MacDone`), a software
stamp (fat, `HostRecv`), and PIO optical (ns, deterministic, `ScheduledAt`) —
because a trait shaped around one backend is that backend's API in a costume. The
PIO optical face is worth building early partly *for this reason*: it is the
maximally-different second implementation that keeps the abstraction honest.

---

## 5. The capability model — disparate clocks, self-describing

Mirrors `RadioCapability`. Pure, `no_std`, `Copy`-friendly.

```rust
pub enum TimeSourceKind {
    Gnss, Ptp, Ntp, Rtc, Oscillator, PeerDerived, Manual,
}
pub enum Traceability { Utc, Tai, Gnss, Ensemble /* internally-agreed only */, None }

pub struct Holdover {                 // frequency stability → uncertainty growth rate
    pub drift_ppm: f32,
    pub allan_dev_1s: f32,
    pub aging_ppm_per_day: f32,
    pub temp_sensitive: bool,
}

pub struct ClockCapability {
    pub kind: TimeSourceKind,
    pub traceable: Traceability,
    pub holdover: Holdover,
    pub base_uncertainty_ns: u64, // intrinsic ± at the source (GNSS ~tens of ns; WAN NTP ~ms)
    pub disciplinable: bool,      // can the loop steer it? (GNSS: no; OS clock: yes)
    pub reference_only: bool,     // pure source that never consumes peer time (stratum-0-like)
}
```

Presets follow the `RadioCapability::wifi_monitor_5ghz(...)` idiom
(`::gnss_disciplined()`, `::oscillator_tcxo()`, `::esp32_rc()`, `::ntp_uplink()`).
A node may hold several at once, and a peer's capability *rides its signed beacon*,
so the swarm learns "that node has GPS + an OCXO" the way the radio plane learns a
neighbour's reach class.

---

## 6. Faces and timestamp precision — priors, then measured truth

`FaceTimeProfile` is the per-face prior (sibling of `LinkProfile`), giving a fresh
path a sane uncertainty before any sample, refined once `LinkStamp`s flow. The
important reframe from the earlier draft: **the profile is derived from the face's
advertised `LinkStamp` capability, not a hand-maintained table of magic numbers**,
and every figure below is a *prior to be replaced by measurement*, not a claim.

| Face (backend) | Stamp source | latch | prior precision | notes |
|---|---|---|---|---|
| monitor-wifi (TSFT) | radiotap TSFT | `MacDone` | ~1 µs (widen if uncalibrated) | offset a *function* of MCS/BW |
| Ethernet / `AfPacket` | `SO_TIMESTAMPING` | `HostRecv`/hw | ~1 µs–ms | symmetric, stable delay |
| optical (PIO) | PIO cycle counter | `ScheduledAt` | ns-class | LOS, no multipath |
| Wi-Fi Aware / Direct | software | `HostRecv` | tens of µs | |
| BLE advertising | software | `HostRecv` | ~ms | coarse; honest fat `precision_ns` |

The generic core weights each sample by its combined interval (source ⊕ face
precision ⊕ asymmetry ⊕ holdover·age) *and* its provenance (Cut 5). A GPS sample
over BLE is limited by BLE's coarse stamp; the same sample over TSFT is far
tighter — the weighting is recomputed continuously from live residuals, which is
the "dynamically adaptive to capabilities" requirement.

---

## 7. Measurement — three modes, chosen per face

All three reuse existing transport and now ride the `LinkStamp`/`EventId` cuts, so
they are bearer-agnostic.

**(M1) Two-way exchange.** PTP-style `t1…t4` → offset `((t2−t1)−(t4−t3))/2`, RTT
`(t4−t1)−(t3−t2)`. Measured RTT bounds the claimed uncertainty (self-consistency,
§9). Hardware stamps slot into `t2`/`t3`. Produces a coarse `ChannelObs::Range`
for free.

**(M2) One-way broadcast with reciprocity prior.** Producer stamps `tx`; each
receiver records its `LinkStamp`. Offset `= rx − tx − modelled_oneway_delay`;
uncertainty includes the asymmetry term since the reverse path is unmeasured.

**(M3) Common-view.** Receivers hearing the same `EventId` subtract stamps:
`offset_AB = rx_A − rx_B − (prop_A − prop_B)`. Cancels the transmitter's clock
error and the common path. The event may be a beacon, an ordinary frame, or an
ambient emission via SDR. **Security note:** common-view resists a *malicious
transmitter* (its error cancels) but not a *relay* that re-radiates the event to
one receiver (T1). Provenance must record `distance_bounded: false` for
common-view unless a PHY distance bound is actually present.

The loop ingests all modes across all faces simultaneously, each weighted by
interval and provenance.

---

## 8. The anchor election — the best local clock self-selects

Reuses the CCLF kernel (`cclf_elect`) verbatim, swapping content-connectivity for
clock quality. Weight `q` is monotone in traceability rank and `1/uncertainty`,
penalised by stratum; timer `t = T·uncertainty` (jittered) so the *tightest* clock
beacons `/<scope>/time/anchor` first and worse clocks overhear-and-cancel;
density suppression thins dense neighbourhoods. A local GPS out-elects a WAN NTP
uplink by construction. **Failover is the same mechanism as election** — a clock
that loses GPS widens its uncertainty, lengthens its timer, and yields to the
next-best. (Election is a *liveness/efficiency* mechanism; it is not by itself a
defence against a Sybil flood of candidates — that is the authority gate's job,
§10 T2.)

---

## 9. The discipline loop, and what the security model *gives*

**SENSE → DECIDE → ACT**, pure and sans-IO like `MediumState`/`RadioPolicy`.

- **SENSE — `TimeState`**: validated `TimeSample`s (now `Measured<_>`, carrying
  provenance) on one bus, EWMA-smoothed per peer. *See §14 for why the EWMA
  windows are a latent bug at swarm velocity.*
- **DECIDE — `TimePolicy::discipline`**: combine intervals and emit a
  `Correction`. Marzullo intersection discards outliers; regression over
  `captured_mono_ns` estimates offset **and** frequency skew. **Marzullo is a
  *robustness* mechanism, not an *admission* mechanism** — it rejects a *minority*
  of disagreeing sources; it does nothing against a fabricated *majority* (§10 T2).
  Security admission happens upstream, at the authority gate.
- **ACT — `Discipline`**: slew (never step monotonic consumers back), write
  `NodeSignals.clock_ms`, re-beacon own `(wall, ±u, provenance)`. "Re-emit if it
  tightens a downstream peer's interval." Capability-gated: track an
  un-steerable GPS, steer the OS clock.

**What the model gives (and this part is sound):**

1. **Authenticity/integrity via `SafeData`.** Beacons validate through `Validator`
   + LVS → `SafeData`; the loop accepts only `SafeData`. "An *unauthenticated*
   reply steered my clock" is unreachable. This is inherited, not bolted on.
2. **Replay rejection.** `ReplayGuard` keys on `(sig_nonce, sig_time,
   sig_seq_num)` with a sticky monotonic floor that works *before* wall-clock
   sync exists (it uses ordering, not a global clock).
3. **Self-consistency.** A source claiming 1 µs while its RTT jitters 40 ms is
   downweighted to its *measured* dispersion — you cannot merely *assert* a tight
   clock.

**What the model does *not* give** — and this is the correction to the earlier
draft — is *truth of the measurement*. A signed, replay-guarded, self-consistent
sample can still have been **delayed** or **relayed**, and a signed beacon can be
one of thousands minted by a single **Sybil**. Those are §10.

---

## 10. Threat model — the adversary spec

"Apply the security model to time" is a real claim only if it names the attacks
signing does not stop, states what the design grants the adversary, and discharges
what it can. This section is the adversary spec: assumptions first, then the three
problems (T1 relay/delay, T2 Sybil, T3 bootstrap), then how the provenance lattice
(§4 Cut 5) composes them and where the monotonic floor carries load on its own.

### 10.0 Adversary capabilities and trust assumptions

The medium is the pessimistic case the rest of the design already embraced: a
shared, connectionless, association-free broadcast channel that anyone can inject
on. We grant the adversary the following, and design so that trusted time survives
them where it can and *fails loud* where it cannot.

| Granted to the adversary | Denied to the adversary |
|---|---|
| Inject, capture, and **replay** arbitrary frames on the raw medium | **Forge a signature** without the corresponding private key |
| **Delay** frames (jam-then-resend) and add **asymmetric** path delay | Make a validated node's **monotonic clock run backward** |
| **Relay / wormhole**: re-radiate a genuine event to a distant receiver | Violate the **speed of light** (a true PHY distance *upper* bound, if one exists, binds them) |
| Mint an **unbounded number of identities** and unsigned/self-signed beacons | Sign as an **authorised time authority** without that authority's key |
| **Jam** to keep a node's ±u high, or **eclipse** a node entirely | Extract keys from an **uncompromised** node's TPM/secure element |
| **Compromise/capture** a node and obtain *its* keys | Retain authority **after grant expiry** (given §T2's expiry-by-default) |

Trust anchors we *do* assume: a valid LVS trust root reachable through the chain
(the same anchor the rest of `ndn-rs` relies on); the local monotonic clock as a
non-regressing ordering source (P3); and a **liveness assumption** — that *some*
honest, authorised time source is periodically reachable with bounded ±u. Where
the liveness assumption fails (sustained jam/eclipse), the safe outcome is
denial-of-service, never silent acceptance of bad time; T3 makes that precise.

The unifying principle: **signing decides *who* and *whether-altered*; it never
decides *where the emitter physically was* or *when the photons actually
arrived*.** T1–T3 are the three ways that gap is exploited.

### T1 — Delay / replay-with-delay / relay (wormhole)

*The headline gap; genuinely open on commodity radios.* The adversary takes an
authentic, correctly-signed measurement and **moves it in space or time**: adds
asymmetric propagation delay to skew a two-way offset, or re-radiates an event to a
distant receiver to induce a wrong range and a wrong clock. Every signature
verifies; `ReplayGuard` may not even fire, because in a wormhole the frame is
*genuinely fresh*, merely delivered by a path physics did not intend.

The missing primitive is **distance-bounding** — a cryptographic PHY round-trip
that proves an *upper bound* on physical distance, so a relayed event can be
rejected for arriving "too late for how close it claims to be." On commodity Wi-Fi
this is arguably infeasible at the precision that matters: the responder's
processing-time jitter (tens of ns to µs) swamps the light-travel term (≈3.3 ns/m)
you are trying to bound, so the bound is loose enough to drive a wormhole through.
Dedicated PHYs help — UWB's sub-ns timing is why it is the ranging bearer of
choice — but assuming distance-bounding on the Wi-Fi path is exactly the wrong idea
this document exists to prevent.

*Partial mitigations, none a solution:*
- **Common-view / broadcast** (M3) removes the *transmitter's* error and the
  *common* path — but **not** a relay that re-radiates to one receiver. M3 samples
  therefore carry `distance_bounded: false`.
- **Disjoint-path cross-check.** Delaying a Wi-Fi *and* a wired *and* a LoRa path
  symmetrically and consistently is hard; disagreement beyond the union of
  intervals is treated as tampering that **widens ±u**, never as a point to trust.
  This is a *detection/degradation* defence, not prevention.
- **RTT-vs-claimed-±u self-consistency** caps how much delay an attacker can inject
  while keeping a sample internally plausible.

*In the type system:* these measurements are `distance_bounded: false`, and the
combiner (§10.4) must never let such measurements *alone* establish a high-stakes
fix — they can tighten a fix that an independent bounded/diverse measurement has
already anchored, but they cannot found one. **Status: OPEN. Build so that the
absence of distance-bounding is represented and respected, not papered over.**

### T2 — Sybil

*Cheap on exactly the medium we embraced; reduces to key custody.* On a
raw-injection, association-free medium, one attacker mints an arbitrary **majority**
of well-formed beacons for free. Marzullo-over-a-fabricated-majority merely
launders the attacker's chosen value — which is why §9 is emphatic that **Marzullo
is robustness, not admission**. Robustness assumes a *bounded fraction* of bad
inputs; Sybil removes that bound. Admission must therefore happen *upstream* of the
combiner, and there is exactly one mechanism that does it: the **LVS time-authority
schema** — only keys authorised for `/<scope>/time/*` are admitted as authorities,
so a thousand unsigned or self-signed beacons are a thousand rejects, not a
majority.

This is the right answer, and it **relocates the whole security of time onto key
custody + revocation**. That is not a weakness of the design; it is the design
telling the truth about where the hard problem lives — and it lands on the
field-onboarding and offline-revocation questions raised earlier in the session,
which stop being far-field and become the load-bearing dependency:

- **Zero-touch proximate enrolment.** A fresh node joins the trust domain over a
  physically-scoped channel — the bare IR-LED/photodiode PHY (§18), BLE, or QR —
  where an attacker cannot inject without being *in the beam / in the room*. IR's
  containment makes "attests physical presence" a real property, then authority is
  handed to the RF plane.
- **Expiry-by-default over revocation-by-fetch.** A captured node cannot be reached
  to revoke, and no CRL server is reachable in the field. So authority is granted
  as **short-lived, auto-renewing** capabilities: a compromised key stops being an
  authority when its grant lapses, with no revocation message required. Renewal
  requires continued good standing, which *is* reachable (the node is present); the
  attacker's captured key is not renewed.

*In the type system:* an admitted sample is
`authenticity: AuthenticatedDomainPeer(KeyId)`; everything else is
`Unauthenticated` and can influence *nothing* security-relevant. **Status:
mechanism known (the authority gate). Its hard part — proximate onboarding and
offline expiry — is a distinct workstream this design depends on but does not
solve here.**

### T3 — Bootstrap ordering, and its denial-of-trust corollary

*The one dischargeable now — and here it is discharged.* Cert validity windows need
trusted time; trusted time needs authenticated peers; authentication needs valid
certs. The escape is the soft→hard uncertainty ratchet:

1. *Boot (epoch unknown).* The monotonic clock is trusted for ordering. Cert
   **chains** validate **hard** — signatures need no clock, so forgery is blocked
   from the first instant (this is where T2's authority gate does clock-free work).
   Only the validity-**window** check runs **soft**, against a coarse floor (build
   time / persisted last-known-good / RTC) plus monotonic-since-boot.
2. *As authorised, bounded samples arrive*, ±u shrinks; window enforcement promotes
   to **hard** once ±u is below the action's threshold.
3. *On promotion*, anything soft-passed that would now hard-fail is re-evaluated and
   flagged; the flag is monotonic-clock-anchored and sticky.

**(a) Which direction soft-mode fails — chosen and justified: fail-closed.** "Soft"
does **not** mean "leniently accept a cert whose window can't be checked." It means
**"cannot vouch for the window, therefore cannot authorise a high-stakes action
that depends on it."** Soft mode *withholds*; it never *grants*. The consequence is
the safe inversion of the reviewer's denial-of-trust concern: an adversary who
keeps ±u high (jam, or Sybil-with-fat-±u) pins nodes in soft mode — but pinned-soft
means **"refuses high-stakes actions,"** i.e. denial-of-*service*, never
"accepts what it should reject." Denial-of-trust is thereby *converted into*
denial-of-service by construction, and DoS on a broadcast medium is already loud
and visible (±u is huge and published). The one thing soft mode must permit is
bootstrapping the *time plane itself* — validating the beacons that will tighten
±u — and that is safe precisely because those beacons are chain-hard (T2) and
cross-checked by Marzullo before any of them is allowed to move the clock.

**(b) Termination — the argument, not a hope.** Model a node's enforcement state as
`(E, granted)` where `E ≥ E_min > 0` is current wall-clock uncertainty and
`granted` is the append-only set of authorisations made hard (each stamped in
monotonic time). Four facts give a monotone path from "no time, no trust" to
"bounded time, enforced trust" with no deadlock and no cycle:

- **Progress.** Under the liveness assumption (§10.0), an authorised sample with
  bounded ±u is periodically admitted; Marzullo intersection is *narrowing* (the
  combined interval is a subset of prior ∩ new), so absent holdover growth `E`
  strictly decreases toward `E_min`, crossing any fixed threshold `θ` in finite
  time → promotion to hard occurs.
- **No permissive cycle.** `granted` is append-only in monotonic time and its
  entries are sticky; `E` may later *regrow* (holdover, eclipse) and re-enter soft
  *for future decisions*, but re-entering soft only ever **withholds** new
  authority — it cannot retroactively un-flag a past rejection or grant anything.
  So the *granted-trust* order has no cycle; only the *capability-to-enforce*
  oscillates, and that oscillation is monotone-safe (withhold-only).
- **No silent deadlock.** The sole way to be stuck is pinned-soft, which is
  fail-closed DoS (loud, visible), not silent bad-accept.
- **No forgery shortcut.** Chain validation is hard throughout, so the ratchet
  never opens a window an attacker can climb through with a forged or unauthorised
  cert; the soft region is strictly the *window* check on *already-chain-valid*
  certs.

Together: the system either reaches hard enforcement (liveness holds) or sits in
loud, safe DoS (liveness denied), and never transits into accepting what it should
reject. That is the ratchet, discharged. **Status: dischargeable now — the
fail-closed direction and this termination argument are the deliverable, and they
are here.**

### 10.4 How the provenance lattice composes (Cut 5, operationalised)

The combiner does not sum green checkmarks. Each admitted `Measured<_>` carries a
`MeasurementProvenance`, and measurements are ordered only *within* a threat class:
authenticity is a total order (`AuthenticatedDomainPeer > Unauthenticated`);
`distance_bounded` and `replay_protected` are per-threat flags. The combine rule
for an action of a given stakes class is:

- Compute the **meet** (worst case) of provenance over the measurements that
  *jointly* establish the fix; it must clear the floor that action requires (e.g.
  "authorise a TSCH transmit slot" requires `AuthenticatedDomainPeer` and either
  `distance_bounded` **or** ≥2 measurements over **T1-disjoint** paths).
- **Threat-diversity, not count.** Two `distance_bounded: false` samples over the
  *same* relay add *no* T1 robustness — they share the exposure. Robustness against
  a threat requires inputs that are *independent with respect to that threat*
  (disjoint faces/paths for T1; distinct authorised keys for T2). The combiner
  tracks exposure classes and requires diversity across the class that matters for
  the action, exactly so that an attacker who controls one exposure class cannot
  manufacture apparent agreement.

This is what makes §4's fifth cut load-bearing rather than decorative: the type
carries the exposure, and the combiner's admission logic is written against the
lattice, so "an unbounded, unauthenticated, replayable measurement counts as much
as a bounded, authenticated, fresh one" is not a reachable code path.

### 10.5 The monotonic floor as independent security

P3's split is not just a bootstrap convenience; under attack it is a *second,
clock-independent* line the adversary cannot pin. Ordering, replay rejection, and
sticky flags all ride the monotonic clock, which the adversary is *denied* the
ability to reverse. So even a node held in soft-validity forever by a jammer
retains: correct event ordering, replay protection, hard chain validation, and
every authorisation already granted. Pinning the wall-clock plane degrades a node
to "cannot gain *new* high-stakes trust"; it cannot strip trust already
established, cannot reorder history, and cannot forge admission. The wall-clock
plane is the attackable surface; the monotonic plane is the floor beneath it that
must — and by this construction does — carry real security load alone.

**Eclipse** (a node cut off from all good clocks) is then just the liveness-denied
case of T3: ±u grows along the holdover curve, the node reports "I no longer know,"
high-stakes consumers refuse, and everything on the monotonic floor keeps working.
Fail loud, not silent.

---

## 11. Tiered policy — targets, one mechanism

`TimePolicy` sets the *required* ±u and cadence; the single election + loop realise
whatever tier the topology supports. **Every figure below is a target contingent
on the on-air measurement (G1), not a result.**

| Tier | Topology | Target ±u (pending G1) | Mechanism |
|---|---|---|---|
| **L0** | all peers in radio/wire range | tens of µs – sub-ms | TSFT common-view + wired two-way; best local clock anchors; no WAN |
| **L1** | local, only BLE/sw-ts faces | ms | M2 broadcast; coarser, no WAN |
| **L2** | some peers over WAN | tens of ms | WAN uplink enters the election as a *low-quality* candidate; local GPS still wins |
| **L3** | local, no external reference | µs *relative*, non-UTC | ensemble "paper clock" (P4) |

L2 is not a mode you switch into — the WAN server is a candidate the election ranks
below any decent local clock. Deadline class ties into `NameContext.priority`;
`Urgent` raises the required-±u bar, met by cadence + face choice.

---

## 12. Transport, and experimental waters (flagged honestly)

**Carriage** (no new wire crate): **SVS** for the group beacon set (the "thin
SVS-synced delta rendezvous"), **pub/sub** for anchor fan-out, **standing
Interests** for the real-time push. **Name shape:** `/<scope>/time/<node>/<seq>`;
`/<scope>/time/anchor/<seq>`; `localhop`-scoped by default. `name_group_mac` gives
a pre-decode hint (verify-on-decode stays authoritative).

- **Opportunistic ambient common-view** ⚑ — SDR-stamp an un-owned periodic
  emission (AP beacon at TBTT, broadcast pilot) as an `EventId`. Needs SDR;
  identifiability of a good reference is open. Carries `distance_bounded: false`.
- **Ensemble "paper clock"** ⚑ — weighted-median/Kalman ensemble of members'
  oscillators; "more stable than the best member" needs weighting tuned to real
  Allan data.
- **ToF ranging from M1 stamps** ⚑ — `d ≈ c·rtt/2` minus turnaround, emitted as
  `ChannelObs::Range` into §14. Commodity ToF is noisy; a cross-check, not a
  survey instrument — and **not** distance-bounding (T1): honest ToF is not an
  adversarial *upper* bound.
- **Mutual reinforcement with TSCH-by-name** — sync enables slots; slot boundaries
  are themselves a recurring sync event. `freq = HopSeq[(ASN + H(prefix)) mod nCh]`
  consumes the disciplined ASN.

---

## 13. The same substrate carries more than time

`LinkStamp` + `TxDiscipline` + `MeasurementProvenance` are not time-only; the
session established that several subsystems are the *same* measurement-and-
actuation substrate seen from other angles. Sketched here as pointers; each is its
own doc.

- **LP echo / link OAM** — a `LinkServiceFeature` piggybacking a `LinkStamp`-ed
  probe TLV on outgoing frames (the `TraceContext`/`CongestionMark` splice
  pattern), PIT-free, below the network layer. *Shares packets with M1/M2/M3* —
  one feature, two readings — and one broadcast emission + reception reports gives
  a neighbourhood RTT/loss map, not N pairwise pings.
- **QoS becomes physical and per-name** — `NameContext.priority` → cognitive plane
  → PHY (rate/FEC/power/`TxDiscipline`), with the class **schema-gated by name**
  so it can't be grabbed. Same trust-binding as the time-authority gate.
- **URLLC lane** — a latency *class*, not a second stack: one-emission-two-classes
  (systematic-first FEC), standing-Interest push, drop-if-late, and a *measured
  SLA refuse* path (the fail-loud ethos applied to latency). Bounded-jitter
  soft-real-time on commodity wifi until `ScheduledAt` hardware + async URBs land.
- **Positioning** — `ChannelObs` from CSI/UWB/optical fused in §14.

---

## 14. The moving reference frame — foundational, not far-field

Filing this under "far-field" earlier was a prioritisation error: for the drone
domain it is foundational, and there is a concrete latent bug. The EWMA staleness
windows in the sense bus are tuned for a quasi-static medium; **at swarm relative
velocities they lag the truth**, smoothing over exactly the dynamics the estimator
must track (Doppler on the carrier, neighbour-set churn within seconds, a
continuously changing common-view propagation-difference term). Two consequences
for the design:

- Sync, ranging, and kinematics should fuse into **one** estimator: range gives
  geometry, geometry tightens the sync path-delay term, range-rate gives velocity,
  velocity predicts the next neighbour set. The coupled time-and-shape solution is
  what yields GPS-denied *relative* positioning.
- That estimator (§4 Cut 3's consumer) is a genuine **nonlinear estimator with
  observability concerns**, not a one-liner: whether the relative-position-and-
  clock state is observable depends on geometry and motion — a stationary or
  collinear formation can leave it unobservable regardless of measurement quality.
  This is a named design risk. Range is more forgiving than bearing here too;
  bearing/AoA to decimeter is a lab-conditions result (per-antenna phase
  calibration drifts with temperature), so `ChannelObs::Bearing.sigma` must be
  honest and the estimator must not lean on bearing it can't trust.

---

## 15. Crate layout & integration points

- **`ndn-time`** (`ndn-rs`, `[scope]=spec`, `no_std`): `TimeSample`/`Measured<_>`,
  `ClockCapability`, `Holdover`, `Traceability`, `ClockDomainId` + cross-domain
  mapping, `MeasurementProvenance`, `TimeState`, `TimePolicy`, the Marzullo
  combiner, holdover/uncertainty math, the soft→hard ratchet state machine. Pure,
  conformance-pinned.
- **`ndn-time-sources`** (`ndn-ext`, `[scope]=extension`): GNSS (NMEA/PPS), OS
  clock, RTC, NTP/PTP shim, and the `PeerDerived` source.
- **`ndn-frame-io`**: `LinkStamp` / `ClockDomainId` / `LatchPoint` land here
  (Cut 1), implemented monitor-wifi-first; `EventId` (Cut 4) tags captures.
- **`ndn-transport`**: `TxDiscipline` (Cut 2) on the face; `FaceTimeProfile` becomes
  trait-derived, not a static table.
- **No new wire crate.** Beacons are signed Data on `ndn-sync` / pub-sub; the LVS
  schema lives in `ndn-security`'s trust context.

Touch points that already exist: `NodeSignals.clock_ms` (ACT output); `ndn-frame-io`
radiotap RX (TSFT → `LinkStamp`); `MonitorWifiFace` (fixed-rate FEC slot,
`PromptBounded` via EDCCA-ignore); `ndn-strategy-cclf` `cclf_elect` (anchor
election); `ndn-security` `Validator`/LVS/`ReplayGuard`/`iso8601` (gate, authority
schema, replay, soft→hard ratchet); `ndn-sync` (carriage);
`ndn-radio-cognition` (sibling sense bus; consumes disciplined ASN).

---

## 16. Status — reuse (built) vs new vs open

| Piece | Status |
|---|---|
| `SafeData` validation gate; LVS authority schema; `ReplayGuard`; `iso8601` | **built** (`ndn-security`) — reuse / author schema |
| `clock_ms` slot + local/wire telemetry boundary; EWMA anti-oscillation | **built** (`ndn-signals-core`, `ndn-radio-cognition`) — reuse |
| CCLF election kernel; SVS carriage | **built** (`ndn-strategy-cclf`, `ndn-sync`) — reuse |
| Monitor face + radiotap RX + per-frame rate + userspace-driver determinism | **built** (`ndn-face-monitor-wifi`, `ndn-frame-io`) — reuse |
| `LinkStamp`/`ClockDomainId`/`LatchPoint` (Cut 1), TSFT-first | **new** — nearly free, in-pattern |
| `TxDiscipline` (Cut 2), `ChannelObs` (Cut 3), `EventId` (Cut 4) | **new** — trait seams |
| `MeasurementProvenance` (Cut 5) + provenance-aware combiner | **new** — the security cut; shape it early |
| `ndn-time` taxonomy + Marzullo + skew + holdover math | **new** — pure, unit-testable (no hardware) |
| Soft→hard ratchet **with a written termination argument** | **new** — pure + `Validator` hook; T3 obligation |
| Anchor-election adapter (CCLF, time quality) | **new (thin)** |
| `ndn-time-sources` backends | **new** — I/O layer |
| M1/M2 measurement | **new** — PTP-modelled; sim-testable |
| **M3 common-view over `EventId`** | **new — strongest novel piece; needs on-air validation (G1)** |
| TSFT latch-offset **as a function of MCS/BW** (was: "constant") | **new — corrected** — widen `precision_ns` when uncalibrated |
| Coupled time+range+kinematics estimator (§14) | **new — nonlinear, observability concerns** — not a one-liner |
| **Distance-bounding (T1)** | **OPEN — research; likely infeasible at precision on commodity Wi-Fi** |
| **Sybil-resistant onboarding + offline revocation (T2)** | **OPEN — reduces to key custody; own workstream** |
| Ambient common-view (SDR); ensemble paper-clock; ToF cross-check | **frontier** ⚑ |

**The spine to a first result:** (i) `LinkStamp` on monitor-wifi; (ii) the pure
`ndn-time` core (combiner + holdover + ratchet-with-proof), unit-testable with a
`SimStampSource` (injectable jitter/drift/asymmetry) exactly as `measure.rs`
tests the radio loop; (iii) the CCLF election adapter; (iv) **G1 — the on-air M3
number**: "are we tighter than NTP-over-WAN with peers in the room?" Everything
load-bearing is a pure module over existing seams; the *engineering* risk is
concentrated in G1, and the *security* risk in T1–T3, which are stated openly here
so they are designed for, not discovered later.

---

## 17. The honest status line

Trusted time is not "signed time." It is **signatures + distance-bounding + a
Sybil-resistant authority gate + a proven-terminating bootstrap ordering** — and
of those four, signatures are built, the authority gate is known but reduces to an
onboarding/revocation workstream (T2), the bootstrap ordering is dischargeable now
if we write the termination argument and the soft-mode failure direction (T3), and
distance-bounding on commodity radios is genuinely open and possibly infeasible
(T1). Writing it this way is what stops the one wrong idea — *signed equals
trusted* — from propagating into the implementation.

---

## 18. Naming

`named-time` (sibling of `named-radio`, `named-data`); crates `ndn-time` /
`ndn-time-sources`. Wire object: **time beacon**. Internal scale: **ensemble**.
Elected node: **anchor**. "Trusted" is not a mode — it is the default and only
path, because the only time that reaches the loop is `SafeData` *and* the combiner
weights every sample by the adversary exposure its provenance declares.

> On the two renamed items from the session, to avoid confusion downstream: the
> proximate optical trust channel is a **bare IR-LED/photodiode PHY**, *not* the
> defunct **IrDA** SIR/FIR stack (the containment / OOB-pairing analysis stands;
> the name does not). And on an RP2040 (133 MHz M0+, no FPU), **OOK/PAM is the
> floor and DCO-OFDM the aspirational ceiling** — lead with the former.
