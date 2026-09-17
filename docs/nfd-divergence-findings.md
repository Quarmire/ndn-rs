# ndn-rs vs NFD/ndn-cxx — divergences found on a live Wi-Fi fleet

Field findings from running `ndn-fwd` as the production forwarder for a
3-airframe UAS fleet (miniMUAS), against `nfd` on the same hardware, same
radios, same application stack. Every item below was measured, not reasoned
about; each names the NFD source it diverges from.

Context: the two stacks are runtime-switchable per node, so NFD is always
available as a control on the same RF conditions minutes apart. That control
is what made these findings falsifiable.

## Fixed

### 1. `ReliabilityConfig::wifi()` was dead code
`LpLinkService::new()` — the default for every network face — handed out
`ReliabilityConfig::default()` with `max_retries: 1`. The tuned `wifi()`
profile (retries 3, unacked 512, retx/tick 16) was referenced only from a
unit test. NFD's LpReliability defaults to 3 retries.

On a link that fragments every multi-KB packet into six, giving up after ONE
retransmission lets a single unlucky fragment kill its whole group.

Measured on the GCS's face to the video source:
`complete=73.7%` → **`99.0%`**, `fragments-wasted` 256/1192 (21% of fragment
airtime) → 152/18580 (0.8%). Video 2.8 → 6.5 fps.

Note the loss model that misled us first: predicting from INDEPENDENT
per-fragment loss said one retry should already give ~1.5% group failure
against the 26% observed, so the retry count "couldn't" be the cause. Wi-Fi
loss is bursty/correlated, so extra retries recover far more than an
independent model predicts. When a loss model is off by >10x, doubt the
independence assumption before the mechanism.

### 2. The retransmit/Ack tick was reset by egress activity
The per-face send loop recreated its timer every iteration:

```rust
loop {
    let retx_sleep = runtime.sleep(retx_tick_dur);  // new timer each pass
    tokio::select! {
        biased;                                      // egress polled first
        item = ... => { send }                       // wins whenever queued
        _ = retx_sleep, if ... => { acks + retransmissions }
    }
}
```

Any packet restarted the timer, so the tick fired only during an idle gap >=
the interval — starved exactly when the link was busy, i.e. when recovery
matters. NFD has no such coupling: its LpReliability timers (idle-ack,
per-packet RTO) are scheduled independently of egress.

Diagnostic that proved it: busy faces read `rto=1000000µs`, the INITIAL
value, never updated — no RTT samples were being taken at all. After the fix
every face reads `rto=200000µs`, the RFC6298 floor, i.e. the estimator now
runs and is merely clamped.

Fix: hold an absolute deadline, advanced only when the tick fires. Also
explains why shortening the interval 50ms -> 10ms did nothing: a timer that
resets on every packet still never fires when packets arrive every ~10 ms.

### 3. Acks were emitted on the tick, not on receipt
A deferred Ack puts a floor under the PEER's RTT sample and therefore under
its RTO, so the peer's RTO can never track a 1-2 ms mesh. The two are also a
trap for each other: lowering the RTO below the tick (Quic's ~4.5 ms against
a 10 ms pump) lets the sender retransmit BEFORE an Ack is physically
possible. On the fleet that surfaced as NDNSF service calls timing out
wholesale — video ZERO, not merely slow — and had to be reverted.

`LpLinkService::recv` now Acks on receipt. `take_acks` drains all pending
Acks into one frame, so a burst of fragments costs one Ack frame.

### 4. No link-layer duplicate-frame suppression
NFD `LpReliability::processIncomingPacket` (`daemon/face/lp-reliability.cpp`)
queues the Ack, checks `m_recentRecvSeqs` for a duplicate, and returns
`!isDuplicate`; `GenericLinkService::decodeFragment` returns early on false —
so a retransmitted frame never reaches reassembly or forwarding. The window
is aged by the estimated RTO.

ndn-rs `on_receive` extracted Acks but tracked no received frames, so the
duplicate travelled up the pipeline.

### 5. No point-to-point same-face duplicate-nonce exemption
NFD `Forwarder::onIncomingInterest` masks off `DUPLICATE_NONCE_IN_SAME` when
`linkType == POINT_TO_POINT`: a duplicate nonce from the SAME face is a
RETRANSMISSION, not a loop, and reaches the strategy — which is the entire
reason `RetxSuppressionExponential::decidePerUpstream` exists.

ndn-rs treated every duplicate nonce as a loop:
```rust
if entry.nonces_seen.contains(&nonce) {
    entry.forward_cancelled = true;
    return CheckResult::Loop;
}
```

**4 and 5 compound, and that is the finding.** Either alone is benign.
Together, every LP retransmission of an Interest reached the PIT, was
misclassified as a forwarding loop, was dropped, AND set
`forward_cancelled = true` — tearing down a pending scheduled forward for an
Interest still outstanding. Every fleet face is point-to-point and the video
face measured `resent=140` per 180 s, so this fired ~0.8x/s on the video
path. Result after fixing: fragment completion 99.1% -> **100.0%** over 3560
groups, `timed-out` 16 -> **0**, `resent` 140 -> 25-52.

### 6. `ReassemblyBuffer::purge_expired` was never called on a timer
Its only call site was inside `process`, on the branch taken when a face's
table is FULL (`MAX_PENDING_PACKETS` = 1024). So the 5 s timeout was
effectively inert, and `timed_out` / `fragments_wasted` read ZERO however
many groups were being abandoned — the counters were actively misleading.
Now swept on `DEFAULT_REASSEMBLY_TIMEOUT`.

## Observability added

`faces/list` (TLV 0xE3..0xE9) and `ndn-ctl face list` now report:
- `reassembly:` fragments-in / completed / timed-out / fragments-wasted /
  rejected / evicted-groups / **complete=NN.N%**
- `reliability:` rto / resent / **gave-up** (retries exhausted) /
  **evicted** (dropped from the retransmit buffer by the max_unacked cap)

Multi-fragment delivery is all-or-nothing, so its completion rate is the
number that matters on a lossy link, and it is invisible in the byte and
packet counters. Diagnosing items 1-5 required external AF_PACKET capture
purely because the forwarder reported nothing about it.

## Latent, not currently biting

### Data-path validation has no NFD counterpart
NFD `Forwarder::onIncomingData` is synchronous and straight through: tag ->
/localhost scope -> PIT match -> CS insert -> strategy sends downstream. **No
signature verification anywhere.**

ndn-rs `data_pipeline` awaits `validation.process()` and `try_self_learn()`
before `cs_insert`. On `ValidationResult::Pending` the validation stage spawns
a cert fetch, PARKS the Data in a pending queue and returns `Drop` — a
stall-and-burst generator on the forwarding hot path.

Inert on this fleet only because the config sets `[security] profile =
"disabled"`. Anyone arming the validator on a lossy link should expect this
to dominate their latency profile.

### Stage order is inverted relative to NFD
NFD inserts into the PIT FIRST and consults the CS only
`if (!pitEntry->hasInRecords())` — an aggregated Interest never touches the
CS. ndn-rs runs `cs_lookup` -> `pit_check` -> `strategy`, so every Interest,
including every parked prefetch and every retransmission, does a full awaited
CS lookup.

### RFC6298's floor is wrong for a local mesh
`Rfc6298` uses a 100 ms granularity and a 200 ms RTO floor — WAN-TCP numbers.
This mesh runs ~1-2 ms RTT, so the RTO pins at the floor (`rto=200000µs` read
straight off a live face: the clamp binding, not an estimate). Because a
predictive stream delivers in cursor order, every recovery
head-of-line-blocks the frames behind it for that whole window.

`Quic` (1 ms granularity/floor) computes ~5-10 ms on the same link. It is
deferred, not rejected: it needs the converging RTT estimator that items 2-3
provide, and must be demonstrated on hardware before the profile switches.
See `rfc6298_pins_at_its_floor_on_a_mesh_rtt_where_quic_tracks_the_link`.

## Method notes

- **Always keep the C++ stack as a same-window control.** RF conditions drift;
  a number without a control taken minutes apart is not evidence.
- **Never conclude from one window taken right after a service restart.** Two
  findings in this session were briefly mis-called because of this — once
  declaring a working fix broken, once declaring a broken fix working.
- **Pick a counter only the suspected mechanism can move.** "Does `rto` leave
  its initial value" settled item 2 in one reading; aggregate throughput would
  not have.

## Round 2 — systematic sweep of the async seams

The six items above were all in the link-service / reliability / reassembly
timing layer. That is not a coincidence: it is the part of the stack with **no
NFD design to copy**, because NFD is single-threaded and event-loop driven
while this is tokio. The well-known protocol constants are all correct
(InterestLifetime default 4 s, DeadNonceList 6 s, HopLimit decrement + drop at
0, /localhost ingress scope, CS serve/admit gates, MustBeFresh, CanBePrefix,
ImplicitSha256Digest verification against cached wire bytes). So this sweep
targeted the seams instead.

### Clean: the timer-reset class does not recur
Finding 2 (a `select!` timer recreated each iteration, reset by a competing
work branch) was checked against every `loop { … select! { … sleep … } }` in
the workspace. The other four — validation `drain_pending`, the discovery
tick, PIT expiry, RIB expiry — each have only `cancel` + `sleep` branches,
with no work branch to reset the timer. The bug was unique to the per-face
send loop. No further instances.

### Fixed: inbound pipeline drops were uncounted
`out_drops` existed; there was no `in_drops`. When the forwarding pipeline's
channel filled, `run_face_reader` discarded the packet behind a `debug!` and
nothing else, so the loss was indistinguishable from radio loss at every
level above it. NFD has no analogue because it forwards inline with no
inbound queue — the queue is ours, so the accounting has to be too. Added
`FaceCounters::in_drops`.

### NOT A FINDING — PIT keyed by a 64-bit name hash (corrected)

An earlier revision of this document listed the hash-keyed PIT as an open
divergence. That framing was wrong on both counts and is retracted here.

**It is documented design, not an oversight.** `docs/wiki/.../forwarding-pipeline.md`
lists the PIT key as "`PitToken` (name-hash + discriminator)"; the `PitToken`
doc comment sets out precisely what is excluded from the key (ForwardingHint,
selectors) and why, mirroring NFD's keying by name rather than hint; and the
DeadNonceList likewise keys on `(name_hash, nonce)` fingerprints. Hashed
identity keys are a consistent, witnessed choice across the tables, bought for
a `DashMap<u64, _>` on the forwarding hot path instead of a nametree walk.

**The consequence was overstated.** The claim was that a collision hands a
consumer "the wrong object under the right name". It cannot: Data carries its
own name, and the receiving application matches it against its pending
Interest (`Interest::matchesData` in ndn-cxx). A collision therefore
misdelivers a correctly-named Data to a face that did not ask for it, and the
app drops it as unsolicited. The narrower real risk is that `should_reap`
removes the shared entry and takes the colliding Interest's in-records with
it, turning that Interest into a timeout rather than a satisfied fetch.

**Probability**: ~N/2^64 per insert; ~5e-12/s at 10^4 entries. A targeted
second-preimage is 2^64. Not reachable by accident or by an attacker.

Left as designed. Recorded here only so the next reader does not re-derive
the same false alarm.

## Round 3 — guided by the audit ledger

`testbed/EXPECTED_FAILURES.md` is frozen with **zero open rows**, and its
coverage (A/B/C/D/E/F/G/N/X series, each with a witness) is genuinely broad.
Worth noting what that implies: every defect found in this session — the dead
`wifi()` profile, the egress-reset timer, tick-bound Acks, missing duplicate
suppression, `purge_expired` never on a timer — is a **runtime/wiring**
defect, not a spec-conformance one. A conformance matrix cannot catch them,
which is why they survived an otherwise rigorous audit. Hunt the seams, not
the spec.

### Checked clean this round
- `CongestionMarkingFeature` defaults to disabled; NFD's
  `allowCongestionMarking` also defaults to **false**. Match, not a gap.
- `set_base_cong_interval` is reachable in production via the `faces/update`
  `FaceOption` path (not test-only).
- Protocol constants re-confirmed: InterestLifetime 4 s, DNL 6 s, HopLimit
  decrement + drop-at-0, `/localhost` ingress scope, CS serve/admit,
  MustBeFresh, CanBePrefix, ImplicitSha256Digest verified against cached wire.

### OPEN — no retransmission suppression in any strategy
NFD gates every upstream through `RetxSuppressionExponential`
(`daemon/fw/retx-suppression-exponential.hpp`, default 10 ms initial, x2,
250 ms max) in BOTH `best-route` and `multicast`:

```cpp
auto suppressResult = m_retxSuppression->decidePerUpstream(*pitEntry, outFace);
if (suppressResult == RetxSuppressionResult::SUPPRESS) { continue; }
```

ndn-rs has no equivalent. `MulticastStrategy` is stateless
(`struct MulticastStrategy { name }`) and `decide` returns every nexthop
excluding the in-face, unconditionally. `best_route` prefers an untried
upstream but explicitly falls back to re-sending ("a retransmission should
still be re-sent") with no time gate.

**The state needed is already there**: `OutRecord` carries `sent_at: u64`.
What is missing is the gate — and a way for a strategy to see it, since
`StrategyContext` currently exposes `tried_faces` but no send timestamps.

**Disclosure — this gap is now more reachable because of a fix in this
session.** Before the point-to-point same-face nonce exemption (round 1,
item 5), a retransmitted Interest was dropped at the PIT as a loop and never
reached the strategy at all. It now does. NFD pairs that exemption with
suppression; ndn-rs currently has the exemption without it, so on a shared
medium each consumer retransmission fans out to every nexthop with no
backoff — the same airtime-amplification shape chased earlier in this
session.

Not biting on the fleet today (post-fix: `resent` 140 -> 25-52, 100%
fragment completion, ~10 fps), because the retransmission rate is low. It
would bite during a lossy burst or with a more aggressive consumer.

Left unimplemented deliberately: a faithful port needs per-(entry, upstream)
backoff state and a `StrategyContext` addition, i.e. a strategy-API change
that wants hardware validation rather than an append to a long session.

## Retx suppression: implemented, reverted from the fleet, NOT validated

`RetxSuppressionExponential` is ported (ndn-rs `a1021b7b`, NoRoute fix
`0156f643`) and unit-tested, but it is **reverted on the fleet** and should
not be redeployed without bench work. Two attempts, two problems:

**Attempt 1 — outage (my bug).** The suppressed-upstream filter fed the
strategy's existing `faces.is_empty()` branch, which meant "the FIB has no
usable nexthop" and answers `Nack(NoRoute)`. So a moment when every upstream
sat inside its 10 ms window told the consumer the name was unreachable.
Video ZERO, telemetry gapping on all three airframes, immediately. Fixed by
separating the two emptiness checks; `nacks=0` on every peer face confirms it
on hardware. Guard: `all_upstreams_suppressed_sends_nothing_not_noroute`.
*Changing what feeds a condition changes what the condition means.*

**Attempt 2 — reverted on a MIS-ATTRIBUTION (corrected).** With the NoRoute
fix in place: video 7.9-8.0 fps (baseline range), `nacks=0` on every peer
face, iuas-01 and wuas-01 telemetry clean — but iuas-02 at 2.59-2.67/s with
5 gaps>2 s in both runs. I attributed that to suppression and reverted.

**That attribution was wrong — and so were my next two.** Corrected in full:

1. I blamed suppression. After the revert the same gapping appeared on a
   DIFFERENT node (wuas-01 2.57/s, 6 gaps) while iuas-02 recovered, so it did
   not follow the change.
2. I then called it stack-specific, on a same-window A/B: NFD clean on all
   three, ndn-fwd gapping. But the ndn-fwd samples were taken minutes after
   deploys and the NFD sample after things had settled — the A/B was
   confounded by exactly the variable it was meant to control.
3. On the SAME binary (a070c93e, verified by store path) a later run showed
   all three airframes at 3.21-3.25/s with ZERO gaps, and a further one the
   same.

The gapping was **transient deploy churn** — four deploys and many service
restarts in quick succession — not suppression, not ndn-fwd, not RF. Same
binary, clean before and clean after.

The standing rule, now paid for three times in one session: after a fabric
switch or service restart this fleet needs to settle, and a measurement taken
inside that window is worthless — including as one arm of an A/B. Wait, then
measure, then compare arms taken under the same conditions.

The revert still stands, for a different and weaker reason: suppression's
benefit is unmeasurable at current loss rates, so there is no case for
carrying an unvalidated forwarding change on the fleet. It was not shown to
be harmful.

**A fidelity bug found while reasoning about it, still unfixed.** NFD grows
the per-entry window once per FORWARD DECISION (`decidePerPitEntry`); this
port grows it inside `add_out_record`, which multicast calls once per
upstream — so a 3-nexthop fan-out grows the window 2^3 per Interest instead
of 2x, pinning it at the 250 ms cap almost immediately. That only affects
best-route entries (multicast reads the fixed per-upstream window), so it is
not obviously the iuas-02 cause, but it is wrong and would have to be fixed
before any retry.

**Honest status of the benefit:** never demonstrated. At current loss rates
(`resent` 25-52 per 180 s) the fleet cannot show an improvement from
suppression — only the absence of harm. The case for it is conformance with
NFD and behaviour under lossy bursts, not measured gain. Next attempt belongs
on the two-node netns bench with induced loss (`/tmp/bench.sh` on
minidronesys-04), where retransmission rates can be driven high enough for
the effect to be visible at all.

---

## Round 4 — why ndn-fwd is less smooth than NFD

Framing: at comparable aggregate bitrate (3799 vs 4478 kbps, NFD ~18% ahead),
ndn-fwd's 3-stream video was *markedly choppier* — worst frame gap 6.00 s vs
2.62 s, 32 stutters vs 4. A gap that shows up in the latency tail but barely
in throughput is a specific signature: the same repairs happen, they just
happen late. Both findings below have that shape, and both were found by
reading NFD's `daemon/face/lp-reliability.cpp` against
`ndn-transport/src/reliability.rs`.

### 4.1 No fast retransmit — every loss cost at least an RTO (200 ms)

**NFD does not wait for the RTO to repair a loss.** `findLostLpPackets()`
(lp-reliability.cpp:245) counts, for each unacked frame, how many Acks for
*greater* TxSequences have gone by. At `Options::seqNumLossThreshold` — 3,
the 3-duplicate-ack analogue — the frame is declared lost and resent
immediately, from the receive path.

ndn-fwd had exactly one repair trigger: RTO expiry in `check_retransmit`. The
RFC 6298 floor is `RFC6298_MIN_RTO_US = 200_000`. So on a link whose RTT is
single-digit milliseconds, *every* lost frame waited 200 ms before a repair
was even attempted — 50-100x NFD's repair latency.

Aggregate throughput hides this completely: the same frames get retransmitted
either way. A sequential consumer does not hide it at all. A predictive NDNSF
stream delivers in cursor order, so one late repair stalls everything behind
it, and a handful of losses compound into the multi-second gaps measured.

Fixed by porting the mechanism: `UnackedEntry::n_greater_seq_acks`,
`SEQ_NUM_LOSS_THRESHOLD = 3`, and `take_fast_retransmits()` flushed from the
receive path next to the Ack flush, so recovery costs about an RTT rather
than a retransmit tick.

**Deliberate divergence retained:** NFD re-stamps a fresh TxSequence on every
retransmission (`assignTxSequence`, lp-reliability.cpp:316) and therefore
keys duplicate suppression on `Sequence`. This port keeps the TxSequence
stable and keys duplicate suppression on it instead (documented on
`on_receive`). Fast retransmit works either way; Karn's check still excludes
retransmits from RTT sampling via `is_retx`. Reassigning TxSequence per
retransmission remains an open divergence.

### 4.2 Retransmission picked an arbitrary subset, not the oldest

`check_retransmit` resends at most `max_retx_per_tick` frames per tick (16 on
the wifi profile). `unacked` was a `HashMap`, so when more frames were overdue
than the cap allowed, *which* ones got repaired was hash order — and an
individual lost fragment could be skipped tick after tick while others were
repaired repeatedly. NFD walks an ordered `std::map` and repairs oldest-first.

Same signature again: the retransmit *rate* is identical, so throughput barely
moves; the per-frame recovery latency grows a long tail. Fixed by making
`unacked` a `BTreeMap`, which also turns the `max_unacked` eviction from an
O(n) `keys().min()` scan into `pop_first()`.

The regression test is not vacuous — against the old map it repaired frames
`[1, 7, 6]` where it should have repaired `[0, 1, 2]`.

### 4.3 Not a defect: piggybacked Ack cap

`on_send` attaches at most `MAX_PIGGYBACKED_ACKS = 16`, which looked like it
might silently drop Acks and provoke spurious retransmissions. It does not —
`drain(..len.min(16))` leaves the remainder queued for the next outgoing
frame or for `flush_acks`. Checked and cleared.

### 4.4 Status

Both fixes are unit-tested and pinned to the fleet on branch
`fleet-transport-fixes` (a070c93e + these two commits only). They are
deliberately NOT shipped from `main`, which also carries the unvalidated
RetxSuppressionExponential port — shipping both together would make the
smoothness result unattributable, which is the mistake §3 already paid for.

Hardware validation of the smoothness claim is still outstanding.
