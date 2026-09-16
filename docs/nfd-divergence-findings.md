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

### OPEN — PIT is keyed by an unverified 64-bit hash
`PitToken::from_name_hash_keyed` derives the PIT key from
`DefaultHasher(name_hash, discriminator)`, and the Data match path
(`PitMatchStage::consume_entry`) resolves purely by that token. `PitEntry`
stores `name: Arc<Name>`, but **it is never compared to the arriving Data's
name.** NFD keys its PIT by the actual Name via the nametree and applies
`Interest::matchesData` on every match.

Consequence of a token collision: Data for name A satisfies a pending
Interest for name B, and the consumer is handed the wrong object under the
right name.

Honest risk assessment — this is hardening, not an open hole:
- accidental collision ≈ N/2^64 per insert; at 10^4 entries that is ~5e-12/s.
  Effectively never.
- a targeted second-preimage against a victim's specific pending name is
  2^64 work. Infeasible.
- an attacker-chosen colliding PAIR is only 2^32 offline (and
  `DefaultHasher::new()` uses a FIXED key, so it is reproducible off-box),
  but exploiting it still requires the victim to express Interest for one of
  the attacker's two names — little practical leverage.

Recommended fix, mirroring `Interest::matchesData`: before consuming an
entry, require that `entry.name` can actually satisfy the Data — equal after
digest handling, or a proper prefix when the in-record set `CanBePrefix`.
The name is already in hand, so the cost is one comparison on the Data path.
Deliberately NOT applied here: the check has to cover both the persistent and
classical consumption paths, and it sits on the Data hot path — it wants a
change made with test coverage in front of it, not appended to a long
session.
