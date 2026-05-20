# Faces

A face is a single send/recv endpoint on the forwarder — a UDP socket, a TCP
stream, a shared-memory ring, an in-process channel, an Ethernet frame source,
a WebTransport datagram channel. The `faces/*` management module creates,
inspects, updates, and destroys them; subscribers on
`/localhost/nfd/faces/notifications` see lifecycle and semantic events as they
happen.

This page is the operator-level reference: every knob the management protocol
exposes, every error code, and the field shape `ndn-ctl face list` prints. The
implementation-side companion is
[Link Service composition](../design/link-service.md).

## The model

```
+-----------------------------+
|             Face            |
|  +-----------------------+  |
|  |     LinkService       |  |   feature pipeline, framing, runtime knobs
|  +-----------------------+  |
|  +-----------------------+  |
|  |      Transport        |  |   bytes on the wire, MTU, persistency
|  +-----------------------+  |
+-----------------------------+
```

A face is a `Transport` (raw bytes) paired with a `LinkService` (framing,
policy, per-feature behaviour). NFD's `Face` is the same split — `daemon/face/face.hpp:41-101`.

Two `LinkService` impls ship in ndn-rs:

- **`PassthroughLinkService`** — for local-scope faces (App, Shm, InProc,
  Internal, Management, Unix, WebSocket, WebTransport, WebRtc). Ships bytes
  through verbatim and carries in-process source-face provenance via
  `Transport::send_bytes_with_source`. No LP framing.
- **`LpLinkService`** — for non-local faces (Udp, Tcp, Ethernet, Serial,
  Bluetooth, Multicast). LP-wraps every outbound packet, applies the
  per-feature pipeline (see below), drives the per-face reliability state
  machine when enabled.

## Face lifecycle

```sh
ndn-ctl face create udp4://192.168.1.1:6363
ndn-ctl face list
ndn-ctl face destroy 259
```

`faces/create` accepts a URI scheme prefix:

| Scheme         | Notes                                                     |
| ---            | ---                                                       |
| `udp4://`      | Unicast UDP. MTU runtime-mutable (≤ 65507).               |
| `udp6://`      | IPv6 variant of the above.                                |
| `tcp4://`      | Stream face — no link MTU.                                |
| `tcp6://`      | IPv6 variant.                                             |
| `shm://`       | Single-producer/single-consumer shared-memory ring.       |
| `unix://`      | Unix domain socket.                                       |

`ndn-rs` does not yet accept `ether://` for unicast Ethernet face creation
(tracked under design doc Q5 / TLV-allocation deferral).

## faces/update — runtime knobs

`faces/update` carries any subset of the typed options below; per-option
failure surfaces a named-field error body so operators can grep the audit log
without decoding bitmaps. The control parameters are NFD-canonical TLV codes;
the field-name strings the response uses are kebab-case so they survive
copy-paste into a wiki page.

### Flag bits

NFD `FaceFlags` (TLV 0x6C) carries three runtime-mutable bits. `faces/update`
takes them as `flags` + `mask`; each set bit in `mask` takes its value from
`flags`, every other bit is preserved.

| Flag                | NFD bit | Effect                                                 |
| ---                 | ---     | ---                                                    |
| `LocalFields`       | 0       | Egress `IncomingFaceId` LP stamping (for `nfdc face show`-style routes). |
| `LpReliability`     | 1       | Per-face reliability state machine ON/OFF.             |
| `CongestionMarking` | 2       | CoDel egress marking ON/OFF.                           |

Examples:

```sh
# Turn on LpReliability (bit 1):
ndn-ctl face update 259 --flags 0x2 --mask 0x2

# Turn off CongestionMarking without touching LocalFields:
ndn-ctl face update 259 --flags 0x0 --mask 0x4
```

### MTU

`mtu` overrides the per-face effective MTU. UDP clamps requests to
`UDP_HARD_MAX = 65507`; smaller values flow through to the LP-layer
fragmenter. Stream faces (TCP, Unix) report `NotSupported` because there is
no link MTU. Shm faces report `Immutable` because the slot size is baked at
ring-segment creation time.

```sh
ndn-ctl face update 259 --mtu 8800
```

### Persistency

`face_persistency` updates how the forwarder treats the face's failure mode:

| Code | Value         | Lifetime                                                  |
| ---  | ---           | ---                                                       |
| `0`  | `Persistent`  | Created by mgmt; survives I/O errors.                     |
| `1`  | `OnDemand`    | Created by listener; idle-times out.                      |
| `2`  | `Permanent`   | Never destroyed (multicast, always-on links).             |

Shm / InProc / Internal faces reject persistency updates — the value is
intrinsic to creation, not a runtime setting.

### CoDel parameters

When `CongestionMarking` is on, two TLVs configure the CoDel algorithm:

| TLV    | Field                              | Default            |
| ---    | ---                                | ---                |
| `0x87` | `base_cong_interval` (µs)          | `100_000` (100 ms) |
| `0x88` | `def_cong_threshold` (queue items) | `65_536`           |

The defaults mirror NFD; tune `base_cong_interval` down for low-latency
links and `def_cong_threshold` down for small per-face queues.

## faces/update — error taxonomy

The handler maps each typed-option outcome to a status code with a
machine-readable body. Operators can detect every refusal kind by status
code; the body names the exact field:

| Code  | Meaning                                        | Body shape                                                  |
| ---   | ---                                            | ---                                                         |
| `200` | All requested options applied.                 | Echo `face_id` + applied subset.                            |
| `400` | Bad parameters (value out of range).           | `field=<option> reason=<machine-readable>`.                 |
| `404` | Face does not exist.                           | Free-text.                                                  |
| `409` | Option exists but is immutable on this face.   | `field=<option> reason=immutable-on-<face-kind>`.           |
| `423` | Target is locked (management face protection). | `field=management-face reason=management-face-protected`.   |
| `503` | Transport / LinkService doesn't support it.    | `field=<option> reason=transport-not-eligible`.             |

Examples the field shape pins:

```
field=mtu reason=immutable-on-shm                 (409)
field=mtu reason=udp-max-65507                    (400)
field=flags:lp-reliability reason=transport-not-eligible    (503)
field=persistency reason=invalid-value            (400)
field=management-face reason=management-face-protected      (423)
```

Refused-option requests do not silently apply a partial subset. The first
failed option short-circuits and the FaceState bitmap stays unchanged.

## faces/list — what each line means

`ndn-ctl face list` prints the dataset returned by
`/localhost/nfd/faces/list`. Every field on the wire is rendered; lines that
require ndn-rs extension TLVs are silent for pre-Tier-4 forwarders or
local-scope faces (no noise).

Example output:

```
faceid=259  udp4  persistent  non-local  point-to-point  mtu=8800
  remote: udp4://192.168.1.10:6363
  local:  udp4://192.168.1.5:53412
  flags:  local-fields lp-reliability
  in:  interests=12503  data=8741  nacks=12  bytes=4.20 MiB
  out: interests=8741   data=12503  nacks=0   bytes=3.10 MiB
  congestion: base-interval=100000µs  threshold=50000  marks-sent=3  marks-received=0
  reliability: rto=420µs  resent=14
  features: fragmentation reassembly local-fields incoming-face-id nack trace-context reliability congestion-marking
```

Line shapes:

- `faceid=… kind persistency scope link-type [mtu=…]` — matches `nfdc face list`.
- `remote: / local:` — URIs, omitted when empty.
- `flags:` — kebab-case bit labels for the three NFD flag bits.
- `in: / out:` — NFD-canonical packet counters.
- `congestion:` — `base-interval` / `threshold` / `marks-sent` / `marks-received`.
- `reliability:` — `rto` (microseconds) / `resent` count.
- `features:` — feature pipeline names in registration order; the headline
  ndn-rs distinction over NFD.

The dataset also carries `effective_mtu`, `n_lp_acks_received`, and
`n_lp_rto_expirations` (TLVs `0xDF`, `0xDA`, `0xDC`); future ndn-ctl rendering
adds them under a `--detailed` flag.

## faces/notifications — semantic events

Subscribers on `/localhost/nfd/faces/notifications` see every face-level
event the management module publishes. The wire shape is NFD-canonical
`FaceEventNotification = 0xC0` carrying `FaceEventKind = 0xC1`; NFD reserves
kinds 1..=4 for lifecycle. Tier 4 adds kinds 5..=9 for ndn-rs-headline
semantic events. NFD clients that don't decode kinds > 4 ignore the extended
events; ndn-rs clients (notably `ndn-ctl` and `ndn-dashboard`) read every
kind.

| Kind | Variant                | Payload                                  |
| ---  | ---                    | ---                                      |
| 1    | `Created`              | `face_id`                                |
| 2    | `Destroyed`            | `face_id`                                |
| 3    | `Up`                   | `face_id`                                |
| 4    | `Down`                 | `face_id`                                |
| 5    | `MtuChanged`           | `face_id` + `old` + `new`                |
| 6    | `PersistencyChanged`   | `face_id` + `old` + `new`                |
| 7    | `ReliabilityBackoff`   | `face_id` + `attempt` + `rto_us`         |
| 8    | `CongestionMark`       | `face_id` + `direction` + `mark`         |
| 9    | `OptionRefused`        | `face_id` + `option` + `reason`          |

The full per-event-payload TLV codes are in
[`docs/notes/ndn-rs-tlv-allocations-2026-05-20.md`](https://github.com/Quarmire/ndn-rs/blob/main/docs/notes/ndn-rs-tlv-allocations-2026-05-20.md).

## Management-face protection

A face whose `FaceKind` is `Management` cannot be updated or destroyed from
a non-management face. The handler returns `423 LOCKED` with body
`field=management-face reason=management-face-protected`. This is distinct
from `401 UNAUTHORIZED` (no credentials at all) — `423` is "you can never do
this from this role", a stronger statement.

In practice this matters when a misbehaving application tries to destroy
the router's own management socket. The guard is enforced before any other
update logic runs, so the management face's state cannot drift partially
mid-attack.

## Witnesses

The face system ships its own audit harness under
`testbed/tests/audit/face_*.sh`. Each script exits 1 against a broken
codebase and 0 after the fix; they double as documentation of the contract.

| Witness                                        | What it pins                                           |
| ---                                            | ---                                                    |
| `face_state_flags_only_via_options.sh`         | Tier 0 — flag bits funnelled through accessors.        |
| `face_link_service_composition.sh`             | Tier 1 — LpLinkService is a feature composer.          |
| `lp_trace_context_codec.sh`                    | Tier 1 — TraceContext LP TLV codec + Nonce fallback.   |
| `pit_trace_id_aggregation.sh`                  | Tier 1 — PIT in-record carries trace IDs.              |
| `face_options_typed.sh`                        | Tier 2 — typed `FaceOption` + `LinkService::apply`.    |
| `face_mtu_runtime_mutable.sh`                  | Tier 2 — `Transport::set_send_mtu` per-transport matrix. |
| `face_options_refused.sh`                      | Tier 2 — named-field error taxonomy.                   |
| `face_apply_flips_runtime.sh`                  | Tier 3 — apply flips Reliability + CongestionMarking.  |
| `face_reliability_tracks_for_retx.sh`          | Tier 3 — ReliabilityFeature retx + `n_lp_resent_packets`. |
| `face_congestion_mark_propagates.sh`           | Tier 3 — CoDel egress marking + LP TLV on the wire.    |
| `face_status_extended_fields.sh`               | Tier 4 — FaceStatus extension TLVs round-trip.         |
| `face_event_extended_kinds.sh`                 | Tier 4 — FaceEvent kinds 5..=9 round-trip.             |
| `ndnctl_face_list_renders_new_fields.sh`       | Tier 4 — `ndn-ctl face list` renders extension fields. |
| `face_otel_overhead.sh`                        | Tier 4 — Criterion bench scaffold (SKIP until Phase-3). |

Run any one with:

```sh
./testbed/tests/audit/face_apply_flips_runtime.sh
```

Failing transcripts (before/after) live under
`docs/notes/witness-transcripts-face-system-tier{2,3,4}/`.

## Related

- [Link Service composition](../design/link-service.md) — feature trait, the
  default eight-feature pipeline, CoDel + reliability state machines.
- `docs/notes/face-system-design-2026-05-20.md` — design doc with every
  decision and the rationale.
- `docs/notes/ndn-rs-tlv-allocations-2026-05-20.md` — TLV codes for every
  extension on the wire.
