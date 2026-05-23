# SubscriptionRequest sub-TLV

> **Status:** ndn-rs-proprietary, experimental TLV range.
> **TLV-TYPE:** `0x230` (inside `ApplicationParameters`).
> **Reference impl:** [`crates/ndn-packet/src/subscription.rs`](../../crates/ndn-packet/src/subscription.rs).

A nested TLV inside `ApplicationParameters` that promotes a normal
Interest into a **persistent Interest**: a PIT entry that may satisfy
more than one Data packet and is reaped only when its declared
bounds are exhausted.

This spec defines the wire shape. PIT install behaviour, reaping
semantics, and replay-guard interactions live in the PIT substrate
doctrine (internal).

## Wire shape

```text
SubscriptionRequest = TYPE(0x230) LENGTH(9) VALUE(
    version        [1 byte, must be 1]
    max_data_count [4 bytes, big-endian u32]
    max_lifetime   [4 bytes, big-endian u32; seconds]
)
```

- **TYPE `0x230`** sits in the experimental range and is **even**,
  therefore **non-critical**: a forwarder that does not implement the
  extension ignores the sub-TLV and treats the Interest as a normal
  long-lifetime one (graceful degradation).
- **LENGTH `9`** fits in the 1-byte varint form.
- **VALUE** is fixed-length 9 bytes; any other length means the
  sub-TLV is malformed and MUST be ignored (the rest of the Interest
  is unaffected).

The full TLV in NDN varint form is:

```text
0xFD 0x02 0x30 | 0x09 | <9-byte value>
```

## Field semantics

| Field | Width | Semantics |
|---|---|---|
| `version` | 1 B | Must be `1`. Other values MUST cause the sub-TLV to be ignored. |
| `max_data_count` | 4 B | Hard upper bound on the number of Data packets this PIT entry may satisfy before the forwarder reaps it. `0` means "unbounded except by `max_lifetime`". |
| `max_lifetime_secs` | 4 B | Hard upper bound on the lifetime of the PIT entry, in seconds. The forwarder caps this at `MAX_PERSISTENT_LIFETIME_SECS = 3600` (one hour) — values higher than the cap MUST be clamped. |

The Interest's standard `InterestLifetime` field is **ignored** when
a SubscriptionRequest is present; `max_lifetime_secs` is the only
lifetime that matters. (Forwarders that ignore the sub-TLV fall back
to honouring `InterestLifetime` as usual — the graceful-degradation
path.)

## Placement

The sub-TLV lives **inside** the Interest's `ApplicationParameters`
TLV:

```text
Interest
├── Name (with trailing ParametersSha256Digest)
├── CanBePrefix / MustBeFresh / …
├── Nonce / InterestLifetime / HopLimit
└── ApplicationParameters
    └── SubscriptionRequest  ← TLV 0x230, here
```

Multiple sub-TLVs may share an `ApplicationParameters` payload; the
reference decoder (`SubscriptionRequest::find_in`) walks the payload
linearly and accepts the first matching SubscriptionRequest, skipping
unrelated siblings.

## Forwarder behaviour

A forwarder that implements this extension installs a **persistent
PIT entry** instead of the normal short-lived one:

- The entry's out-records remain after a Data match; subsequent Data
  packets matching the same name prefix are still forwarded back to
  the recorded in-records.
- The entry is reaped when **either** `max_data_count` Data packets
  have been satisfied **or** `max_lifetime_secs` elapse, whichever
  comes first.
- Replay-guard cooperation: the entry's `(name, nonce)` pair is held
  in the replay guard for the full `max_lifetime_secs`, not just the
  classical 4-second window. Otherwise a long-running subscription
  could be replayed at any point during its lifetime.

A forwarder that does not implement the extension SHOULD ignore the
sub-TLV (the critical-bit rule guarantees it) and treat the Interest
as a normal one. The behaviour difference is bounded: the requester
sees a single Data reply instead of a stream, and re-expresses the
Interest as needed.

## Critical-bit rule

Per NDN-TLV §3.6 (critical bit): TLV-TYPE `0x230` is even, therefore
non-critical. Forwarders that do not recognise the type **MUST**
ignore it (rather than reject the enclosing Interest). This is the
guarantee that makes the extension safe to deploy unilaterally.

## Implementation status

- **Codec:** complete (`crates/ndn-packet/src/subscription.rs`).
- **PIT substrate:** persistent-entry semantics implemented in
  `crates/ndn-store/src/pit.rs`; replay-guard cooperation in
  `crates/ndn-security/`.
- **Replay-guard lifetime cap:** capped at `MAX_PERSISTENT_LIFETIME_SECS`
  (one hour); cannot be raised without a code change. Operators who
  need longer lifetimes are expected to re-express the subscription.

## Backwards compatibility

Future revisions adding fields MUST bump `version`. Decoders MUST
reject unknown `version` values by treating the sub-TLV as absent
(graceful degradation), not by raising an error on the enclosing
Interest.
