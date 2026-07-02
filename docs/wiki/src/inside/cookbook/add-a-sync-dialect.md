# Add a sync dialect

NDN dataset synchronisation lets a group of nodes converge on a shared set of
named publications without a server. ndn-rs ships two families in `ndn-sync`:

- **SVS** (State Vector Sync) — nodes multicast a *state vector* (per-producer
  sequence numbers) and fetch the gaps. Two wire dialects coexist: **v2**
  (ndn-svs, C++) and **v3** (ndnd, Go).
- **PSync** — IBF/Bloom-filter set reconciliation (`psync.rs`,
  `psync_bloom.rs`, `psync_partial.rs`), wire-compatible with the C++ PSync.

This page covers adding a new **SVS wire dialect** — a third format that the rest
of the crate consumes through the same interface as v2 and v3. The dialect
selector is `ndn-sync/src/dialect.rs`; the notification core is
`ndn-sync/src/svs_sync.rs`; the v3 codec is `ndn-sync/src/svs_local.rs`.

## The seam: `WireDialect` over `StateEntry`

The crate never branches on wire format outside `dialect.rs`. A single
`WireDialect` enum selects (a) the Sync Interest name version and (b) the
state-vector codec, behind a `StateEntry`-based encode/decode interface:

```rust,ignore
// ndn-sync/src/dialect.rs
pub enum WireDialect { V2, V3 }

impl WireDialect {
    pub fn sync_version(self) -> u64;                                  // v=N name component
    pub fn encode_state_vector(self, entries: &[StateEntry]) -> Bytes;
    pub fn decode_state_vector(self, bytes: &Bytes) -> Option<Vec<StateEntry>>;
}
```

`StateEntry { name, boot, seq }` (`svs_local.rs`) is the shared vocabulary. v2
has no boot dimension, so its entries decode with `boot = 0`; v3 carries a
`BootstrapTime` that disambiguates a producer's pre- and post-restart sequence
spaces. The two dialects differ **only** in these two functions.

| Dialect | Sync Interest name | State-vector TLVs |
|---|---|---|
| **v2** (ndn-svs) | `<group>/v=2` | `StateVector=201`, `StateVectorEntry=202`, `SeqNo=204`, `Name=7` |
| **v3** (ndnd) | `<group>/v=3` | `SvsData`/`StateVector` `0xC9`/`0xCA`, entry/boot/seq `0xD2`/`0xD4`/`0xD6` |

## Adding a dialect

1. **Add a variant** to `WireDialect` (e.g. `V4`).
2. **Assign the Sync Interest version** in `sync_version()` — the `v=N` component
   appended after the group prefix.
3. **Write the codec** — an `encode`/`decode` pair over `&[StateEntry]`, wired
   into `encode_state_vector` / `decode_state_vector`. Define the wire TLV
   constants as named `const`s at the top of the module (as v2 does with
   `TLV_STATE_VECTOR = 201`); do not hard-code magic numbers inline. Decode must
   reject an over-large vector up front (`entries.len() >
   MAX_TRACKED_PRODUCERS`) before it reaches `merge` — untrusted input bounds
   are load-bearing here.
4. **Round-trip test it.** Every dialect needs the three tests v2/v3 already
   have in `dialect.rs`: a boot-preserving (or boot-ignoring) round-trip, and a
   `dialects_are_not_cross_decodable` check that your format does not silently
   decode as another. See [the testing guide](../testing.md).

Because the notification core, merge logic, and suppression FSM all speak
`StateEntry`, a new dialect changes nothing above `dialect.rs`.

## The transport-agnostic `mpsc<Bytes>` boundary

The SVS core never touches a socket. It is driven entirely over a pair of
`tokio::sync::mpsc` channels of `Bytes`, so the identical protocol code runs
natively, in the browser, and in a simulator:

```rust,ignore
// ndn-sync/src/svs_sync.rs
pub fn join_svs_group(
    group: Name,
    local_name: Name,
    send: mpsc::Sender<Bytes>,     // Sync Interests out (you bridge to a face)
    recv: mpsc::Receiver<Bytes>,   // Sync Interests in
    config: SvsConfig,
) -> SyncHandle;
```

The caller owns the bridge between these channels and an actual face; the sync
layer stays pure. A new dialect inherits this boundary unchanged — you only
supply bytes.

## The suppression FSM

`svs_sync.rs` runs the ndn-svs two-state suppression FSM to damp Interest storms
in a large group:

- **Steady** — emit the state vector periodically.
- **Reply-to-stale (suppressing)** — when an incoming Sync Interest carries an
  *older* vector than ours, schedule a single catch-up reply within
  `SvsConfig::suppression_period` (~200 ms) instead of every node replying at
  once; an incoming *newer-or-equal* vector cancels the pending reply.

A new dialect reuses this FSM verbatim — it is format-independent.

## Authentication seam

Sync Interests carry the state vector in `ApplicationParameters`; on an untrusted
link an unauthenticated peer could inject false state or hijack a producer's
sequence space (a real risk for v2, which has no boot timestamp). Signing closes
that. The core calls `SyncValidator::validate` *before* merge and
`SyncSigner::sign` on every outgoing Interest (`ndn-sync/src/security.rs`):

```rust,ignore
pub trait SyncSigner: Send + Sync + fmt::Debug {
    fn sign(&self, builder: InterestBuilder) -> Bytes;
}
pub trait SyncValidator: Send + Sync + fmt::Debug {
    fn validate(&self, raw: &Bytes) -> Result<(), Rejected>;
}
```

Both default to `Insecure` (`SIGNER_TYPE_NULL`); `HmacKey` (`SIGNER_TYPE_HMAC`,
a shared group key) is the closed-group default. These are dialect-independent —
opt in through `SvsConfig`. The signed-Interest encoding reuses ndn-packet's
spec-compliant `InterestBuilder`/`signed_region` machinery, so a signed Sync
Interest is a real Signed Interest (§5.4).

## Above the notification core

If you need publications rather than raw sequence numbers, build on the Layer 1
data plane (`svsync.rs`): `SvSync` adds a `DataStore`, canonical `svs_data_name`
naming, `publish_data`, and a windowed `fetch_range` pipeline. `SvsPubSub`
(`pubsub.rs`) layers named publications and prefix subscriptions on top. A new
dialect flows up through both unchanged.

## See also

- [ADR 0001 · Real NDN wire format](../adr/0001-real-ndn-wire-format.md) — why the dialects are byte-exact ndn-svs / ndnd, not an ndn-rs invention.
- [The conformance matrix](../conformance-matrix.md) — SVS/PSync test coverage.
