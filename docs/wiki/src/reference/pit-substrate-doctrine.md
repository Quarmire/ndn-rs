# PIT Substrate Doctrine

ndn-rs deliberately diverges from NFD-spec PIT semantics on a small
number of points to support NDF SparkStream persistent-attach. This
page summarises the choices and the discipline they impose on
callers; the canonical record is
[`docs/notes/substrate-extension-pit-doctrine-2026-05-11.md`](https://github.com/Quarmire/ndn-rs/blob/main/docs/notes/substrate-extension-pit-doctrine-2026-05-11.md).

## What's the same as NFD

- One PIT entry per `(LogicalName, ForwardingHint)` for classical
  Interests.
- `NameTrie` FIB with longest-prefix match.
- Per-`InRecord` originator selectors (`CanBePrefix`,
  `MustBeFresh`) per audit D.04.
- NDNLPv2 `PitToken` propagation on Data and Nack.

## What ndn-rs does differently

### 1. PSDC is not a multiplexing key

Both PIT and Content Store strip a trailing
`ParametersSha256DigestComponent` (`0x02`) or
`ImplicitSha256DigestComponent` (`0x01`) from the lookup name
symmetrically on insert and match. Two signed Interests at the
same logical name with different PSDCs aggregate into one PIT
entry rather than occupying separate slots.

**Discipline.** Any future signed-Interest RPC pattern where the
only difference between two concurrent calls is the
`ApplicationParameters` payload (and therefore the PSDC) must
disambiguate via an explicit name component — a request-id,
session-id, or sequence number. PSDC alone is not enough.

Existing callers comply already:

- **`MgmtClient`** — no `ApplicationParameters`, no PSDC.
- **NDNCERT** — request-id components in the Name precede any
  PSDC-bearing tail.

### 2. Marker gates persistence, not stripping

The substrate marker — the `SubscriptionRequest` sub-TLV inside
`ApplicationParameters` — controls two things and only two things:

1. Whether a `PersistentState` is installed on the in-record.
2. Which variant of `PitKeyDiscriminator` the entry uses
   (`PersistentAttach` for marker-bearing, `Classical` for
   non-marker).

Strip-at-insert is independent of the marker and applies
universally.

Marker-bearing and non-marker Interests at the same logical name
occupy distinct PIT entries. No semantic collision.

### 3. Per-`InRecord` credit

`PersistentState` lives on each `InRecord`. Each subscriber owns
its own credit pool, deadline, and lifecycle. Two subscribers
aggregating into one entry track their credit independently.

**Trust-model consequence.** Revocation, expiry, and ACL evaluation
are per-subscriber, not per-entry. NDF mediator policy code must
scope these decisions to the `InRecord`, not the `PitEntry`.

### 4. Replay guard is the integrity floor

`ndn_security::ReplayGuard` is a per-signer-key LRU of recently
seen `SignatureInfo` records. It rejects replays — duplicate
`SignatureNonce`, `SignatureTime`, or `SignatureSeqNum` under the
same key — *before* PIT insert.

The replay guard is not optional. Once PSDC is no longer a
multiplexing key, two replayed signed Interests would otherwise
silently coalesce into one PIT entry. Treat the guard as a
structural prerequisite of the universal-strip choice.

**Wired by default, native and wasm.** Both `EngineBuilder::build()`
and `WasmEngineBuilder::build()` populate the guard from their
respective config. The default
(`ReplayGuardConfig::default()`) is `enabled: true,
per_key_capacity: 64, monotonic: false`. `monotonic = false` is
the safe default — legitimate signed-Interest emitters re-attach
after clock skew, device sleep, or process restart, and enforcing
monotonic timestamps at the engine level would reject those.

Opt-in to monotonic floors:
`EngineBuilder::new(EngineConfig { replay_guard: ReplayGuardConfig::monotonic(), .. })`.
Disable entirely (test-only): `EngineBuilder::replay_guard_disabled()`.

The doctrine witness is
`builder::tests::default_build_has_replay_guard_active` in
`crates/spec/ndn-engine/src/builder.rs`.

## Future work

- **Secondary-index PIT** — a localised redesign that restores
  wire-name multiplexing if NFD-producer interop becomes a real
  requirement. Not built today; the secondary-index option is
  local to `ndn-store::pit` and does not touch SparkStream.
- **`subscribe_sync`** — engine-local subscription registry over
  PSync or StateVectorSync, for low-rate fan-out-heavy workloads.
  Roadmap item, not a replacement for persistent-attach.
