# SVS wire-conformance fixtures

Golden bytes captured from the reference implementations on disk, used by
byte-level tests in `crates/ndn-sync` to keep the interop claims honest.
Each value below is hand-derived from the cited source line (the same
provenance style as `svs_local::tests::encode_svs_data_byte_level`, which
is hand-computed against ndnd).

## Sync Interest name (gap #9 — settled)

The single most interop-sensitive question: what component does the Sync
Interest name append after the group/sync prefix?

| Dialect | Source | Appended component |
|---------|--------|--------------------|
| **v2** (ndn-svs, C++) | `ndn-svs/ndn-svs/core.cpp:351` — `Interest(Name(m_syncPrefix).appendVersion(2))` | `VERSION` (TLV-TYPE `0x36`) = **2** |
| **v3** (ndnd, Go)     | `ndnd/std/sync/svs.go:136` — `opts.GroupPrefix.Append(enc.NewVersionComponent(3))` | `VERSION` (TLV-TYPE `0x36`) = **3** |

Both append a **typed VERSION name component**, *not* a generic `"svs"`
component. ndn-rs `Name::append_version(n)` emits TLV-TYPE `0x36` with an
NNI value, byte-identical to ndn-cxx `appendVersion` and ndnd
`NewVersionComponent`, so `group.append_version(2)` is wire-compatible
with a C++ ndn-svs peer.

### `sync_interest_v2_name.hex`

The NAME TLV (no trailing ParametersSha256DigestComponent) for
`syncPrefix = /ndn/svs`, v2 dialect:

```
07 0D                Name, len 13
   08 03 6E 64 6E       GenericNameComponent "ndn"
   08 03 73 76 73       GenericNameComponent "svs"
   36 01 02             VersionNameComponent  v=2
```

## State vector TLV codes (`ndn-svs/ndn-svs/tlv.hpp`)

| Name             | Code |
|------------------|------|
| StateVector      | 201  |
| StateVectorEntry | 202  |
| SeqNo            | 204  |
| MappingData      | 205  |
| MappingEntry     | 206  |
| LzmaBlock        | 211  |

`StateVectorEntry = NodeID(Name 0x07) || SeqNo(204)` — confirmed against
`version-vector.cpp VersionVector::encode()`.

## ApplicationParameters body order (`core.cpp:316-340`)

On the wire (after prepend reversal): `StateVector(201)` ‖ optional
mapping block ‖ `Content(0x15) = currentTime` (a NonNegativeInteger
heartbeat timestamp). ndn-rs omits the trailing `Content` block today;
peers ignore it on decode, so basic interop holds, but it is recorded
here as the one remaining v2 body delta.

## Signing (`core.cpp:354-`)

Sync Interests are signed with `SIGNER_TYPE_HMAC` (group key) or left
unsigned (`SIGNER_TYPE_NULL`). This is the basis for the
`SyncSigner`/`SyncValidator` HMAC path in `crate::security`.
