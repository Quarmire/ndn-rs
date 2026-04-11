# ndn-packet

Core NDN packet types and their TLV wire-format codec. Fields are decoded lazily via `OnceLock` so fast-path operations (e.g. Content Store hits) avoid parsing unused fields. Compiles `no_std`; an allocator is required.

## Key Types

| Type | Role |
|------|------|
| `Name` / `NameComponent` | Hierarchical NDN name backed by `SmallVec<[NameComponent; 8]>` |
| `Interest` | Interest packet with optional `Selector`, lazy nonce/lifetime decode |
| `Data` | Data packet carrying content, `MetaInfo`, and `SignatureInfo` |
| `Nack` / `NackReason` | Network-layer negative acknowledgement |
| `LpHeaders` / `CachePolicyType` | NDNLPv2 link-protocol header fields |
| `SignatureInfo` / `SignatureType` | Signature metadata for signed packets |
| `tlv_type` | Module of well-known TLV type code constants |

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `std` | on | Enables `ring`-backed signatures and NDNLPv2 fragment reassembly. Disable for `no_std` targets. |

## Usage

```rust
use ndn_packet::{Name, Interest};

let name: Name = "/example/hello".parse().unwrap();
let interest = Interest::new(name);
let wire = interest.encode();
```

Part of the [ndn-rs](../../README.md) workspace.
