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
| `std` | off (opt-in) | Enables the `encode` / `wire` / `fragment` modules and `sha2` / `blake3` hashing helpers. Leave off for `no_std` targets. |
| `portable-atomic` | off | Routes `bytes::Bytes` / `Arc` refcounting through `portable-atomic` for `no_std` targets without hardware atomic CAS (`riscv32imc`, `thumbv6m`, …). |

## no_std

`ndn-packet` builds `#![no_std]` out of the box — `std` is **not** a default
feature (`default = []`). An allocator is required (`extern crate alloc`).
`Name` / `Interest` / `Data` and the NDNLPv2 `LpPacket` codec
(`LpPacket::decode`, `encode_lp_packet`, both re-exported at the crate root) are
all available without `std`.

```toml
# Bare-metal / embedded: keep std off (the default).
ndn-packet = { version = "...", default-features = false }

# Hosted build that also wants the encode/wire/fragment modules + hashing:
ndn-packet = { version = "...", features = ["std"] }
```

Targets without hardware atomic CAS (e.g. `riscv32imc`, `thumbv6m`) additionally
need the `portable-atomic` feature, and the final binary must select a CAS
polyfill (typically `--cfg portable_atomic_unsafe_assume_single_core` on a
uniprocessor MCU):

```toml
ndn-packet = { version = "...", default-features = false, features = ["portable-atomic"] }
```

## Usage

```rust
use ndn_packet::{Name, Interest};

let name: Name = "/example/hello".parse().unwrap();
let interest = Interest::new(name);
let wire = interest.encode();
```

Part of the [ndn-rs](../../README.md) workspace.
