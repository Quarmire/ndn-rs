# ndn-did

Thin re-export shim for backwards compatibility. The `ndn-did` crate has been
merged into `ndn-security`; all DID types now live under `ndn_security::did`.
This crate re-exports everything from that module so existing dependents continue
to compile without changes.

## Migration

New code should depend on `ndn-security` directly:

```toml
# Preferred
[dependencies]
ndn-security = { version = "*" }
```

```rust
// New code
use ndn_security::did::{DidDocument, DidKey, UniversalResolver};

// Legacy code (still works via this shim)
use ndn_did::{DidDocument, DidKey, UniversalResolver};
```

## Key types

All types are re-exported from `ndn_security::did`. See the
[`ndn-security`](../ndn-security/README.md) crate for documentation.
