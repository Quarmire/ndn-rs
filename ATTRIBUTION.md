# Attribution

Third-party work this repo builds on, ports, or interoperates with. Provisional
notes for proper crediting later.

## Protocols / specs (wire-compatible or based on)
- **NFD / YaNFD** (named-data) — management protocol; NFD-compatible wire format.
- **State Vector Sync (SVS)** — based on `ndn-svs` / the named-data SVS spec (incl. HMAC signer type).
- **PSync (Partial Sync)** — wire-faithful to named-data **PSync** (C++): IBLT + zlib encoding.
- **W3C DID Core + did:key** — `did:ndn` method follows W3C DID Core; resolver handles `did:key`.
- **NDNts** (yoursunny) / **esp8266ndn** — BLE wire-framing (1-byte fragmentation header) interop.

## Cryptography
- **`rabe`** crate — Rust ABE implementation; the `abe` feature builds on it.
  Schemes **BSW** (Bethencourt–Sahai–Waters) and **AW11** (Attrapadung–Waters).

## Reference implementations (not used; cited for correctness)
- **NFD**, **ndn-cxx**, **NDNts**, **ndnd**, **python-ndn** (all named-data / yoursunny).
