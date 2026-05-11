# Identity, keys, and SafeBags

This page clears up the most-asked question on the security path:

> If I enroll an identity in the browser, persist a SafeBag, and then
> want to talk to NFD as well, do I have a "split identity"?  Why do
> we even pick an algorithm?

**Short answer:** no split. An NDN identity is a *Name* — under it
you can have any number of keys, any number of algorithms.  The
SafeBag is one *key bundle*, not the identity.  You pick the
algorithm based on who needs to verify your signatures.

## The model

```
identity   /alice              ← a Name; people / apps know you by this
   │
   ├── key  /alice/KEY/<id1>   ← one Ed25519 keypair under /alice
   │       └── cert            ← certificate issued for this key (self-signed
   │                              for testing, NDNCERT-issued in production)
   │
   └── key  /alice/KEY/<id2>   ← a second keypair, e.g. ECDSA-P256, under
           └── cert              the same /alice identity
```

An identity can carry **many keys** simultaneously.  Each key has
its own certificate.  Both keys legitimately speak for `/alice`.

A **SafeBag** is the portable on-disk shape of *one* key:

- the encrypted private key (PKCS#8 PrivateKeyInfo, PBES2-wrapped)
- its certificate (a Data packet)

`ndnsec export /alice` produces a SafeBag for the active key under
`/alice`.  `ndnsec import` reverses it.

## Why algorithm matters: who verifies?

Different NDN implementations support different signature types:

| SignatureType                    | Code | ndn-rs | ndn-cxx / NFD     | Notes                                                  |
| -------------------------------- | ---- | ------ | ----------------- | ------------------------------------------------------ |
| `DigestSha256`                   | 0    | ✓      | ✓                 | Hash-only; useful for localhost; not a real signature  |
| `SignatureSha256WithRsa`         | 1    | ✗      | ✓                 | RSA-PKCS1 v1.5; widely supported but slow              |
| `SignatureSha256WithEcdsa`       | 3    | ✓      | ✓ (KeyType::EC)   | **The lowest common denominator for interop**          |
| `SignatureHmacWithSha256`        | 4    | ✓      | ✓ (KeyType::HMAC) | Symmetric; out-of-band shared secret                   |
| `SignatureEd25519`               | 5    | ✓      | ✗                 | Fast, small, **ndn-rs-only today**                     |
| `SignatureBlake3`                | 6    | ✓      | ✗                 | ndn-rs extension (yoursunny registration)              |
| `SignatureSha256WithBlake3`      | 7    | ✓      | ✗                 | ndn-rs extension                                       |

The ndn-cxx `KeyType` enum at `security-common.hpp:106` is the
authoritative list of what NFD can *generate* and *verify* today:

```cpp
enum class KeyType { NONE = 0, RSA, EC, AES, HMAC };
```

No Ed25519, no BLAKE3.  ndn-cxx's wire decoder *recognizes* code 5
for display strings, but the security stack can't verify it —
`tools/ndn-iperf.cpp:290` literally falls back when asked for
Ed25519.

## The practical guidance

| You want…                                       | Pick                         |
| ----------------------------------------------- | ---------------------------- |
| ndn-rs forwarder + ndn-rs clients only          | `Ed25519` (fast, small)      |
| ndn-rs forwarder + NFD / `nfdc` / `ndnsec` interop | `ECDSA-P256`              |
| Browser-only deployment (everything is ndn-rs)  | `Ed25519`                    |
| Anything that might federate with the testbed   | `ECDSA-P256`                 |

You can also hold **both** — generate one key per algorithm under
the same identity Name, store separate SafeBags, sign with
whichever the consumer expects.  No split identity; the Name
`/alice` is the same.

## What ndn-rs defaults to today

- **`KeyChain::ephemeral(name)`** — Ed25519 (the historical default).
- **`KeyChain::ephemeral_ecdsa(name)`** — ECDSA-P256.
- **`ndn-fwd`** auto-init: **ECDSA-P256** since 2026-05-11, because the
  daemon's mgmt responses need to be verifiable by whatever client
  shows up (often `ndn-ctl` *but sometimes* `nfdc`).
- **dioxus-demo SharedWorker** ephemeral fallback: **ECDSA-P256** for
  consistency.  An IdbPib-persisted Ed25519 SafeBag still wins via
  `IdbPib::build_signer`, which inspects the SafeBag's algorithm OID
  and returns the matching `Signer` impl.

## What `IdbPib::build_signer` does

```rust
let bag = pib.get_safebag(&key_name).await?;
match bag.algorithm(&passphrase)? {
    SafeBagAlgorithm::Ed25519   => Arc::new(Ed25519Signer::from_seed(seed, key_name)),
    SafeBagAlgorithm::EcdsaP256 => Arc::new(EcdsaP256Signer::from_pkcs8_der(&pkcs8, key_name)?),
    SafeBagAlgorithm::Other(oid) => return Err("unsupported OID"),
}
```

This is the path that lets a single persisted identity be reused
across page-loads without baking the algorithm into the codebase.

## Witness gates

After 2026-05-11 the engine fails closed if:

- A SafeBag carries an algorithm we can't build a Signer for
  (`SafeBagAlgorithm::Other`).
- A SafeBag is present but the companion passphrase row is missing
  (storage corruption — the join flow always writes both
  atomically).

This is intentional: silently falling back to DigestSha256 would
mask a real corruption.

## What about RSA?

ndn-rs has RSA verification (via the `rsa` crate, default-features
off so it stays wasm-clean) but no `RsaSigner` yet.  Generating an
RSA key in-browser is also expensive (slow keygen).  Until a real
consumer surfaces, RSA stays read-only.  `SafeBagAlgorithm::Other`
captures the OID so a future RSA path can dispatch off it without
re-touching the public API.
