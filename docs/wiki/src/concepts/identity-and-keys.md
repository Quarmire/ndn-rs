# Identity and keys

An NDN identity is a name plus a key pair, signed by a certificate.
The `KeyChain` is the single object that holds identities, their
keys, and the policies that govern signing and validation. This
page covers the three things an application author needs to know:
identities, signing info, and trust policies.

## KeyChain

```rust,ignore
use ndn::prelude::*;
use ndn::KeyChain;

# fn run() -> Result<(), Box<dyn std::error::Error>> {
// In-memory, self-signed — tests and short-lived producers:
let keychain = KeyChain::ephemeral("/com/example/alice")?;
// Or file-backed, generated on first run and reloaded after:
let keychain = KeyChain::open_or_create("/var/lib/ndn/pib".as_ref(), "/com/example/alice")?;
# Ok(()) }
```

The opened keychain knows its identity, its signing key, and any
trust anchors that have been added. `KeyChain` lives at
`crates/security/ndn-security/src/keychain.rs`; the Develop tier re-exports it
as `ndn::KeyChain`.

## Identities

A `KeyChain` **is** one identity: a name, a signing key, and that key's
certificate. To hold several identities, hold several keychains.

```rust,ignore
# use ndn::prelude::*;
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let keychain = KeyChain::ephemeral("/alice")?;
let _name = keychain.name();          // /alice
let _key_name = keychain.key_name();  // /alice/KEY/<key-id>
let _signer = keychain.signer()?;     // signs with that key
# Ok(()) }
```

The key is Ed25519 (or ECDSA via `KeyChain::ephemeral_ecdsa`); its
certificate is a `Data` packet under the standard NDN naming convention
(`/<identity>/KEY/<key-id>/<issuer-id>/<version>`). A file-backed
keychain persists both in its PIB (see below).

## Certificates

A certificate is a signed `Data` packet whose content is the identity's
public key, with a validity period and a key locator pointing to the
issuer's key. A fresh keychain's cert is **self-signed** — it is its own
trust anchor; a CA-issued cert chains to the CA instead.

| Verb | API |
|---|---|
| Sign with this identity | `keychain.signer()?` / `keychain.sign_data(builder)` |
| Trust another identity's cert | `keychain.add_trust_anchor(cert)` |
| Get a CA-issued cert | NDNCERT enrollment — `NdncertClient::new(consumer, ca_prefix).enroll(signer, validity_secs, challenge)` (fleet: `Identity::provision(config)`) |
| Issue a cert for another key | `SecurityManager::certify(subject, pubkey, issuer, validity)` |
| Operator workflow | [NDNCERT setup](../guides/ndncert-setup.md) |

## SigningInfo

`SigningInfo` is the "sign me with X" selector that `KeyChain::sign_packet`
resolves before signing — useful when a keychain holds more than the
default key, or to force digest-only.

```rust,ignore
# use ndn::prelude::*;
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let info = SigningInfo::identity("/alice".parse()?);           // by identity name
let _info = SigningInfo::key("/alice/KEY/k1".parse()?);        // by specific key
let _info = SigningInfo::digest_sha256();                      // integrity only, no key

let keychain = KeyChain::ephemeral("/alice")?;
let wire = keychain.sign_packet(DataBuilder::new("/alice/note", b"hi"), &info)?;
# Ok(()) }
```

Under the hood a `SigningInfo` resolves to a `SignerSelection`
(`KeyChain::resolve_selection`) before the bytes are signed. `identity(..)`
resolves any identity whose key the keychain's `SecurityManager` holds, and
`suggested(..)` picks the held identity with the longest name covering the
packet name. When nothing matches, both return an error instead of signing
with a different identity's key.

## Trust policies

When you fetch a `Data` through a `VerifiedConsumer`, its `Validator`
decides whether to accept it by enforcing a `TrustSchema`. Both are
re-exported from the Develop umbrella:

```rust,ignore
use ndn::{TrustSchema, Validator};
```

| Schema | What it accepts |
|---|---|
| `TrustSchema::hierarchical()` | Data and signing key share their first name component. |
| `TrustSchema::from_lvs_binary(..)` | Light Versatile Schema rules (LVS) — pattern-based. |
| `TrustSchema::new()` + `add_rule` | Your own `"<data> => <key>"` rules. |
| `TrustSchema::accept_all()` | Any name pair; only the anchor set limits signers. |

For a tabular catalog with rule examples: [Trust policies](../reference/trust-policies.md).

## PIB backends

The keychain's key and cert live in a PIB (Personal Information Base),
chosen by the constructor:

| Constructor | Storage |
|---|---|
| `KeyChain::ephemeral(name)` | In-memory; nothing persisted. |
| `KeyChain::open_or_create(path, name)` | File-backed PIB at `path`. |

The lower-level PIB type is `ndn_security::pib::FilePib` (file-backed),
the default native PIB. A PIB can hold several identities. `open_or_create`,
`SecurityManager::auto_init` and `SecurityManager::from_pib` load only the
requested identity's key, i.e. any key whose name starts with
`/<identity>/KEY/`. That covers every naming form in use:
`/KEY/<key-id>/self/v=0` (`ndn-sec keygen`), `/KEY/self` (`auto_init`),
`/KEY/root` (namespace root) and `/KEY/<key-id>`. When an identity has several
keys, `FilePib::default_key` picks the one whose valid certificate was
issued most recently, falling back to name order. Use `FilePib` directly
for the SafeBag import/export below; SafeBag is also the portable way to
move keys to and from an ndn-cxx keychain.

To read and write ndn-cxx's own key store in place, enable the opt-in
`ndnsec-compat` feature on `ndn-security` (passed through by `ndn-app` and
`ndn-rs-prelude`). It adds `ndn_security::sqlite_pib::SqlitePib`, which
opens `~/.ndn/pib.db` with ndn-cxx's `pib-sqlite3` schema, and
`ndn_security::file_tpm::FileTpm`, which reads and writes the
`~/.ndn/ndnsec-key-file/` private keys in ndn-cxx's `tpm-file` format
(RSA and ECDSA-P256; Ed25519 uses an ndn-rs-only file suffix that ndn-cxx
ignores). `FileTpm` can also export and import SafeBags directly. The
feature pulls in bundled SQLite, so it is off by default and does not
build for wasm.

## SafeBag — exporting identities

A `SafeBag` is a passphrase-encrypted bundle of an identity's
certificate and private key. The format is interoperable with
`ndnsec`; the operator workflow is in
[NDNCERT setup → invite tokens](../guides/ndncert-setup.md).

The file-based PIB exports and imports the bundle directly:

```rust,ignore
use ndn_security::pib::FilePib;
# fn run(key_name: &ndn_packet::Name) -> Result<(), Box<dyn std::error::Error>> {
let pib = FilePib::open("~/.ndn/pib")?;
let bytes = pib.export_safebag(key_name, b"passphrase")?;
std::fs::write("alice.safebag", &bytes)?;

// Receiving side — the embedded cert names the key:
let dst = FilePib::new("~/.ndn/pib")?;
dst.store_safebag(key_name, &bytes, b"passphrase")?;
# Ok(()) }
```

### From the command line (`ndn-sec`)

The same workflow is available without writing code. `ndn-sec`
manages a file-based PIB and moves whole identities through the
SafeBag wire for **both** supported signature types — Ed25519
(ndn-rs-native) and ECDSA P-256 (interoperable with ndn-cxx / NFD
and `ndnsec`):

```bash
# Generate a key (Ed25519 default; ECDSA for ndn-cxx interop).
ndn-sec keygen /alice
ndn-sec keygen /alice --type ecdsa

# Export an identity as a SafeBag (base64 by default — paste/email-safe;
# `--format raw` for binary). Prompts for the passphrase if --password
# is omitted.
ndn-sec export /alice -o alice.safebag

# Import elsewhere. The file may be raw TLV or base64, and the key name
# is read from the embedded certificate. `--anchor` also trusts it.
ndn-sec import alice.safebag
ndnsec import alice.safebag   # ndn-cxx accepts the ECDSA form too
```

The PIB location follows `--pib`, then `$NDN_PIB`, then `~/.ndn/pib`.
The dashboard's Security view performs the same import/anchor
operations over the management protocol, and its Settings view shows
which PIB the connected forwarder uses.

## When you need more: `Identity`

`KeyChain` is the atom — sign and verify; most code needs nothing
else. When you need the identity *lifecycle* NDN leaves to
applications, reach for `Identity` (in `ndn-identity`). It derefs to a
`KeyChain` (signs and verifies identically) and adds **enrollment**
under a CA, **rotation** (change the operational key under the prior
key's authority), **recovery** (a pre-committed authority installs a
new key if yours is lost), and **device delegation** — e.g.
`Identity::create(KeyChain::ephemeral("/alice")?, recovery)?`. Creating
a recoverable principal designates the recovery authority up front: by
design you cannot silently make an unrecoverable identity.

## See also

- [NDNCERT setup](../guides/ndncert-setup.md) — operator and enrollee
  workflow for automated certificate issuance.
- [Trust policies](../reference/trust-policies.md) — concrete policy
  catalog with rule shapes.
- [Develop tier → KeyChain](../api/develop.md#keychain) — full API
  surface.
- `crates/security/ndn-security/` — implementation; the trust surfaces
  are in `trust_schema.rs`, `validator/`, `keychain.rs`.
