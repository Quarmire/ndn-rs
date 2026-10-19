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
let _cert = keychain.cert_name();     // Some(/alice/KEY/<key-id>/self/<version>)
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

Naming follows NDN Certificate Format v2: the key is
`/<identity>/KEY/<key-id>` and each certificate of it
`<key>/<issuer-id>/<version>`, with issuer id `self` (self-signed),
`NDNCERT` (issued by the namespace CA) or `NA`. A key can hold several
certificates — a renewal adds a new one, the old stays valid until it
expires. KeyLocators name the key; a verifier fetches by key name
(CanBePrefix + MustBeFresh) and uses the newest valid certificate. A
KeyLocator only ever resolves to a certificate of the key it names: other
Data under that name (another key's certificate, an NDNCERT approval
`<key>/ndncert-approve/<id>`) never answers for it.

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
let wire = keychain.sign_packet(DataBuilder::new(name!("/alice/note"), b"hi"), &info)?;
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
`/<identity>/KEY/`. On first start `auto_init` generates
`/<identity>/KEY/<random 8-byte hex>` with a signed self-signed certificate
`<key>/self/v=<ms>`; namespace roots use `/KEY/root`, and PIBs from earlier
releases may still hold `/KEY/self`. When an identity has several
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

### On-disk layout and permissions

A `FilePib` directory looks like this:

```text
<pib>/                      0700
  keys/<sha256(name)>/      0700  one directory per key
    private.pkcs8.der       0600  the private key (PKCS#8 DER)
    name.uri                0600  the key name
    certs/<sha256(cert)>.data 0600  each certificate of the key (signed Data);
                                  storing one drops the key's expired ones
    cert.ndnc, cert.data    0600  legacy summary / certificate (still loaded)
  anchors/<sha256(name)>/   0700  trust anchors (cert.ndnc, name.uri)
  default-identity          0600
  contexts/*.tc             0600  adopted signed trust contexts (newest version)
  contexts/*.versions/      0700  every version held, <N>.tc (0600), served by name
  ca/                       0700  CA state on CA hosts (certs, issued/,
                                  revoked/, redeemed-tokens/)
```

The whole PIB is owner-only, not just the private keys, so a single rule
covers everything in it. Every file is created with its final mode before
any content is written (a temp file opened `0600`, then renamed into place),
so a key is never readable by others, not even briefly. This holds
regardless of umask. `FilePib::new` and `FilePib::open` check an existing
PIB. A directory or file that group or other can access is tightened to
owner-only, and a warning names the path and its old mode. An entry owned
by a different user, or a symlink inside the PIB, is refused with an error
rather than used. `FileTpm` follows the same rule, writing key files `0400`
the way ndn-cxx's `tpm-file` does. `ndn-sec export` writes SafeBag files
`0600`. The helpers are in `ndn_security::secure_fs`.

On non-unix targets there are no permission bits. Files inherit the ACL of
their parent directory, and the repair and ownership checks do nothing. On
Windows, keep the PIB under the user's profile directory, which only that
user (plus SYSTEM and Administrators) can read.

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

## Root custody: where a namespace root key lives

A namespace root (`<ns>/KEY/root` from `init`, `<ns>/KEY/<id>` after a
recovery) is what every adopter trusts, and it
signs rarely — the anchor, the CA's certificate, each new trust-context
version (a revocation). So `ndn-fwd init` puts it in a **root store**,
not with the keys the daemon uses unattended, and records the store in
`<pib>/root/<hex of the trusted prefix>/store.toml`, its SafeBag beside it
(`ndn_cert::root_store`; an older PIB's one root stays in `<pib>/root/`). A
device can hold the roots of several trusted prefixes, one store each; root
commands then name one with `--namespace <prefix>`:

| `--root-store` | Private key | A root operation needs |
|---|---|---|
| `os-keyring` (default when reachable) | SafeBag `root-keychain.safebag` in the store's directory, sealed by a random 32-byte secret in the OS keychain (Secret Service, macOS Keychain, Windows Credential Manager; `keyring` crate) | nothing beyond the user's login |
| `sealed-file` | SafeBag `root.safebag` in the store's directory under your passphrase (PBES2, 600 000 PBKDF2 rounds) | the passphrase |
| `yubikey-piv` | generated on a YubiKey PIV slot (P-256, never exportable; PIN policy `always`) | the PIN, and a touch per the recorded touch policy |
| `file` | plaintext in the FilePib, file modes only | nothing — the daemon warns at startup |

Without a reachable keychain (a headless Linux box with no Secret Service)
`init` refuses and says to pass `--root-store sealed-file`. Passphrases and
PINs come from `NDN_ROOT_PASSPHRASE` / `NDN_ROOT_PIN`, a
`--passphrase-file` / `--pin-file`, else the terminal without echo — never
the command line. `ndn-fwd root-key status` shows the store; `ndn-fwd
root-key move --to os-keyring|sealed-file` moves a software root (the new
store must sign as the root before the old copy goes; a plaintext file is
overwritten, then deleted — on copy-on-write filesystems and SSDs only
full-disk encryption guarantees the old blocks are gone). An Ed25519 root
cannot move onto a YubiKey (PIV keeps only P-256 keys generated on it): a
hardware root means a new namespace, or root rotation once it exists.

The CA key and the device's admin key stay in the FilePib: the daemon
signs with them without anyone present (every issued certificate, every
management response). What they can do is bounded by the certificate the
root signed and by the context the root controls.

## Recovery kits: when the root device is lost

A root store protects the root on its device; a **recovery kit** is what
survives losing that device. A kit holds a separate **recovery key**, never
a copy of the root — a YubiKey root cannot be exported, and the root written
out as words would simply be the root. The root signs a context version that
lists the recovery key as an extra anchor, marked `recovery-anchor`; as every
anchor of the held version may sign the next one, the recovery key can later
sign the version that installs a new root, and every node adopts it without
new trust machinery. A recovery anchor is root-equivalent: keep the kit
offline.

```sh
ndn-fwd recovery-kit create --format words          # 24 BIP39 words, shown once
ndn-fwd recovery-kit create --format file --out kit # SafeBag under a kit passphrase
ndn-fwd recovery-kit create --format yubikey        # P-256 on a second token
ndn-fwd recovery-kit list | check <kit> | revoke <key>
ndn-fwd recover --kit words --old-root destroyed     # on a replacement device
```

The recovery key is named `<ns>/KEY/r<hex>` from its public key, so a word
list alone rebuilds it; the last word's checksum refuses a mistyped list.
`recover` makes a new root, CA key and admin identity with fresh key ids,
and the recovery key signs the version that lists the new root —
keeping the old root an anchor (`--old-root destroyed`: devices keep their
certificates and renew with the new CA) or revoking it with the old CA and
admin keys (`--old-root compromised`: devices enroll again). The new root
then signs the next version, so its fingerprint is the expected fingerprint
of anchor links and invites from then on. Nodes that missed the recovery
follow these versions one by one, from any node that kept them. See
[Recovery kits and `ndn-fwd recover`](../reference/recovery.md).

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
