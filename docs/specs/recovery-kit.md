# Recovery kits and namespace recovery

- **Status:** Draft
- **Scope:** The three recovery-kit formats (words, file, YubiKey), how a
  recovery key is derived and named, how a recovery anchor is added to and
  removed from a namespace's trust context, and the recovery procedure that
  replaces a lost root device (versions `N+1` and `N+2`). The goal is that a
  kit made by one implementation restores in another. This document covers
  flows F7 (create a recovery kit) and F8 (restore after losing the root
  device) of [personal-namespace.md](personal-namespace.md).
- **Out of scope:** the trust-context wire format and the continuity rule
  ([trust-context.md](trust-context.md)), the `ndn-trust://` container
  ([trust-envelope.md](trust-envelope.md)), and the identity-level "recovery
  bundle" (`ndn-trust://recovery/…`, envelope kind 4) used by ndn-mobile.
  That bundle is a separate mechanism; see §9, Q7.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174)
when, and only when, they appear in all capitals, as shown here.

## 1. Terminology

- **Namespace** `<ns>`: an NDN name prefix owned by one person, e.g.
  `/home/bob`.
- **Trust context**: the signed, versioned Data at
  `<ns>/32=trust-context/v=<N>` that lists the namespace's anchors, schema,
  CA endpoints, revocations and key roles ([trust-context.md](trust-context.md)).
  `N` is its *version*.
- **Root**, **root device**: the namespace's root key and the device whose
  root store holds it. A device is the root device when its root key's
  public key is one of the anchors of the context it holds.
- **Recovery key**: a key of its own, never a copy of the root.
- **Recovery anchor**: an anchor of the trust context whose key name carries
  the key role `recovery-anchor` (KeyRole code 1).
- **Recovery kit**: what the owner keeps offline to use the recovery key
  later: 24 words, a sealed file, or a second YubiKey.
- **Continuity rule**: a node holding version `N` adopts version `M > N`
  only if `M` verifies under one of `M`'s own anchors, and the key that
  signed it is an anchor of `N` ([trust-context.md](trust-context.md)).
- **Expected fingerprint**: SHA-256 over the `public_key` of an anchor
  certificate, as decoded per §3.3. For Ed25519 that is the raw 32-byte key;
  for P-256 it is the 91-byte SPKI DER. An anchor link or invite carries it
  to authenticate the signer of a trust context.
- **Adopt**: take a trust context as the held one, either by expected
  fingerprint or by the continuity rule.
- **Hand over**: give a version signed in a CLI process to the local
  daemon, which adopts, stores and publishes it.
- **Relay**, **route**, **link**, **enroll**, **invite**, **approval**: as
  in [personal-namespace.md](personal-namespace.md).

Byte strings are shown in lowercase hex. "TLV" means NDN TLV with
VAR-NUMBER type and length (NDN packet spec §1.2).

## 2. Overview (informative)

A recovery kit holds a **separate** recovery key. Its self-signed
certificate is added to the trust context as an extra anchor, marked
`recovery-anchor`, in a version that the root signs (§5.1). Like every
anchor, it can sign the next version of the context. When the root device
is lost, the recovery key signs version `N+1`, which installs a new root.
The new root then signs `N+2` with the same content, so the newest version
is root-signed again (§6). Every node holding `N` follows `N` → `N+1` →
`N+2` by the continuity rule.

| Format | Key | Kit carries | Opened with |
|---|---|---|---|
| `words` | Ed25519 | 24 BIP39 English words (nothing stored) | the words |
| `file` | Ed25519 | `ndn-trust://bag` envelope: PBES2-sealed key + anchor cert + namespace + expected fingerprint | the kit passphrase |
| `yubikey` | ECDSA P-256 | the key, generated in a PIV slot of a second token and never exportable | the token's PIV PIN (and touch) |

## 3. Recovery key and its name

### 3.1 Canonical public key

The **canonical public key** of a recovery key is:

- **Ed25519**: the raw 32-byte public key (RFC 8032). If an implementation
  has the key as a 44-byte RFC 8410 SPKI (prefix
  `302a300506032b6570032100`), it MUST strip the 12-byte prefix first.
- **ECDSA P-256**: the 91-byte DER SubjectPublicKeyInfo. This is the 26-byte
  prefix `3059301306072a8648ce3d020106082a8648ce3d030107034200` followed by
  the 65-byte uncompressed point `04 || X || Y`. It is used as is.
  Compressed points MUST NOT be used.

### 3.2 Recovery key name

```
recovery_key_name(<ns>, pk) = <ns> / "KEY" / ("r" || lowerhex(SHA-256(canonical(pk))[0..8]))
```

- `"KEY"` and the key-id component are both **GenericNameComponent** (TLV
  type `0x08`).
- The key id is exactly 17 ASCII bytes: `r` followed by 16 lowercase hex
  digits (the first 8 bytes of the digest). Implementations MUST emit
  lowercase. ndn-rs compares names byte for byte, so it refuses a file kit
  whose key name uses uppercase hex (§4.2.3 step 4).
- In every case, the key id equals the first 8 bytes of the key's expected
  fingerprint (§1). This holds because the anchor certificate's decoded
  public key is the canonical public key (§3.3).
- The name depends on `<ns>`: the same words in another namespace give the
  same key under another name.

An implementation that signs with a recovery key MUST put this exact name
in the KeyLocator. A trust context is opened by resolving its KeyLocator to
one of its anchors by key name (`<ns>/KEY/<id>`, or a certificate name under
it). A recovery key named any other way does not resolve.

### 3.3 Recovery anchor certificate

The recovery anchor is a self-signed certificate (NDN Certificate Format v2)
made by the recovery key:

| Field | Value |
|---|---|
| Name | `<ns>/KEY/r<16 hex>/self/<version>`; `self` is a GenericNameComponent, `<version>` a VersionNameComponent (type `0x36`) holding the issuance time in ms since the Unix epoch, as a NonNegativeInteger |
| MetaInfo | ContentType (`0x18`) = 2 (KEY); FreshnessPeriod (`0x19`) = 3 600 000. ndn-rs writes both as 8-byte NonNegativeIntegers |
| Content | DER SPKI: the 44-byte RFC 8410 form for Ed25519; the 91-byte form of §3.1 for P-256 |
| SignatureType | 5 (Ed25519) for word and file kits; 3 (SHA256withECDSA, DER signature) for YubiKey kits |
| KeyLocator | Name = the recovery key name (§3.2) |
| ValidityPeriod (`0xfd`) | NotBefore (`0xfe`) = the issuance time; NotAfter (`0xff`) = `25540721T233433` (ndn-rs formats `u64::MAX` ns that way; it means "never expires") |

On decode, a Content that is a 44-byte Ed25519 SPKI is unwrapped to the raw
key. Any other Content is kept as is. The result is the certificate's
`public_key`, the input to both the name (§3.2) and the expected
fingerprint.

When the anchor is added (§5.1), the certificate MUST be valid at that
moment (`NotBefore ≤ now ≤ NotAfter`). Otherwise ndn-rs refuses it
(`AnchorNotValid`).

## 4. Kit formats

### 4.1 Word kit (`words`)

#### 4.1.1 Words → key

1. **Wordlist**: the BIP-39 English wordlist (2048 words). No other language
   is accepted.
2. **Entropy**: exactly 256 bits (32 bytes). That gives 24 words: 256
   entropy bits plus an 8-bit checksum (the first 8 bits of
   SHA-256(entropy)), split into 24 groups of 11 bits, per BIP-39.
3. **Key derivation**: the 32 entropy bytes **are** the Ed25519 secret key
   (the RFC 8032 32-byte private key, expanded with SHA-512 as RFC 8032
   §5.1.5 specifies). There is no BIP-39 passphrase, no BIP-39
   PBKDF2-HMAC-SHA512 "seed", no HKDF, no SLIP-0010 / BIP-32 derivation and
   no slicing. Implementations MUST NOT use the BIP-39 64-byte seed; the
   test vectors show both values so the mistake is easy to detect.
4. The key name is `recovery_key_name(<ns>, pk)` (§3.2).

#### 4.1.2 Words → text and back

- **Emitting**: the 24 words in BIP-39 order, lowercase, separated by a
  single ASCII space. The ndn-fwd CLI shows them once, numbered `1.`–`24.`,
  and stores nothing about them.
- **Parsing**: an implementation MUST accept any whitespace between words
  and any letter case. ndn-rs splits on Unicode whitespace and lowercases
  each character before matching. It MUST refuse the input, before
  anything is signed, when:
  - the word count is not 24;
  - a word is not on the list (prefixes and abbreviations are refused);
  - the checksum does not match (a word mistyped or two swapped).

  ndn-rs reports only the position of an unknown word, never the word
  itself.

The ndn-fwd CLI reads the words from the `NDN_KIT_WORDS` environment
variable, else from the **first line** of `--words-file`, else from the
terminal (informative).

### 4.2 File kit (`file`)

A file kit is a text file whose content, ignoring leading and trailing
whitespace, is one `ndn-trust://bag/<base64url>` URI
([trust-envelope.md](trust-envelope.md)). ndn-rs writes the URI followed
by `\n`, in a file readable by the owner only. When reading, ndn-rs also
accepts exactly the `https://<domain>/t/bag#<base64url>` mirror form
(`http://` and other paths are refused). No binary file form exists
([trust-envelope.md](trust-envelope.md) §5.7).

#### 4.2.1 Envelope

base64url uses the URL-safe alphabet with no padding (RFC 4648 §5). The
decoded bytes are:

```
TrustEnvelope (0x0470) {
  FormatVersion (0x0471) = 01
  Kind          (0x0472) = 05                  ; bag
  Body          (0x0473) {
    KeyName           (0x0488) = UTF-8 NDN URI of the recovery key name, e.g. "/home/bob/KEY/rb2e88ab584a63a2c"
    Wire              (0x0482) = SafeBag TLV (§4.2.2)
    Namespace         (0x0489) = UTF-8 NDN URI of <ns>                 ; REQUIRED for a recovery kit
    AnchorFingerprint (0x048e) = 32 bytes                              ; OPTIONAL
  }
}
```

- The encoder writes fields in the order shown. Decoders MUST accept any
  order and decode the envelope as
  [trust-envelope.md](trust-envelope.md) specifies. ndn-rs refuses a URI
  kind that differs from the TLV `Kind`, a repeated field, an unknown
  critical type and trailing bytes; it ignores unknown non-critical
  fields.
- `Namespace` is what makes a bag a recovery kit. ndn-rs refuses a bag
  without it as "not a recovery kit".
- `AnchorFingerprint` is the expected fingerprint of the namespace **when
  the kit was made**: the fingerprint of the anchor whose public key is the
  root store's. ndn-rs always writes it when the root's anchor is found in
  the held context. During recovery it is used only when the device holds
  no context (§6.2, row "not held"), and only as an expected fingerprint:
  it MUST match the anchor that signed the version adopted, as for any
  anchor link ([trust-envelope.md](trust-envelope.md)). A reader MUST NOT
  accept it because it matches a listed anchor or the signer of an older
  version.
- After a version that changes the root (a recovery's `N+2`, §6.5), the
  field is stale. Adoption by it then fails, and the operator adopts the
  namespace with a current anchor link first (ndn-fwd says so). The kit
  itself still recovers a device that holds the context. The field is
  outside the sealed key, so an implementation MAY rewrite it with the
  current expected fingerprint without the passphrase. ndn-rs has no
  command for that; `recovery-kit create` makes a kit with the current
  one.

#### 4.2.2 SafeBag

The SafeBag uses the ndn-cxx SafeBag layout:

```
SafeBag (0x80) {
  Data (0x06) { the recovery anchor certificate of §3.3, complete wire }
  EncryptedKey (0x81) { DER EncryptedPrivateKeyInfo (RFC 5958) }
}
```

`EncryptedPrivateKeyInfo` as ndn-rs writes it:

| Element | Value |
|---|---|
| encryptionAlgorithm | id-PBES2 `1.2.840.113549.1.5.13` |
| keyDerivationFunc | id-PBKDF2 `1.2.840.113549.1.5.12` |
| salt | OCTET STRING, 16 random bytes |
| iterationCount | 600 000 |
| keyLength | absent |
| prf | hmacWithSHA256 `1.2.840.113549.2.9`, parameters NULL (always encoded explicitly) |
| encryptionScheme | aes256-CBC `2.16.840.1.101.3.4.1.42`, IV = 16 random bytes |
| encryptedData | AES-256-CBC with PKCS#7 padding over the PKCS#8 below |

The plaintext is the Ed25519 private key as a PKCS#8 **v1**
PrivateKeyInfo (RFC 8410 §7), 48 bytes:

```
30 2e  02 01 00                          ; version 0 (v1)
       30 05 06 03 2b 65 70              ; id-Ed25519
       04 22 04 20 <32-byte secret key>  ; CurvePrivateKey
```

Encoders MUST emit v1: BoringSSL, and so Chrome's WebCrypto, refuses a
PrivateKeyInfo whose version is not 0. Decoders MUST accept v1 and the
RFC 5958 v2 OneAsymmetricKey (version 1, with `[1] publicKey`). With v2,
the public key MUST match the secret key; ndn-rs (ed25519-dalek) refuses
it otherwise. ndn-rs wrote v2 (83 bytes) before 2026-10-18; those kits
still open (§8.4).

**Password**: the passphrase in Unicode Normalization Form C (NFC), as
UTF-8 octets, as in the RFC 8265 OpaqueString profile. An encoder MUST
normalize a UTF-8 passphrase to NFC before sealing. A reader MUST first try
the octets as given. If they fail and are UTF-8 not in NFC, it MUST then
try their NFC form. Kits sealed before this rule (ndn-rs before
2026-10-18) used the octets as given, and the first try still opens them.
Octets that are not UTF-8 are used as given. The ndn-fwd CLI passes the
UTF-8 bytes of the text. From the terminal it strips the trailing CR/LF.
From `--kit-passphrase-file` it takes the first line and strips a trailing
`\r`. It also reads `NDN_KIT_PASSPHRASE` verbatim. An empty passphrase
MUST be refused.

Encoders MUST use the parameters above. Decoders MUST accept them. ndn-rs
also opens other PBES2 parameter sets:

- PBKDF2 with HMAC-SHA-224/256/384/512, or scrypt;
- AES-128/192/256-CBC.

It refuses hmacWithSHA1 (pkcs5 0.7.1 without `sha1-insecure`).

**Cost cap.** A reader MUST refuse a kit whose PBKDF2 `iterationCount` is
above 10 000 000, before asking for the passphrase: a crafted kit could
otherwise take hours to open. ndn-rs applies this cap to every SafeBag it
decrypts (`MAX_PBKDF2_ITERATIONS`). It also refuses scrypt whose
`128 · N · r · p` exceeds 2^30 bytes (`MAX_SCRYPT_WORK`; `N = 2^20, r = 8,
p = 1` passes).

#### 4.2.3 Reading and opening a file kit

A reader MUST perform these checks, in this order, before asking for the
passphrase:

1. Decode the URI and envelope. It MUST be kind 5 (bag) and carry
   `Namespace`.
2. Parse `Namespace` and `KeyName` as NDN names, and decode the SafeBag.
3. Decode the Data inside the SafeBag as a certificate.
4. Refuse the kit unless the certificate's key name (its name without the
   last two components) equals `KeyName`, **and**
   `recovery_key_name(Namespace, cert.public_key)` equals `KeyName`.

5. Refuse the kit if its key derivation is above the cost cap (§4.2.2).

To open the kit:

6. Decrypt `EncryptedKey` with the passphrase (as given, then its NFC
   form, §4.2.2) and decode an Ed25519 key from the PKCS#8. If no try
   gives a key, report a wrong passphrase.
7. Refuse the kit unless the decrypted key's public key equals the
   certificate's public key, comparing in canonical form (§3.1).

ndn-rs does not verify the certificate's self-signature when reading a
kit. Trust comes from the context: the key must be a recovery anchor of
the held version (§6.3).

### 4.3 YubiKey kit (`yubikey`)

The key is generated on a PIV token and never leaves it. To restore in
another implementation, plug in the token. Nothing is exported.

| Item | Rule |
|---|---|
| Algorithm | PIV `ECCP256` (ECDSA P-256) |
| Slot | `9a`, `9c`, `9d` or `9e`, case-insensitive. Default `9d` (KEY MANAGEMENT) |
| PIN policy | `always`: the PIN is verified before each signature |
| Touch policy | `always` (default), `cached` or `never`, as the owner chooses |
| Management key | generation authenticates with the factory-default PIV management key |
| Public key | after generation, the SPKI built from the returned point (§3.1). When opening later, the slot's public key comes from PIV GET METADATA (firmware 5.3 or later) |
| Firmware | 5.3 or later. Creation MUST be refused on older firmware, before anything is generated: such a kit could never be opened, because reading its key back needs GET METADATA |
| Signature | ECDSA over SHA-256 of the signed region, DER-encoded, SignatureType 3 |
| Name | `recovery_key_name(<ns>, SPKI)` (§3.2) |

Slot guard (MUST):

- The kit's key MUST NOT be generated on the token that holds the
  namespace's root. Compare token serials.
- A recovery MUST NOT generate the new root on the kit's token (§6.4).
- Generation into a slot that holds a key, or whose state the token cannot
  report, MUST be refused unless the operator explicitly allows replacing
  it (`--replace-slot`).

ndn-rs writes no PIV certificate object to the slot. Another
implementation MUST identify the key by the slot's public key, not by a
stored certificate.

## 5. Adding and removing a recovery anchor (F7)

Both operations run on the root device: a device whose root store's public
key is an anchor of the held context. Each makes version `N+1` from the
held version `N`, signed by an anchor of `N` (the root). `N+1` MUST satisfy
the continuity rule against `N` before it is handed over.

### 5.1 Create

1. Generate the recovery key: 32 random bytes for `words`/`file`, or a key
   on the token for `yubikey`. Make its anchor certificate (§3.3).
2. **File kit only:** write the kit file (§4.2) **before** the root signs.
   The `AnchorFingerprint` is the fingerprint of the anchor of `N` whose
   public key is the root store's. If step 4 ends in a *refusal*, delete
   the file. A kit file MUST NOT overwrite an existing file.
3. Version `N+1` = the content of `N`, carried over unchanged, plus:
   - the anchor certificate added to the anchor set;
   - a `KeyRole` entry (`0x041e`) with value `01 || Name-TLV(recovery key
     name)`, unless the same entry already exists.

   Refuse if the recovery key's public key is already an anchor of `N`.
4. Hand over `N+1` (§7).
5. **Word kit only:** show the 24 words (§4.1.2) once the outcome is known.
   ndn-fwd also shows them when the outcome is *unknown* (§7), because the
   version may still be adopted. The kit is kept so that no anchor exists
   without its kit.

Several kits may coexist. Every later version MUST carry over every
`KeyRole` entry it does not deliberately change.

### 5.2 Revoke

Version `N+1` = the content of `N`, with these changes:

- remove every anchor certificate whose key name is the kit's key;
- remove every `KeyRole` entry naming that key;
- add a `Revocation` (`0x0418`) for the key name, unless it is already
  revoked.

Refuse the revocation if:

- the key is not marked `recovery-anchor` in `N`;
- the signer's public key is an anchor certificate of that key (a key
  cannot sign its own removal).

### 5.3 Check (informative)

`recovery-kit check` opens a kit (§4) and confirms that its public key is a
recovery anchor of the held version (§6.3). It signs nothing.

## 6. Recovery (F8)

### 6.1 Preconditions

On the replacement device, before anything is generated or signed:

1. The device MUST NOT already hold a root store. If it holds one for this
   namespace, it is the root device and there is nothing to recover; one
   for another namespace is a conflict. In ndn-fwd the PIB must also hold
   no CA certificate files.
2. The operator MUST state what happened to the old root device:
   `destroyed` or `compromised` (§6.4). There is no default.
3. The held version MUST be the newest one (§6.2).
4. The held version MUST verify under its own anchors (self-consistency).
5. The kit's public key MUST be a recovery anchor of that version (§6.3).
   With `compromised`, every kit named to keep MUST be one too.

### 6.2 Anti-fork decision

Recovering from a version older than one that exists would make two
different versions with the same number: a fork. Before recovering, the
device asks the namespace for its newest version by name, the same as a
context refresh. The outcome decides:

| Refresh outcome | Meaning | Recovery |
|---|---|---|
| Updated | a newer version was adopted | proceed from it |
| Current | the namespace serves the held version | proceed |
| UpstreamOlder | what answered serves an older version than held | proceed from the held version |
| Behind | a newer version is known to exist (its signed Data passed the continuity rule over sync) but is not held | MUST refuse; refresh until it is held |
| Unreachable | nothing answered | MUST refuse, unless the operator explicitly vouches that no newer version exists (`--from-held`). Then proceed from the held version, and report it as not confirmed |
| Failed | the check failed, or a version answered and was refused | MUST refuse |
| Source | this device holds the root key | MUST refuse (it is the root device) |
| not held | the device holds no context for the namespace | adopt first: with a file kit, by its `Namespace` + `AnchorFingerprint` (a fingerprint-only anchor link, [trust-envelope.md](trust-envelope.md)); with words or YubiKey, MUST refuse and ask for the namespace's anchor link |

A context fetched with nothing to authenticate it MUST NOT be recovered
from. A forgery could list the kit's public anchor, and the recovery key
would then sign it.

After the decision, the version the recovery starts from MUST equal the
version the device holds and stores. ndn-fwd checks the daemon's answer
against the copy in `<pib>/contexts/`.

### 6.3 Matching the kit to the context

The kit's key is found by **public key**, not by name. It is the anchor of
the held context whose certificate `public_key` equals the kit's canonical
public key; an Ed25519 SPKI is unwrapped before comparing. That anchor's
key name MUST carry KeyRole `recovery-anchor`. If no anchor matches, the
kit was never added, has since been revoked, or belongs to another
namespace. An anchor that matches but is not marked `recovery-anchor`
(e.g. the root) is refused too.

### 6.4 Version `N+1` (signed by the recovery key)

Fresh keys first. Each uses `new_key_name`: `<identity>/KEY/<16 lowercase
hex>` from 8 random bytes, all GenericNameComponents.

- **New root** `<ns>/KEY/<id>`, in the root store the operator chooses.
  It is never on the kit's token. Its self-signed anchor certificate follows
  §3.3, with the root's own key and signature type.
- **New CA key** `<ns>/CA/KEY/<id>`, certified by the new root (issuer id
  `NA`).
- **New admin device identity** `<ns>/admin/<device>`, with key
  `<ns>/admin/<device>/KEY/<id>`, certified by the new CA (issuer id
  `NDNCERT`).

`N+1` starts as the content of `N`: anchors, schema, CA endpoints,
enrollment hint, revocations, link policy and key roles. Then:

1. Remove every `root-device` (2) KeyRole entry.
2. Add `root-device` entries for the new CA key, then the new admin device
   key.
3. Add the new root's anchor certificate.
4. Sort the anchors of `N` into:
   - **kits**: those whose key is marked `recovery-anchor`;
   - **old root keys**: every other anchor.

**`destroyed`:** nothing more. Every anchor of `N` stays, including the old
root and every kit, and no revocation is added. Naming kits to keep MUST be
refused.

**`compromised`:**

5. The kits kept are the signing kit plus the kits the operator names. Every
   other kit is a *removed kit*. Remove its `recovery-anchor` entry.
6. Remove from the anchor set every certificate whose key is an old root key
   or a removed kit.
7. The *old root-device keys* are the keys marked `root-device` in `N`. If
   there are none (a namespace made before roles were recorded), use
   `<ns>/CA/KEY/ca`.
8. For each old root key, old root-device key and removed kit, add a
   `Revocation` for the key name, unless it is already revoked. Refuse the
   whole recovery if such a name is a prefix of a remaining anchor's
   certificate name. Revocation entries are encoded in canonical name
   order ([trust-context.md](trust-context.md) §3.2), so the order in which
   they are added does not matter.

Then:

- Sign `N+1` with the recovery key, its KeyLocator being the recovery key
  name (§3.2).
- Check that it satisfies the continuity rule against `N`. It does, because
  the recovery key is an anchor of `N`, and with both choices it stays an
  anchor of `N+1`.

### 6.5 Version `N+2` (signed by the new root)

`N+2` has exactly the content of `N+1`, version `N+2`, signed by the new
root. It is an anchor of `N+1`, so `N+2` follows by the continuity rule. Once
`N+2` is adopted, the namespace's expected fingerprint is the new root's.
Anchor links and invites minted from then on MUST carry it. Links and
invites made before carry the old root's fingerprint and no longer adopt
the namespace on a device that holds nothing.

An implementation MUST NOT print or publish an anchor link carrying the
recovery key's fingerprint. Until `N+2` is taken, no anchor link is
produced.

### 6.6 Publication and other nodes

The recovering device MUST keep and serve both `N+1` and `N+2` at their
names (`<ns>/32=trust-context/v=<N+1>` and `v=<N+2>`). Every other node:

- adopts `N+1` (signed by an anchor of `N`), then `N+2` (signed by an anchor
  of `N+1`);
- if it misses them, follows the versions in between by exact name, oldest
  first, each under the continuity rule from the one before. At most 128
  versions are followed (`MAX_CATCH_UP_VERSIONS`).

A node that fetches only `N+2` while holding `N` MUST NOT adopt it
directly: `N+2` is not signed by an anchor of `N`. It walks instead.

## 7. Hand-over and undo rules

Any implementation that signs a version in one process and has another
process adopt it MUST follow these rules. In ndn-fwd, the CLI signs and
the daemon adopts through `security/context-update` (informative).

**Outcome.** A hand-over has exactly three outcomes:

- **taken**: the adopter answered that it adopted the version;
- **refused**: nothing was handed over, or the adopter answered that it did
  not adopt it;
- **unknown**: the version was handed over and no answer says what became
  of it.

**Undo only on refusal.** Work made for a version (a kit file, a new root
store, new keys and certificates) MAY be undone only when the outcome is
*refused*. On *unknown*, nothing may be undone: the adopter may still adopt
the version. The operator is told how to find the outcome later.

**Idempotent retry.** The adopter MUST answer *taken* (ndn-fwd: `200`) for
a version it already adopted and stores byte for byte. A requester that
gets no answer within its wait (ndn-fwd: 30 s) MUST send the **same bytes**
again, never a re-signed version. A requester MUST bound these resends, and
the outcome when it stops is *unknown*. ndn-fwd:

- ends with *unknown* after 10 waits without an answer in all
  (`HAND_OVER_WAITS`, about five minutes), and sends nothing after the
  last;
- ends with *unknown* after 2 consecutive other transport failures once a
  request was sent.

**No adopter running.** If nothing listens (socket missing or connection
refused), ndn-fwd stores the version in the PIB for the adopter's next
start, unless a byte-identical copy is already stored. A requester MUST
refuse to hand a version to an adopter that uses a different PIB: that
adopter would adopt the version while this PIB stays behind, and the next
version made here would fork it.

**Recovery order.**

1. Hand over `N+1`:
   - *refused*: undo everything §6.4 wrote (root store, the three keys, the
     PIB trust anchor, the certificate files) and stop;
   - *unknown*: keep everything, and tell the operator how to check which
     version the adopter stores.
2. Only after `N+1` is *taken*, hand over `N+2`. Nothing is undone from this
   point on, because `N+1` names the new root. If `N+2` is not taken, the
   newest version stays signed by the recovery key until the new root signs
   a later one. ndn-fwd tells the operator to run `recovery-kit create`,
   which makes the root sign the next version.

## 8. Test vectors

Namespace `/home/bob`; Name TLV `070b0804686f6d650803626f62`.

### 8.1 Words → key → name (vector A: all-zero entropy)

```
words      = abandon abandon abandon abandon abandon abandon abandon abandon
             abandon abandon abandon abandon abandon abandon abandon abandon
             abandon abandon abandon abandon abandon abandon abandon art
entropy    = 0000000000000000000000000000000000000000000000000000000000000000   (= Ed25519 secret key)
BIP39 seed = 408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70
             5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840   (NOT USED)
public key = 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
SHA-256(pk)= 139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070
key name   = /home/bob/KEY/r139e3940e64b5491
Name TLV   = 07230804686f6d650803626f6208034b455908117231333965333934306536346235343931
```

### 8.2 Words → key → name (vector B: BIP-39 reference entropy)

```
words      = hamster diagram private dutch cause delay private meat slide toddler
             razor book happy fancy gospel tennis maple dilemma loan word shrug
             inflict delay length
entropy    = 68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c   (= Ed25519 secret key)
BIP39 seed = 17e4b5661796eeff8904550f8572289317ece7c1cc1316469f8f4c986c1ffd7b
             9f4c3aeac3e1713ffc21fa33707d09d57a2ece358d72111ef7c7658e7b33f2d5   (NOT USED)
public key = 7d2cb63ef6edcc26ff3024e8c99fb1f845a863e575cb1a9966ae9194e0985439
SHA-256(pk)= b2e88ab584a63a2c7aed693647da49dd06f747f31b3b26fb3e3ee5e12bb220be   (= expected fingerprint of its anchor)
key name   = /home/bob/KEY/rb2e88ab584a63a2c
Name TLV   = 07230804686f6d650803626f6208034b455908117262326538386162353834613633613263
PKCS#8     = 302e020100300506032b65700422042068a79eaca2324873eacc50cb9c6eca8cc68ea5d9
             36f98787c60c7ebc74e6ce7c                                          (v1, §4.2.2)
PKCS#8 v2  = 3051020101300506032b65700422042068a79eaca2324873eacc50cb9c6eca8cc68ea5d9
             36f98787c60c7ebc74e6ce7c8121007d2cb63ef6edcc26ff3024e8c99fb1f845a863e5
             75cb1a9966ae9194e0985439                                          (as ndn-rs wrote before 2026-10-18)
```

The same name results when the public key is given as its 44-byte SPKI
(`302a300506032b6570032100 || pk`).

These variants of vector B were also checked:

- Upper case with tabs and extra spaces between the words, plus leading and
  trailing whitespace: accepted, same key.
- The first two words swapped: refused, "the checksum does not match: a
  word is mistyped, or two are swapped".
- The first 23 words only: refused, "23 words; a recovery kit has 24".

KeyRole entry for this key, assembled by hand from §5.1 step 3, not
produced by running code:

```
fd041e 26 01 07230804686f6d650803626f6208034b455908117262326538386162353834613633613263
```

### 8.3 P-256 (YubiKey-style) name

The 91-byte SPKI is hashed whole. The key is P-256 from the private scalar
`2222…22`, standing in for a token key:

```
SPKI     = 3059301306072a8648ce3d020106082a8648ce3d03010703420004d65a93977caa3d1b
           081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a
           137557e473fddb6755f05bd507c3c533fce9c91285
key name = /home/bob/KEY/rbfcba2b742a807bb
```

### 8.4 File kit (vector B key)

Passphrase `correct horse battery staple` (ASCII). The `AnchorFingerprint`
is the root's: the root here is the Ed25519 key from the secret key
`1111…11`, whose public key is
`d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737`, giving
fingerprint `10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d`.
The salt, IV and timestamps are random or time-dependent, so this kit is a
fixed artifact to **open**, not one to reproduce byte for byte.

```
ndn-trust://bag/_QRw_QJM_QRxAQH9BHIBBf0Ec_0CPP0EiB8vaG9tZS9ib2IvS0VZL3JiMmU4OGFiNTg0YTYzYTJj_QSC_QHigP0B3gb9AREHMwgEaG9tZQgDYm9iCANLRVkIEXJiMmU4OGFiNTg0YTYzYTJjCARzZWxmNggAAAGhUJ-pERQUGAgAAAAAAAAAAhkIAAAAAAA27oAVLDAqMAUGAytlcAMhAH0stj727cwm_zAk6MmfsfhFqGPldcsamWaukZTgmFQ5FlQbAQUcJQcjCARob21lCANib2IIA0tFWQgRcmIyZTg4YWI1ODRhNjNhMmP9AP0m_QD-DzIwMjYxMDE4VDIwMDY0M_0A_w8yNTU0MDcyMVQyMzM0MzMXQPiZ1DoBYjjq1HQ8z_qAQk53C6d49mZmNr7bX3X4vTlNKxPvAtYIQuJraq914rTSobKvGWaQUd2S6WmIEVUKkAuBxzCBxDBgBgkqhkiG9w0BBQ0wUzAyBgkqhkiG9w0BBQwwJQQQKh87KEgz5nOJidEzLms8agIDCSfAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBALEkrH8MkRg6QsnUCfJ8PBBGCDLlU143SIGMAj_EYTTDrn-bJs4KgbIQDveIo9gW4m0Fv76qt0qHiae47y5rl2C8ygz9GlO3a37_t-oXW1DfIjIO25zATNwN3T5Dv9gOE3nazOwbgDG2fc3WJ2FI-mypz9BIkJL2hvbWUvYm9i_QSOIBC6aCyK0TUTlx6LVogaq4vXAruAd5bsqBkyxzWpTW5t
```

Structure of the decoded envelope:

```
fd0470 fd024c                                    TrustEnvelope, 588 bytes
  fd0471 01 01                                   FormatVersion 1
  fd0472 01 05                                   Kind 5 (bag)
  fd0473 fd023c                                  Body
    fd0488 1f 2f686f6d652f626f622f4b45592f7262326538386162353834613633613263
                                                 KeyName "/home/bob/KEY/rb2e88ab584a63a2c"
    fd0482 fd01e2                                Wire
      80 fd01de                                  SafeBag
        06 fd0111 …                              anchor certificate (below)
        81 c7 30 81c4 …                          EncryptedKey (below)
    fd0489 09 2f686f6d652f626f62                 Namespace "/home/bob"
    fd048e 20 10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d
                                                 AnchorFingerprint
```

Anchor certificate (inside the SafeBag):

```
06 fd0111
  07 33 0804686f6d65 0803626f62 08034b4559 08117262326538386162353834613633613263
        080473656c66 3608000001a1509fa911          /home/bob/KEY/rb2e88ab584a63a2c/self/v=1792354003217
  14 14 1808 0000000000000002 1908 000000000036ee80      ContentType KEY, FreshnessPeriod 3600000
  15 2c 302a300506032b6570032100 7d2cb63ef6edcc26ff3024e8c99fb1f845a863e575cb1a9966ae9194e0985439
  16 54 1b0105                                            SignatureType 5 (Ed25519)
        1c25 0723 0804686f6d65 0803626f62 08034b4559 08117262326538386162353834613633613263
        fd00fd26 fd00fe0f 323032363130313854323030363433   NotBefore 20261018T200643
                 fd00ff0f 323535343037323154323333343333   NotAfter  25540721T233433
  17 40 f899d43a016238ead4743ccffa80424e770ba778f6666636bedb5f75f8bd394d
        2b13ef02d60842e26b6aaf75e2b4d2a1b2af19669051dd92e9698811550a900b
```

EncryptedPrivateKeyInfo:

```
30 81c4
  30 60
    06 09 2a864886f70d01050d                       id-PBES2
    30 53
      30 32
        06 09 2a864886f70d01050c                   id-PBKDF2
        30 25
          04 10 2a1f3b284833e6738989d1332e6b3c6a   salt
          02 03 0927c0                             iterationCount 600000
          30 0c 06 08 2a864886f70d0209 05 00       prf hmacWithSHA256
      30 1d
        06 09 60864801650304012a                   aes256-CBC
        04 10 0b124ac7f0c91183a42c9d409f27c3c1     IV
  04 60 832e5535e3748818c023fc46134c3ae7f9b26ce0a81b2100ef788a3d816e26d0
        5bfbeaab74a8789a7b8ef2e6b9760bcca0cfd1a53b76b7effb7ea175b50df223
        20edb9cc04cdc0ddd3e43bfd80e1379daccec1b8031b67dcdd6276148fa6ca9c
```

Decrypting it with the passphrase yields the PKCS#8 **v2** of §8.2: the
kit was made before encoders switched to v1, and a reader MUST open it.
The kit then opens as `/home/bob/KEY/rb2e88ab584a63a2c`. Opening with the
passphrase `wrong` fails with "the kit passphrase does not open …".

### 8.5 Provenance

§8.1–§8.4 come from a throwaway program run on 2026-10-18 and deleted
afterwards (`ndn-rs/crates/security/ndn-cert/examples/specvec_recovery.rs`,
`cargo run -p ndn-cert --example specvec_recovery`). It used the public
ndn-rs API:

- `RecoverySeed::{from_words, to_words, signer}`, `recovery_key_name`,
  `recovery_anchor`, `seal_file_kit`, `FileKit::{read, open}`;
- `ndn_security::safebag::{SafeBag, ed25519_seed_to_pkcs8}`;
- `TrustEnvelope::{from_uri, encode}`;
- the `bip39` crate's `to_entropy_array` and `to_seed("")`. `to_seed`
  supplied only the "NOT USED" contrast values.

The program asserted that `RecoverySeed` agrees with
`Ed25519Signer::from_seed(entropy)`, and that the words round-trip.

The structural annotations in §8.4 and the KeyRole line in §8.2 were
written by hand from the program's hex output. The v1 PKCS#8 line in §8.2
was assembled by hand from §4.2.2: the v2 line with its version byte set to
0, its `[1] publicKey` removed and its length fixed. ndn-rs's encoder now
writes exactly that layout (`ed25519_seed_pkcs8_is_v1_and_v2_still_opens`,
for another seed).

## 9. Open questions

7. **ndn-mobile namespace recovery.** ndn-boltffi has no namespace
   recovery-kit implementation. Its "recovery" (`make_recoverable` /
   `restore_identity`, envelope kind 4) is a different, identity-level
   mechanism with an Ed25519 seed but no BIP39 and no context versions.
   Should mobile implement this spec (check a kit, recover on a phone as the
   replacement device)? **Recommendation:** yes, through the same
   `ndn_cert::recovery` / `ndn_namespace::admin` code ndn-fwd uses (words
   and file kits first; YubiKey kits once the app reaches PIV over NFC or
   USB), keeping the kind 4 identity bundle a separate mechanism. Until
   then mobile refuses kits (decision Q7 below).

### Decisions

- **Q1 Stale expected fingerprint in file kits.** Adoption by a kit's
  `AnchorFingerprint` matches only the anchor that signed the version
  adopted, never a listed anchor or the signer of an older version. A stale
  fingerprint makes adoption fail, and the operator adopts with a current
  anchor link first. Implementations MAY rewrite the field without the
  passphrase (§4.2.1). Reason: after a `compromised` recovery, the old
  root's holder can sign a fork. Accepting the old fingerprint at any point
  of a chain would let it hand a fresh device its own chain, and a listed
  anchor proves nothing because anyone can list one.
- **Q2 Passphrase normalization.** Encoders seal with the NFC form of a
  UTF-8 passphrase. Readers try the octets as given, then their NFC form
  (§4.2.2). Reason: NFC is the RFC 8265 password normalization, and it
  keeps the meaning of the text (NFKC would fold distinct characters).
  Trying the octets as given first keeps every kit made before this rule
  opening with the same input.
- **Q3 PBKDF2 iteration cap.** Readers refuse `iterationCount` above
  10 000 000 before asking for the passphrase. ndn-rs also caps scrypt at
  `128 · N · r · p ≤ 2^30` (§4.2.2), for every SafeBag it opens. Reason:
  kits are sealed with 600 000, and a crafted kit must not tie a reader up
  for hours.
- **Q4 PKCS#8 version.** Encoders emit v1; decoders accept v1 and v2
  (§4.2.2). Reason: BoringSSL (Chrome's WebCrypto) parses only version 0,
  while OpenSSL and ed25519-dalek read both. ndn-rs reads both, so kits made
  before still open.
- **Q5 YubiKey firmware below 5.3.** Creation refuses such a token before
  anything is generated, with an error that says why (§4.3). Reason: the
  kit could never be opened. Writing a PIV certificate object instead
  would add a second way to find the key that other implementations would
  also have to support.
- **Q6 Unbounded resend on timeouts.** A requester bounds its resends, and
  the hand-over ends as *unknown* (§7). ndn-fwd stops after 10 waits of
  30 s. Reason: a wedged adopter must not hold the CLI forever. *Unknown*
  keeps the undo rule safe, and ndn-fwd already tells the operator how to
  find the outcome.
- **Q7 A file kit given to mobile.** ndn-boltffi keeps a bag's `Namespace`
  and `AnchorFingerprint`. Its `load_identity` refuses a recovery key's
  SafeBag, recognized by a key name derived from the certificate's public
  key (§3.2). The refusal says to use the kit to recover its namespace.
  Reason: a namespace recovery key is root-equivalent and must not become
  a device identity. Whether mobile implements recovery stays open (Q7
  above).
- **Q8 Revocation order.** Producers write `AnchorSet` entries by
  certificate name and `Revocation` entries in canonical NDN name order,
  and decoders accept any order ([trust-context.md](trust-context.md) §3.2,
  Decision Q1). Reason: revocations are a set, and a canonical order gives
  the same content the same bytes, which byte-for-byte hand-over checks
  and test vectors rely on.

## Appendix A. Code references (non-normative)

Paths are relative to the workspace root. Code in `ndn-fwd/binaries/ndn-fwd/src/` may move into library crates (planned `ndn-namespace`); the lines below are as read on 2026-10-18 (rows for the files touched by the §9 decisions re-read after those changes).

| Claim | Location |
|---|---|
| Kit formats, env vars `NDN_KIT_PASSPHRASE`/`NDN_KIT_WORDS`/`NDN_KIT_PIN`, default slot `9d`, 24 words | `ndn-rs/crates/security/ndn-cert/src/recovery.rs:18-31,79-91` |
| Canonical public key (strip Ed25519 SPKI) | `recovery.rs:279-285`; SPKI prefix `ndn-rs/crates/security/ndn-security/src/spki.rs:24-60` |
| `recovery_key_name` (SHA-256, first 8 bytes, lowercase hex, `r` prefix) | `recovery.rs:273-275,289-295` |
| `Name::append` makes GenericNameComponents | `ndn-rs/crates/core/ndn-foundation-types/src/name.rs:317-321` |
| Words parsing: whitespace split, lowercase, count 24, English, checksum, entropy = seed | `recovery.rs:314-356` |
| Words emission | `recovery.rs:359-368`; CLI display `ndn-fwd/binaries/ndn-fwd/src/recovery_kit.rs:503-513` |
| Seed → Ed25519 (`SigningKey::from_bytes`), named by its public key | `recovery.rs:372-376`; `ndn-rs/crates/security/ndn-security/src/signer.rs:62-65` |
| PKCS#8 v1 from seed (`KeypairBytes` without public key); v1 and v2 read, v2 public key checked | `recovery.rs:378-382`; `ndn-rs/crates/security/ndn-security/src/safebag.rs:255-276`; test `safebag.rs` `ed25519_seed_pkcs8_is_v1_and_v2_still_opens` |
| Anchor certificate: `<key>/self/<v>`, validity `u64::MAX` | `recovery.rs:388-398`; `ndn-rs/crates/security/ndn-security/src/manager.rs:162-213` |
| Certificate wire (ContentType 2, Freshness 3600000, SPKI content, ValidityPeriod) | `manager.rs:505-594`; cert name/version `ndn-rs/crates/security/ndn-security/src/cert_name.rs:27-34,74-103` |
| Certificate decode unwraps Ed25519 SPKI | `ndn-rs/crates/security/ndn-security/src/cert_cache.rs:31-61` |
| Expected fingerprint = SHA-256(cert.public_key) | `ndn-rs/crates/security/ndn-security/src/trust_context/mod.rs:1060-1063` |
| P-256 SPKI 91-byte prefix | `signer.rs:147-165` |
| File kit sealing (empty passphrase refused; NFC passphrase; Bag fields) | `recovery.rs:402-444` |
| File kit read checks (Namespace required, name/cert/key match, KDF cost cap before the passphrase) | `recovery.rs:461-516`; test `recovery.rs` `a_file_kit_asking_for_too_many_iterations_is_refused_before_its_passphrase` |
| File kit open (as given then NFC; wrong passphrase; key matches cert) | `recovery.rs:518-539`; `signer.rs:69-72`; test `recovery.rs` `a_file_kit_opens_with_its_passphrase_in_either_unicode_normalization` |
| Envelope TLV numbers, format version 1, kind 5, body order, unknown fields ignored, base64url no pad | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:42-76,89-130,218-229,249-257,311-325,344-372,374-463,465-520` |
| SafeBag TLV 0x80/0x81 | `safebag.rs:7-12,36-37,116-165` |
| PBES2: PBKDF2-HMAC-SHA256, 600000 iterations, 16-byte salt, AES-256-CBC, 16-byte IV | `safebag.rs:167-195` |
| PBES2 accepted on decrypt (no SHA-1); cost cap 10 000 000 PBKDF2 iterations / scrypt 2^30 | `safebag.rs:49-53,65-101,197-220`; `pkcs5-0.7.1/src/pbes2/encryption.rs:83-89,113-140` (crate registry); test `safebag.rs` `a_bag_asking_for_too_costly_a_key_derivation_is_refused_before_deriving` |
| Passphrase bytes, first line of file, trailing CR/LF trimmed, empty refused | `ndn-rs/crates/security/ndn-cert/src/root_store.rs:1424-1466,1494-1503` |
| CLI writes kit + `\n`, owner-only, no overwrite | `recovery_kit.rs:361-370,412-429` |
| YubiKey kit: P-256, PIN policy always, touch default, slots | `recovery.rs:541-660`; `recovery_kit.rs:74-87`; `ndn-rs/crates/security/ndn-security/src/yubikey.rs:17-18,75-93,145-165,286-302,383-427` |
| YubiKey kit refused below firmware 5.3 | `recovery.rs:260-265,557-572,601`; `yubikey.rs:258-276`; test `recovery.rs` `a_yubikey_kit_is_refused_on_firmware_before_5_3` |
| YubiKey signature: SHA-256 digest, ECDSA P-256, SignatureType 3 | `yubikey.rs:439-474` |
| Slot guard (not on root's token, occupied slot refused unless replace) | `ndn-rs/crates/security/ndn-cert/src/root_store.rs:224-267`; `recovery_kit.rs:390-397`; `ndn-fwd/binaries/ndn-fwd/src/recover.rs:218-221` |
| KeyRole codes 1/2, names, TLV 0x041E value = role byte ‖ Name | `trust_context/mod.rs:249-267,991-997`; `ndn-rs/crates/security/ndn-security/src/trust_context/tlv.rs:73-81` |
| Revocation TLV 0x0418 | `tlv.rs:53-54`; `trust_context/mod.rs:807-809` |
| `add_anchor` requires validity now | `trust_context/mod.rs:617-623` |
| KeyLocator resolves to anchor by key name | `trust_context/mod.rs:631-653,1113-1156` |
| Context signed with signer's key name in KeyLocator | `trust_context/mod.rs:879-894` |
| RDR name `<ns>/32=trust-context/v=<N>` | `trust_context/mod.rs:55,827-835` |
| Continuity rule | `ndn-rs/crates/security/ndn-cert/src/context_update.rs:721-756` |
| Version walk, 128 max | `context_update.rs:510,845-880` |
| Kit ↔ anchor match by public key, role required | `recovery.rs:697-727`; `root_store.rs:381-393` |
| Add / remove / reissue | `recovery.rs:731-849` |
| Recovery version rules (`destroyed`/`compromised`, kept kits, revocations, `CoversAnchor`) | `recovery.rs:851-1031` |
| Revocation and AnchorSet encoded in canonical order | `trust_context/mod.rs:802-850` |
| Unrecorded root-device keys → `<ns>/CA/KEY/ca` | `recovery.rs:1000-1004`; `ndn-rs/crates/security/ndn-cert/src/namespace.rs:59-62` |
| Recovery in PIB: preconditions, fresh keys, CA (`NA`) / device (`NDNCERT`) certs, N+1 then N+2, undo | `recovery.rs:1069-1269`; `cert_name.rs:59-69` |
| Root-device check | `recovery_kit.rs:174-187`; `root_store.rs:620-624` |
| Hand-over outcomes, 30 s wait, 10 waits / 2 failures → unknown, resend same bytes, keep for next start, same-PIB check | `ndn-rs/crates/security/ndn-namespace/src/admin.rs:61-70,174-179,213-221,240-318`; `recovery_kit.rs:40-46,191-338`; test `admin.rs` `a_device_that_never_answers_leaves_it_unknown_after_the_last_wait` |
| Daemon `context-update`: idempotent 200 on stored copy, 403 refusal, 409 changed meanwhile | `ndn-fwd/binaries/ndn-fwd/src/context_refresh.rs:335-480` |
| Create order (file before sign, removal on refusal, keep on unknown) | `recovery_kit.rs:356-546` |
| Revoke | `recovery_kit.rs:627-690` |
| Check | `recovery_kit.rs:596-625` |
| Anti-fork table, 60 s fetch, adopt by kit fingerprint | `recover.rs:58-164` |
| RefreshState meanings | `ndn-rs/crates/forwarding/ndn-mgmt/src/lib.rs:596-621`; producers `context_refresh.rs:132-283` |
| Recover CLI: `--old-root` required, root store refused, stored = newest, self-consistency, kit anchor, kept kits, N+1/N+2 hand-over, link only after N+2 | `recover.rs:166-407` |
| ndn-mobile Bag keeps namespace/fingerprint; `load_identity` refuses a recovery key; identity-level recovery | `ndn-mobile/crates/ndn-boltffi/src/trust.rs:136-145,165-200`; `ndn-mobile/crates/ndn-boltffi/src/identity_core.rs:573-610,1561-1660`; test `ndn-mobile/crates/ndn-boltffi/src/engine.rs` `load_identity_refuses_a_namespace_recovery_kit` |
