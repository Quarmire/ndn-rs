# Trust envelopes: `ndn-trust://`

> **Status:** Draft.
> **Scope:** the out-of-band container that hands NDN trust material to a device outside NDN:
> by QR code, deep link, clipboard paste or file. It covers the six envelope kinds, the
> TLV encoding (types `0x0470`–`0x048F`), the text forms (the `ndn-trust://` URI, the `https`
> mirror and the legacy `ndn-ctx:1:` form), base64url, QR parameters and size limits, the
> file and paste forms, and the checks a parser runs. Most payloads are opaque at this layer:
> trust contexts, certificates, SafeBags and delegations are specified elsewhere.
> **Reference implementation:** `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs`
> (codec). Consumers: `ndn-rs/crates/security/ndn-cert` (anchor and invite links, file kits)
> and `ndn-mobile/crates/ndn-boltffi/src/trust.rs` (mobile parser). For file:line references
> see [Appendix A](#appendix-a-code-references-non-normative).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in
all capitals, as shown here.

Related specs:
- [trust-context.md](trust-context.md): the trust context an `anchor` envelope carries or
  points to, and the anchor fingerprint.
- [ndncert-extensions.md](ndncert-extensions.md): the invite token an `invite` envelope
  carries, and the CA it names.
- [recovery-kit.md](recovery-kit.md): the file recovery kit, which is a `bag` envelope.
- [ndn-link.md](ndn-link.md): links. A device usually needs one before it can fetch a context
  that an envelope only points to.
- [local-refusal.md](local-refusal.md): refusals a device may see while adopting.
- The design and flows (F1 create, F2 add a device, F7/F8 recovery kit, F9 share) are in
  [personal-namespace.md](personal-namespace.md).

## 1. Terminology

- **Envelope**: one encoded value of this spec. It is a single TLV element of type
  `0x0470` (§4), or one of the text forms of that element (§5).
- **Kind**: what the envelope transfers: `anchor`, `invite`, `delegation`, `recovery`, `bag`
  or `capability` (§3).
- **Namespace**: an NDN name prefix `/<ns>` owned by one root key. A **root device** holds
  that key.
- **Trust context**: the root-signed Data `/<ns>/32=trust-context/v=<N>`. It lists the
  namespace's anchors, schema, CA endpoints and revocations ([trust-context.md](trust-context.md)).
- **Adopt**: accept a namespace's trust context as authoritative. The context is checked
  against an expected fingerprint.
- **Expected fingerprint**: 32 bytes. It is SHA-256 over the public key of the namespace's
  root anchor certificate (§4.4). An adopted context must be signed by an anchor whose
  fingerprint equals it.
- **Enroll**: obtain a CA-issued certificate for `/<ns>/<role>/<device>`.
- **Invite**: a one-time NDNCERT token that lets a device enroll without an approval.
- **Recovery kit**: material that restores authority over a namespace after the root device
  is lost. A file kit is a `bag` envelope ([recovery-kit.md](recovery-kit.md)).
- **Producer**: software that emits envelopes. **Parser**: software that decodes them.
  **Consumer**: the flow that acts on a decoded envelope (adopt, enroll, recover, pair).
- **Canonical encoding**: the exact bytes the reference implementation emits for a given
  envelope value (§4.3).

Byte strings are written in hex. TLV elements are written `TYPE LENGTH VALUE`.

## 2. Overview

An envelope is unsigned. A consumer gets authenticity from two sources:

1. **The channel.** A QR code shown on the root device's screen, a link from a known person,
   or a file the user wrote.
2. **The expected fingerprint inside the envelope.** It is checked against the signed objects
   the consumer later receives (the context, the issued certificate chain).

Every signed object an envelope carries inline (the context Data, a certificate, a delegation)
is verified by the consumer. The envelope layer never verifies it.

The same TLV bytes are used in every carriage: base64url in a URI or QR code, raw bytes in a
binary file. The kind in a URI is only a routing hint. The `Kind` TLV is authoritative.

## 3. Kinds

| Kind token | Code | Direction | Carries | Consumer |
|---|---|---|---|---|
| `anchor` | `1` | in | Namespace, expected fingerprint, context version, signed context Data (inline and/or by reference) | adopt (F1, F2) |
| `invite` | `2` | in | CA prefix, identity namespace `/<ns>/<role>`, token, remaining lifetime, expected fingerprint | enroll by invite (F2) |
| `delegation` | `3` | in/out | A signed delegation and the principal's public key | device delegation (mobile) |
| `recovery` | `4` | in | A recovery bundle (public history, no private keys) | restore (mobile) |
| `bag` | `5` | in | A password-encrypted SafeBag and its key name; for a recovery kit also the namespace and expected fingerprint | key migration; file recovery kit (F7, F8) |
| `capability` | `6` | out | A scoped, expiring capability request or grant | pairing (F9) |

The kind token is the lowercase ASCII string in the first column. The code is the one-byte
value of the `Kind` TLV (§4.2). Codes `0` and `7`–`255` are unassigned. A parser MUST reject
an unassigned code (§6.2).

## 4. TLV encoding

### 4.1 TLV framing

Envelopes use NDN Packet Format v0.3 TLV framing.

- TLV-TYPE and TLV-LENGTH are VAR-NUMBERs.
- A producer MUST encode each VAR-NUMBER in its shortest form. Every type in this spec is
  ≥ 253, so it is written as `FD` followed by two big-endian bytes. For example, `0x0470` is
  written `FD 04 70`.
- A parser MUST reject a non-minimal VAR-NUMBER, a TLV-TYPE above `0xFFFFFFFF` or written in
  the 9-byte form, and a TLV-LENGTH that runs past the enclosing buffer.

### 4.2 Registry

All types are in the range `0x0470`–`0x048F`. This range was chosen to stay clear of the
trust-context range `0x0410`–`0x041F`. The types have meaning only inside an envelope.

| Type | Name | Where | Value | Used by kinds |
|---|---|---|---|---|
| `0x0470` | Envelope | outermost | nested: FormatVersion, Kind, Body | all |
| `0x0471` | FormatVersion | in Envelope | 1 byte, `01` | all |
| `0x0472` | Kind | in Envelope | 1 byte: kind code (§3) | all |
| `0x0473` | Body | in Envelope | nested: the body fields below | all |
| `0x0474`–`0x0480` | — | — | unassigned | — |
| `0x0481` | Version | in Body | u64 (§4.4) | anchor: context version |
| `0x0482` | Wire | in Body | opaque bytes | anchor: legacy unsigned context Content; delegation: signed delegation; recovery: bundle; bag: SafeBag |
| `0x0483` | CaPrefix | in Body | NDN name string (§4.4) | invite |
| `0x0484` | IdentityNamespace | in Body | NDN name string | invite |
| `0x0485` | Token | in Body | UTF-8 string | invite |
| `0x0486` | TtlSecs | in Body | u64 | invite (optional), capability (required) |
| `0x0487` | PrincipalPubkey | in Body | opaque bytes | delegation |
| `0x0488` | KeyName | in Body | NDN name string | bag |
| `0x0489` | Namespace | in Body | NDN name string | anchor, bag, capability |
| `0x048A` | ScopePattern | in Body, repeatable | UTF-8 string | capability |
| `0x048B` | Nonce | in Body | opaque bytes | capability |
| `0x048C` | Grant | in Body | opaque bytes (NDN Data wire of a certificate) | capability |
| `0x048D` | Direction | in Body | 1 byte: `00` request, `01` grant | capability |
| `0x048E` | AnchorFingerprint | in Body | exactly 32 bytes | anchor, invite, bag |
| `0x048F` | ContextData | in Body | full NDN Data wire of the signed trust context | anchor |

### 4.3 Structure and canonical order

```
Envelope        = FD0470 TLV-LENGTH FormatVersion Kind Body
FormatVersion   = FD0471 01 01
Kind            = FD0472 01 kind-code
Body            = FD0473 TLV-LENGTH *body-field
```

A producer MUST emit the three Envelope children in the order FormatVersion, Kind, Body. It
MUST emit the body fields of each kind in exactly the order below, omitting an absent optional
field. This ordering gives byte-identical output for equal values. `?` marks an optional field
and `*` a field that repeats zero or more times.

| Kind | Body fields, in canonical order |
|---|---|
| anchor | Namespace?, AnchorFingerprint?, Version?, ContextData?, Wire? |
| invite | CaPrefix, IdentityNamespace, Token, TtlSecs?, AnchorFingerprint? |
| delegation | Wire, PrincipalPubkey |
| recovery | Wire |
| bag | KeyName, Wire, Namespace?, AnchorFingerprint? |
| capability | Direction, Namespace, ScopePattern*, TtlSecs, Nonce?, Grant? |

Further producer rules:
- **anchor.** A producer MUST include at least one of AnchorFingerprint, ContextData or Wire.
  It SHOULD include Namespace and AnchorFingerprint: both consumers in this repo refuse an
  anchor without them (§7.1). It MUST NOT emit Wire (the legacy unsigned form) in new
  envelopes; use ContextData.
- **capability.** A producer MUST omit Nonce when the nonce is empty. A decoded capability
  without Nonce has an empty nonce. ScopePattern elements keep their order.
- **No other fields.** A producer MUST NOT emit fields not listed for the kind, and MUST NOT
  emit a field twice, ScopePattern excepted.

### 4.4 Value encodings

- **u64 (Version, TtlSecs).** Unsigned big-endian integer.
  - A producer MUST emit exactly 8 bytes. This is not the minimal NonNegativeInteger form:
    `2` is `00 00 00 00 00 00 00 02`.
  - A parser MUST accept any length from 1 to 8 bytes, left-padded with zeros. It MUST reject
    length 0 and lengths above 8.
- **NDN name string (CaPrefix, IdentityNamespace, KeyName, Namespace).** The UTF-8 NDN URI
  form of a Name, for example `/home/bob`. The envelope layer only requires valid UTF-8.
  Consumers parse the string as an NDN URI (§7).
  - Producers SHOULD emit the canonical URI form: generic components unescaped where
    URI-unreserved, typed components in their `<type>=<value>` form.
  - A namespace that a consumer validates (invite, §7.2) MUST consist only of
    GenericNameComponents whose bytes are ASCII letters, digits, `-`, `_`, `.` and `~`.
- **UTF-8 string (Token, ScopePattern).** UTF-8 bytes, no terminator. A parser MUST reject
  invalid UTF-8.
  - The token grammar is `<role>-<secret>[-until<unix-secs>]` ([ndncert-extensions.md](ndncert-extensions.md)).
  - ScopePattern is a trust-schema pattern string, opaque at this layer (e.g.
    `/work/acme/<**rest>`).
- **AnchorFingerprint.** Exactly 32 bytes: SHA-256 over the anchor certificate's public key.
  - If the certificate's Content is a 44-byte Ed25519 SubjectPublicKeyInfo (prefix
    `302a300506032b6570032100`), the hash input is the 32-byte raw key.
  - Otherwise the hash input is the Content bytes unchanged, for example a P-256 SPKI DER.
  - A re-issued certificate for the same key therefore keeps its fingerprint. See also
    [trust-context.md](trust-context.md).
- **Direction, FormatVersion, Kind.** One byte.
- **ContextData.** The complete wire of the signed trust-context Data
  `/<ns>/32=trust-context/v=<N>`, signed by one of its anchors.
- **Wire, by kind:**
  - anchor: the legacy unsigned `SignedTrustContext` Content, the bytes `ndn-ctx:1:` carried.
  - delegation: the `SignedDelegation` wire.
  - recovery: the recovery bundle.
  - bag: the encoded SafeBag ([recovery-kit.md](recovery-kit.md) for kit bags).
  The envelope layer treats all of these as opaque.
- **PrincipalPubkey.** The principal's public key bytes as returned by the signer, opaque here.
- **Grant.** The granting operator's certificate as NDN Data wire.
- **Nonce.** Opaque bytes chosen by the requester. This spec sets no length.

## 5. Text forms and carriage

### 5.1 base64url

Every text form carries the canonical TLV (§4.3) encoded as base64url: the RFC 4648 §5
alphabet `A–Z a–z 0–9 - _`, **without padding**.

A parser MUST reject the following:
- any character outside that alphabet, including `=`, `+`, `/` and interior whitespace;
- an encoding whose length is ≡ 1 (mod 4);
- non-canonical trailing bits. A final 2-character group must end in one of `A Q g w`. A
  final 3-character group must end in one of `A E I M Q U Y c g k o s w 0 4 8`.

### 5.2 Grammar (ABNF, RFC 5234)

Emitted forms:

```abnf
trust-uri     = "ndn-trust://" kind-token "/" payload
mirror-url    = "https://" domain "/t/" kind-token "#" payload
kind-token    = "anchor" / "invite" / "delegation" / "recovery" / "bag" / "capability"
payload       = b64url                         ; base64url(Envelope TLV), §5.1
domain        = 1*( ALPHA / DIGIT / "-" / "." ) ; host chosen by the issuer; not validated
b64url        = *( 4b64 ) [ b64 b64-tail2 / 2b64 b64-tail3 ]
b64           = ALPHA / DIGIT / "-" / "_"
b64-tail2     = "A" / "Q" / "g" / "w"
b64-tail3     = "A" / "E" / "I" / "M" / "Q" / "U" / "Y" / "c" / "g" / "k" / "o" / "s"
              / "w" / "0" / "4" / "8"
```

A producer MUST set `kind-token` to the token of the envelope's Kind (§3). Its output MUST
match `trust-uri` or `mirror-url` exactly, with no surrounding whitespace.

Accepted forms. A parser compatible with ndn-rs MUST accept everything below. The reference
parser accepts exactly this set, quirks included (§10):

```abnf
envelope-text = *ws ( p-trust-uri / p-mirror / p-legacy ) *ws
p-trust-uri   = "ndn-trust://" p-kind "/" *ws payload *ws
p-kind        = *( %x00-2E / %x30-10FFFF )      ; anything without "/", may be empty;
                                                ; NOT checked against the Kind TLV
p-mirror      = ( "https://" / "http://" ) p-before "#" *ws payload *ws
p-before      = *( %x00-22 / %x24-10FFFF )      ; no "#"; the whole text MUST contain "/t/"
p-legacy      = "ndn-ctx:1:" version ":" *ws payload *ws
version       = [ "+" ] 1*DIGIT                 ; decimal u64
ws            = <Unicode White_Space>
```

The prefixes `ndn-trust://`, `https://`, `http://` and `ndn-ctx:1:` are matched
case-sensitively. A parser processes the text as follows:

1. Strip leading and trailing whitespace from the whole text.
2. If the text starts with `ndn-ctx:1:`, it is the legacy form (§5.5).
3. Otherwise, if it starts with `ndn-trust://`, the payload is everything after the first
   `/` that follows the prefix. No `/` there gives MalformedUri.
4. Otherwise, if it starts with `https://` or `http://` and contains `/t/` anywhere, the
   payload is everything after the first `#`. No `#` gives MalformedUri.
5. Anything else gives UnknownScheme.
6. Strip whitespace from the payload, base64url-decode it (§5.1, failure gives BadBase64) and
   decode the TLV (§6).

A query string or a second `#` stays part of the payload and therefore fails base64url.

### 5.3 URI form

The URI form `trust-uri` is used for QR codes, NFC, clipboard and deep links. It is also the
value of `ControlParameters.Uri` in the `ndn-fwd` management verbs `security/context-adopt`
and `security/enroll`, and the argument of `ndn-fwd adopt` / `ndn-fwd enroll`.

The length is `12 + len(kind-token) + 1 + ceil(4·n/3)` characters, where `n` is the TLV
length.

### 5.4 Universal-link mirror

The universal-link mirror is `mirror-url`. The payload rides in the URL fragment, so it is
never sent to the web server and never appears in HTTP access logs. A web page at
`https://<domain>/t/<kind>` MAY hand the fragment to an installed app.
- `ndn-fwd-tokens new --domain <d>` emits this form for invites.
- `ndn-fwd init` prints an `anchor_url` with domain `ndn.local`.

A producer MUST NOT move the payload into the path or query.

### 5.5 Legacy form (parse-only)

`ndn-ctx:1:<version>:<payload>`, where the payload is base64url of the bare unsigned context
Content. A parser that supports it decodes it to an `anchor` with:
- Version = `<version>`;
- Wire = the decoded payload;
- no Namespace, no AnchorFingerprint, no ContextData.

No producer emits this form. New implementations MUST NOT emit it and MAY parse it.
Consumers refuse the result (§7.1).

### 5.6 QR codes

The QR content is the exact octets of a `trust-uri` or `mirror-url`. There is no other
wrapping, BOM, ECI or line break.

Producer rules:
- **Error correction.** A producer SHOULD use level **M**, which is what every ndn-rs renderer
  uses.
- **Version and mode.** A producer SHOULD pick the smallest version (1–40) that fits, and MAY
  use any segment mode. ndn-rs uses optimal segmentation: base64url has lowercase letters, so
  this is byte mode, with numeric segments where digit runs pay off.
- **Quiet zone.** A producer MUST keep a quiet zone of at least 4 modules.
- **Size limit.** A producer MUST NOT emit an envelope that does not fit one QR symbol at its
  chosen error-correction level. Structured Append (multi-symbol) is not used.
- **Large envelopes.** For an `anchor` too large for one symbol, the producer SHOULD switch to
  the fingerprint-only form (Namespace + AnchorFingerprint + Version, no ContextData). The
  consumer then fetches the context by name.

Parser rules: a parser MUST accept any version, error-correction level and mode a standard
decoder produces.

Capacity of one version-40 symbol in byte mode (ISO/IEC 18004), and the largest `trust-uri`
measured to fit with the reference renderer:

| EC level | Byte capacity | Largest URI measured |
|---|---|---|
| L | 2953 | 2949 |
| M | 2331 | 2327 |
| Q | 1663 | 1661 |
| H | 1273 | not measured |

Measurements used the `qrcode` 0.14.1 crate, `recovery` envelopes with a pseudo-random payload,
and kind token `recovery`. They grow in steps of 4 characters, which is why each largest URI
sits slightly below the capacity.

Typical sizes from §8:
- a fingerprint-only anchor for `/home/bob` is 125 characters (version 8 at M);
- an invite carrying an expected fingerprint is 230 characters (version 11 at M);
- an inline anchor with a real signed context is usually 1–3 KB. Check its size against the
  table.

### 5.7 File and paste

- **Text file.** One `trust-uri` (or `mirror-url`) in UTF-8. A trailing newline is allowed
  (§5.2 step 1). File recovery kits use this form:
  - `ndn-fwd recovery-kit create` writes `<uri>\n` with mode `0600`;
  - `ndn_cert::FileKit::read` parses it.
  A producer MUST write files that carry a secret (an invite token, a SafeBag) readable by
  the owner only.
- **Binary file `.ndntrust`.** The raw Envelope TLV bytes (§4), with no base64. This form is
  documented in the codec, but no producer or consumer in this repository reads or writes it
  (§10, Q11).
- **Paste / clipboard / deep link.** The `trust-uri` or `mirror-url` text, parsed as in §5.2.
  Surrounding whitespace is ignored.
- **NFC.** The `trust-uri` text. The NDEF record type is not specified (§10, Q13).

## 6. Decoding and validation

A parser MUST behave as follows. The error names are the reference implementation's. A parser
MAY report them differently but MUST accept and refuse the same inputs. Behaviours marked
*[lenient]* are what the reference does today and are listed as open questions (§10).
Independent parsers MUST accept everything the reference accepts. Producers MUST NOT rely on
any lenient behaviour.

### 6.1 Outer element

1. Read one TLV from the start of the buffer. An empty or truncated buffer, or a malformed
   VAR-NUMBER, gives Truncated.
2. If its type is not `0x0470`, the result is BadTag(type).
3. *[lenient]* Bytes after the Envelope element are ignored.

### 6.2 Envelope children

1. Read the children in any order. Any malformed child gives Truncated.
2. FormatVersion and Kind are the first byte of their value.
   - An empty value counts as absent.
   - *[lenient]* Bytes after the first are ignored.
3. A repeated child replaces the earlier one (last wins).
4. *[lenient]* Children of any other type are ignored, whatever their critical bit.
5. Then, in this order:
   - FormatVersion absent: MissingField("format version").
   - FormatVersion ≠ `1`: UnsupportedVersion.
   - Kind absent: MissingField("kind").
   - Kind not in 1–6: UnknownKind.
   - Body absent: MissingField("body").

### 6.3 Body fields

The body is decoded in two passes.

**Pass 1** reads every body field in wire order, whatever the Kind. Any malformed field
gives Truncated. Each known field is validated as it is read, and the first failure is
returned:
- Version, TtlSecs: 1–8 bytes, else Malformed("u64 field length").
- CaPrefix, IdentityNamespace, Token, KeyName, Namespace, ScopePattern: valid UTF-8, else
  Malformed("non-utf8 string field").
- AnchorFingerprint: exactly 32 bytes, else Malformed("anchor fingerprint length").
- Direction: first byte. An empty value counts as absent; *[lenient]* extra bytes are
  ignored.

Further pass-1 rules:
- *[lenient]* Fields that do not belong to the Kind are validated in the same way and then
  dropped. For example, a 31-byte AnchorFingerprint inside a `delegation` is an error, while
  a Token inside an `anchor` is silently ignored.
- ScopePattern accumulates in order. For every other field the last occurrence wins
  *[lenient]*.
- *[lenient]* Unknown types are ignored, whatever their critical bit.

**Pass 2** checks the per-kind requirements:

| Kind | Requirement | Error |
|---|---|---|
| anchor | at least one of Wire, ContextData, AnchorFingerprint | MissingField("anchor content or fingerprint") |
| invite | CaPrefix, IdentityNamespace, Token present (Token may be empty here, §7.2) | MissingField("ca prefix" / "identity namespace" / "token") |
| delegation | Wire, PrincipalPubkey present | MissingField("delegation wire" / "principal pubkey") |
| recovery | Wire present (may be empty) | MissingField("recovery bundle") |
| bag | KeyName, Wire present | MissingField("key name" / "safebag") |
| capability | Direction present and `00` or `01`; Namespace, TtlSecs present | MissingField("direction") / Malformed("capability direction") / MissingField("capability namespace" / "capability ttl") |

An `anchor` that carries both ContextData and Wire decodes with both fields set. Consumers
use ContextData (§7.1).

### 6.4 Round trip

For every envelope the producer rules allow, decoding and then re-encoding MUST give the
original bytes, and encoding and then decoding MUST give the original value. The vectors in §8
are canonical. A conforming producer MUST reproduce them byte for byte from the stated values.

## 7. Consumer checks (per kind)

These checks run after §6, in the consumer that acts on the envelope. They are normative for
interoperating with ndn-rs flows.

### 7.1 `anchor` (adopt, approval enrollment)

`ndn_cert::AnchorLink` and the mobile parser apply the following:

1. **Namespace.** It MUST be present and MUST parse as an NDN Name.
2. **AnchorFingerprint.** It MUST be present.
3. **Context Data.**
   - If ContextData is present, it MUST decode as an NDN Data packet. Wire is then ignored.
   - If only Wire is present (the legacy unsigned form), the consumer MUST refuse. It MAY
     adopt only on an explicit, separate user opt-in to unverified adoption.
   - If neither is present, the context is fetched by name: `/<ns>/32=trust-context`
     discovered by RDR ([trust-context.md](trust-context.md)).
4. **Verification.** The consumer verifies the inline or fetched context, which:
   - MUST be signed by an anchor of the context whose fingerprint equals AnchorFingerprint;
   - MUST root Namespace.
5. **Version.** If Version is present, the consumer MUST refuse a context with a version below
   it (downgrade).

### 7.2 `invite` (enroll by invite)

`ndn_cert::InviteLink` applies the following:

1. CaPrefix MUST parse as a non-empty Name.
2. IdentityNamespace MUST parse as a Name of at least 2 components. Its last component MUST
   be the GenericNameComponent `member` or `guest`, matched exactly and case-sensitively.
   The prefix before that component is the namespace and MUST pass the namespace rule of §4.4.
3. Token MUST be non-empty.
4. If Token ends in `-until<digits>`, the consumer MUST refuse it once
   `now ≥ <digits>` (Unix seconds).
5. The token's role prefix MUST equal the role in IdentityNamespace.
   - The role prefix is the text before the first `-`, matched exactly against `admin`,
     `member`, `node` or `guest`, with a non-empty rest.
   - A token without a role prefix counts as `member`.
6. AnchorFingerprint, if present, is the expected fingerprint used to adopt the namespace's
   context before enrolling.
7. TtlSecs is informational. It holds the remaining token lifetime, computed when the
   envelope was emitted, and consumers ignore it. The authoritative expiry is the token's
   `-until` suffix.

### 7.3 `bag`

- **Key migration.** KeyName and the SafeBag.
- **File recovery kit** (`ndn_cert::FileKit`):
  1. Namespace MUST be present.
  2. KeyName and Namespace MUST parse as Names.
  3. The SafeBag MUST decode and carry a certificate whose key name equals KeyName.
  4. KeyName MUST equal the namespace's recovery key name for that key.
  5. AnchorFingerprint (OPTIONAL) is the namespace's expected fingerprint when the kit was
     made.

  Details are in [recovery-kit.md](recovery-kit.md).

### 7.4 `capability`, `delegation`, `recovery`

The envelope layer adds no checks for these kinds:
- `capability`: the Grant certificate is decoded and its key learned by the bearer.
- `delegation`: the signed delegation is verified against PrincipalPubkey.
- `recovery`: the bundle is consumed by the restore flow.

These payload formats are outside this spec (§10, Q14).

## 8. Test vectors

Generated by encoding the stated values with `ndn-trust-envelope` and checking that
`decode(encode(v)) == v` and `from_uri(to_uri(v)) == v` (Appendix B). Opaque payloads are
short placeholders, not real Data or SafeBags.

In every vector, `FP` is the 32 bytes `00 01 02 … 1f`. The QR column gives the version chosen
by the reference renderer at EC level M and at level L.

### 8.1 Annotated: `anchor`, fingerprint only

Namespace `/home/bob`, AnchorFingerprint `FP`, Version 2.

```
fd0470 4b                                    Envelope, length 75
  fd0471 01 01                               FormatVersion 1
  fd0472 01 01                               Kind 1 (anchor)
  fd0473 3d                                  Body, length 61
    fd0489 09 2f686f6d652f626f62             Namespace "/home/bob"
    fd048e 20 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                                             AnchorFingerprint
    fd0481 08 0000000000000002               Version 2 (8-byte u64)
```

Hex (79 bytes):
```
fd04704bfd04710101fd04720101fd04733dfd0489092f686f6d652f626f62fd048e20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1ffd0481080000000000000002
```
URI (125 characters, QR version 8 at M / 6 at L):
```
ndn-trust://anchor/_QRwS_0EcQEB_QRyAQH9BHM9_QSJCS9ob21lL2JvYv0EjiAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eH_0EgQgAAAAAAAAAAg
```

### 8.2 `anchor`, inline signed context

Namespace `/home/bob`, AnchorFingerprint `FP`, Version 1, ContextData `0603aabbcc`. The
placeholder is not a valid Data, so §7.1 would refuse it. The vector is for the envelope
layer only.

```
fd047054fd04710101fd04720101fd047346fd0489092f686f6d652f626f62fd048e20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1ffd0481080000000000000001fd048f050603aabbcc
```
```
ndn-trust://anchor/_QRwVP0EcQEB_QRyAQH9BHNG_QSJCS9ob21lL2JvYv0EjiAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eH_0EgQgAAAAAAAAAAf0EjwUGA6q7zA
```
137 characters; QR version 8 at M / 7 at L.

### 8.3 `anchor`, legacy unsigned (decode only; consumers refuse)

Version 7, Wire `637478` ("ctx"):
```
fd047021fd04710101fd04720101fd047313fd0481080000000000000007fd048203637478
```
```
ndn-trust://anchor/_QRwIf0EcQEB_QRyAQH9BHMT_QSBCAAAAAAAAAAH_QSCA2N0eA
```

The legacy text `ndn-ctx:1:42:Y3R4` decodes to an anchor with Version 42 and Wire `637478`,
and nothing else.

### 8.4 `invite`, all fields

- CaPrefix `/home/bob`
- IdentityNamespace `/home/bob/member`
- Token `member-00112233445566778899aabbccddeeff-until1893456000`
- TtlSecs 3600
- AnchorFingerprint `FP`

```
fd04709afd04710101fd04720102fd04738cfd0483092f686f6d652f626f62fd0484102f686f6d652f626f622f6d656d626572fd0485376d656d6265722d30303131323233333434353536363737383839396161626263636464656566662d756e74696c31383933343536303030fd0486080000000000000e10fd048e20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```
```
ndn-trust://invite/_QRwmv0EcQEB_QRyAQL9BHOM_QSDCS9ob21lL2JvYv0EhBAvaG9tZS9ib2IvbWVtYmVy_QSFN21lbWJlci0wMDExMjIzMzQ0NTU2Njc3ODg5OWFhYmJjY2RkZWVmZi11bnRpbDE4OTM0NTYwMDD9BIYIAAAAAAAADhD9BI4gAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
```
230 characters; QR version 11 at M / 9 at L.

### 8.5 `invite`, required fields only, and its mirror

CaPrefix `/home/bob`, IdentityNamespace `/home/bob/guest`, Token `guest-a1b2`.

```
fd04703cfd04710101fd04720102fd04732efd0483092f686f6d652f626f62fd04840f2f686f6d652f626f622f6775657374fd04850a67756573742d61316232
```
```
ndn-trust://invite/_QRwPP0EcQEB_QRyAQL9BHMu_QSDCS9ob21lL2JvYv0EhA8vaG9tZS9ib2IvZ3Vlc3T9BIUKZ3Vlc3QtYTFiMg
https://join.example/t/invite#_QRwPP0EcQEB_QRyAQL9BHMu_QSDCS9ob21lL2JvYv0EhA8vaG9tZS9ib2IvZ3Vlc3T9BIUKZ3Vlc3QtYTFiMg
```

### 8.6 `delegation`

Wire `de1e6a7e`, PrincipalPubkey `01020304`:
```
fd04701efd04710101fd04720103fd047310fd048204de1e6a7efd04870401020304
```
```
ndn-trust://delegation/_QRwHv0EcQEB_QRyAQP9BHMQ_QSCBN4ean79BIcEAQIDBA
```

### 8.7 `recovery`

Wire `b00b`:
```
fd047014fd04710101fd04720104fd047306fd048202b00b
```
```
ndn-trust://recovery/_QRwFP0EcQEB_QRyAQT9BHMG_QSCArAL
```

### 8.8 `bag`, key migration

KeyName `/home/bob/admin/laptop/KEY/18b5e7d515966f90`, Wire `80020000`:
```
fd047045fd04710101fd04720105fd047337fd04882b2f686f6d652f626f622f61646d696e2f6c6170746f702f4b45592f31386235653764353135393636663930fd04820480020000
```
```
ndn-trust://bag/_QRwRf0EcQEB_QRyAQX9BHM3_QSIKy9ob21lL2JvYi9hZG1pbi9sYXB0b3AvS0VZLzE4YjVlN2Q1MTU5NjZmOTD9BIIEgAIAAA
```

### 8.9 `bag`, recovery-kit shape

KeyName `/home/bob/KEY/r0011223344556677`, Wire `80020000`, Namespace `/home/bob`,
AnchorFingerprint `FP`:
```
fd04706afd04710101fd04720105fd04735cfd04881f2f686f6d652f626f622f4b45592f7230303131323233333434353536363737fd04820480020000fd0489092f686f6d652f626f62fd048e20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```
```
ndn-trust://bag/_QRwav0EcQEB_QRyAQX9BHNc_QSIHy9ob21lL2JvYi9LRVkvcjAwMTEyMjMzNDQ1NTY2Nzf9BIIEgAIAAP0EiQkvaG9tZS9ib2L9BI4gAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
```

### 8.10 `capability`, request

- Direction request
- Namespace `/work/acme/dashboard`
- ScopePattern `/work/acme/<**rest>`, then `/work/acme/x`
- TtlSecs 300
- Nonce `09090909`

```
fd047066fd04710101fd04720106fd047358fd048d0100fd0489142f776f726b2f61636d652f64617368626f617264fd048a132f776f726b2f61636d652f3c2a2a726573743efd048a0c2f776f726b2f61636d652f78fd048608000000000000012cfd048b0409090909
```
```
ndn-trust://capability/_QRwZv0EcQEB_QRyAQb9BHNY_QSNAQD9BIkUL3dvcmsvYWNtZS9kYXNoYm9hcmT9BIoTL3dvcmsvYWNtZS88KipyZXN0Pv0Eigwvd29yay9hY21lL3j9BIYIAAAAAAAAASz9BIsECQkJCQ
```

### 8.11 `capability`, grant (empty nonce omitted)

Direction grant, Namespace `/work/acme/dashboard`, no ScopePattern, TtlSecs 300, Grant `0600`:
```
fd04703dfd04710101fd04720106fd04732ffd048d0101fd0489142f776f726b2f61636d652f64617368626f617264fd048608000000000000012cfd048c020600
```
```
ndn-trust://capability/_QRwPf0EcQEB_QRyAQb9BHMv_QSNAQH9BIkUL3dvcmsvYWNtZS9kYXNoYm9hcmT9BIYIAAAAAAAAASz9BIwCBgA
```

### 8.12 Parser vectors

The body `B` below is `fd048e20` followed by `FP`, a fingerprint-only anchor body. "Accept"
means the decode succeeds.

| Input | Result |
|---|---|
| `fd047032fd04710101fd04720101fd047324` B | accept: anchor, fingerprint only |
| same, FormatVersion `02` | UnsupportedVersion(2) |
| same, FormatVersion value `0100` | accept *[lenient]* |
| same, FormatVersion value empty (`fd047100`) | MissingField("format version") |
| same, Kind `00` / `07` | UnknownKind |
| `fd047032fd047324` B `fd04720101fd04710101` (children reversed) | accept |
| B followed by `aabb` after the Envelope | accept *[lenient]* |
| `fd04710101` (outer type `0x0471`) | BadTag(0x471) |
| empty input | Truncated |
| AnchorFingerprint of 31 or 33 bytes | Malformed("anchor fingerprint length") |
| AnchorFingerprint length written `fd0020` (non-minimal) | Truncated |
| anchor body with Namespace only | MissingField("anchor content or fingerprint") |
| Version of 0 or 9 bytes | Malformed("u64 field length") |
| Version `05` (1 byte) | accept, version 5 |
| Namespace `ff` | Malformed("non-utf8 string field") |
| unknown field `fd0490` or `fd0491` in Body | accept *[lenient]* |
| Namespace `/a` then `/b` | accept, namespace `/b` *[lenient]* |
| capability Direction `02` | Malformed("capability direction") |
| capability Direction value `0105` | accept, grant *[lenient]* |
| invite with empty Token | accept at the envelope layer (refused by §7.2) |
| recovery with empty Wire | accept |
| `ndn-trust://anchor/` + base64url(§8.7 bytes) | accept as **recovery** (kind token not checked) |
| `ndn-trust:///` + same payload | accept |
| `"  \n" + §8.7 URI + " \t\n"` | accept |
| §8.7 payload with an inner space, `==` padding, or `?x=1` appended | BadBase64 |
| `ndn-trust://recovery/+w` | BadBase64 |
| `ndn-trust://recovery/BB` (non-canonical trailing bits) | BadBase64 |
| `NDN-TRUST://recovery/…` | UnknownScheme |
| `http://x/t/recovery#` + payload | accept |
| `https://x/recovery#` + payload | UnknownScheme |
| `https://x/t/recovery` | MalformedUri |
| `ndn-trust://anchor` | MalformedUri |
| `ndn-ctx:1:+42:Y3R4` | accept, version 42 |

## 9. Security considerations

- **Bearer secrets.** An `invite` URI, and any QR or file holding one, is a bearer credential
  until the token is redeemed or expires. A `bag` holds an encrypted private key. Producers
  write such files owner-only, and the mirror keeps the payload in the fragment (§5.4, §5.7).
- **No signature on the envelope.** An attacker who can substitute the envelope can
  substitute the expected fingerprint. Show and scan anchors over a channel the user trusts
  (a screen they can see). Inline signed objects only protect against tampering in transit
  if the expected fingerprint itself is authentic.
- **Downgrade.** An `anchor` with a Version lets the consumer refuse an older context served
  by name (§7.1). A fingerprint-only anchor without Version accepts any version signed by the
  expected anchor.
- **Unsigned legacy context.** It is never adopted by default (§5.5, §7.1).

## 10. Open questions

- **Q1. Trailing bytes after the Envelope element.** They are accepted and ignored (§6.1).
  Should a parser reject them?
- **Q2. Unknown children and body fields.** They are ignored whatever the NDN critical bit
  (§6.2, §6.3). Should an unknown type that is critical under NDN rules (odd, ≥ 32) be
  rejected, so that future required fields can be added safely?
- **Q3. Extra bytes after the first.** For FormatVersion, Kind and Direction they are
  ignored. Should their length be required to be exactly 1?
- **Q4. Duplicates.** Fields other than ScopePattern take the last occurrence. Reject
  duplicates instead?
- **Q5. Fields of another kind** are validated (and can fail decoding) but are otherwise
  ignored (§6.3). Should a parser skip them unvalidated, or reject them?
- **Q6. URI kind token.** It is not checked against the Kind TLV; an empty token is
  accepted. Should a mismatch be refused?
- **Q7. u64 fields.** They are emitted as 8 bytes, not as NDN NonNegativeInteger (1/2/4/8
  minimal), and decoded from any 1–8 bytes. Should the format switch to NonNegativeInteger
  in a FormatVersion 2?
- **Q8. Mirror detection.** It accepts `http://` and finds `/t/` anywhere in the string,
  fragment included (§5.2). Should it be limited to `https://` with `/t/<kind>` as the path?
- **Q9. Legacy version.** It accepts a leading `+`, because Rust `u64::from_str` does.
- **Q10. Mobile `bag`.** The ndn-mobile parser (`NdnTrust::parse`) drops Namespace and
  AnchorFingerprint from `bag`, so a mobile host cannot learn a file kit's namespace or
  expected fingerprint. ndn-cert `FileKit::read` keeps them. Which behaviour is intended for
  mobile recovery?
- **Q11. `.ndntrust` binary files.** The crate documents raw-TLV `.ndntrust` files, but the
  only file the tree writes (the recovery kit) is the text URI. Keep the binary form,
  or define files as text only?
- **Q12. QR error-correction level.** All renderers use M (2331-byte limit). The namespace
  test asserts an inline anchor fits L (2953). Which level is normative? See the bug report
  below.
- **Q13. NFC and OS integration.** The NFC NDEF record type is not specified in this tree,
  and neither is the OS deep-link registration (`ndn-trust` scheme handler, universal-link
  association for `/t/`).
- **Q14. Delegation and recovery payloads.** The formats of the `delegation` Wire
  (`SignedDelegation`), PrincipalPubkey (raw key, which algorithm?) and the `recovery` bundle
  are not specified by any spec in this set.
- **Q15. Capability timing and nonce.** TtlSecs has no reference time in the envelope (the
  envelope has no issuance time). The nonce has no minimum length or uniqueness rule, and
  `ndn-pair-kiosk` uses a constant nonce.
- **Q16. Name strings.** No canonical-form requirement is enforced. Two producers can emit
  different strings for the same Name, so their envelopes are not byte-identical.

## Appendix A. Code references (non-normative)

Paths are relative to the workspace root. Code in `ndn-fwd` may move to library crates.

| Claim | Location |
|---|---|
| Kinds, directions, carriage list | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:4-40` |
| TLV type numbers 0x0470–0x048F | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:48-68` |
| Fingerprint length 32, FORMAT_VERSION 1, scheme and legacy tags | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:70-77` |
| Kind codes 1–6, unknown-kind error, kind tokens | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:96-131` |
| Direction codes 0/1 | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:142-156` |
| Envelope order FormatVersion, Kind, Body | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:249-257` |
| Body field order per kind; 8-byte u64; empty nonce omitted | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:259-341` |
| Outer decode, BadTag, children order-free, first byte, ignore unknown, error order | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:344-372` |
| Body decode (pass 1), fingerprint length, last-wins, ScopePattern push | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:374-418` |
| Per-kind requirements (pass 2) | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:420-463` |
| `to_uri`, `to_https_url` | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:465-482` |
| `from_uri`: trim, legacy, scheme split, mirror rule, base64 | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:487-520` |
| UTF-8 and u64 (1–8 bytes) rules | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:523-534` |
| Error set | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:536-557` |
| base64 engine `URL_SAFE_NO_PAD`, crate 0.22.1 | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:42-43`; `ndn-rs/Cargo.toml:181`; `ndn-rs/Cargo.lock:136-137` |
| VAR-NUMBER minimal decode | `ndn-rs/crates/core/ndn-tlv/src/lib.rs:24-61` |
| TLV-TYPE range, length bound | `ndn-rs/crates/core/ndn-tlv/src/reader.rs:47-107` |
| Minimal VAR-NUMBER encode | `ndn-rs/crates/core/ndn-tlv/src/writer.rs:33-66` |
| Anchor fingerprint = SHA-256(cert public key) | `ndn-rs/crates/security/ndn-security/src/trust_context/mod.rs:1056-1063` |
| Cert public key: Ed25519 SPKI unwrapped, else Content | `ndn-rs/crates/security/ndn-security/src/cert_cache.rs:31-38`; `ndn-rs/crates/security/ndn-security/src/spki.rs:46-49` |
| Anchor consumer checks | `ndn-rs/crates/security/ndn-cert/src/onboarding.rs:237-298` |
| Invite consumer checks | `ndn-rs/crates/security/ndn-cert/src/invite.rs:85-152` |
| Token role / `-until` expiry; namespace component rule | `ndn-rs/crates/security/ndn-cert/src/roles.rs:91-93,204-232,303-340` |
| File kit: URI text, reading and checks | `ndn-rs/crates/security/ndn-cert/src/recovery.rs:396-492` |
| File kit written as `<uri>\n`, 0600 | `ndn-fwd/binaries/ndn-fwd/src/recovery_kit.rs:484-485` |
| Namespace init emits inline signed anchor | `ndn-rs/crates/security/ndn-cert/src/namespace.rs:159-165` |
| QR capacity test (asserts ≤ 2953, EC L) | `ndn-rs/crates/security/ndn-cert/src/namespace.rs:589-592` |
| `ndn-fwd init` prints `anchor_uri`, `anchor_url` (ndn.local), `anchor_uri_fp` | `ndn-fwd/binaries/ndn-fwd/src/onboard.rs:474-491` |
| Invite emission, TtlSecs = remaining token life, mirror via `--domain` | `ndn-fwd/binaries/ndn-fwd-tokens/src/main.rs:215-229` |
| QR rendering (QrCode::new, ASCII 2×1, SVG ≥256 px, 0600) | `ndn-fwd/binaries/ndn-fwd-tokens/src/main.rs:257-283` |
| Context authoring: signed vs unsigned legacy anchor | `ndn-fwd/binaries/ndn-trust-context/src/lib.rs:103-148`; `ndn-fwd/binaries/ndn-trust-context/src/main.rs:142-188` |
| QR rendering in `ndn-trust-context` | `ndn-fwd/binaries/ndn-trust-context/src/main.rs:258-276` |
| Dev emitter, QR via QrCode::new | `ndn-rs/crates/security/ndn-trust-envelope/examples/emit.rs:48-58` |
| `qrcode` defaults: `new` = EC M, auto version, quiet zone 4 | `qrcode-0.14.1/src/lib.rs:75-76,92-94,250` (cargo registry) |
| Mobile parser and Bag field drop | `ndn-mobile/crates/ndn-boltffi/src/trust.rs:27-30,80-147` |
| Mobile builders (delegation, recovery, capability) | `ndn-mobile/crates/ndn-boltffi/src/trust.rs:37-77` |
| Capability request with constant nonce | `ndn-fwd/binaries/tooling/ndn-pair-kiosk/src/main.rs:72-80` |
| Mgmt verbs take the link in `ControlParameters.Uri` | `ndn-rs/crates/core/ndn-mgmt-wire/src/nfd_command.rs:121-131`; `ndn-rs/crates/forwarding/ndn-mgmt/src/modules/security.rs:318-387` |

## Appendix B. Vector provenance (non-normative)

The vectors in §8 were produced on 2026-10-18 by a temporary example in the
`ndn-trust-envelope` crate, run with `cargo run --example` and deleted afterwards. The program:
- encoded each value in §8 with `TrustEnvelope::encode` / `to_uri` / `to_https_url`;
- asserted both round trips;
- fed the hand-built inputs of §8.12 to `TrustEnvelope::decode` / `from_uri`;
- rendered every URI with `qrcode::QrCode::new` (EC M) and `with_error_correction_level(L)`
  to report versions;
- searched for the largest `recovery` URI with a pseudo-random payload that fits each EC level
  (§5.6).
