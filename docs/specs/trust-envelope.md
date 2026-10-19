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

The same TLV bytes are used in every carriage: base64url in a URI, QR code or file. The kind
in a URI is a routing hint that MUST match the `Kind` TLV (§5.2); the TLV is authoritative.

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
| `0x0474` | DeviceName | in Body | UTF-8 device name (one name component) | invite (optional): the device name the inviter suggests, a hint and not a constraint. Even type, so a reader that does not know it skips it. |
| `0x0475`–`0x0480` | — | — | unassigned | — |
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
| invite | CaPrefix, IdentityNamespace, Token, TtlSecs?, AnchorFingerprint?, DeviceName? |
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
  - A request MUST carry a Nonce of 16 bytes (`CAPABILITY_NONCE_LEN`) from a
    cryptographically secure RNG, fresh for every request.
  - A grant SHOULD carry the Nonce of the request it answers.
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
  Consumers parse the string as an NDN URI (§7) and compare Names, never strings.
  - A producer MUST emit the canonical URI form: the string ndn-rs `Name` displays for the
    parsed Name, so that parsing and displaying it again gives the same string. Generic
    components are percent-escaped except URI-unreserved bytes; typed components use their
    `<type>=<value>` form. Equal Names then give byte-identical envelopes. Parsers do not
    check the form.
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
- **Nonce.** Opaque bytes chosen by the requester: 16 fresh random bytes in a request (§4.3).
- **TtlSecs, capability.** A lifetime in seconds, counted from when the consumer decodes the
  envelope. The envelope carries no issuance time. The consumer MUST treat it as a ceiling: it
  does not act on the capability, or keep what it granted, past that time.

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
domain        = 1*( ALPHA / DIGIT / "-" / "." ) [ ":" 1*DIGIT ] ; issuer's host, optional port
b64url        = *( 4b64 ) [ b64 b64-tail2 / 2b64 b64-tail3 ]
b64           = ALPHA / DIGIT / "-" / "_"
b64-tail2     = "A" / "Q" / "g" / "w"
b64-tail3     = "A" / "E" / "I" / "M" / "Q" / "U" / "Y" / "c" / "g" / "k" / "o" / "s"
              / "w" / "0" / "4" / "8"
```

A producer MUST set `kind-token` to the token of the envelope's Kind (§3). Its output MUST
match `trust-uri` or `mirror-url` exactly, with no surrounding whitespace.

Accepted forms. A parser MUST accept exactly the forms below:

```abnf
envelope-text = *ws ( p-trust-uri / p-mirror / p-legacy ) *ws
p-trust-uri   = "ndn-trust://" kind-token "/" *ws payload *ws
p-mirror      = "https://" p-domain "/t/" kind-token "#" *ws payload *ws
p-domain      = 1*( %x00-22 / %x24-2E / %x30-3E / %x40-10FFFF ) ; no "/", "?" or "#"
p-legacy      = "ndn-ctx:1:" 1*DIGIT ":" *ws payload *ws         ; DIGIT run is a u64
ws            = <Unicode White_Space>
```

In `p-trust-uri` and `p-mirror`, `kind-token` MUST be the token of the decoded Kind (§3).
The prefixes `ndn-trust://`, `https://` and `ndn-ctx:1:` and the kind token are matched
case-sensitively. A parser processes the text as follows:

1. Strip leading and trailing whitespace from the whole text.
2. If the text starts with `ndn-ctx:1:`, it is the legacy form (§5.5). A version that is not
   one or more ASCII digits fitting a u64 gives MalformedUri.
3. Otherwise, if it starts with `ndn-trust://`, the kind token is everything up to the first
   `/` after the prefix and the payload is everything after that `/`. No `/` there gives
   MalformedUri.
4. Otherwise, if it starts with `https://`:
   - split off the fragment at the first `#`, then split the rest at its first `/` into
     domain and path;
   - if the path is not `t/<token>` with a token free of `/` and `?`, the text is not a
     trust link: UnknownScheme;
   - an empty domain, a domain containing `?`, or no `#` gives MalformedUri;
   - the fragment is the payload.
5. Anything else, `http://` included, gives UnknownScheme.
6. Strip whitespace from the payload, base64url-decode it (§5.1, failure gives BadBase64) and
   decode the TLV (§6).
7. If the kind token differs from the token of the decoded Kind, the result is
   KindMismatch.

A query string or a second `#` in the payload fails base64url.

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

A producer MUST NOT move the payload into the path or query. `<domain>` is a host name,
optionally with `:port`. The mirror has no other path: the parser refuses anything but
`/t/<kind>` (§5.2).

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
- **Error correction.** A producer MUST use level **M**.
- **Version and mode.** A producer MUST encode the text as one byte-mode segment, and SHOULD
  pick the smallest version (1–40) that holds it. Byte mode makes the size limit independent
  of the text. ndn-rs renders through `ndn_trust_envelope::qr::encode`.
- **Quiet zone.** A producer MUST keep a quiet zone of at least 4 modules.
- **Size limit.** A producer MUST NOT render a text longer than **2331 bytes**
  (`qr::MAX_TEXT_LEN`), the byte-mode capacity of a version-40 symbol at level M.
  Structured Append (multi-symbol) is not used.
- **Large anchors.** If the `trust-uri` of an `anchor` exceeds the limit, the producer MUST
  render the by-reference form instead (`TrustEnvelope::qr_uri`):
  - the same Namespace, AnchorFingerprint and Version;
  - no ContextData and no Wire.

  The consumer then fetches the context by name. That needs a link and a route to a node
  that serves the context ([ndn-link.md](ndn-link.md)). Other kinds have no fallback: the
  producer refuses to render them.

Parser rules: a parser MUST accept any version, error-correction level and mode a standard
decoder produces.

Byte capacity of one version-40 symbol (ISO/IEC 18004):

| EC level | Byte capacity | Used by ndn-rs |
|---|---|---|
| L | 2953 | no |
| M | 2331 | yes: the size limit |
| Q | 1663 | no |
| H | 1273 | no |

In byte mode every text up to the capacity fits. The test
`qr::tests::limit_matches_the_renderer` checks this at M with the `qrcode` 0.14.1 crate:
2331 bytes fit and 2332 bytes do not.

Why M:
- A QR is scanned off a screen or paper. M recovers about 15 % of the codewords, L about 7 %.
- Parsers accept any level, so the choice does not affect interoperability.
- L would hold an inline anchor only for the shortest namespaces (below), so the by-reference
  fallback is needed at either level.

Typical sizes:
- a fingerprint-only anchor for `/home/bob` is 125 characters (version 8);
- an invite carrying an expected fingerprint is 230 characters (version 11);
- an inline anchor carries the whole signed context:
  - The context `ndn-fwd init` makes for `/home/bob` was 1977 bytes, measured on a stored
    `contexts/*.tc` file (2026-10-16).
  - That gives a 2066-byte envelope and a 2774-character `trust-uri`: above the M limit, so
    the QR carries the by-reference form. It is just under the L capacity.
  - The namespace occurs about 21 times in that context. Each further byte of namespace adds
    about 28 characters, so `/com/example/users/alice-smith` exceeds even L.

### 5.7 File and paste

- **Text file.** One `trust-uri` (or `mirror-url`) in UTF-8. A trailing newline is allowed
  (§5.2 step 1). File recovery kits use this form:
  - `ndn-fwd recovery-kit create` writes `<uri>\n` with mode `0600`;
  - `ndn_cert::FileKit::read` parses it.
  A producer MUST write files that carry a secret (an invite token, a SafeBag) readable by
  the owner only.
- **Files are text only.** No binary file form is defined. A file holds one `trust-uri` (or
  `mirror-url`). Earlier codec docs mentioned a raw-TLV `.ndntrust` file, which nothing read
  or wrote.
- **Paste / clipboard / deep link.** The `trust-uri` or `mirror-url` text, parsed as in §5.2.
  Surrounding whitespace is ignored.
- **NFC.** The `trust-uri` text. The NDEF record type is not specified (§10, Q13).

## 6. Decoding and validation

A parser MUST behave as follows. The error names are the reference implementation's. A parser
MAY report them differently but MUST accept and refuse the same inputs.

**Evolvability rule.** A parser applies the NDN rule (NDN Packet Format v0.3, TLV-TYPE
evolvability) to every element it does not recognize in its place:
- A TLV-TYPE is **critical** if it is ≤ 31 or odd.
- An unrecognized critical element makes the envelope invalid: UnknownCritical(type).
- An unrecognized non-critical element is skipped, without looking at its value.

A later format can therefore add optional fields with even types and required fields with odd
types.

### 6.1 Outer element

1. Read one TLV from the start of the buffer. An empty or truncated buffer, or a malformed
   VAR-NUMBER, gives Truncated.
2. If its type is not `0x0470`, the result is BadTag(type).
3. Bytes after the Envelope element give Malformed("bytes after the envelope").

### 6.2 Envelope children

1. Read the children in any order. Any malformed child gives Truncated.
2. FormatVersion and Kind MUST have a 1-byte value, else Malformed("format version length") or
   Malformed("kind length").
3. A second FormatVersion, Kind or Body gives Malformed("repeated field").
4. Any other child is unrecognized (evolvability rule).
5. Then, in this order:
   - FormatVersion absent: MissingField("format version").
   - FormatVersion ≠ `1`: UnsupportedVersion. This comes before the next check, so a newer
     format is refused as such and not by one of its new children.
   - An unrecognized critical child: UnknownCritical(type).
   - Kind absent: MissingField("kind").
   - Kind not in 1–6: UnknownKind.
   - Body absent: MissingField("body").

### 6.3 Body fields

The body is decoded in two passes.

**Pass 1** reads every body field in wire order. Any malformed field gives Truncated. A field
that the Kind defines (§4.3) is validated as it is read, and the first failure is returned:
- Version, TtlSecs: 1–8 bytes, else Malformed("u64 field length").
- CaPrefix, IdentityNamespace, Token, KeyName, Namespace, ScopePattern: valid UTF-8, else
  Malformed("non-utf8 string field").
- AnchorFingerprint: exactly 32 bytes, else Malformed("anchor fingerprint length").
- Direction: exactly 1 byte, else Malformed("capability direction length").
- A second occurrence of any field but ScopePattern: Malformed("repeated field").
  ScopePattern accumulates in order.

A field that the Kind does not define is unrecognized, whether its type is unassigned or
defined for another kind (evolvability rule). For example:
- a Token (`0x0485`, odd) inside an `anchor` is refused;
- a 31-byte AnchorFingerprint (`0x048E`, even) inside a `delegation` is skipped.

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
- **Mobile** (`NdnTrust::parse`) keeps KeyName, the SafeBag, Namespace and AnchorFingerprint.
  A bag with Namespace is a file recovery kit, not an identity. Mobile `load_identity`
  refuses a SafeBag whose key is a namespace recovery key: its key name is
  `<ns>/KEY/r<hex>`, derived from the certificate's own public key.

### 7.4 `capability`, `delegation`, `recovery`

The envelope layer adds no checks for these kinds:
- `capability`: the Grant certificate is decoded and its key learned by the bearer. TtlSecs
  counts from decoding (§4.4). The envelope has no issuance time, so a captured request can
  be replayed. A granting device SHOULD refuse a request whose Nonce it already granted
  within TtlSecs.
- `delegation`: the signed delegation is verified against PrincipalPubkey.
- `recovery`: the bundle is consumed by the restore flow.

These payload formats are outside this spec (§10, Q14).

## 8. Test vectors

Generated by encoding the stated values with `ndn-trust-envelope` and checking that
`decode(encode(v)) == v` and `from_uri(to_uri(v)) == v` (Appendix B). Opaque payloads are
short placeholders, not real Data or SafeBags.

In every vector, `FP` is the 32 bytes `00 01 02 … 1f`. The QR column gives the version in byte
mode at EC level M (what the reference renderer uses) and, for comparison, at level L.

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
| same, FormatVersion value `0100` or empty (`fd047100`) | Malformed("format version length") |
| same, Kind `00` / `07` | UnknownKind |
| same, Kind value `0100` | Malformed("kind length") |
| same, Kind written twice | Malformed("repeated field") |
| `fd047032fd047324` B `fd04720101fd04710101` (children reversed) | accept |
| B followed by `aabb` after the Envelope | Malformed("bytes after the envelope") |
| unknown Envelope child `fd0476` / `fd0477` | accept (skipped) / UnknownCritical(0x477) |
| `fd04710101` (outer type `0x0471`) | BadTag(0x471) |
| empty input | Truncated |
| AnchorFingerprint of 31 or 33 bytes | Malformed("anchor fingerprint length") |
| AnchorFingerprint length written `fd0020` (non-minimal) | Truncated |
| anchor body with Namespace only | MissingField("anchor content or fingerprint") |
| Version of 0 or 9 bytes | Malformed("u64 field length") |
| Version `05` (1 byte) | accept, version 5 |
| Namespace `ff` | Malformed("non-utf8 string field") |
| unknown field `fd0490` in Body | accept (skipped) |
| unknown field `fd0491` in Body | UnknownCritical(0x491) |
| Token `fd0485` in an anchor body | UnknownCritical(0x485) |
| Namespace `/a` then `/b` | Malformed("repeated field") |
| capability Direction `02` | Malformed("capability direction") |
| capability Direction value `0105` | Malformed("capability direction length") |
| invite with empty Token | accept at the envelope layer (refused by §7.2) |
| recovery with empty Wire | accept |
| `ndn-trust://anchor/` + base64url(§8.7 bytes) | KindMismatch |
| `ndn-trust:///` + same payload | KindMismatch |
| `"  \n" + §8.7 URI + " \t\n"` | accept |
| §8.7 payload with an inner space, `==` padding, or `?x=1` appended | BadBase64 |
| `ndn-trust://recovery/+w` | BadBase64 |
| `ndn-trust://recovery/BB` (non-canonical trailing bits) | BadBase64 |
| `NDN-TRUST://recovery/…` | UnknownScheme |
| `https://x/t/recovery#` + payload | accept |
| `https://x:8443/t/recovery#` + payload | accept |
| `http://x/t/recovery#` + payload | UnknownScheme |
| `https://x/recovery#` + payload, `https://x/a/t/recovery#` + payload | UnknownScheme |
| `https://x/t/recovery` | MalformedUri |
| `ndn-trust://anchor` | MalformedUri |
| `ndn-ctx:1:42:Y3R4` | accept, version 42 |
| `ndn-ctx:1:+42:Y3R4` | MalformedUri |

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
- **Capability replay.** A capability carries no issuance time. A captured request can be
  shown again; the fresh Nonce lets a granting device notice (§7.4).
- **Kind token.** A URI whose token disagrees with its Kind is refused (§5.2), so a link
  cannot be routed to one flow while carrying another kind.

## 10. Open questions

- **Q7. u64 fields.** They are emitted as 8 bytes, not as NDN NonNegativeInteger (1/2/4/8
  minimal), and decoded from any 1–8 bytes. Should the format switch to NonNegativeInteger
  in a FormatVersion 2? **Recommendation:** yes, in FormatVersion 2 only: emit
  NonNegativeInteger and refuse lengths other than 1, 2, 4 and 8. FormatVersion 1 parsers
  already accept those lengths, but new output changes the canonical bytes and the §8
  vectors.
- **Q13. NFC and OS integration.** The NFC NDEF record type is not specified in this tree,
  and neither is the OS deep-link registration (`ndn-trust` scheme handler, universal-link
  association for `/t/`). **Recommendation:** one NFC Forum URI record (TNF well-known, type
  `U`, identifier code `00`, the `trust-uri` text). Register the `ndn-trust` scheme, and an
  associated-domains / App Links entry for paths `/t/*` on the issuer's mirror domain.
- **Q14. Delegation and recovery payloads.** The formats of the `delegation` Wire
  (`SignedDelegation`), PrincipalPubkey (raw key, which algorithm?) and the `recovery` bundle
  are not specified by any spec in this set. **Recommendation:** specify them, with an
  algorithm tag for PrincipalPubkey, in a spec of the mobile delegation and restore flows,
  and reference it from §4.4.

### Decisions

- **Q1 Trailing bytes.** Refused (§6.1). No producer emits them, and ignoring them let a
  damaged or altered file pass.
- **Q2 Unknown types.** NDN evolvability rule: critical types (≤ 31 or odd) refused, others
  skipped (§6). A later format can add required fields safely. Every producer emits only
  registry types.
- **Q3 One-byte fields.** FormatVersion, Kind and Direction must be exactly 1 byte (§6.2,
  §6.3). Producers always emit 1 byte, and extra bytes had no meaning.
- **Q4 Duplicates.** A repeated field other than ScopePattern is refused (§6.3). With last
  wins, a reviewer of the bytes could see one value while the parser used another. No
  producer repeats a field.
- **Q5 Fields of another kind.** Treated as unrecognized: critical refused, non-critical
  skipped unread (§6.3). One rule covers unknown and foreign fields. No producer emits them.
- **Q6 URI kind token.** It must equal the token of the Kind TLV, else KindMismatch (§5.2).
  A host routes on the token before decoding, so a mismatch steers the wrong flow. Every
  producer derives the token from the Kind.
- **Q8 Mirror detection.** `https://` only, path exactly `/t/<kind>`, payload in the
  fragment (§5.2). `ndn-fwd-tokens` and `ndn-fwd init` emit only this form, and `http://`
  would load the page carrying a bearer secret in clear.
- **Q9 Legacy version.** One or more ASCII digits; a leading `+` is refused (§5.2). Nothing
  emits the legacy form.
- **Q10 Mobile `bag`.** Mobile keeps Namespace and AnchorFingerprint, and `load_identity`
  refuses a namespace recovery key's SafeBag (§7.3). A host needs the kit's namespace and
  expected fingerprint to recover, and a recovery key loaded as the operator identity would
  sign as a device.
- **Q11 Binary files.** Files carry the text form only (§5.7). Nothing read or wrote
  `.ndntrust`, and one file form keeps files and pastes identical.
- **Q12 QR level.** Level M, byte mode, limit 2331 bytes (`qr::MAX_TEXT_LEN`). An inline anchor
  above the limit is rendered by reference (§5.6). Every renderer already used M, M survives
  damage better, and even L cannot hold an inline anchor for longer namespaces. The
  namespace test now checks against the shared limit, not L's.
- **Q15 Capability timing and nonce.** TtlSecs counts from decoding by the consumer. A request
  carries 16 fresh random bytes of Nonce, which a grant echoes, and a granting device should
  refuse a nonce it already granted (§4.3, §4.4, §7.4). An issuance time would need a format
  change; the nonce is the replay guard. `ndn-pair-kiosk` now draws a fresh nonce.
- **Q16 Name strings.** Producers emit the canonical URI form; parsers do not check it, and
  consumers compare parsed Names (§4.4). Equal values give byte-identical envelopes without a
  Name codec in the envelope layer. The CA's invite maker (`ndn_cert::CaInvites::create`)
  and `ndn-pair-kiosk` emit Names in canonical form.

## Appendix A. Code references (non-normative)

Paths are relative to the workspace root. Code in `ndn-fwd` may move to library crates.

| Claim | Location |
|---|---|
| Kinds, directions, carriage list, decoding rules summary | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:4-51` |
| TLV type numbers 0x0470–0x048F | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:61-81` |
| Fingerprint length 32, FORMAT_VERSION 1, `CAPABILITY_NONCE_LEN` 16, scheme, mirror and legacy tags | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:83-95` |
| Kind codes 1–6, unknown-kind error, kind tokens, fields per kind | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:114-181` |
| Direction codes 0/1 | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:192-206` |
| Envelope order FormatVersion, Kind, Body | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:297-307` |
| Body field order per kind; 8-byte u64; empty nonce omitted | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:309-391` |
| Outer decode: BadTag, trailing bytes, one-byte and repeated children, critical rule, error order | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:393-434` |
| Body decode (pass 1): fields per kind, critical rule, repeated fields, fingerprint and Direction length, ScopePattern push | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:436-490` |
| Per-kind requirements (pass 2) | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:492-535` |
| `to_uri`, `to_https_url` | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:537-554` |
| `qr_uri`: inline anchor falls back to by-reference | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:556-584` |
| `from_uri`: trim, legacy digits, scheme split, mirror rule, base64, kind-token check | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:586-646` |
| Critical rule, repeated field, one-byte value | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:648-669` |
| UTF-8 and u64 (1–8 bytes) rules | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:671-682` |
| Error set (incl. UnknownCritical, KindMismatch) | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:684-709` |
| Decoding-rule tests (trailing bytes, critical rule, one-byte, repeated, kind token, mirror, legacy) | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:911-1124` |
| QR: level M, limit 2331, byte-mode `encode`; limit/renderer and fallback tests | `ndn-rs/crates/security/ndn-trust-envelope/src/qr.rs:12-32,59-122` |
| base64 engine `URL_SAFE_NO_PAD`, crate 0.22.1 | `ndn-rs/crates/security/ndn-trust-envelope/src/lib.rs:53-54`; `ndn-rs/Cargo.toml:181`; `ndn-rs/Cargo.lock:136-137` |
| VAR-NUMBER minimal decode | `ndn-rs/crates/core/ndn-tlv/src/lib.rs:24-61` |
| TLV-TYPE range, length bound | `ndn-rs/crates/core/ndn-tlv/src/reader.rs:47-107` |
| Minimal VAR-NUMBER encode | `ndn-rs/crates/core/ndn-tlv/src/writer.rs:33-66` |
| Anchor fingerprint = SHA-256(cert public key) | `ndn-rs/crates/security/ndn-security/src/trust_context/mod.rs:1056-1063` |
| Cert public key: Ed25519 SPKI unwrapped, else Content | `ndn-rs/crates/security/ndn-security/src/cert_cache.rs:31-38`; `ndn-rs/crates/security/ndn-security/src/spki.rs:46-49` |
| Anchor consumer checks | `ndn-rs/crates/security/ndn-cert/src/onboarding.rs:237-298` |
| Invite consumer checks | `ndn-rs/crates/security/ndn-cert/src/invite.rs:85-152` |
| Token role / `-until` expiry; namespace component rule | `ndn-rs/crates/security/ndn-cert/src/roles.rs:91-93,204-232,303-340` |
| File kit: URI text, reading and checks | `ndn-rs/crates/security/ndn-cert/src/recovery.rs:400-513` |
| File kit written as `<uri>\n`, 0600 | `ndn-fwd/binaries/ndn-fwd/src/recovery_kit.rs:484-485` |
| Namespace init emits inline signed anchor | `ndn-rs/crates/security/ndn-cert/src/namespace.rs:159-165` |
| Init anchor link has a QR form within the shared limit (inline or by reference) | `ndn-rs/crates/security/ndn-cert/src/namespace.rs:589-611` |
| `ndn-fwd init` prints `anchor_uri`, `anchor_url` (ndn.local), `anchor_uri_fp`, QR hint by size | `ndn-fwd/binaries/ndn-fwd/src/onboard.rs:472-497` |
| Invite emission (CA prefix and scope as Names, TtlSecs = remaining token life, DeviceName hint) | `ndn-rs/crates/security/ndn-cert/src/invites.rs` (`CaInvites::create`) |
| Mirror via `--domain`; QR rendering (`qr::encode`, ASCII 2×1, SVG ≥256 px, 0600) | `ndn-fwd/binaries/ndn-fwd-tokens/src/main.rs` (`shown_link`, `render_qr`) |
| Context authoring: signed vs unsigned legacy anchor; QR via `qr_uri` | `ndn-fwd/binaries/ndn-trust-context/src/lib.rs:103-148`; `ndn-fwd/binaries/ndn-trust-context/src/main.rs:142-206` |
| QR rendering in `ndn-trust-context` | `ndn-fwd/binaries/ndn-trust-context/src/main.rs:274-298` |
| Dev emitter, QR via `qr::encode` | `ndn-rs/crates/security/ndn-trust-envelope/examples/emit.rs:47-58` |
| `qrcode` byte mode and terminator, `with_bits`, quiet zone 4 | `qrcode-0.14.1/src/bits.rs:495-501,720-748`; `qrcode-0.14.1/src/lib.rs:149-158,250` (cargo registry) |
| Mobile parser; Bag keeps Namespace and AnchorFingerprint | `ndn-mobile/crates/ndn-boltffi/src/trust.rs:28-31,83-157,159-203`; `ndn-mobile/crates/ndn-boltffi/src/types.rs:419-431` |
| Mobile `load_identity` refuses a namespace recovery key | `ndn-mobile/crates/ndn-boltffi/src/identity_core.rs:568-586,602-609`; test `ndn-mobile/crates/ndn-boltffi/src/engine.rs:2250-2282` |
| Mobile builders (delegation, recovery, capability) | `ndn-mobile/crates/ndn-boltffi/src/trust.rs:38-80` |
| Capability request with a fresh 16-byte nonce, canonical namespace | `ndn-fwd/binaries/tooling/ndn-pair-kiosk/src/main.rs:65-83,209-229` |
| Mgmt verbs take the link in `ControlParameters.Uri` | `ndn-rs/crates/core/ndn-mgmt-wire/src/nfd_command.rs:121-131`; `ndn-rs/crates/forwarding/ndn-mgmt/src/modules/security.rs:318-387` |

## Appendix B. Vector provenance (non-normative)

The vectors in §8 were produced on 2026-10-18 by a temporary example in the
`ndn-trust-envelope` crate, run with `cargo run --example` and deleted afterwards. The program:
- encoded each value in §8 with `TrustEnvelope::encode` / `to_uri` / `to_https_url`;
- asserted both round trips;
- fed the hand-built inputs of §8.12 to `TrustEnvelope::decode` / `from_uri`;
- rendered every URI with `qrcode::QrCode::new` (EC M) and `with_error_correction_level(L)`
  to report versions.

The §8.12 results were then revised by hand for the stricter decoding rules (§10, Decisions
Q1–Q6, Q8, Q9). The unit tests in `ndn-trust-envelope` (`src/lib.rs`, `src/qr.rs`) cover
each revised row. QR versions in §8 match the byte-mode capacities at M and L, which is
how the renderer now encodes (§5.6); `qr::tests::vector_versions` checks §8.1 and §8.4.
