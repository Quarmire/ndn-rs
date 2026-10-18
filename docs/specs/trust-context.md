# Trust context: wire format, versioning, publication and sync

- **Status:** Draft
- **Scope:** the signed trust context of a namespace as ndn-rs encodes,
  signs, verifies, adopts, publishes, refreshes and synchronizes it. This
  covers the TLV registry `0x0410–0x041E` and every value encoding, the name
  and signature of a context Data, the continuity rule between versions, the
  catch-up walk, RDR publication, the refresh state machine and the
  context-sync group. An independent implementation (NDNts, python-ndn, …)
  that follows this document can fetch, verify, apply and publish contexts
  interoperably with ndn-rs.
- **Out of scope:** how a context is first handed to a device out of band
  ([trust-envelope.md](trust-envelope.md)), recovery-key derivation and kit
  formats ([recovery-kit.md](recovery-kit.md)), link admission that reads
  `LinkPolicy` ([ndn-link.md](ndn-link.md)), NDNCERT behaviour that reads
  `EnrollmentHint` ([ndncert-extensions.md](ndncert-extensions.md)), and the
  refusal Nacks a validating forwarder answers with
  ([local-refusal.md](local-refusal.md)). The design rationale and flow names
  (F1–F11) are in [personal-namespace.md](personal-namespace.md).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174)
when, and only when, they appear in all capitals, as shown here.

Every byte-level statement below is taken from the ndn-rs code at the time of
writing. Appendix A gives the file and line for each one. Where the code is
ambiguous, or the ndn-fwd and ndn-mobile copies differ, this document states
what the library and ndn-fwd do and lists the point under §12 "Open
questions".

## 1. Terminology

| Term | Meaning |
|---|---|
| namespace | An NDN name prefix `/<ns>` that one root key governs. |
| root device | The device holding the namespace root key, where new context versions are made (`ndn-fwd init`). |
| trust context (context) | The root-signed statement of a namespace's anchors, schema, CA endpoints, revocations, key roles and policies. It is versioned and published as NDN Data. |
| version | The unsigned integer `N` in the context's name. Versions of one namespace are totally ordered. |
| anchor | A certificate listed in the context's `AnchorSet`. A key named by an anchor is root-equivalent: it can sign the next version. |
| expected fingerprint | SHA-256 over an anchor's public key (§3.3.2), learned out of band. It authenticates the first context a device adopts. |
| adopt | Accept a context into the set this node validates with (its *keyring*). |
| held version | The version of a namespace's context this node currently has adopted. |
| continuity rule | Version `M > N` is accepted on top of held version `N` only if a key that is an anchor of `N` signed `M` (§5.2). |
| walk / catch-up | Following versions `N+1 … M` one by one, each under the continuity rule from the one before it (§5.4). |
| keep | Persist a version and publish it (§7). |
| enroll, invite, link, relay, route, approval, recovery kit | As in the "Terms used throughout" table of [personal-namespace.md](personal-namespace.md). |

Name notation follows NDN URI conventions. `32=x` is a
`KeywordNameComponent` (TLV-TYPE 32 = `0x20`) with value the ASCII string
`x`. `v=N` is a `VersionNameComponent` (TLV-TYPE `0x36`). `seg=N` is a
`SegmentNameComponent` (TLV-TYPE `0x32`). Both carry `N` as a
NonNegativeInteger. Every other literal component is a
`GenericNameComponent` (TLV-TYPE `0x08`). ndn-rs prints keyword components
as `keyword=x`.

"NonNegativeInteger" means the NDN encoding: big-endian in 1, 2, 4 or 8
octets. ndn-rs always writes the shortest of these forms (canonical form).

## 2. Overview

A namespace's context is one NDN Data packet per version:

```
/<ns>/32=trust-context/v=<N>        Content = TrustContext TLV (0x0410)
                                    signed by an anchor key of the context itself
```

It is published by RDR with a metadata Data that names the newest version
(§7). A node that holds nothing adopts a first version when its signing
anchor matches an expected fingerprint (§4.4). A node that holds version `N`
adopts `M > N` only under the continuity rule (§5). Versions reach nodes by a
periodic pull refresh (§8) and, optionally, by a push over an SVS sync group
(§9). Every node keeps and serves every version it held, so a node that
missed versions can walk from the version it holds to the newest.

## 3. Content encoding

### 3.1 TLV registry

All TLV-TYPEs are in the application range. Parity follows the ndn-cxx
evolvability rule: a type is *critical* iff `type <= 31` or `type` is odd.

| TLV-TYPE | Name | Crit. | Where | Count | Value |
|---|---|---|---|---|---|
| `0x0410` | TrustContext | (outer) | Data Content | 1 | sub-TLVs below |
| `0x07` | Name (namespace) | yes | in TrustContext | 1 (REQUIRED) | Name *components* (§3.3.1) |
| `0x0411` | AnchorSet | yes | in TrustContext | 0..1 (see §3.3.2) | concatenated certificate Data (`0x06`) |
| `0x0412` | LinkPolicy | no | in TrustContext | 0..1 | UTF-8 text (§3.3.10) |
| `0x0413` | TrustSchemaBlob | yes | in TrustContext | 1..n (REQUIRED) | `SchemaFormat` + `SchemaBody` |
| `0x0414` | CaEndpoint | no | in TrustContext | 0..n | a complete Name TLV (`07 L …`) |
| `0x0415` | SchemaFormat | yes | in TrustSchemaBlob | 1 | 1 octet: `1` native text, `2` LVS binary |
| `0x0416` | EnrollmentHint | no | in TrustContext | 0..1 | flags octet + text (§3.3.7) |
| `0x0417` | SchemaBody | yes | in TrustSchemaBlob | 1 | schema bytes per SchemaFormat |
| `0x0418` | Revocation | no | in TrustContext | 0..n | a complete Name TLV |
| `0x041A` | SourceBundleHash | no | in TrustContext | 0..1 | 32 octets |
| `0x041C` | SchemaAuthoritative | no | in TrustContext | 0..1 | empty (flag) |
| `0x041E` | KeyRole | no | in TrustContext | 0..n | 1 role octet + a complete Name TLV |

`0x0419`, `0x041B`, `0x041D` and `0x041F` are unassigned. `0x0403–0x040F` is
left free below the block. The block is provisional and has not been
submitted to the NDN TLV registry.

The value encodings differ in one place that implementers must notice. The
namespace Name is written *directly* as a `0x07` child of TrustContext. The
values of CaEndpoint, Revocation and KeyRole *contain* a full `0x07` Name TLV,
header included.

### 3.2 Structure and producer order

```
TrustContext   = 0x0410 TLV-LENGTH
                   Name                         ; the namespace
                   AnchorSet
                   1*TrustSchemaBlob
                   [SchemaAuthoritative]
                   *CaEndpoint
                   [EnrollmentHint]
                   *Revocation
                   [SourceBundleHash]
                   *KeyRole
                   [LinkPolicy]
AnchorSet      = 0x0411 TLV-LENGTH *Data         ; each a certificate, 0x06
TrustSchemaBlob= 0x0413 TLV-LENGTH SchemaFormat SchemaBody
SchemaFormat   = 0x0415 1 (%x01 / %x02)
SchemaBody     = 0x0417 TLV-LENGTH *OCTET
SchemaAuthoritative = 0x041C 0
CaEndpoint     = 0x0414 TLV-LENGTH Name
EnrollmentHint = 0x0416 TLV-LENGTH Flags *OCTET
Revocation     = 0x0418 TLV-LENGTH Name
SourceBundleHash = 0x041A 32 32OCTET
KeyRole        = 0x041E TLV-LENGTH RoleCode Name
LinkPolicy     = 0x0412 TLV-LENGTH *OCTET        ; UTF-8
```

A producer MUST emit the fields in the order above. ndn-rs always emits
`AnchorSet`, even when it is empty. Within a repeatable field, ndn-rs emits
CaEndpoint, Revocation and KeyRole entries in the order they were added. A
new version made from an earlier one carries the earlier entries first and
appends new ones (Test vector T7). Anchor order inside AnchorSet is not
defined (§12, Q1). TLV-LENGTH uses the shortest NDN VAR-NUMBER form.

The Content of a context Data MUST be exactly one TrustContext TLV. ndn-rs
ignores bytes after it.

### 3.3 Field semantics and value encodings

#### 3.3.1 Namespace (`0x07`)

The TLV-VALUE is the namespace's name components. The namespace MUST equal
the name prefix before `32=trust-context` in the Data name (§4.1). A decoder
MUST reject a TrustContext without a namespace.

#### 3.3.2 AnchorSet (`0x0411`)

The value is zero or more NDN certificates (Certificate Format v2), each a
complete Data TLV (`0x06`), concatenated. A decoder MUST skip any element
whose TLV-TYPE is not `0x06`. It MUST reject the context when an element of
TLV-TYPE `0x06` does not decode as a Data or as a certificate.

ndn-rs reads these parts of each certificate:

- **Name** — `…/KEY/<key-id>/<issuer-id>/<version>`. An anchor's *key name*
  is its certificate name without the last two components. A name whose
  fourth-last component has value `KEY` is a certificate name; any other
  name is used unchanged as a key name.
- **Public key** — the certificate Content. If the Content is the 44-octet
  Ed25519 SPKI (`302a300506032b6570032100` ‖ 32-octet key), the public key is
  the 32 raw octets. Otherwise it is the Content verbatim, e.g. the DER SPKI
  of a P-256 key.
- **ValidityPeriod** — NotBefore/NotAfter, `YYYYMMDDTHHMMSS`.

The **anchor fingerprint** is `SHA-256(public key)`, with the public key as
defined above. For Ed25519 that is SHA-256 over the 32 raw octets, not over
the SPKI. The fingerprint does not change when a certificate for the same key
is re-issued.

Anchors match by key (§6.2). A decoder does not check anchor validity
periods (§12, Q4). ndn-rs producers add an anchor only when it is valid at
the time of encoding. ndn-rs makes root anchors self-signed, with NotAfter
derived from `u64::MAX` ns (`25540721T233433`) and name
`/<ns>/KEY/root/self/v=<ms>`. The anchor format of a recovery kit is in
[recovery-kit.md](recovery-kit.md).

#### 3.3.3 TrustSchemaBlob (`0x0413`), SchemaFormat (`0x0415`), SchemaBody (`0x0417`)

Each blob carries exactly one SchemaFormat and one SchemaBody. A decoder:

- MUST reject a blob that lacks either sub-TLV;
- MUST reject a SchemaFormat whose first octet is not `1` or `2`. An empty
  SchemaFormat reads as `0` and is rejected;
- ignores any other sub-TLV inside a blob, whatever its parity (§12, Q6);
- MUST reject a TrustContext with no blob at all.

- **Format 2, LightVerSec binary.** This is the portable form, the binary
  LVS model that python-ndn and NDNts produce and read.
- **Format 1, native text.** UTF-8 lines; empty lines are ignored and each
  line is trimmed. Each line is `<data pattern> => <key pattern>`, split at
  the first `=>`. A pattern is `/`-separated. In a pattern:
  - `name` is a literal GenericNameComponent with those raw UTF-8 bytes (no
    percent-decoding);
  - `<v>` captures one component, and every capture with the same `v` must
    match the same component across the data and key patterns;
  - `<**v>` matches all remaining components, zero or more, and MUST be last;
    it binds nothing;
  - `<!x>` matches one component that is not the literal `x`.

  A rule admits a `(data name, key name)` pair if both patterns match with
  consistent captures.

The runtime schema is the logical OR of all blobs. A context MUST NOT carry
more than one format-2 blob, and a decoder MUST reject a context that does.
The namespace context `ndn-fwd init` generates carries one LVS blob and one
native-text blob. The native blob holds the rules LVS cannot express (see
the `init_namespace` structure under §11). A node that understands only some
blobs authorizes less, never more. However, ndn-rs rejects an unknown
*format code*, so it does not skip a blob it cannot read (§12, Q5).

#### 3.3.4 SchemaAuthoritative (`0x041C`)

An empty flag; ndn-rs ignores the length on decode. When it is present, the
schema governs alone: there is no hierarchy floor, and every certificate hop
of a chain walk is checked against the schema (§6.4). When it is absent, the
decoded context enforces the hierarchy floor. Contexts generated by
`ndn-fwd init`, and every schema update, carry the flag.

#### 3.3.5 CaEndpoint (`0x0414`)

The value is one complete Name TLV naming a CA prefix, e.g. `/<ns>/CA`. The
field is repeatable. A decoder MUST reject the context if the value is not a
valid Name TLV. CA endpoints affect three things:

- the certification rule (§6.4);
- whether enrollment links are admitted (§3.3.10);
- where devices enroll ([ndncert-extensions.md](ndncert-extensions.md)).

#### 3.3.6 Revocation (`0x0418`)

The value is one complete Name TLV, and the field is repeatable. A decoder
MUST reject the context if the value is not a valid Name TLV. A name `X` is
revoked by the context iff some entry `R` is a component-wise prefix of `X`.
Revoking a key name `/<id>/KEY/<k>` therefore revokes every certificate of
that key, including certificates issued later.

A producer (root device) MUST NOT add an entry that:

- is not a key name under the namespace, i.e. not of the form
  `<…>/KEY/<k>` with `KEY` as the second-to-last component, and with the
  namespace as a prefix; or
- is a prefix of an anchor's certificate name.

It MUST NOT repeat an entry that is already covered. A decoder accepts any
Name.

#### 3.3.7 EnrollmentHint (`0x0416`)

```
value = flags challenges [ ";" roles ]
flags = 1 OCTET     ; bit 0x01 REQUIRE_ALL, bit 0x02 HAS_ROLES
challenges = [ id *( "," id ) ]   ; UTF-8 NDNCERT challenge ids
roles      = [ role *( "," role ) ]
```

**Encoding.** `flags` gets `0x01` if every challenge is required for the
approval roles, and `0x02` iff the role list is non-empty. The challenge list
is joined with `,`. When roles are present, `;` and the role list (joined
with `,`) follow. Nothing is escaped: an identifier MUST NOT contain `,` or
`;`.

**Decoding.**

- An empty value is flags `0` with no challenges.
- If `flags & 0x02`, the text is split at the first `;`.
- If `flags & 0x02` is clear, the whole text is the challenge list and the
  role list is empty. In that case `require_all = (flags != 0)`: this is the
  legacy form, where any non-zero octet meant "all required". Otherwise
  `require_all = (flags & 0x01 != 0)`.
- An empty list text gives an empty list, and invalid UTF-8 is replaced
  (lossy).
- A malformed hint never rejects the context.

The known challenge ids are `token`, `pin`, `email`, `proof-of-possession`,
`device-approval` and `yubikey`. The default that `ndn-fwd init` writes is
`flags=0x02`, `token,device-approval;admin,node`. The meaning is in
[ndncert-extensions.md](ndncert-extensions.md).

#### 3.3.8 SourceBundleHash (`0x041A`)

The value is 32 octets: the SHA-256 implicit digest of the trust bundle this
context was compiled from. It is a provenance hint only. A value of any other
length MUST be ignored (skipped as non-critical) and does not reject the
context.

#### 3.3.9 KeyRole (`0x041E`)

```
value = RoleCode Name      ; RoleCode = 1 OCTET; Name = complete 0x07 TLV
```

| RoleCode | Meaning |
|---|---|
| `1` | **recovery-anchor**: the named key is an anchor generated for a recovery kit. It is kept offline and used only to sign a version that replaces a lost root device ([recovery-kit.md](recovery-kit.md)). |
| `2` | **root-device**: the named key lives on the root device beside the root, e.g. the CA key `/<ns>/CA/KEY/ca` and the root device's admin key. A recovery after a compromise revokes these keys. |
| other | Unknown. A decoder MUST keep the entry and MUST re-emit it unchanged when it makes a new version from this one. |

The Name is a key name. Entries are unique per (code, name). A value of
length ≤ 1, or one whose remainder is not a valid Name TLV, MUST be dropped
without rejecting the context. A node that does not understand KeyRole
treats every anchor alike, which is correct for a recovery anchor.

#### 3.3.10 LinkPolicy (`0x0412`)

```
value = roles ";" relay-roles [ ";" ( "enrollment" / "no-enrollment" ) ]   ; UTF-8
roles = [ role *( "," role ) ]     ; empty = every device role
```

**Encoding.** ndn-rs always writes all three fields.

**Decoding.** Split the value at `;`. A missing first or second field, a
third field other than `enrollment` or `no-enrollment`, or invalid UTF-8
makes the *field* invalid: the context is kept and the default policy
applies. A missing third field means `enrollment`. Empty role names inside
a list are dropped. Fields after the third are ignored (§12, Q7).

**Semantics.** A device's role is the component after the namespace in its
certificate name, `/<ns>/<role>/<device>`.

- A device with role `r` may link iff `roles` is empty or contains `r`.
- It may relay iff it may link *and* `relay-roles` contains `r`.
- A relay admits *enrollment links* iff the third field is `enrollment`
  *and* the context has at least one CaEndpoint.

When the field is absent the default applies: `roles` empty,
`relay-roles = node`, `enrollment`, which encodes as `;node;enrollment`.
Admission itself is in [ndn-link.md](ndn-link.md).

### 3.4 Decoder rules

A decoder:

1. MUST reject Content whose first TLV is not `0x0410`, or any truncated
   TLV.
2. Processes the TrustContext children in order. A later Name, EnrollmentHint,
   SourceBundleHash or LinkPolicy overwrites an earlier one, so a later
   *invalid* LinkPolicy resets the policy to the default. CaEndpoint,
   Revocation, KeyRole and TrustSchemaBlob accumulate. AnchorSet
   accumulates across repeated AnchorSets.
3. MUST reject an unknown critical child type (`<= 31` or odd), and MUST
   skip an unknown non-critical one (even). A KeyRole or SourceBundleHash
   that fails its length check is skipped as non-critical.
4. MUST reject the context when the namespace is missing, no
   TrustSchemaBlob is present, or the schema does not import (LVS error,
   native-text parse error, more than one LVS blob).

## 4. The context Data

### 4.1 Name

```
/<ns>/32=trust-context/v=<N>
```

- `<ns>` is the namespace (§3.3.1), with all its components.
- `32=trust-context` is a KeywordNameComponent with value
  `74 72 75 73 74 2d 63 6f 6e 74 65 78 74`.
- `v=<N>` is a VersionNameComponent; `N` is the version, a NonNegativeInteger.

The version lives only in the name; the Content carries no version field. A
consumer MUST take the version from the last name component. It MUST then
check that the Data name is byte-for-byte equal to the name rebuilt from the
decoded namespace and that version, written with the canonical (shortest)
NonNegativeInteger. A context Data whose version component is not in
canonical form is therefore rejected. Producers MUST use canonical form.

The first version a namespace gets from `ndn-fwd init` is `1`. Every new
version is the previous one plus one; ndn-rs refuses to bump past
`u64::MAX`.

### 4.2 Data fields

ndn-rs emits a context Data with these fields:

- Name (§4.1).
- **No MetaInfo.** ContentType is therefore BLOB and there is no
  FreshnessPeriod. A consumer MUST NOT require MetaInfo.
- Content: the TrustContext TLV.
- SignatureInfo: SignatureType and a KeyLocator of type Name. ndn-rs writes
  the signer's *key name*, e.g. `/<ns>/KEY/root`. A consumer MUST also
  accept a KeyLocator that names one of that key's certificates.
- SignatureValue.

The signature MUST be a public-key signature: SignatureSha256WithRsa (`1`),
SignatureSha256WithEcdsa (`3`) or SignatureEd25519 (`5`). A consumer MUST
reject a context whose SignatureType is DigestSha256, HMAC or anything else,
because anyone could re-sign a tampered context with those. A consumer MUST
also reject a context with no KeyLocator, or with a KeyLocator that is not a
Name.

### 4.3 Who signs: self-consistency

A context Data is **self-consistent** iff all of these hold:

1. its name matches §4.1;
2. its Content decodes (§3.4);
3. its KeyLocator resolves to an anchor of *the context it carries* (§6.2);
4. its signature verifies under that anchor's public key, over the standard
   NDN signed portion (Name through SignatureInfo).

Self-consistency proves only that the context is exactly what one of its own
anchors signed. Whether that anchor is trusted is decided by §4.4 for a
first adoption, and by §5.2 for an update. A version MUST therefore list,
among its anchors, the key that signs it.

ndn-rs signs:

- version 1 with the namespace root key `/<ns>/KEY/root`;
- revocation and schema-update versions with an anchor key of the version
  before, normally the root;
- a recovery version (`N+1`) with a recovery-anchor key;
- the re-issued `N+2` with the new root (§5.3).

A signer that is not an anchor of the held version is refused before
anything is signed.

### 4.4 First adoption (nothing held)

A node that holds no context for `<ns>` MUST adopt a context Data only if
all of these hold:

- it is self-consistent (§4.3);
- its namespace equals the namespace the out-of-band link named;
- the anchor that signed it has the **expected fingerprint** from that link
  (§3.3.2);
- its version is at least the version the link names, when the link names
  one. This closes a first-contact downgrade to an older genuine context.

The link and envelope formats are in [trust-envelope.md](trust-envelope.md).
How the context is fetched is in §8.1. ndn-rs refuses unsigned (legacy
`ndn-ctx:1:`) content on every default path.

## 5. Versioning and continuity

### 5.1 Anti-rollback

A node MUST NOT replace its held version with a lower one. ndn-rs applies
two rules:

- **Adoption from a link** (§4.4) replaces the held context iff the offered
  version is ≥ the held version. An equal version replaces it (§12, Q3).
- **Update** (§5.2) replaces it iff the offered version is *strictly*
  greater. ndn-rs also requires that the held context is still the exact
  one the update was checked against, a compare-and-swap. If another
  adoption changed it meanwhile, nothing is adopted and the next refresh
  starts from the new held version.

When an adoption adds revocations that the replaced version did not have,
the node SHOULD purge cached Data signed by the newly revoked keys.

### 5.2 Continuity rule

A node holding version `N` (context `H`) MUST accept a context Data `D` as an
update only if all of these hold:

1. `D` is self-consistent (§4.3), and its signer anchor is `A`;
2. the namespace of `D` equals the namespace of `H`;
3. the version of `D` is greater than `N`;
4. some anchor of `H` has a public key byte-equal to `A`'s public key (§3.3.2).

So version `N+1` is authorized by version `N`. A version may add anchors,
for a root rotation or a new recovery anchor, but those anchors carry trust
only once that version is adopted. Rule 4 compares public keys, not names: a
re-issued certificate of the same key satisfies it.

### 5.3 Root hand-over (informative summary)

The continuity rule carries every authority change. The recovery and kit
procedures are specified in [recovery-kit.md](recovery-kit.md).

- **Revocation bump (F4–F6):** `N+1` is `N` plus new Revocation entries,
  signed by an anchor of `N`. Everything else is carried over verbatim.
- **Schema update:** `N+1` carries new blobs, the EnrollmentHint, the
  SchemaAuthoritative flag, and optionally a new LinkPolicy. It is signed by
  an anchor of `N`. ndn-rs refuses a narrowing unless the operator consents,
  but that is a producer-side check only.
- **Recovery anchor added or removed (F7):**
  - When a recovery key is added, `N+1` gains the new anchor and a KeyRole
    `1` entry, signed by the root.
  - When one is removed, `N+1` drops that anchor and its KeyRole entries and
    revokes the key, signed by a different anchor.
- **Recovery (F8):** `N+1` is signed by a recovery key that is an anchor of
  `N`.
  - It adds the new root as an anchor and replaces the KeyRole `2` entries.
  - With `--old-root compromised`, it also removes and revokes the old root,
    the old root-device keys, and the recovery anchors nobody vouched for.
  - The new root then re-issues the same content as `N+2`, signed by itself
    as an anchor of `N+1`.

  A node holding `N` cannot accept `N+2` directly, because `N+2` is not
  signed by an anchor of `N`. It walks `N → N+1 → N+2` instead (§5.4).

### 5.4 Catch-up walk

When a refresh (§8.2) or a sync update (§9.5) has a newest Data `D` at
version `M` that fails rule 4 of §5.2 against held `N`, the node walks the
versions in between. In a refresh, a forwarder refusal of `D` triggers the
walk as well. The walk applies only if `M > N + 1`; otherwise `D` is
refused.

- **Positions:** `N+1 … M` for a refresh; `max(low_seq, N+1) … M` for a sync
  update (§12, Q8).
- **Bound:** if the number of positions exceeds **128**
  (`MAX_CATCH_UP_VERSIONS`), the walk is refused before anything is fetched.
- **Deadline:** no fetch starts after **40 s** (`MAX_CATCH_UP_TIME`). The
  clock starts when the refresh begins fetching the newest version. A
  position not fetched by then counts as missing.
- **Fetch:** position `p` is fetched by exact name `/<ns>/32=trust-context/v=<p>`
  (refresh), or as the group Data `<member>/seg=<p>` (sync, §9.3). Position
  `M` reuses `D`.

For each position `p` in order, with `from` = the last version reached
(initially `H`):

1. If the Data arrives and passes §5.2 against `from`, it becomes the version
   reached, and any record of passed-over positions is cleared.
2. If it arrives with a version not greater than `from` and `p < M`, skip
   it.
3. If nothing usable arrives and `p < M`, record `p` as passed over and
   continue.
4. If nothing usable arrives and `p = M`, stop: **unreachable**.
5. Any other refusal stops the walk. This covers a Data that arrived and
   failed §5.2 (forged, foreign, not signed by an anchor of `from`), a
   forwarder refusal, and a not-newer Data at `p = M`. It is reported as
   **missing `[first…last]`** when positions were passed over since the
   last version reached, else as **refused at `p`**.

The walk succeeds only if position `M` is reached. A node MUST NOT adopt any
intermediate version on its own; it adopts only the newest, under §5.1. A
stopped walk changes nothing. After a successful walk, the node SHOULD keep
and serve every version it walked through as well as the newest (§7), so
nodes behind it can walk the same way.

## 6. Applying a context (validation)

### 6.1 Context selection

A node validates a packet or certificate named `X` under the adopted
context whose namespace is the **longest** component-wise prefix of `X`. If
no adopted context matches, it uses the ambient context. In a plain
`Keyring`, the ambient context is deny-all: hierarchical with no anchors.
A chain walk terminates only at an anchor of the selected context.

### 6.2 Anchor matching

A name `K` (key name or certificate name) refers to an anchor of the context
when either:

- an anchor is stored under exactly `K`; or
- some anchor has the same key name as `K` (§3.3.2), or an anchor's
  certificate name is `K` plus two components (`K/<issuer>/<version>`).

Among several matches, ndn-rs prefers, in order: valid now, then newest
NotBefore, then the greatest name.

### 6.3 Revocation

During a chain walk, every key and certificate name passed is checked against
§3.3.6. A covered name fails validation. This holds whichever form the
KeyLocator uses, and for certificates issued after the revocation.

### 6.4 Authorization

**Signing a packet:** `(data name D, key name K)` is authorized iff both of
these hold:

- *Hierarchy floor*, only when SchemaAuthoritative is absent: the identity of
  `K` is a prefix of `D`. The identity is `K` truncated before the first
  component whose value is `KEY`.
- *Schema*: some rule of the runtime schema admits `(D, K)`.

ndn-rs also tries the equivalent key forms. The pair is authorized if any
combination admits it:

- for the signer: the KeyLocator as given, the resolved certificate name, or
  the key name;
- for the signed name: the name as given, and for a certificate also its
  key name.

**Certifying a key:** issuer `I` may certify certificate `C` iff any of
these holds:

- `I` refers to an anchor;
- the identity of `I` is a prefix of the identity of `C`;
- the identity of `I` is one of the context's CaEndpoints and the identity
  of `C` lies under the namespace.

When SchemaAuthoritative is set, every certificate hop must also satisfy the
schema. A context decoded from the wire always judges certificate hops,
because it has either the floor or the flag.

## 7. Publication (RDR)

A node that keeps contexts SHOULD publish them. ndn-fwd does so unless
`[security] serve_contexts = false`; the default is `true`. ndn-boltffi
(mobile) does not publish.

### 7.1 Names and answers

Per namespace, the publisher registers the prefix
`/<ns>/32=trust-context` and answers Interests as follows:

| Interest name (exact) | Answer |
|---|---|
| `/<ns>/32=trust-context/32=metadata` | the current metadata Data (§7.2) |
| `/<ns>/32=trust-context/v=<N>`, `N` held | the stored signed context Data of version `N`, **byte-identical** to what was verified on adoption, never re-signed |
| anything else under the prefix | Nack, reason NoRoute (150) |

"Anything else" includes a version that is not held, `…/32=metadata/v=…`,
and the bare prefix. Matching is on the Interest name only:

- the metadata answer requires the name to equal the metadata name exactly;
- a versioned answer requires exactly one component after the prefix,
  decoded as a VersionNameComponent.

The Nack makes a walk past a version this node never held move on at once.

### 7.2 Metadata Data

```
Name     = /<ns>/32=trust-context/32=metadata/v=<N>/seg=0     ; N = newest version held
MetaInfo = FreshnessPeriod 1000 (ms)                            ; no ContentType
Content  = Name TLV of /<ns>/32=trust-context/v=<N>             ; nothing else
Signature= DigestSha256 (SignatureType 0, no KeyLocator)
```

The metadata version component is the *context* version, not a timestamp,
and the segment is always `0`. Content carries only the Name. There is no
FinalBlockId or size, because the context is a single Data.

The metadata Data is deliberately signed with DigestSha256, for two reasons:

- A first-contact adopter cannot check a node signature anyway.
- Every forwarder that holds the namespace context validates arriving Data
  against the generated schema. That schema has no rule for the metadata
  name, so a key-signed metadata Data would be dropped one hop away.
  DigestSha256 Data is accepted as integrity-only.

A consumer MUST NOT trust the metadata beyond the confinement in §8.1.

### 7.3 What to publish, and cache hygiene

- A node MUST serve every version it holds or held (stored newest plus
  stored version history), so that walks succeed (§5.4).
- The metadata names the highest version held. Adding an older version, for
  example one walked through, does not change it.
- When the newest version changes, the publisher SHOULD evict
  `/<ns>/32=trust-context/32=metadata/…` from its own Content Store before
  answering again. Otherwise a cached pointer to the superseded version
  satisfies MustBeFresh for up to 1 s.
- While a node fetches its own namespace's context upstream (adoption by
  fingerprint, refresh), it MUST NOT answer those Interests from its own
  publisher. ndn-fwd removes the publisher's FIB nexthop for the duration
  and evicts cached metadata before asking.

## 8. Fetching and refreshing

### 8.1 Fetch by name

1. Express an Interest for `/<ns>/32=trust-context/32=metadata` with
   CanBePrefix and MustBeFresh. ndn-rs writes InterestLifetime 4000 ms
   (its encoder default), and its consumer waits at least 4.5 s.
2. The reply's name MUST have that metadata name as a prefix and MUST carry
   Content.
3. Decode the Content as TLVs and take the first `0x07`; other TLVs are
   ignored. The resulting pointer MUST be exactly
   `/<ns>/32=trust-context/v=<N>`: the RDR prefix plus one
   VersionNameComponent. Anything else is a foreign pointer and MUST be
   refused.
4. Express an Interest for that exact name, with no CanBePrefix and no
   MustBeFresh. The reply's name MUST equal it.
5. Authenticate the Data under §4.4 (first adoption) or §5.2 (update).

A forged pointer can only lead to one of these outcomes:

- a forged or foreign context, which fails the fingerprint or continuity
  check;
- an older genuine context, which anti-rollback refuses, or the link's
  minimum version refuses on first contact;
- a name nobody serves, which fails the fetch.

### 8.2 Refresh

A node that does not hold the namespace root key refreshes each held context
as follows. "Holds the root key" means its root store holds the key of an
anchor of the held version; that node is the source of new versions and
does not fetch.

1. Fetch the pointer (§8.1 steps 1–3). Let `O` be the offered version and
   `N` the held version.
   - No answer (timeout, no route, Nack) → **Unreachable**.
   - Another pointer error → **Failed**.
2. If `O = N` → **Current**. If `O < N` → **UpstreamOlder**. In both cases
   nothing else is fetched.
3. Fetch `O` by exact name. A fetch error → **Failed**.
4. Check §5.2 against the held context.
   - On a pass, the result is the newest.
   - On failure of rule 4 (or a forwarder drop) with `O > N+1`, walk (§5.4).
   - Any other refusal → **Failed**.
5. Adopt the newest under §5.1 (compare-and-swap). If the held version
   changed meanwhile → **Failed** ("changed meanwhile").
6. Keep the walked versions first, then the newest: store, publish (§7),
   and hand to the sync group (§9.4) → **Updated**.

**Behind rule (ndn-fwd).** Suppose the outcome is Current or UpstreamOlder
with answered version `a`, but the context-sync group has *verified* a
version `v > max(N, a)` (§9.7). Then the outcome is **Behind** instead:
the answer is stale, and nothing changes. A bare sequence number never
counts as verified.

**Outcomes.** ndn-fwd reports:

- **Source**: the node holds the root key;
- **Current**, **UpstreamOlder**, **Updated**, **Behind**;
- **Unreachable**: no answer to the metadata Interest;
- **Failed**: everything else.

ndn-boltffi reports only `current`, `upstream-older`, `updated` and
`failed`, and maps Unreachable to `failed` (§12, Q9).

**Schedule (ndn-fwd).** Refresh every `[security] context_refresh_secs`
seconds; the default is **300**, and `0` means never. The first check runs
as soon as every fetched namespace's FIB route has a nexthop face, or after
`min(period, 30 s)`.

### 8.3 Local hand-over (informative)

The root device's CLI signs a version offline. It hands the version to its
own daemon through the local management verb `security/context-update`,
which applies §5.2 and §5.1. If the version is already stored
byte-identical and is not newer than held, the verb answers 200, so the CLI
can retry idempotently. A refusal is 403 and a lost compare-and-swap is
409. This verb is local to one host, not an interoperability surface.

## 9. Context sync group

With `[security] context_sync = true` (default `false`), ndn-fwd also joins
an SVS group per held namespace. The group pushes new versions; the pull
refresh still runs.

### 9.1 Names

```
group   = /<ns>/32=trust-context/32=sync
member  = <group>/<member-id>                    ; SVS node name
sync    = <group>/v=2                             ; Sync Interest prefix (SVS v2 dialect)
data    = <member>/seg=<version>                  ; group Data
```

`<member-id>` is one GenericNameComponent. It MUST be stable across restarts
of a node, because SVS keeps one entry per member, and it MUST be distinct
per node. ndn-fwd derives it as follows (informative):

- `m` = the contents of the first readable file among `/etc/machine-id`,
  `/proc/sys/kernel/hostname` and `/etc/hostname`, whitespace-trimmed;
- `p` = the canonicalized PIB path as OS bytes;
- `h` = FNV-1a 64 (offset `0xcbf29ce484222325`, prime `0x100000001b3`) over
  `m ‖ 0x00 ‖ p`;
- the component is the 16 lowercase hex digits of `h`, as ASCII.

### 9.2 SVS parameters

The group uses ndn-rs SVS with the `wan` preset and the V2 (ndn-svs) dialect:

| Parameter | Value |
|---|---|
| Sync Interest name | `<group>/v=2` (plus ParametersSha256Digest) |
| ApplicationParameters | StateVector (201) of entries (202) = Name (7), SeqNo (204) |
| Interest signing | none (insecure signer and validator) |
| InterestLifetime | 1000 ms |
| Periodic interval | 15 s + uniform jitter 0–2000 ms |
| Suppression period | 500 ms |
| Forwarding strategy on `<group>` | multicast |

### 9.3 Group Data

For a signed context Data `C` of version `N`, the member `P` publishes:

```
Name     = P/seg=<N>
MetaInfo = (none)
Content  = C, verbatim (the complete signed context Data TLV)
Signature= DigestSha256
```

A producer MUST NOT publish group Data for a `C` that is not named
`/<ns>/32=trust-context/v=<N>`. The member serves `P/seg=<N>` for each version
it put into the group, and answers anything else under `P` with Nack
NoRoute. The group Data is integrity-only. What it carries is authenticated
by the context's own signature, under §5.2.

### 9.4 Publishing (root device only)

- Only a node whose root store holds an anchor key of a version puts that
  version into the group. Other members only subscribe, and join with
  sequence number 0.
- **The SVS sequence number equals the context version.**
  - At start, the root device joins announcing its held version.
  - It serves every version it has stored.
  - When it keeps a version `V` greater than its sequence number, it serves
    that version's group Data and then advances the sequence number one
    step at a time up to `V`, because each SVS publication advances by one.
- A sequence number between two versions may therefore carry no Data. Such
  a position is Nacked and skipped by walks.

### 9.5 Subscribing

On an SVS update for member `P` with range `[low, high]`, where the held
version `H < high`:

1. Fetch `P/seg=<high>` and decode its Content as a Data whose name is a
   context name (§4.1).
   - Not a Data, or not a context name → drop.
   - A namespace not held → drop. A group never yields a first adoption.
2. Check §5.2 against the held context. If rule 4 fails, walk (§5.4) over
   `max(low, H+1) … high`, using `P/seg=<n>` as the source. The walk is not
   tried when `max(low, H+1) ≥ high`.
3. Adopt the newest under §5.1 and keep it like a refreshed version: walked
   versions, then the newest.

**Retries.** When the newest version could not be fetched, or the held
version changed meanwhile, ndn-rs retries the announcement:

- after 1 s, doubling up to 60 s between tries;
- while the announcement is newer than the held version;
- merging the ranges of later announcements from the same member.

A member none of whose announcements ever passed §5.2 is tried at most
**6** times, and at most **8** such members wait at once. A refused
announcement, or one whose walk stopped, is not retried: the pull refresh
follows genuine versions by name.

### 9.6 Routing (informative, ndn-fwd)

The group needs routes in both directions:

- **Up:** the node adds `<group>` and `<group>/v=2` nexthops on the
  non-local faces that `/<ns>` is routed over. It does so when it joins and
  again on each Sync Interest it sends or receives.
- **Down:** each face a group Sync Interest arrives on gets both routes, at
  cost 10.
- **Own faces:** the node's own sync face is a nexthop of `<group>/v=2` only;
  its serving face is a nexthop of `<member>` only.

A relay carries the group only if it runs context sync itself. Otherwise the
devices behind it get updates by refresh.

### 9.7 What an announcement proves

Nothing. Sync Interests are unauthenticated, so anyone can name any member
and any sequence number. A version is **verified** only once its signed Data
has passed §5.2, either against the held version or against a version walked
through from it. Only verified versions may feed the Behind rule (§8.2).

## 10. Security considerations

- Trust enters only through an expected fingerprint (§4.4), and thereafter
  only through the continuity rule (§5.2). Metadata, group Data and sync
  announcements are unauthenticated pointers. Each is confined by name, and
  everything it leads to is checked by the context signature.
- Anti-rollback depends on the node persisting its held version. A node that
  loses its store can be offered an older genuine version on re-adoption,
  unless the link names a minimum version.
- A relay that serves a forged newest version and lets intermediate versions
  time out costs at most one walk (128 positions, 40 s). ndn-rs does not
  retry such a walk from sync.
- A recovery anchor is root-equivalent. A compromise recovery therefore
  removes every recovery anchor the operator does not vouch for (§5.3).

## 11. Test vectors

All vectors below were produced by running the ndn-rs code (§Provenance at
the end of this section). Hex is lowercase and wrapped at 32 octets.

**Key.** Ed25519 seed `000102…1f` (the octets `0x00` through `0x1f`), key
name `/home/bob/KEY/root`. Ed25519 signatures are deterministic, so every
signed vector reproduces exactly.

```
public key (raw) 03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
fingerprint      56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c
                 (= SHA-256 of the 32 raw octets)
```

### T1 Anchor certificate (242 octets)

The certificate is `/home/bob/KEY/root/self/v=1`, self-signed:
ContentType KEY, FreshnessPeriod 3600000, NotBefore `20231114T221320`,
NotAfter `25540721T233433`. In this encoder, MetaInfo integers are written
as 8 octets.

```
06f0071f0804686f6d650803626f6208034b45590804726f6f74080473656c66
3601011414180800000000000000021908000000000036ee80152c302a300506
032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1d
dc8664125531b816471b01051c1807160804686f6d650803626f6208034b4559
0804726f6f74fd00fd26fd00fe0f323032333131313454323231333230fd00ff
0f32353534303732315432333334333317408179b8add1e2b0da55cc806f3d59
c67e107814cde57b2a253521216d52304e36229491d3b6c84ac5c5cd75e45c47
c8a503576d7fba17b723f9cbfd20c7345b09
```

### T2 TrustContext content, version 1 (489 octets)

Contents:

- namespace `/home/bob`;
- anchor T1;
- one native-text blob `/home/bob/shared/<**d> => /home/bob/admin/<dev>/KEY/<**k>`;
- SchemaAuthoritative;
- CaEndpoint `/home/bob/CA`;
- the default EnrollmentHint;
- Revocation `/home/bob/member/phone/KEY/k1`;
- KeyRole root-device `/home/bob/CA/KEY/ca`;
- the default LinkPolicy, stated.

```
fd0410fd01e3070b0804686f6d650803626f62fd0411f206f0071f0804686f6d
650803626f6208034b45590804726f6f74080473656c66360101141418080000
0000000000021908000000000036ee80152c302a300506032b657003210003a1
07bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b81647
1b01051c1807160804686f6d650803626f6208034b45590804726f6f74fd00fd
26fd00fe0f323032333131313454323231333230fd00ff0f3235353430373231
5432333334333317408179b8add1e2b0da55cc806f3d59c67e107814cde57b2a
253521216d52304e36229491d3b6c84ac5c5cd75e45c47c8a503576d7fba17b7
23f9cbfd20c7345b09fd041342fd04150101fd0417392f686f6d652f626f622f
7368617265642f3c2a2a643e203d3e202f686f6d652f626f622f61646d696e2f
3c6465763e2f4b45592f3c2a2a6b3efd041c00fd041411070f0804686f6d6508
03626f6208024341fd04162102746f6b656e2c6465766963652d617070726f76
616c3b61646d696e2c6e6f6465fd04182507230804686f6d650803626f620806
6d656d626572080570686f6e6508034b455908026b31fd041e1b020718080468
6f6d650803626f620802434108034b455908026361fd0412103b6e6f64653b65
6e726f6c6c6d656e74
```

Breakdown:

```
fd0410 fd01e3                      TrustContext, length 483
  070b 0804686f6d65 0803626f62     Name /home/bob (namespace, direct child)
  fd0411 f2  06f0…                 AnchorSet (T1)
  fd0413 42                        TrustSchemaBlob
    fd0415 01 01                   SchemaFormat = 1 (native text)
    fd0417 39 2f686f6d65…6b3e      SchemaBody (57 octets of rule text)
  fd041c 00                        SchemaAuthoritative
  fd0414 11 070f…08024341          CaEndpoint = Name TLV /home/bob/CA
  fd0416 21 02 746f6b656e2c…6e6f6465
                                   EnrollmentHint flags=0x02 "token,device-approval;admin,node"
  fd0418 25 0723…08026b31          Revocation = Name TLV /home/bob/member/phone/KEY/k1
  fd041e 1b 02 0718…08026361       KeyRole code 2 (root-device), Name /home/bob/CA/KEY/ca
  fd0412 10 3b6e6f64653b656e726f6c6c6d656e74
                                   LinkPolicy ";node;enrollment"
```

### T3 Signed context Data, version 1 (625 octets)

The name is `/home/bob/32=trust-context/v=1`, with name TLV
`071d0804686f6d650803626f62200d74727573742d636f6e74657874360101`. There is
no MetaInfo. The Content is T2. The signature is Ed25519 with KeyLocator
`/home/bob/KEY/root`. `open_signed` accepts the Data and returns signer
anchor `/home/bob/KEY/root/self/v=1`.

```
06fd026d071d0804686f6d650803626f62200d74727573742d636f6e74657874
36010115fd01e9fd0410fd01e3070b0804686f6d650803626f62fd0411f206f0
071f0804686f6d650803626f6208034b45590804726f6f74080473656c663601
011414180800000000000000021908000000000036ee80152c302a300506032b
657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc86
64125531b816471b01051c1807160804686f6d650803626f6208034b45590804
726f6f74fd00fd26fd00fe0f323032333131313454323231333230fd00ff0f32
353534303732315432333334333317408179b8add1e2b0da55cc806f3d59c67e
107814cde57b2a253521216d52304e36229491d3b6c84ac5c5cd75e45c47c8a5
03576d7fba17b723f9cbfd20c7345b09fd041342fd04150101fd0417392f686f
6d652f626f622f7368617265642f3c2a2a643e203d3e202f686f6d652f626f62
2f61646d696e2f3c6465763e2f4b45592f3c2a2a6b3efd041c00fd041411070f
0804686f6d650803626f6208024341fd04162102746f6b656e2c646576696365
2d617070726f76616c3b61646d696e2c6e6f6465fd04182507230804686f6d65
0803626f6208066d656d626572080570686f6e6508034b455908026b31fd041e
1b0207180804686f6d650803626f620802434108034b455908026361fd041210
3b6e6f64653b656e726f6c6c6d656e74161d1b01051c1807160804686f6d6508
03626f6208034b45590804726f6f74174044d72d92f3e10d8333c791db87406d
772562567e29e5886b547e57a88d49ef741b262f5a85f765bd649e472805fc14
eb12633874eec35fc5073236a39520e40c
```

### T4 RDR names and metadata Data

```
RDR prefix   /home/bob/32=trust-context
             071a0804686f6d650803626f62200d74727573742d636f6e74657874
metadata     /home/bob/32=trust-context/32=metadata
             07240804686f6d650803626f62200d74727573742d636f6e7465787420086d65746164617461
```

The metadata Data (124 octets) points at T3. Its name is
`/home/bob/32=trust-context/32=metadata/v=1/seg=0`, with MetaInfo
`1404 190203e8` (FreshnessPeriod 1000 ms). Its Content is
`151f 071d…360101`, the versioned Name. Its signature is DigestSha256
(`16031b0100`), and its SignatureValue is SHA-256 over the signed portion.

```
067a072a0804686f6d650803626f62200d74727573742d636f6e746578742008
6d657461646174613601013201001404190203e8151f071d0804686f6d650803
626f62200d74727573742d636f6e7465787436010116031b0100172057b9bf15
146037d9593760633f51c5c5dbd117e59363969a8aef7dda9fac6d82
```

`context_pointer` on that Content returns `/home/bob/32=trust-context/v=1`.

### T5 Value encodings in isolation

```
LinkPolicy default (stated)     fd0412 10 3b6e6f64653b656e726f6c6c6d656e74          ";node;enrollment"
LinkPolicy admin,node; ; off    fd0412 19 61646d696e2c6e6f64653b3b6e6f2d656e726f6c6c6d656e74
                                                                                     "admin,node;;no-enrollment"
EnrollmentHint require_all,
  no roles                      fd0416 16 01 746f6b656e2c6465766963652d617070726f76616c
                                                                                     flags 0x01 "token,device-approval"
```

Decoder behaviour, from `decode_content` on this input:

```
fd0410340703080168fd041309fd04150101fd041700fd04160605746f6b656efd041e06
09070308016bfd04120561646d696efd04980178
```

That is, namespace `/h`, an empty native blob, then:

- EnrollmentHint `05 "token"`: flags `0x05` with no HAS_ROLES bit, so the
  legacy rule applies. Result: `require_all = true`, challenges `[token]`,
  roles `[]`.
- KeyRole `09 0703 08016b`: unknown code 9 is kept as `(9, /k)`.
- LinkPolicy `"admin"`: only one field, so the field is invalid. The context
  is accepted with no stated policy, and the default applies.
- `fd0498 01 78`: an unknown even type, skipped.

Replacing the last child with `fd0499 01 78`, an unknown *odd* type, makes
the decoder reject the context ("unknown critical sub-TLV").

### T6 Sync group (namespace `/home/bob`)

```
group          /home/bob/32=trust-context/32=sync
               07200804686f6d650803626f62200d74727573742d636f6e74657874200473796e63
Sync Interest  /home/bob/32=trust-context/32=sync/v=2
               07230804686f6d650803626f62200d74727573742d636f6e74657874200473796e63360102
member id      machine-id "0123456789abcdef0123456789abcdef", PIB path "/var/lib/ndn/pib"
               → FNV-1a64 = 4248be188e6d916a → component 0810 34323438626531383865366439313661
group Data     /home/bob/32=trust-context/32=sync/4248be188e6d916a/seg=1
               07350804686f6d650803626f62200d74727573742d636f6e74657874200473796e63
                 081034323438626531383865366439313661320101
```

The group Data for T3 is 727 octets: `06 fd02d3`, the name above, then
`15 fd0271` followed by the 625 octets of T3, then `16031b0100`, then
`1720 df954a67b0a80e006f95d13ccc6d1e2a0666d03288f01bfeaa8a4ef9b056d033`.

### T7 Version 2 (revocation bump) and continuity

`bump_context_revoking(root, T3, [/home/bob/guest/tv/KEY/k2])` gives
`/home/bob/32=trust-context/v=2` (662 octets). `open_context_update(v1, v2)`
passes, with signer anchor `/home/bob/KEY/root/self/v=1`. Its content
(526 octets) differs from T2 in only two places: the outer length
(`fd0208`), and an extra Revocation that follows the first one:

```
fd041821071f0804686f6d650803626f62080567756573740802747608034b455908026b32
```

The full v2 Data is reproducible with the seed above (sign over the
NDN signed portion, same SignatureInfo as T3).

### Generated namespace structure (not a byte vector)

`ndn_cert::init_namespace(/home/bob)` gives a context Data of 1944 octets
(Content 1808 octets), signed Ed25519 with KeyLocator `/home/bob/KEY/root`.
Its TrustContext children are, in order:

- `0x07` (11 octets);
- `0x0411` (249 octets);
- `0x0413` LVS (941-octet body);
- `0x0413` native (500-octet body);
- `0x041C` (0 octets);
- `0x0416` (33 octets);
- `0x0412` (16 octets).

The in-memory `init_namespace` adds no CaEndpoint and no KeyRole.
`init_namespace_in_pib`, the path `ndn-fwd init` uses, adds `/<ns>/CA` and
the root-device KeyRoles (Appendix A).

### Provenance

T1–T7 come from a throwaway example program in `ndn-identity`, run with
`cargo run --example`. It called these real library functions:

- `ndn_security::encode_cert_data`, `SignedTrustContext::{encode_content, sign_into_data, open_signed, decode_content}`;
- `ndn_cert::{rdr_prefix, rdr_metadata_name, onboarding::context_pointer, bump_context_revoking, open_context_update, init_namespace}`;
- `ndn_identity::context_sync::{group_prefix, group_data}`;
- `ndn_app::rdr::MetaData::encode`.

Two parts were copied from ndn-fwd, because the originals are private there:

- the metadata Data, built line-for-line as
  `context_publisher.rs::metadata_data` builds it;
- the member id, computed with the FNV-1a loop of `context_sync.rs::member_id`
  on fixed inputs.

The program was deleted after the run. An independent Python SHA-256 check
confirmed the fingerprint and the metadata DigestSha256 value.

## 12. Open questions

- **Q1 Anchor order.** `encode_content` iterates the anchor map in hash-map
  order, so for more than one anchor the AnchorSet order is unspecified and
  can change between encodings of the same context. Decoders do not depend
  on the order. Should a canonical order (e.g. by certificate name) be
  fixed, so that a re-encoded version is reproducible?
- **Q2 Duplicates.** A later Name, EnrollmentHint or LinkPolicy overwrites
  an earlier one. A later *invalid* LinkPolicy resets the policy to the
  default, even after a valid one. Should duplicates of single-valued
  fields reject the context?
- **Q3 Equal-version re-adoption.** `Keyring::adopt`, the link path,
  accepts a context with a version *equal* to the held one and replaces the
  held one, even if its content differs (a fork signed by the root).
  Updates require strictly newer. Is the equality intended?
- **Q4 Anchor validity.** `open_signed` and the continuity check do not
  look at the signing anchor's ValidityPeriod. `decode_content` keeps
  expired anchors; only `add_anchor` at production time refuses them. Must
  a consumer refuse a context signed by an expired anchor?
- **Q5 Unknown SchemaFormat.** A blob whose format code is unknown rejects
  the whole context, although the module notes say a node keeping fewer
  blobs "authorizes less, never more". Should an unknown format code
  instead be skipped when another blob is understood? This matters for
  implementations without the ndn-rs native-text grammar: format `1` is
  ndn-rs-specific.
- **Q6 Unknown sub-TLVs inside TrustSchemaBlob** are ignored whatever their
  parity. Should odd (critical) ones reject the context?
- **Q7 LinkPolicy extra fields.** Text after a third `;` is ignored.
  Reserve it for extension, or reject?
- **Q8 Sync walk lower bound.** The sync walk starts at
  `max(low_seq, H+1)`, not `H+1`. If an earlier announcement of the same
  member was dropped, for example refused, the positions below `low_seq`
  are not walked, and the update falls back to the pull refresh. Intended?
- **Q9 ndn-fwd and ndn-boltffi differ.** The mobile copy
  (`identity_core.rs::refresh_contexts`) calls the same library refresh,
  but:
  - it has no Source, Behind or Unreachable outcomes;
  - it returns only the newest version to the host, so walked versions are
    neither kept nor served;
  - it publishes nothing, so §7.3 does not apply;
  - [INFERENCE] it does not evict cached metadata before a refresh, so a
    pointer cached within the last 1 s can make a refresh report Current.
- **Q10 Pattern grammar.** The doc comment of `NamePattern` says `<**v>`
  captures "one or more" components, but `matches` accepts zero. This
  document specifies the code (zero or more).
- **Q11 Version decoding.** `NameComponent::as_version` accepts any length
  and silently drops high-order octets past 8. Verification still fails,
  because the name is rebuilt in canonical form. However, the publisher's
  `answer` maps such an Interest to a held version, and returns a Data
  whose name differs from the Interest's.
- **Q12 KEY detection.** `key_identity` and `is_cert_name` compare only the
  component *value* `KEY`, not its TLV-TYPE. Implementations should match,
  or the floor and anchor matching will differ for names containing a
  non-generic component with value `KEY`.

## Appendix A. Code references (non-normative)

Paths are relative to the workspace root. ndn-fwd code is being moved into
libraries by concurrent work; locations under `ndn-fwd/binaries/ndn-fwd/src`
may move.

**TLV registry and codec** — `ndn-rs/crates/security/ndn-security/src/trust_context/`

- `tlv.rs:29` TrustContext 0x0410; `:32` AnchorSet 0x0411; `:38` TrustSchemaBlob 0x0413; `:42` CaEndpoint 0x0414; `:45` SchemaFormat 0x0415; `:48` SchemaBody 0x0417; `:51` EnrollmentHint 0x0416; `:54` Revocation 0x0418; `:61` SourceBundleHash 0x041A; `:71` SchemaAuthoritative 0x041C; `:81` KeyRole 0x041E; `:90` LinkPolicy 0x0412; `:93-95` format codes 1/2; `:3-25` provisional block and parity.
- `mod.rs:55` keyword `trust-context`; `:73-79` format code decode (unknown → error); `:106-124` native-text parsing (trim, skip empty lines); `:128-136` OR of blobs, multiple LVS → error.
- `mod.rs:179-182` hint flags; `:188-194` default hint; `:196-211` hint encode; `:213-243` hint decode (legacy rule `:235-240`).
- `mod.rs:256-266` KeyRole codes 1/2.
- `mod.rs:293-303` LinkPolicy default; `:306-307` words; `:311-318` allows_link/relay; `:340-352` encode; `:354-375` decode.
- `mod.rs:606-608` admits_enrollment_links; `:617-623` add_anchor validity check; `:637-653` anchor_for; `:660-662` is_revoked; `:685-696` authorizes (floor + schema); `:712-724` authorizes_hop; `:742-754` authorizes_certification.
- `mod.rs:777-824` encode_content (order; anchor map iteration `:785`); `:828-835` rdr_name; `:849-873` sign_into_data (KeyLocator = signer key name); `:879-894` async variant.
- `mod.rs:900-1037` decode_content: `:901-904` outer type; `:922-927` namespace; `:928-944` AnchorSet (skip non-Data `:933-935`); `:945-967` blob (inner unknown ignored `:959`; missing fields `:963-965`); `:968` authoritative; `:969-974` CaEndpoint; `:975` hint; `:980-984` SourceBundleHash length 32; `:985-990` Revocation; `:993-997` KeyRole; `:1000` LinkPolicy; `:1002-1006` unknown critical → reject; `:1011-1015` required fields; `:1026` floor unless authoritative.
- `mod.rs:1041-1053` derived native blob; `:1060-1063` anchor_fingerprint; `:1067-1081` context_namespace_of; `:1113-1156` open_signed (name equality `:1123`, signer must be own anchor `:1133-1135`, public-key sig types `:1139-1144`); `:1204-1206` is_critical; `:1209-1221` read_tlv (trailing bytes ignored); `:1226-1232` key_identity.

**Supporting library code**

- `ndn-rs/crates/security/ndn-security/src/keyring.rs:97-116` adopt (≥); `:123-135` adopt_update (>); `:145-163` adopt_update_from (CAS); `:240-253` context_for (longest prefix).
- `ndn-rs/crates/security/ndn-security/src/cert_cache.rs:31-37` public key from Content (Ed25519 SPKI unwrapped).
- `ndn-rs/crates/security/ndn-security/src/spki.rs:31-33` Ed25519 SPKI prefix.
- `ndn-rs/crates/security/ndn-security/src/cert_name.rs:43-57` is_cert_name, key_name_of; `:74-80` cert_name.
- `ndn-rs/crates/security/ndn-security/src/manager.rs:514-594` certificate encoding (8-octet MetaInfo integers, ValidityPeriod).
- `ndn-rs/crates/security/ndn-security/src/trust_schema.rs:39-91` pattern grammar; `:121-123` MultiCapture matches zero or more; `:146-163` rule parse/check.
- `ndn-rs/crates/core/ndn-packet/src/signature.rs:36-40` signature type codes.
- `ndn-rs/crates/core/ndn-packet/src/encode/data.rs:411-416` `build` = DigestSha256; `:535-588` sign_sync (MetaInfo only if set).
- `ndn-rs/crates/core/ndn-packet/src/lib.rs:105-108` SEGMENT 0x32, KEYWORD 0x20, VERSION 0x36.
- `ndn-rs/crates/core/ndn-foundation-types/src/name.rs:99-111` keyword/version components; `:124-136` as_segment/as_version; `:149-163` NNI encode (shortest) / decode (any length).
- `ndn-rs/crates/app/ndn-app/src/rdr.rs:83-107` MetaData encode (Name only when other fields absent).
- `ndn-rs/crates/app/ndn-app/src/consumer.rs:196` DEFAULT_TIMEOUT 4.5 s; `ndn-rs/crates/security/ndn-identity/src/engine_exchange.rs:38-40` wait = max(lifetime, default).
- `ndn-rs/crates/core/ndn-packet/src/encode/interest.rs:194,236` InterestLifetime defaults to 4000 ms; `:199-210,240-241` ApplicationParameters + ParametersSha256Digest component.

**ndn-cert**

- `ndn-rs/crates/security/ndn-cert/src/onboarding.rs:41` `metadata`; `:52` CONTEXT_EXPECTATION_TTL 30 s; `:57-69` rdr_prefix, rdr_metadata_name; `:184-200` authenticate (namespace, expected fingerprint); `:289-297` minimum version; `:350-404` adopt_anchor_link; `:509-515` fetch_context; `:521-550` pointer fetch (CanBePrefix, MustBeFresh, prefix check); `:554-575` exact fetch, name check; `:580-612` context_pointer confinement.
- `ndn-rs/crates/security/ndn-cert/src/context_update.rs:83-93` key_name_of; `:178-200` revocations_to_add; `:211-237` bump_context_revoking; `:241-255` ensure_anchor; `:257-261` next_version; `:510` MAX_CATCH_UP_VERSIONS 128; `:519` MAX_CATCH_UP_TIME 40 s; `:727-756` open_context_update (public-key equality `:749`); `:783-811` fetch_update; `:830-843` ByName source; `:869-938` follow_versions; `:964-1091` refresh_context (pointer compare `:1005-1013`, walk condition `:1042-1043`, CAS `:1067-1076`).
- `ndn-rs/crates/security/ndn-cert/src/namespace.rs:55-57` root key name; `:60-62` CA key name; `:137-156` build_namespace (version 1, hint, link policy, blobs, authoritative, CA endpoint, root-device KeyRoles).
- `ndn-rs/crates/security/ndn-cert/src/recovery.rs:740-756` add recovery anchor; `:762-790` remove; `:800-806` reissue; `:921-988` recovery_version.
- `ndn-rs/crates/security/ndn-cert/src/context_store.rs:5-8` on-disk layout (newest + every version).

**ndn-identity**

- `ndn-rs/crates/security/ndn-identity/src/adopt.rs:51-59` refresh_context_via_engine.
- `ndn-rs/crates/security/ndn-identity/src/context_sync.rs:144-148` group_prefix; `:155-162` group_data (seg=version, DigestSha256); `:250-368` check_and_adopt (fetch `:256`, walk lower bound `:297-300`); `:387-409` GroupVersions; `:422-430` Retry 1 s/60 s; `:436` UNPROVEN_TRIES 6; `:440` UNPROVEN_PENDING 8; `:473-588` run (range merge `:501-505`); `:606-692` obtain.

**ndn-sync**

- `ndn-rs/crates/protocols/ndn-sync/src/svs_sync.rs:185-201` defaults; `:229-236` wan preset; `:653-656` Sync Interest name and 1000 ms lifetime.
- `ndn-rs/crates/protocols/ndn-sync/src/dialect.rs:36-52` V2 default, `v=2`; `:91-106` V2 state vector TLVs.
- `ndn-rs/crates/protocols/ndn-sync/src/security.rs:66-69,144-151` insecure default signer and validator.

**ndn-fwd (current locations; may move)**

- `ndn-fwd/binaries/ndn-fwd/src/context_publisher.rs:55` METADATA_FRESHNESS 1 s; `:84-90` metadata names newest; `:189-201` metadata_data; `:205-217` answer; `:253-256` Nack NoRoute; `:312-339` publish + metadata eviction; `:346-358` bypass; `:373-382` forget_cached_metadata.
- `ndn-fwd/binaries/ndn-fwd/src/context_refresh.rs:58` FIRST_CHECK_LATEST 30 s; `:97-105` holds_root_key; `:143-150` Source; `:152-157` bypass + eviction; `:164-194` behind rule; `:276-279` Unreachable/Failed; `:300-333` keep_update; `:348-456` apply_update (200/403/409); `:460-480` stored_copy; `:496-526` periodic schedule.
- `ndn-fwd/binaries/ndn-fwd/src/context_adopt.rs:189-219` keep (409 when newer held); `:239-263` store, publish, sync; `:268-296` adopt_link (bypass).
- `ndn-fwd/binaries/ndn-fwd/src/context_sync.rs:79` MEMBER_COST 10; `:108-122` kept (root check); `:148-170` SvsConfig::wan; `:175-189` member_id; `:201-248` join and seq rules; `:280-292` multicast strategy, sync and serve routes; `:310-314` local_seq; `:363-372` serve_stored; `:388-426` put (seq = version); `:440-475` group Data serving / Nack; `:492-524` routes.
- `ndn-rs/crates/platform/ndn-config/src/config.rs:1954-1955,1994-1996` serve_contexts default true; `:1971-1972,1998-2000` context_refresh_secs default 300; `:1981` context_sync default false.

**ndn-mobile**

- `ndn-mobile/crates/ndn-boltffi/src/identity_core.rs:215-304` refresh_contexts (four states; only newest returned `:297`).
