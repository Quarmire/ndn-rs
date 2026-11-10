# Trust context: wire format, versioning, publication and sync

- **Status:** Draft
- **Scope:** the signed trust context of a namespace as ndn-rs encodes,
  signs, verifies, adopts, publishes, refreshes and synchronizes it. This
  covers the TLV registry `0x0410–0x041E` and `0x0420–0x042E` and every value encoding, the name
  and signature of a context Data, self-certifying namespaces
  (`/user/<h>`, name component type `0xA1`) and their genesis rule, the
  continuity rule between versions, the
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
writing. Appendix A gives the file and line for each one. Points where the
code was ambiguous, or where the ndn-fwd and ndn-mobile copies differed, are
recorded with the decision taken under §12 "Decisions".

## 1. Terminology

| Term | Meaning |
|---|---|
| namespace | An NDN name prefix `/<ns>` that one root key governs. |
| root device | The device holding the namespace root key, where new context versions are made (`ndn-fwd init`). |
| trust context (context) | The root-signed statement of a namespace's anchors, schema, CA endpoints, revocations, key roles and policies. It is versioned and published as NDN Data. |
| version | The unsigned integer `N` in the context's name. Versions of one namespace are totally ordered. |
| anchor | A certificate listed in the context's `AnchorSet`. A key named by an anchor is root-equivalent: it can sign the next version. |
| expected fingerprint | SHA-256 over an anchor's public key (§3.3.2), learned out of band. It authenticates the first context a device adopts. A self-certifying namespace needs none: its name is the fingerprint of its genesis root (§4.5). |
| self-certifying namespace | A namespace that is exactly `/user/<h>`, `<h>` a name component of TLV-TYPE `0xA1` holding 32 octets: SHA-256 of the raw Ed25519 public key of its genesis root (§4.5). |
| genesis, genesis root | Version 1 of a self-certifying namespace's context, and the Ed25519 key that signed it (§4.5). |
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
NonNegativeInteger. `<h>` in `/user/<h>` is a self-certifying component
(TLV-TYPE `0xA1`, §4.5), written `161=%xx…` (32 percent-escaped octets) in
URI form. Every other literal component is a
`GenericNameComponent` (TLV-TYPE `0x08`). ndn-rs prints keyword components
as `keyword=x`.

"NonNegativeInteger" means the NDN encoding: big-endian in 1, 2, 4 or 8
octets. ndn-rs always writes the shortest of these forms (canonical form). A
decoder MUST reject any other length (empty, 3, 5–7, or more than 8 octets):
such a component is not a version or segment number, never a truncated one.

## 2. Overview

A namespace's context is one NDN Data packet per version:

```
/<ns>/32=trust-context/v=<N>        Content = TrustContext TLV (0x0410)
                                    signed by an anchor key of the context itself
```

It is published by RDR with a metadata Data that names the newest version
(§7). A node that holds nothing adopts a first version when its signing
anchor matches an expected fingerprint (§4.4), or, for a self-certifying
namespace `/user/<h>`, when version 1 is signed by the key `<h>` names
(§4.5). A node that holds version `N`
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
| `0x0420` | AdvertisedRelay | no | in TrustContext | 0..n | a complete Name TLV + the sub-TLVs below (§3.3.11) |
| `0x0422` | RelayKey | no | in AdvertisedRelay | 0..1 | 32 octets |
| `0x0424` | RelayEndpoint | no | in AdvertisedRelay | 1..n | UTF-8 `host:port` |
| `0x0426` | RelayPreference | no | in AdvertisedRelay | 0..1 | NonNegativeInteger, at most `2^32-1` |
| `0x0428` | RevocationCut | no | in TrustContext | 0..n | a complete Name TLV (the revoked key) + the sub-TLVs below (§3.3.12) |
| `0x042A` | CutRange | no | in RevocationCut | 0..n | a complete Name TLV (a prefix) + 1..n CutRun |
| `0x042C` | CutRun | no | in CutRange | 1..n | two SequenceNumNameComponents (`0x3A`): first, last |
| `0x042E` | CutExact | no | in RevocationCut | 0..n | a complete Name TLV whose last component is an ImplicitSha256DigestComponent |
| `0x0430` | CutKeyDigest | no | in RevocationCut | 0..1 (REQUIRED in a new cut) | 32 octets: SHA-256 of the revoked key's public key (§3.3.12) |
| `0x0432` | CutManifest | no | in RevocationCut | 0..1 (REQUIRED in a new cut with a CutRange) | a complete Name TLV ending in an ImplicitSha256DigestComponent: the cut manifest's root packet (§3.3.12) |
| `0x0434` | DataRequiresCut | no | in TrustContext | 0..n | UTF-8 role name (§3.3.13) |
| `0x0436` | CutManifestNode | (outer) | a cut manifest's Data Content | 1 | ManifestRange entries (a leaf) or ManifestChild entries (an interior node) (§3.3.12) |
| `0x0438` | ManifestRange | no | in CutManifestNode | 0..n | a complete Name TLV (a CutRange prefix) + 1..n ManifestEntry |
| `0x043A` | ManifestEntry | no | in ManifestRange | 1..n | a SequenceNumNameComponent and an ImplicitSha256DigestComponent |
| `0x043C` | ManifestChild | no | in CutManifestNode | 0..n | two ManifestBound + the child's full name (a complete Name TLV) |
| `0x043E` | ManifestBound | no | in ManifestChild | 2 | a complete Name TLV (a prefix) and a SequenceNumNameComponent |

`0x0419`, `0x041B`, `0x041D` and `0x041F` are unassigned. Every even number
of `0x0410–0x041F` being taken, the block continues at `0x0420–0x042F`,
whose even numbers are taken too, and then at `0x0430–0x043F`: `0x0430`,
`0x0432` and `0x0434` above, and `0x0436–0x043E` for the content of a cut
manifest, which is a Data of its own, not part of the TrustContext
(§3.3.12). The odd numbers of both later blocks are unassigned.
`0x0403–0x040F` is left free below the block. The block is provisional and
has not been submitted to the NDN TLV registry.

The value encodings differ in one place that implementers must notice. The
namespace Name is written *directly* as a `0x07` child of TrustContext. The
values of CaEndpoint, Revocation, KeyRole, AdvertisedRelay, RevocationCut,
CutRange, CutExact and CutManifest *contain* a full `0x07` Name TLV, header
included.

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
                   *RevocationCut
                   *DataRequiresCut
                   [SourceBundleHash]
                   *KeyRole
                   [LinkPolicy]
                   *AdvertisedRelay
AnchorSet      = 0x0411 TLV-LENGTH *Data         ; each a certificate, 0x06
TrustSchemaBlob= 0x0413 TLV-LENGTH SchemaFormat SchemaBody
SchemaFormat   = 0x0415 1 (%x01 / %x02)
SchemaBody     = 0x0417 TLV-LENGTH *OCTET
SchemaAuthoritative = 0x041C 0
CaEndpoint     = 0x0414 TLV-LENGTH Name
EnrollmentHint = 0x0416 TLV-LENGTH Flags *OCTET
Revocation     = 0x0418 TLV-LENGTH Name
RevocationCut  = 0x0428 TLV-LENGTH Name [CutKeyDigest] [CutManifest] *CutRange *CutExact
                                                              ; Name = the revoked key
CutKeyDigest   = 0x0430 32 32OCTET                            ; SHA-256 of the key's public key
CutManifest    = 0x0432 TLV-LENGTH Name                       ; ends in an ImplicitSha256DigestComponent
CutRange       = 0x042A TLV-LENGTH Name 1*CutRun              ; Name = a prefix
CutRun         = 0x042C TLV-LENGTH SequenceNumNameComponent SequenceNumNameComponent
                                                              ; first, last; first <= last
CutExact       = 0x042E TLV-LENGTH Name                       ; ends in an ImplicitSha256DigestComponent
DataRequiresCut = 0x0434 TLV-LENGTH 1*OCTET                   ; UTF-8 role name
SequenceNumNameComponent = 0x3A TLV-LENGTH NonNegativeInteger
SourceBundleHash = 0x041A 32 32OCTET
KeyRole        = 0x041E TLV-LENGTH RoleCode Name
LinkPolicy     = 0x0412 TLV-LENGTH *OCTET        ; UTF-8
AdvertisedRelay = 0x0420 TLV-LENGTH Name [RelayKey] 1*RelayEndpoint [RelayPreference]
RelayKey       = 0x0422 32 32OCTET
RelayEndpoint  = 0x0424 TLV-LENGTH 1*OCTET       ; UTF-8 host:port
RelayPreference = 0x0426 TLV-LENGTH NonNegativeInteger
```

A producer MUST emit the fields in the order above. ndn-rs always emits
`AnchorSet`, even when it is empty. Inside AnchorSet, a producer MUST write
the certificates in NDN canonical order of their names, and it MUST write
Revocation entries in NDN canonical order of their Names (component by
component: TLV-TYPE, then TLV-LENGTH, then the octets; a prefix sorts
first). So the same context always encodes to the same bytes, whatever
order its anchors and revocations were added in. RevocationCut entries are
written in canonical order of their key Names, each written canonically
(§3.3.12), and DataRequiresCut entries in ascending octet order of their
values, without repeats (§3.3.13). AdvertisedRelay entries are written in canonical order too: by
RelayPreference, then by device Name in canonical order, then entries
without a RelayKey before those with
one (RelayKey octets compared), then the endpoint lists compared entry by
entry (UTF-8 octets). CaEndpoint and KeyRole
entries are emitted in the order they were added: a new version made from
an earlier one carries the earlier entries first and appends new ones. A
decoder MUST NOT depend on the order of entries within a field, and accepts
any. TLV-LENGTH uses the shortest NDN VAR-NUMBER form.

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
  fourth-last component is the GenericNameComponent `KEY` (TLV-TYPE `0x08`,
  value `KEY`) is a certificate name; a component of another TLV-TYPE with
  value `KEY` (e.g. `32=KEY`) does not count. Any other name is used
  unchanged as a key name.
- **Public key** — the certificate Content. If the Content is the 44-octet
  Ed25519 SPKI (`302a300506032b6570032100` ‖ 32-octet key), the public key is
  the 32 raw octets. Otherwise it is the Content verbatim, e.g. the DER SPKI
  of a P-256 key.
- **ValidityPeriod** — NotBefore/NotAfter, `YYYYMMDDTHHMMSS`.

The **anchor fingerprint** is `SHA-256(public key)`, with the public key as
defined above. For Ed25519 that is SHA-256 over the 32 raw octets, not over
the SPKI. The fingerprint does not change when a certificate for the same key
is re-issued.

Anchors match by key (§6.2). Decoding keeps every anchor whatever its
ValidityPeriod; a consumer checks the validity of the anchor that *signed*
a context it receives (§4.3). ndn-rs producers add an anchor only when it
is valid at the time of encoding. ndn-rs makes root anchors self-signed,
with NotAfter derived from `u64::MAX` ns (`25540721T233433`) and name
`/<ns>/KEY/root/self/v=<ms>`; recovery anchors and the root a recovery
installs get the same NotAfter. The anchor format of a recovery kit is in
[recovery-kit.md](recovery-kit.md).

#### 3.3.3 TrustSchemaBlob (`0x0413`), SchemaFormat (`0x0415`), SchemaBody (`0x0417`)

Each blob carries exactly one SchemaFormat and one SchemaBody. A decoder:

- MUST reject a blob that lacks either sub-TLV, or carries either twice;
- MUST reject a SchemaFormat whose length is not 1 octet;
- treats a format code other than `1` or `2` as *unknown*: the blob is not
  understood. It MUST NOT contribute to the runtime schema, and a producer
  that makes a new version from this one MUST re-emit it unchanged. A
  decoder MUST reject the context when none of its blobs is understood;
- MUST reject an unknown critical sub-TLV inside a blob (TLV-TYPE `<= 31`
  or odd) and MUST skip an unknown non-critical (even) one, as for the
  children of TrustContext (§3.4);
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

The runtime schema is the logical OR of all understood blobs. A context MUST
NOT carry more than one format-2 blob, and a decoder MUST reject a context
that does. The namespace context `ndn-fwd init` generates carries one LVS
blob and one native-text blob. The native blob holds the rules LVS cannot
express (see the `init_namespace` structure under §11). A node that
understands only some blobs authorizes less, never more, which is why a
blob in an unknown format is skipped rather than refused: format `1` is
ndn-rs-specific, and an implementation without the native-text grammar
still validates by the LVS blob.

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

A Revocation entry alone keeps the meaning it always had: every packet the
key signed is refused, and so is every chain through the key. A
RevocationCut for the key (§3.3.12) changes that for one case only: Data the
key itself signed that the cut accepts stays valid (§6.3). A context without
cuts, every context made before them included, means exactly what it meant
before.

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
value  = roles ";" relay-roles [ ";" ( "enrollment" / "no-enrollment" ) [ ";" direct [ ";" pairs ] ] ]   ; UTF-8
roles  = [ role *( "," role ) ]     ; empty = every device role
direct = "direct" / "no-direct"
pairs  = [ pair *( "," pair ) ]     ; empty = no pair
pair   = role ":" role              ; unordered
```

**Encoding.** ndn-rs always writes the first three fields. When the direct
pairs are the default ones (below), it writes the fourth, `;no-direct`,
only when direct paths are off, and nothing after it: a policy that does
not change the pairs encodes exactly as before the fourth and fifth fields
existed. When the pairs are not the default, it writes the fourth field
explicitly (`direct` or `no-direct`) and the fifth: the pairs in canonical
form, each pair's two roles in octet order, the pairs sorted (first role,
then second) without duplicates. Nothing is written after the fifth.

**Decoding.** Split the value at `;`. A missing first or second field, a
third field other than `enrollment` or `no-enrollment`, or invalid UTF-8
makes the *field* invalid: the context is kept and the default policy
applies. A missing third field means `enrollment`. Empty role names inside
a list are dropped. The fourth field is `no-direct` for direct paths off;
missing, `direct`, or any other word means on (an unknown word is a later
extension of the field, so it does not invalidate the policy). The fifth
field lists the direct pairs; empty entries are dropped. A missing fifth
field means the default pairs, and so does a fifth field with an entry
that is not `role:role` (no `:`, more than one, or an empty role): it is a
later form of the field, not an invalid policy. Fields after the fifth are
reserved for extension: a decoder MUST ignore them, and a producer MUST NOT
write them until they are specified.

**Semantics.** A device's role is the component after the namespace in its
certificate name, `/<ns>/<role>/<device>`.

- A device with role `r` may link iff `roles` is empty or contains `r`.
- It may relay iff it may link *and* `relay-roles` contains `r`.
- A relay admits *enrollment links* iff the third field is `enrollment`
  *and* the context has at least one CaEndpoint.
- A device with role `a` and one with role `b`, linked through a relay, may
  try a *direct path* between them (NAT hole punching, keeping the relay
  when it does not open) iff the fourth field is not `no-direct` *and*
  `{a, b}` is one of the pairs (`a:b` or `b:a`; `r:r` for two devices of
  role `r`). A device MUST NOT offer its addresses for, nor accept, a direct
  path the policy does not allow: its addresses go only to devices the
  policy allows. Turning direct paths off, or removing a pair, is a
  narrowing, like removing a role (schema update, §5.3); turning them on or
  adding a pair is a widening.

The default pairs are every pair of `admin`, `member` and `node`, each role
with itself too, and none with `guest`:
`admin:admin,admin:member,admin:node,member:member,member:node,node:node`.

When the field is absent the default applies: `roles` empty,
`relay-roles = node`, `enrollment`, direct paths on between the default
pairs, which encodes as `;node;enrollment`.
Admission itself is in [ndn-link.md](ndn-link.md).

**Older nodes.** A node built before the fifth field reads the first four
and ignores the rest, as this section required of it. It therefore reads
direct paths as on for *every* pair of roles, guests included, whenever the
fourth field is `direct`. That is accepted, for three reasons. A direct path
needs both ends, and a node that reads the fifth field neither offers its
addresses for nor accepts a path the pairs exclude, so only two older nodes
can open one against the matrix. Older ndn-rs builds try a direct path only
toward a peer configured to be reached through a relay (`[[peer]] relay`),
never by membership, so only pairs an operator configured are exposed. And a
direct path changes the route, not authorization: every packet is still
validated by the context's schema. What an older node does not enforce is
the privacy part: it may send its addresses to, and accept a path from, a
device of an excluded role. An operator who needs an excluded pair kept off
older nodes too sets direct paths off (fourth field `no-direct`, which older
nodes honour) until every device runs a build that reads the fifth field.

#### 3.3.11 AdvertisedRelay (`0x0420`)

```
value = Name [RelayKey] 1*RelayEndpoint [RelayPreference]
```

A relay the namespace advertises: every device that holds the context
learns it without local configuration. Repeatable, one entry per relay.

- **Name** (a complete `0x07` TLV): the relay's device name, normally
  `/<ns>/node/<device>`.
- **RelayKey** (`0x0422`, 32 octets): the relay's expected fingerprint, the
  SHA-256 of its public key as its certificate carries it. REQUIRED when the
  device is not under the namespace (a community or hosted relay), which a
  device can admit only by its key; OPTIONAL for a device of the namespace,
  which is admitted by its certificate (and by that key only, when given).
- **RelayEndpoint** (`0x0424`, UTF-8, non-empty): `host:port`, in the order
  a device tries them.
- **RelayPreference** (`0x0426`, NonNegativeInteger of at most 32 bits):
  lower is preferred. ndn-rs always writes it; a missing one means `0`.

**Encoding.** Children in the order above, entries in canonical order
(§3.2), at most one entry per device.

**Decoding.** An entry is dropped, and the context kept, when: it has no
Name or two; a RelayKey is not 32 octets, or appears twice; it has no
RelayEndpoint, or one that is empty or not UTF-8; a RelayPreference is not
a NonNegativeInteger (1, 2, 4 or 8 octets) or exceeds `2^32-1`, or appears
twice; it has an unknown critical child (`<= 31` or odd); its device is not
under the namespace and it has no RelayKey. An unknown non-critical child
(even) is skipped.

**Semantics.** The context only advertises. Each device decides whether it
uses the namespace's relays, how many at once and in which link mode
([ndn-link.md](ndn-link.md)); a relay of the namespace must still hold a
role the LinkPolicy lets relay. Dropping an entry — no entry for its device
any more, or one naming another RelayKey — is a narrowing (§5.3): a device
using that relay loses it. Adding an entry, or changing an entry's
endpoints or preference, is not. A node that does not know the TLV skips it
(even type) and uses only the relays configured on it.

**Privacy.** The endpoints are visible to every member, and to anyone who
fetches the context: it is published unencrypted by name (§7). Advertise
only endpoints that may be public. A relay sees the names of the packets it
forwards (their content is signed, and encrypted where the application
encrypts it); see [ndn-link.md](ndn-link.md).

#### 3.3.12 RevocationCut (`0x0428`)

```
value        = Name [CutKeyDigest] [CutManifest] *CutRange *CutExact
CutKeyDigest = 0x0430 32 32OCTET
CutManifest  = 0x0432 TLV-LENGTH Name
CutRange     = 0x042A TLV-LENGTH Name 1*CutRun
CutRun       = 0x042C TLV-LENGTH SequenceNumNameComponent SequenceNumNameComponent
CutExact     = 0x042E TLV-LENGTH Name
```

A revocation cut is the root's signed statement of where a revoked key's
authority over Data ended: which packets the key signed stay valid. It
replaces any judgement of *when* a packet was signed (§6.3). Repeatable, at
most one entry per key.

- **Name** (a complete `0x07` TLV): the revoked key's name,
  `<identity>/KEY/<k>`.
- **CutKeyDigest** (`0x0430`): 32 octets, the SHA-256 of the public key the
  cut is about: for an Ed25519 key its 32 raw octets (the certificate's
  SubjectPublicKeyInfo unwrapped), for any other algorithm the
  certificate's Content (the SubjectPublicKeyInfo DER) as it is. It binds the cut to
  that key material: the walk excuses the key only through a certificate
  whose public key has this digest (§6.3), so a certificate issued later
  under the same key name for another public key admits nothing through the
  cut. At most one.
- **CutManifest** (`0x0432`): a complete `0x07` TLV, the full name of the
  root packet of the cut's manifest, ending in its ImplicitSha256DigestComponent
  (TLV-TYPE `0x01`, 32 octets). The manifest lists the digest of every
  packet the ranges accept ([below](#cut-manifest)). At most one.
- **CutRange** (`0x042A`): a prefix `P` (a complete `0x07` TLV) and one or
  more runs. **CutRun** (`0x042C`): two SequenceNumNameComponent TLVs
  (TLV-TYPE `0x3A`, value a NonNegativeInteger, §1), the first and the last
  sequence number of the run, inclusive; first ≤ last.
- **CutExact** (`0x042E`): a complete `0x07` TLV whose last component is an
  ImplicitSha256DigestComponent (TLV-TYPE `0x01`, 32 octets): one packet,
  by its full name.

**Acceptance.** Let `X` be a Data packet with name `N` and implicit digest
`d` (SHA-256 of `X`'s whole TLV encoding, as NDN defines the implicit
digest). The cut **accepts** `X` iff either:

- some CutRange has a prefix `P` (which may be empty) such that `N` is `P`
  followed by exactly one component, that component is a
  SequenceNumNameComponent whose NonNegativeInteger is in its shortest form
  (§1), its value `s` lies in one of that CutRange's runs, and, when the cut
  has a CutManifest, the manifest lists exactly `(s, d)` under `P`; or
- some CutExact equals `N` followed by the ImplicitSha256DigestComponent of
  `d`.

Nothing else is accepted: not a longer or shorter name under `P`, not a
sequence number outside the runs, not a sequence number written in a
longer form (`seq=` with value `00 02` is another name than `seq=2`), not
other bytes at an exact name, and, under a manifest, not other bytes at a
name a range lists. A range with a manifest binds names and bytes, as an
exact entry does; a range of a cut without a manifest (one made before
manifests) binds names only (§10). While a reader does not hold every
manifest packet it needs to look `(s, d)` up, the packet is neither accepted
nor refused: it is pending, as for a missing certificate (§6.3). A manifest
packet that does not decode lists nothing, so the packets it would list
are refused. The cut never reads a date, a sequence number's meaning or a
validity period; which names a range lists is the producer's business
(the data layer bounds them by the root's own observation,
[data-layer.md](data-layer.md) §8.1).

<a id="cut-manifest"></a>**Cut manifest.** A cut's ranges can list
thousands of packets, and a digest each does not fit the one Data a context
is. The manifest carries them beside the context, as a tree of Data the cut
binds by digest:

```
Name     = /<ns>/32=trust-context/32=cut/<h>/seg=<i>
                 ; <h>: GenericNameComponent, SHA-256 of the revoked key's Name TLV (header included)
                 ; seg=0 the root; the other nodes seg=1, 2, … bottom-up
MetaInfo = ContentType BLOB, FreshnessPeriod 3600000 (ms)
Content  = CutManifestNode
Signature= DigestSha256 (SignatureType 0, no KeyLocator)

CutManifestNode = 0x0436 TLV-LENGTH ( *ManifestRange / 1*ManifestChild )
                                     ; a leaf (ranges) or an interior node (children), never both
ManifestRange   = 0x0438 TLV-LENGTH Name 1*ManifestEntry    ; Name = a CutRange prefix
ManifestEntry   = 0x043A TLV-LENGTH SequenceNumNameComponent ImplicitSha256DigestComponent
ManifestChild   = 0x043C TLV-LENGTH ManifestBound ManifestBound Name
                                     ; first and last (prefix, seq) the child covers; the child's full name
ManifestBound   = 0x043E TLV-LENGTH Name SequenceNumNameComponent
```

- **Self-certifying.** The manifest is signed with DigestSha256 only. The
  root-signed cut names the root packet by its full name, and every
  interior node names its children by full name, so each packet is bound,
  through the context, to its exact bytes. Whoever holds a packet may serve
  it.
- **Order.** In a leaf, ManifestRange entries are in canonical order of
  their prefixes (§3.2), one per prefix per node, and the entries of a
  range in strictly ascending seq. In an interior node, children are in
  strictly ascending order of their bounds — (prefix in canonical order,
  then seq) — each first ≤ last, never overlapping. A node that breaks
  these rules, or holds an unknown critical (odd) child, does not decode
  and lists nothing; an unknown even child is skipped.
- **Size.** ndn-rs fills each packet greedily up to 8000 octets for the
  whole packet, splitting a leaf between entries, and adds interior levels
  until one root remains; the tree is at most 8 levels deep.
- **Lookup.** To find the digest of `(P, s)`: in a leaf, the entry `s` of
  the range `P`; in an interior node, the child whose bounds contain
  `(P, s)`, fetched by its full name. No such entry or child means the
  manifest does not list `(P, s)`.

A reader fetches the manifest packets by full name, from the context's
publisher (§7.1) or any holder, exactly as it fetches a missing certificate
(§6.3). A node that keeps contexts keeps and serves the manifest packets of
every cut it holds (§7.3).

**Producer (root device).** A producer:

1. MUST add a cut only in the version that adds the Revocation entry of
   exactly its key name (§3.3.6), and only for such a key: never for a key an
   earlier version revoked, never for a key no Revocation entry of the
   version names.
2. MUST carry every cut of version `N` into every later version verbatim,
   except that a later version MAY add CutExact entries to it
   (**re-admission**, §5.3). It MUST NOT change, add or remove a CutRange,
   a run, the CutKeyDigest or the CutManifest, remove a CutExact entry, or
   drop a cut whose key a Revocation entry covers. Re-admission is by exact
   name and digest only, never by range: a range added later would admit
   whatever the key's thief signed at those names. A cut whose key no
   Revocation entry covers (an orphan, which has no effect) is not carried.
3. MUST write each cut canonically: CutRange entries in canonical order of
   their prefixes (§3.2), one per prefix; inside each, runs ascending,
   disjoint and not adjacent (runs `a..b` and `b+1..c` are written as one
   run `a..c`); CutExact entries in canonical order of their names, without
   duplicates; NonNegativeIntegers in their shortest form.
4. MUST give every new cut a CutKeyDigest, computed from the certificate
   whose public key verified the packets the cut lists, and MUST refuse to
   make the cut when those packets verify under two different public keys
   of the one key name. MUST give every new cut that has a CutRange a
   CutManifest listing exactly the `(seq, digest)` of every packet its
   ranges list, and MUST serve the manifest packets from the moment the
   version is published (§7.3). A cut without a CutKeyDigest, or with ranges
   and no CutManifest, is one made before these fields: it is carried as it
   is (rule 2), never made anew.

Which packets a range lists is not judged here; the data layer's producer
lists only packets the root itself verified before the moment the owner
gives as the loss of the key ([data-layer.md](data-layer.md) §8.1), so that
a thief's writes after the theft are not in the cut.

A node adopting a version does not check rules 1, 2 and 4 against the
version it held: the cuts are whatever an anchor signed, as is every other
field, and the anchor is the authority (§5.2). ndn-rs enforces them where
versions are made (`ndn_namespace::root`, `ndn_cert`). An adopter does
notice when a version accepts less than the one it replaces, and treats it
as revoking (§5.1).

**Decoding.** A decoder MUST reject the whole context, not only the entry,
when a RevocationCut is malformed:

- its value does not start with one Name TLV, or a Name (the key's, a
  prefix, an exact name) is not a valid Name TLV;
- a CutRange has no CutRun;
- a CutRun is not exactly two TLVs of type `0x3A`, each a NonNegativeInteger
  of 1, 2, 4 or 8 octets (§1), or its first exceeds its last;
- a CutExact name does not end in an ImplicitSha256DigestComponent of 32
  octets;
- a CutKeyDigest is not exactly 32 octets, or a cut has two;
- a CutManifest is not one Name TLV ending in an ImplicitSha256DigestComponent
  of 32 octets, or a cut has two;
- a RevocationCut or CutRange holds an unknown critical child (`<= 31` or
  odd, a second Name included); an unknown non-critical (even) child is
  skipped;
- two RevocationCut entries name the same key.

The key Name is checked as a Name only; its form (`…/KEY/<k>`) is the
producer's rule (§3.3.6). A decoder accepts cuts, ranges, runs and exact
entries in any order and reads them as their union: overlapping or
adjacent runs, two CutRange entries with one prefix, and a repeated
CutExact mean what their canonical form means (rule 3), which ndn-rs
writes when it re-encodes. A cut whose key no Revocation entry covers is
kept and has no effect (§6.3). Unlike a malformed AdvertisedRelay
(§3.3.11), a malformed cut is not dropped: a cut decides which Data stays
valid, so two decoders must never read one cut differently, and the root's
error is shown at once on every node instead of half-applied.

**Older nodes.** A decoder that predates cuts skips them (even type, §3.4)
and keeps the Revocation entry: it refuses every packet of the key, the
in-cut ones included. That is the meaning the entry had before, so it fails
safe: it loses the in-cut Data until it is updated, and accepts nothing the
cut refuses.

A decoder that knows cuts but predates CutKeyDigest and CutManifest skips
those two (even, so non-critical inside the cut) and reads the cut as one
made before them: its ranges accept any bytes at a listed name, under any
certificate of the key. Such a node keeps the residuals of §10 for that
cut until it is updated; every updated node closes them. The two fields are
even on purpose: an odd (critical) type would make that node reject the
whole version, so it would miss the revocation itself and go on accepting
everything the key signs.

**Size.** A context is one Data packet (§7.2). A cut over a log is a few
runs per prefix, one per stretch of consecutive sequence numbers; each
CutExact costs its name and 34 octets, the CutKeyDigest 34 and the
CutManifest its name. The digest of each packet a range lists is in the
manifest, outside the context, so the context stays one packet however
long the key's log was.

#### 3.3.13 DataRequiresCut (`0x0434`)

```
value = 1*OCTET      ; UTF-8, a role name
```

Repeatable, one role per entry. A device key's **role** is the component
right after the namespace of the selected context (§6.1) in its name,
`/<ns>/<role>/<dev>/KEY/<k>`, for a key whose identity has at least two
components after the namespace. Any other key — the root or a recovery
key, `/<ns>/KEY/<k>`, or `/<ns>/<x>/KEY/<k>` — has no role, and no entry
applies to it.

For a key whose role the context lists, Data the key signs is accepted
under the durable rule (§6.3) only:

1. while some certificate of the key that the node holds, with the same
   public key as the certificate that verifies the Data, is inside its
   ValidityPeriod by the reader's clock. Under a posture whose walks reach
   the anchors, a held certificate counts only when vouched for (§6.5): an
   unverified one — a renewal fetched, or a copy anyone could have served
   with a later ValidityPeriod — is first walked to the anchors as a
   certificate, and counts once that walk reaches them (one it cannot
   reach is dropped; a cache-only walk waits for the certificate it names
   missing). An `accept-signed` walk trusts the certificate as resolved; or
2. once the context revokes the key with a cut (§3.3.12): the cut then
   decides alone, whatever the clock says.

Otherwise the Data is refused as a key revoked without a cut would be
(ndn-rs: `TrustError::Revoked`, saying that the key's certificate lapsed,
that its role needs a cut, and that the owner's revocation with a cut is
awaited). Only the signing key's own certificates (depth 0) are compared
with the clock; issuers' validity periods are still not, as §6.3 says.

The clock here can only refuse. Data that case 1 lets through, the durable
rule accepts anyway; a revocation or a cut refuses what it refuses whatever
the clock says. A reader whose clock runs fast refuses a listed key's Data
early, until it holds the cut; one whose clock runs slow accepts it a
little longer, as a reader that has not yet adopted a revocation does.

**Why.** Without this field, Data ignores expiry entirely (§6.3), so a key
keeps its authority over Data until the owner revokes it. That is right for
a key that renews: its certificate is replaced before it lapses, and a
device that misses a renewal must not lose its honest Data because a
reader's clock passed a date. It is wrong for a key whose certificate is
short-lived precisely to end access, as a guest's is: after its expiry the
guest's links and signed Interests end, and with this field its Data
authority ends too. A listed key whose certificate lapsed fails closed
until the root signs its revocation with a cut; the cut then keeps what the
key wrote while it was trusted ([personal-namespace.md](personal-namespace.md)
F9; the owner ends it with `ndn-fwd end-keys`, with a cut bounded at the
certificate's NotAfter, §5.3).

**Per-role defaults.** A context made by `ndn-fwd init` lists:

| Role | Listed | Why |
|---|---|---|
| `guest` | yes | a guest does not renew by default (`[ca] renewable_roles`); its certificate's end is the end of the invitation |
| `member` | no | renews before expiry; listed, a late renewal or a fast reader clock would refuse its honest Data until a cut, and a cut ends the key |
| `admin` | no | as `member` |
| `node`, `relay` | no | as `member`; their keys renew with the node |

An owner MAY list any role by a schema or policy update (§5.3), and SHOULD
list every role whose renewal it turns off. A producer carries the entries
into every later version verbatim unless the owner changes them. An entry
added for a role makes the version refuse more Data than the one before
(§5.1).

**Decoding.** A decoder MUST reject the context when an entry's value is
empty or not UTF-8: skipping it would make the node refuse less than the
root stated. It reads the entries as a set (order and repeats carry no
meaning); a producer writes them in ascending octet order, without
repeats.

**Older nodes.** A decoder that predates this field skips it (even type)
and accepts a lapsed key's Data as §6.3 says, until it holds the key's
revocation; it is as open as every node was before the field.

### 3.4 Decoder rules

A decoder:

1. MUST reject Content whose first TLV is not `0x0410`, or any truncated
   TLV.
2. MUST reject a TrustContext in which Name, AnchorSet, SchemaAuthoritative,
   EnrollmentHint, SourceBundleHash or LinkPolicy appears more than once,
   whether or not the copies are well formed. CaEndpoint, Revocation,
   RevocationCut, DataRequiresCut, KeyRole, AdvertisedRelay and
   TrustSchemaBlob are repeatable and accumulate (at most one RevocationCut
   per key, §3.3.12).
3. MUST reject an unknown critical child type (`<= 31` or odd), and MUST
   skip an unknown non-critical one (even). A KeyRole or SourceBundleHash
   that fails its length check is skipped as non-critical (it still counts
   as the one SourceBundleHash for rule 2), and so is a malformed
   AdvertisedRelay (§3.3.11). A malformed RevocationCut or DataRequiresCut
   is not skipped: it rejects the context (§3.3.12, §3.3.13).
4. MUST reject the context when the namespace is missing, no
   TrustSchemaBlob is present, no blob is in a format the decoder
   understands (§3.3.3), or the schema does not import (LVS error,
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
consumer MUST take the version from the last name component; a component
whose value is not 1, 2, 4 or 8 octets is not a version (§1), and the name is
not a context name. It MUST then check that the Data name is byte-for-byte
equal to the name rebuilt from the decoded namespace and that version,
written with the canonical (shortest) NonNegativeInteger. A context Data
whose version component is not in canonical form is therefore rejected.
Producers MUST use canonical form.

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

**Validity of the signer.** A node MUST refuse a context Data it *receives*
— on first adoption (§4.4), as an update (§5.2), and at each step of a walk
(§5.4) — when the anchor that signed it is outside its ValidityPeriod at
verification time (NotBefore after now, or NotAfter before now), as it
refuses a chain that ends at such an anchor. The anchor checked is the one
listed in the received version itself. A node opening its *own stored copy*
of a version, for example the root device making the next version, does not
check it. So an expired anchor never stops a namespace: its key signs a new
version that lists a re-issued certificate of the same key, and §5.2 rule 4
matches the held version's anchor by public key, not by its certificate's
validity. ndn-rs gives every anchor it makes NotAfter `25540721T233433`
(§3.3.2), so in practice only a device clock set before the anchor's
NotBefore makes this check fail.

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

- it is self-consistent (§4.3), and the anchor that signed it is valid now
  (§4.3);
- its namespace equals the namespace the out-of-band link named;
- the anchor that signed it has the **expected fingerprint** from that link
  (§3.3.2);
- its version is at least the version the link names, when the link names
  one. This closes a first-contact downgrade to an older genuine context.

The link and envelope formats are in [trust-envelope.md](trust-envelope.md).
How the context is fetched is in §8.1. ndn-rs refuses unsigned (legacy
`ndn-ctx:1:`) content on every default path.

A self-certifying namespace (§4.5) has no expected fingerprint: the third
condition is replaced by the genesis rule (§4.5.2), and a node holding
nothing of it adopts it only from its version 1 (§4.5.3).

### 4.5 Self-certifying namespaces (`/user/<h>`)

A namespace is **self-certifying** iff it has exactly two components:

1. the GenericNameComponent `user` (TLV-TYPE `0x08`, value `75 73 65 72`);
2. a component of TLV-TYPE `0xA1` (`SELF_CERTIFYING`, see the name-component
   registry in [README.md](README.md)) whose value is exactly 32 octets,
   written `<h>`.

`<h>` is SHA-256 over the raw 32-octet Ed25519 public key (RFC 8032
encoding, not the SubjectPublicKeyInfo) of the namespace's **genesis root**,
the key that signs its version 1. That is the anchor fingerprint of §3.3.2
of that key, so the name is the expected fingerprint of its genesis root,
and adopting the namespace needs nothing but its name. The bytes are the
ones ndf-rs's `record::personal_root` computes. Only version 1 is ever
compared with the name; every later version follows by continuity (§5.2),
so a recovery, or a root of another key type, keeps the name.

#### 4.5.1 Where a self-certifying component may appear

A component of TLV-TYPE `0xA1` MUST appear only as the second component of
a self-certifying namespace and of names below it. A node MUST refuse, as
the namespace of a context, a link, an adoption or a namespace to create:

- a name with a `0xA1` component anywhere else: not directly after `/user`,
  with a value other than 32 octets, or with a second `0xA1` component
  (ndn-rs `SelfCertifyingNameError::Misplaced`; the refusal says the only
  form a person's namespace takes);
- a namespace strictly under a self-certifying one, `/user/<h>/…`
  (`SelfCertifyingNameError::Under`): the names under it are that person's,
  judged by `/user/<h>`'s context, and the refusal says to adopt
  `/user/<h>` itself.

`/user` itself is not self-certifying. It MAY be an ordinary namespace
(`/user/alice` is an ordinary name under it), but it never governs a name in
a self-certifying namespace (§6.1).

#### 4.5.2 The genesis rule

A node MUST accept a context Data as the genesis of `/user/<h>` only if all
of these hold:

1. it is self-consistent (§4.3) and, when received, its signing anchor is
   valid now (§4.3; a node's own stored copy is not checked for validity,
   as there);
2. its namespace is `/user/<h>` and its version is 1. A later version
   offered as genesis is refused (ndn-rs `GenesisError::NotVersionOne`,
   which says to fetch `/user/<h>/32=trust-context/v=1`);
3. its SignatureType is SignatureEd25519 (`5`) and the public key of the
   anchor that signed it (§3.3.2) is 32 octets (`GenesisError::NotEd25519`);
4. SHA-256 of that public key equals `<h>` (`GenesisError::Mismatch`).

The rule judges the anchor that *signed* version 1, never the anchors it
lists. A context signed by its own root that also lists the key `<h>` names
is refused: anyone can list a public key, only its holder can sign with it.

A version `N > 1` is judged by §5.2 alone: signed by an anchor of the
version before it, a recovery anchor included (§5.3). A recovery onto a new
root of any supported key type (a P-256 key on a YubiKey, say) and the
re-issue after it therefore keep the name. A genesis root of another key
type would need a component encoding of its own; none is defined.

#### 4.5.3 Adoption by name

A node that holds no context of `/user/<h>` adopts it from the name alone
(ndn-cert `adopt_by_name`; an anchor link naming the namespace alone,
[trust-envelope.md](trust-envelope.md) §7.1):

1. It fetches `/user/<h>/32=trust-context/v=1` by exact name and the RDR
   metadata naming the newest version `M` (§8.1). A validating forwarder on
   the path is told to expect a context of `/user/<h>` whose signing anchor
   has the fingerprint `<h>`, so it admits the genesis it does not yet trust
   and drops a forged one.
2. Version 1 MUST pass §4.5.2. Otherwise nothing is adopted.
3. When the link names a version, an `M` below it is refused (a downgrade,
   as in §4.4).
4. `M = 1`: the genesis is the newest. Otherwise the node fetches version
   `M` and takes it when an anchor of the genesis signed it (§5.2); else it
   walks versions `2 … M` from the genesis (§5.4). A version that does not
   follow, or a stopped walk, adopts nothing, and the refusal says which
   version and why.
5. It adopts the newest together with the genesis (§4.5.4).

A node with a network adopts `/user/<h>` not held by name, as above,
whatever context a link, an envelope or an introduction carries inline
(ndn-cert `AnchorLink::fetches`, `adopt_anchor_link`): an inline version 1
MUST pass §4.5.2 and MUST then equal, in Content byte for byte, the version
1 fetched in step 1; a different one is refused as a fork (two versions 1
signed by the key `<h>` names, ndn-cert `AdoptError::GenesisFork`), and
nothing is adopted. An inline later version is unused. An inline version 1
is never adopted in place of the fetched one: whoever stole the genesis key
can sign a version 1 of his own (§4.5.6 note 1). When the fetch fails, the
node refuses, saying to retry once the person's devices are reachable
(`AdoptError::GenesisUnreachable`). Only a node with no network bound — the
CLI adopting into the PIB with no daemon running (`ndn-fwd adopt`, ndn-cert
`adopt_anchor_envelope`, `adopt_with_tofu`) — takes an inline version 1
checked by §4.5.2 alone, and the adoption says so
(`LinkAdoption::offline_genesis`, `LinkAdoption::OFFLINE_GENESIS_NOTE`:
"adopted from the link's own version 1 without checking the network; …").
An introduction never takes it alone ([data-layer.md](data-layer.md) §19).
A namespace already held moves on only by the continuity rule, from a link
as from anywhere (§5.1).
Adopting a held `/user/<h>` by name again is a refresh of it (§8.2): the
newest version is fetched as an update of the held version, a validating
forwarder is told to expect a version signed by an anchor of the held
version (never a context whose signing anchor has the fingerprint `<h>`),
and the newest is reached from the held version directly or by walking
(§5.4). After a recovery, a version signed by the genesis root — perhaps
stolen — is therefore neither admitted by the forwarder nor adopted. When
the held version is the newest, its Data is fetched the same way and MUST
be the held version (else a fork); a newest version older than the held
one is refused as a rollback, and one older than the link's version as a
downgrade, before anything is adopted.

A node MUST keep the genesis and every version it walked beside the newest
(§7; ndn-cert `LinkAdoption::earlier`, `persist_adoption`). At a restart it
takes the namespace again only from its stored genesis: version 1 read back
and checked by §4.5.2 (as a stored copy), then the stored newest reached
from it by §5.2, directly or by walking the stored versions. Without a
stored genesis the namespace is not taken (ndn-cert
`ContextStoreError::GenesisMissing`), and the node adopts it again by name.

#### 4.5.4 The keyring gate

No path that checks only an expected fingerprint, an inline context or a
stored newest version may enter a self-certifying namespace not held. In
ndn-rs:

- `Keyring::adopt` refuses such a namespace (`AdoptRefusal::GenesisRequired`,
  which says to adopt it by name) and any namespace §4.5.1 refuses
  (`AdoptRefusal::Name`).
- The only entry is `Keyring::adopt_genesis(genesis, newest)`. Its
  `Genesis` is a value only `Genesis::open_received` and
  `Genesis::open_stored` make, after §4.5.2. It refuses a `newest` of
  another namespace, or a version 1 other than the genesis
  (`AdoptRefusal::NotFromGenesis`). A held namespace is never changed here.
- Every adoption path — anchor links and envelopes, `adopt_with_tofu`,
  invite enrollment, stored copies, introductions
  ([data-layer.md](data-layer.md) §19) — reaches the namespace through it.
  A fingerprint a link, envelope or invite carries for a self-certifying
  namespace is ignored, not compared: the genesis decides. An invite to a
  held self-certifying namespace is not compared with its fingerprint
  either, since the held context's current root need not be the genesis
  root.
- `Keyring::of_claim` holds a party's own claimed context, unadopted, to
  check that party's proof against it before anything of it is trusted
  (the data layer's introductions, ndn-link). It never makes the namespace
  trusted, and it refuses what §4.5.1 refuses.
- `ScopedContext::new(genesis, newest)` is the one other value made from a
  `Genesis`, with `adopt_genesis`'s checks: a namespace adopted for one
  scope alone (§4.5.7). It enters no keyring.

#### 4.5.5 Creating one

ndn-rs creates a self-certifying namespace with
`ndn-fwd init --self-certifying [--namespace /user/<h>]` (a new Ed25519 key,
`GenesisKey::generate`), or from an Ed25519 secret held already
(`GenesisKey::from_seed`, the 32-octet RFC 8032 seed — an ndf-rs personal
key, for one) with `init_self_certifying`, `init_self_certifying_in_pib` or
`init_self_certifying_in_pib_with`. The key becomes the root
`/user/<h>/KEY/root`.

**The genesis is a pure function of the key.** Init signs two versions
(§4.3):

- version 1, the genesis (ndn-cert `sign_genesis`): the namespace, the
  hierarchical schema and one anchor — the root's self-signed certificate
  `/user/<h>/KEY/root/self/v=0` with the fixed validity `19700101T000000`
  to `25540721T233433` (0 to 2^64−1 ns, the widest a certificate holds in
  ndn-rs; `GENESIS_ROOT_VALID_FROM_NS`, `GENESIS_ROOT_VALID_UNTIL_NS`) — and
  nothing else: no CA, schema of its own, policy, relay or key role, and no
  field holding the time of signing. Ed25519 signatures are deterministic
  (RFC 8032), so the same key signs a byte-identical version 1 on every
  device, at any time;
- version 2, signed by the root (an anchor of version 1, §5.2): the
  generated namespace schema, the CA endpoint, the root device's key roles,
  the enrollment and link policies, the relays and the DataRequiresCut
  roles — what an ordinary init puts in its version 1.

Both are stored (§7), and the node serves version 1 beside the newest.
Besides the usual anchor links, which carry version 2, `ndn-fwd init`
prints `genesis` (the file of version 1) and `anchor_uri_name`: an anchor
envelope carrying the namespace alone.

**A key held already is looked for first.** A key made now has no genesis
anywhere. A key held already may have made its namespace before, on
another device or before a reinstall; a second init would sign the same
version 1 but another version 2, which every holder of the first refuses
as a fork (§5.1). `GenesisKey::from_seed` therefore returns an
`ExistingGenesisKey`, which makes a namespace only through one of:

- `probe(exchange)`: fetches `/user/<h>/32=trust-context/v=1` over the
  caller's network and checks it by §4.5.2 (as a stored copy, so an
  expired anchor does not hide it). A genesis of the key that answers
  refuses the init before anything is written
  (`NamespaceInitError::GenesisReachable`), saying the namespace exists,
  and to adopt it by name and enroll this device, or to recover it.
  Anything else — no answer, or a version 1 another key signed — is no
  evidence: the init proceeds and states what the fetch met
  (`GenesisCheck::NoneReachable`). Only a genesis refuses: the RDR pointer
  is unauthenticated, and anyone answering it would stop the init. A
  network that drops or hides the genesis cannot be told from one without
  it;
- `offline()`: not looked for, and the init states so
  (`GenesisCheck::Unchecked`).

Every init reports which in `NamespaceInit::genesis_check` (`NewKey` for
a key made now). An application holding its key already (ndf-rs) runs
`GenesisKey::from_seed(seed).probe(&mut exchange).await?` over its engine,
then `init_self_certifying_in_pib_with` with the key it returns.

These are refused before anything is written:

- a self-certifying name given to an ordinary init (`ndn-fwd init
  --namespace /user/<h>` without `--self-certifying`, `init_namespace*`):
  a root made now never hashes to a name chosen before it. The refusal
  says to use `--self-certifying`, or to create the namespace from the key
  it names;
- with `--self-certifying`, a `--namespace` other than the one the new key
  names;
- a YubiKey root store: a PIV slot holds no Ed25519 key. The refusal says
  to use the `os-keyring` or `sealed-file` store; a later recovery can move
  the root onto a YubiKey and keep the name;
- a namespace §4.5.1 refuses;
- a self-certifying namespace that exists in the PIB already, whatever
  force is given (`NamespaceInitError::GenesisExists`): its key would sign
  the same genesis but a second line of versions after it, which every
  holder of the first refuses as a fork (§5.1). The root is replaced by a
  recovery ([recovery-kit.md](recovery-kit.md)), which keeps the name;
- a key held already whose genesis answers the probe (above).

#### 4.5.6 Threat notes

1. **A stolen genesis root.** The name binds version 1 only. Whoever holds
   an anchor of a version — the genesis root included, while it is one —
   can sign a next version that follows by §5.2: a branch as continuous
   from the genesis as the owner's.
   - A node holds one version and moves on only to a newer one signed by
     an anchor of it (§5.1, §5.2). A node that adopted the owner's
     recovery, which removes and revokes the stolen root (§5.3), refuses
     every later version the thief signs, none being signed by an anchor
     it holds, and a thief's version under the number it holds is a fork.
     So holders of the owner's line follow the owner's recovery and refuse
     the thief's branch. A node that adopted a thief's version first holds
     the thief's line: it moves to the owner's only through an owner's
     version signed by an anchor of the version it holds, as for any
     namespace whose root was stolen (§10).
   - A fresh adopter checks version 1 against the name and every later
     version against the one before it. It detects a forged genesis and a
     version that does not follow. It cannot tell which of two continuous
     branches is the owner's: it follows the one its upstream's metadata
     and versions lead to. If it reaches only the thief's branch, it
     follows the thief.
     A version floor in its link refuses an older newest, not a branch
     with a higher number. To take the owner's line after a compromise, a
     fresh adopter must fetch from a node that holds it.
   - What a thief hands over is not a network position. A link, an
     envelope or an introduction carrying the thief's own version 1 inline
     (one leaving out the owner's recovery anchor) moves no node with a
     network: it adopts by name, and the inline version 1 only checks
     against the fetched one — a different one, when the owner's line is
     what its network serves, is refused as a fork and nothing is adopted
     (§4.5.3). Only a node with no network bound takes an inline version 1
     alone, and its adoption says it did not check the network
     (`LinkAdoption::offline_genesis`).
2. **Two lines from one key.** If the owner signs two different versions
   1, or two lines after one genesis, a node holding one refuses the other
   as a fork (§5.1); a node holding neither follows whichever it fetches
   first. The genesis is a pure function of its key (§4.5.5), so making a
   namespace again from its key never forks at version 1; two inits from
   one key (a second device, a reinstall) would fork at version 2. ndn-rs
   refuses that second init when the
   namespace is in the PIB (`GenesisExists`) or its genesis answers the
   probe (`GenesisReachable`); an init from a held key explicitly not
   looked for (`GenesisCheck::Unchecked`), or looked for over a network
   that hides the genesis, can still make a second line, which holders of
   the first refuse.
3. **Collisions.** The name binds 256 bits of SHA-256. Forging another
   party's genesis needs an Ed25519 key whose SHA-256 is that party's
   `<h>`, a second preimage; two keys with one name need a collision,
   useful only to someone holding both keys. The rule is as strong as
   SHA-256's second-preimage and collision resistance.
4. **Names under `/user/<h>` are the person's.** No context of another
   namespace is rooted at or under `/user/<h>` (§4.5.1), and a name in it
   is judged only by `/user/<h>`'s own context (§6.1). A held `/user` or
   `/` context never vouches for it, and neither does the ambient context,
   whatever anchors it holds — a forwarder's holds every PIB trust anchor,
   its own root included, so a key certified under one person's root
   would otherwise vouch for another person's names. Without `/user/<h>`
   held, every signed packet in it is refused, under every security
   profile, `accept-signed` included, with a refusal naming `/user/<h>`
   and saying to adopt it by name first (ndn-rs
   `TrustError::PersonalNamespaceNotHeld`, forwarder refusal
   `untrusted-root`), and a forwarder caches none of it. With `/user/<h>`
   held, or judged through a scoped view (§4.5.7), every walk for a signed
   packet in it ends at an anchor of `/user/<h>`'s context, under every
   profile, `accept-signed` included: that profile ends other names' walks
   at the packet's verified signer, but nothing short of the namespace's
   genesis line vouches for a person's keys, and a certificate anyone
   issued under `/user/<h>` would otherwise vouch for a device they made up
   there (ndn-rs `Validator::accept_signed`; ndn-fwd's accept-signed
   validator walks as deep as the default's). Two kinds of
   packet are not refused: its context versions, under an adoption's
   expectation (§4.4), so it can be adopted by name; and a DigestSha256
   packet, which names no signer and vouches for nothing, so it passes
   integrity-only as under every name — the namespace's metadata pointer,
   whose versions are each checked from the genesis, and a device's
   wrapped `32=held` answers, through which a stranger fetches an offer
   before it trusts the inviter ([data-layer.md](data-layer.md) §19), are
   such packets, and their consumers check what they carry.
5. **No position bound.** The 128-position bound of §5.4 does not apply to
   a self-certifying namespace's walks — a refresh, a sync update, an
   adoption by name, a restart from the stored genesis — because the only
   alternative to a long walk is a longer one from the genesis. A walk over
   the network is bounded by work and by time instead. It fetches at most
   **128** positions it cannot use (`MAX_CATCH_UP_MISSES`: nothing usable
   arrived, or a version not newer than the one reached), and no fetch
   starts after 40 s (`MAX_CATCH_UP_TIME`). The positions left are then
   passed over at once, never stepped through one by one, and only the
   newest, fetched before the walk, is judged: it must follow from the
   version reached, else the walk stops, nothing adopted, naming the
   versions it missed and why (retry once a node that kept them is
   reachable). A walk thus costs the versions it reaches — each signed by an
   anchor of the one before, so no more than the namespace's owner made —
   plus at most 128 misses: a pointer or sync announcement naming an absurd
   version, with every position in between failing at once (a Nack, an old
   version), costs at most 128 Interests and 40 s per attempt, while a line
   of any length after a recovery is still followed. A walk at a restart
   reads only the stored versions, with no network, at a cost of their
   number, not of the distance between versions.
6. **A scope that leaks.** A namespace adopted for one scope (§4.5.7)
   judges only through its view: the keyring never holds it, so every
   other path — a forwarder's validation stage, another view, the
   keyring's own `contexts()` — refuses it as note 4 says, and a held
   context of the namespace always wins over it, never replaced. Where a
   forwarder carries such a namespace in transit for the scope's holder,
   it vouches for and caches none of it (data-layer.md §6.2, "Scope
   leaks").

#### 4.5.7 Adopted for one scope

A holder may adopt a self-certifying namespace by name for one scope of
its own alone — the data layer adopts every self-certifying writer a
folder's members record lists, to judge that folder's data
(data-layer.md §6.3) — without the node trusting it anywhere else.

- The adoption is §4.5.3's (genesis fetched and checked, the newest
  reached by continuity, a validating forwarder told to expect the
  versions, the walk bounded as note 5 says), into no node keyring
  (ndn-cert `adopt_scoped`, `ndn_identity::adopt_scoped_via_engine`). Its
  result, a `ScopedContext`, holds the checked `Genesis`, the newest
  version and that version's signed Data as received
  (`ScopedContext::data`; `with_data` binds it, refusing Data of another
  name or content); a refresh moves it on only from the version held, by
  continuity (`ScopedContext::moved_on` refuses an older version, another
  of the same number, another namespace).
- The holder keeps the newest version it adopted for the scope durably,
  beside its own state: its number, the SHA-256 of its content, and the
  genesis's and that version's signed Data. After a restart it opens them
  again — the genesis by `Genesis::open_stored` (signature and genesis
  rule, no clock), the version by `SignedTrustContext::open_signed` and
  `with_data` — and holds the namespace at that version, refreshing from it
  by continuity, as a holder of the namespace would (§5.1, §5.2): the walk
  never starts at the genesis again, so neither an older version nor a
  branch that does not descend from the version kept — a thief's after a
  recovery, whatever its numbers — is taken. An adoption that reaches an
  older version, or that number with other content, is refused as §5.1
  refuses one for a held namespace; the refusal says which version was
  reached before and to reach a device or relay serving it, and the holder
  asks again later (data-layer.md §6.3).
- A holder apart from its forwarder — an app beside a daemon — cannot
  tell the forwarder's validator to expect the versions: it has the
  forwarder carry the namespace in transit first (mgmt-trust.md
  "Transit", `security/transit` from a local operator or a member of a
  transit group, owned by the connection that asked), then fetches the
  versions over its own connection and checks each itself, as above
  (`ndn_cert::adopt_scoped` with no forwarder). It carries each namespace
  once, whether it adopts it anew or refreshes from a version the scope's
  holder kept, takes back a mark that adoption took if it fails, and the
  one mark when the scope releases the namespace.
- It judges through a view only: `Keyring::with_scoped_view` shares the
  keyring's held contexts live and governs the scoped namespace's names
  by the scoped context **only where no held context covers them**: a
  context of that namespace the keyring holds, adopted before the view or
  after, is used as is. `Validator::scoped_view` is a validator over such
  a view, with the same certificate cache, fetcher, chain depth and
  refusals; the validator it is made from, and every user of its keyring,
  keep refusing the namespace (`PersonalNamespaceNotHeld`). Which packets
  a view judges is the holder's rule (data-layer.md §6.3).
- A view walks every packet it judges to the anchors of the context
  judging it, whatever the posture of the validator it is made from: one
  made from an `accept-signed` validator — a forwarder's, which an
  embedded data layer verifies with — still requires the anchors (note
  4). A certificate a view fetches enters the shared cache unverified
  (§6.5) and vouches for nothing by itself.

*Threat note.* Before a view required the anchors, a view made from an
`accept-signed` validator ended each walk at the packet's verified signer:
Mallory, heard in a folder's group, served a root of a device she made up
under a listed writer's namespace (`/user/<hC>/m`, its key
`/user/<hC>/m/KEY/1`) with a certificate she issued herself; the writer's
schema passed the hop, and her versions were admitted as the writer's.
The genesis check that justified adopting the writer was never used.

## 5. Versioning and continuity

### 5.1 Anti-rollback

A node MUST NOT replace its held version with a lower one, nor with one that
its held version does not authorize. ndn-rs applies two rules:

- **Adoption from a link** (§4.4) — an anchor link, an envelope, a stored
  copy — adopts a namespace not held. For a held namespace it changes
  nothing unless the offered version passes the update rule (§5.2): signed
  by an anchor of the held version and strictly newer. A link names an
  expected fingerprint, but that proves only who signed the offered context,
  not that the namespace's owner made it: anyone can sign a `/<ns>` context
  listing their own root. So a node MUST refuse a newer version of a held
  namespace that does not follow from the held one, whatever fingerprint it
  was checked against. The namespace's owner moves it on by signing the next
  version with a held anchor (a recovery kit's key included), and a node
  that missed versions follows them by refresh (§5.4). An offered version
  *equal* to the held one is accepted only when its content encodes
  identically to the held context's (§3.2), and then changes nothing. A
  different context under the held version number is a fork, and a node
  MUST refuse it. In ndn-rs `Keyring::adopt` never changes a held
  namespace; the link paths check the update rule and then adopt by
  compare-and-swap (`Keyring::adopt_update_from`).
- **Update** (§5.2) replaces it iff the offered version is *strictly*
  greater. ndn-rs also requires that the held context is still the exact
  one the update was checked against, a compare-and-swap. If another
  adoption changed it meanwhile, nothing is adopted and the next refresh
  starts from the new held version.

An adopted version is **revoking** when it may refuse Data the replaced one
accepted. That is the case when it revokes a name the replaced version did
not; when, for a key the replaced version holds a cut of, the new cut does
not contain the old one — the cut is removed, a run of the old cut is not
covered by the new one, a CutExact entry is dropped, or the CutKeyDigest
or CutManifest is added, removed or changed (a new manifest may list other
bytes); and when it lists a role in DataRequiresCut (§3.3.13) that the
replaced version did not. The producer rules forbid shrinking a cut
(§3.3.12), but an adopter does not enforce them, and a version made by a
tool that predates cuts drops them all, so the adopter compares. ndn-rs
(`Keyring`) moves its revocation epoch on every revoking adoption and tells
its revocation listeners which names it concerns (the keys, and for a role
newly listed the prefix `/<ns>/<role>`), so cached Data is judged again
(§6.3).

On a revoking adoption the node SHOULD purge cached Data that the adopted
version refuses: Data signed by a key it revokes that its cut does not
accept (all of it when there is no cut), and Data whose chain passes
through a revoked issuer (§6.3). It SHOULD keep, and serve, the
certificates of a key revoked with a cut, and the packets of its cut's
manifest: the in-cut Data needs them to verify, and the certificates serve
no other use, since every live use refuses a revoked key (§6.3). The
certificates of a key revoked without a cut are purged with its Data.

### 5.2 Continuity rule

A node holding version `N` (context `H`) MUST accept a context Data `D` as an
update only if all of these hold:

1. `D` is self-consistent (§4.3), its signer anchor is `A`, and `A` is valid
   now (§4.3);
2. the namespace of `D` equals the namespace of `H`;
3. the version of `D` is greater than `N`;
4. some anchor of `H` has a public key byte-equal to `A`'s public key (§3.3.2).

So version `N+1` is authorized by version `N`. A version may add anchors,
for a root rotation or a new recovery anchor, but those anchors carry trust
only once that version is adopted. Rule 4 compares public keys, not names: a
re-issued certificate of the same key satisfies it. Rule 4 does not check
the validity of the matching anchor of `H` either, so a root whose held
certificate has expired still authorizes the version that re-issues it.

### 5.3 Root hand-over (informative summary)

The continuity rule carries every authority change. The recovery and kit
procedures are specified in [recovery-kit.md](recovery-kit.md). Every
version below is made from `N` with all of `N`'s revocation cuts carried
verbatim (§3.3.12 rule 2; an orphan cut, whose key no Revocation entry
covers, is dropped), and its DataRequiresCut entries (§3.3.13) carried
unless the owner changes them; only a revocation bump and a recovery add a
cut, and only a re-admission bump adds to one.

- **Revocation bump (F4–F6):** `N+1` is `N` plus new Revocation entries,
  signed by an anchor of `N`, and, when the operator gives one, the
  revocation cut of a key it newly revokes (§3.3.12), with its key digest
  and, when it has ranges, its manifest, which the root device then serves.
  Everything else is carried over verbatim. ndn-rs refuses a new cut
  without a key digest, or with ranges and no manifest.
- **Ending a key without a renewal:** two kinds of keys must end although
  nobody lost them. A key of a role the context lists in DataRequiresCut
  (a guest's) whose last certificate reached its NotAfter is **lapsed**;
  the key of a device identity for which the CA enrolled a newer key (one
  key per device) is **replaced**. The root ends each with a revocation
  bump and a cut bounded at that moment (the last NotAfter of the key's
  certificates, or the first NotBefore of the replacement's): what the
  root verified before it stays valid, nothing later. ndn-rs never revokes
  such a key without a cut, and its daemon never unlocks the root: the
  owner runs `ndn-fwd end-keys`, which signs one version ending every such
  key that has a cut made with that bound, after one confirmation, or
  without one (`--yes`, for a timer) when the root store opens without a
  secret. Until then every root command, `ndn-fwd status` and the admin
  TUI list the keys to end, with the data-host command that makes each
  cut. Meanwhile a lapsed guest's Data already fails closed (§3.3.13); a
  replaced key's does not, so it should be ended soon.
- **Re-admission bump:** `N+1` is `N` with CutExact entries added to the cut
  of a key `N` revokes with a cut, signed by an anchor of `N`. Nothing else
  changes. A key revoked without a cut gets none this way: its cut can only
  be added with its revocation.
- **Schema update:** `N+1` carries new blobs, the EnrollmentHint, the
  SchemaAuthoritative flag, and optionally a new LinkPolicy or new
  AdvertisedRelay entries (otherwise each is carried verbatim, and so are
  the DataRequiresCut entries, which ndn-rs changes only in a version of
  their own, `ndn-fwd schema data-requires-cut`). It is signed by an anchor of `N`. ndn-rs refuses a
  narrowing — a rule, a link permission, a direct pair or an advertised
  relay dropped — unless the operator consents, but that is a producer-side
  check only.
- **Recovery anchor added or removed (F7):**
  - When a recovery key is added, `N+1` gains the new anchor and a KeyRole
    `1` entry, signed by the root.
  - When one is removed, `N+1` drops that anchor and its KeyRole entries and
    revokes the key, signed by a different anchor.
- **Recovery (F8):** `N+1` is signed by a recovery key that is an anchor of
  `N`.
  - It adds the new root as an anchor and replaces the KeyRole `2` entries.
  - With `--old-root compromised`, it also removes and revokes the old root,
    the old root-device keys, and the recovery anchors nobody vouched for,
    and MAY add a cut for any key it newly revokes (the old admin device's
    key, for one: its Data up to the compromise stays valid). The cuts it
    carries were signed by a root that may have been in a thief's hands, so
    the recovery checks each carried cut again and drops the orphans and
    any cut listing a name outside its key's device log, reporting each
    cut it drops. A cut never excuses a revoked issuer (§6.3), and this
    recovery revokes the old CA key, so the new CA must certify again every
    key the recovered context revokes with a cut, from a certificate of it
    the recovering device holds whose public key has the cut's
    CutKeyDigest; the in-cut Data then chains to the new root. ndn-rs does
    this once `N+1` is taken, after showing the operator the cuts and
    asking for confirmation; without it nothing is certified and the
    operator can do it later. A certificate with another public key is
    never certified again, and neither is the key of a cut without a
    CutKeyDigest: whatever key a certificate file carries, the new CA
    vouches only for the key the cut names by digest. Such a certificate
    authorizes nothing outside the cut: the key stays revoked, excused only
    for its own in-cut packets. A cut key not certified again is reported
    with why, and its Data stays refused until the owner certifies it.
  - `N+1` carries every cut of `N` but those dropped, and so does `N+2`.
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

- **Positions:** `N+1 … M`, for a refresh and for a sync update alike. A
  sync update's low sequence number is not a lower bound: it says what the
  member last heard, not which versions exist.
- **Bound:** if the number of positions exceeds **128**
  (`MAX_CATCH_UP_VERSIONS`), the walk is refused before anything is fetched,
  and the refusal says to adopt the namespace again from a current anchor
  link. A self-certifying namespace's walks have no such bound; the misses
  bound and the deadline bound them (§4.5.6, note 5).
- **Misses:** at most **128** positions (`MAX_CATCH_UP_MISSES`) are fetched
  and passed over under rules 2 and 3 below. Once that many have been, the
  positions before `M` are passed over at once, recorded as passed over
  (the reason says the walk's limit), and only `M` is judged. An ordinary
  walk has at most 128 positions, so this binds only a self-certifying one.
- **Deadline:** no fetch starts after **40 s** (`MAX_CATCH_UP_TIME`). The
  clock starts when the refresh begins fetching the newest version. A
  position not fetched by then counts as missing, and the positions left
  are passed over at once.
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
no adopted context matches, it uses the ambient context. What the ambient
context holds depends on the keyring: a `Keyring::new()` makes it
deny-all (hierarchical, no anchors), but a `Validator`'s flat-anchor API
and a forwarder's `default` profile make it a context over every trust
anchor configured — on a forwarder, every PIB trust anchor, the node's own
namespace root included — with the hierarchical schema (data name and
key name share their first component) and no hierarchy floor or
certificate-hop rule.

A name in a self-certifying namespace, `/user/<h>/…` (§4.5), is governed
only by the context of `/user/<h>` itself: a held context of a shorter
prefix (`/user`, `/`) is never selected for it, and **neither is the
ambient context**. Without `/user/<h>` held, such a name is judged by a
fixed context with no anchors and an empty schema, which accepts no signed
packet — anchored or signature-only (`accept-signed`) — and the validator
refuses such a packet up front, naming `/user/<h>` and saying to adopt it by
name (§4.5.6 note 4 gives what passes: context versions under an adoption's
expectation, and integrity-only digests).
Every path that judges a name by its context goes through this one
selection (ndn-rs `Keyring::context_for`; `Keyring::held_for` answers
whether a held context covers a name, `Keyring::unheld_personal_namespace`
which person's namespace is missing): chain-walk anchor termination,
revocation and cut checks, anchor membership (`Keyring::is_anchor`), the
forwarder's content-store re-check, link admission and the data layer.

**The ambient context and the shared `/user`.** Every person's keys sit
under the one component `user`, so the hierarchical schema's
first-component rule no longer separates them for ordinary names under
`/user` (`/user/alice/doc`, no 0xA1 component): a key of `/user/<hB>`
would share `user` with it, and since the ambient context judges no
certificate hop, any key chaining to a configured anchor — a device key of
the node's own root, stolen or not — could sign it, or certify a key named
`/user/alice/KEY/…` that then signs it. The ambient context therefore
treats `/user` as no authority of its own: a data, key or certificate
name under `/user/<x>` is signed or certified in it only by a key under the
same `/user/<x>` (ndn-rs: the ambient's shared-`/user` floor,
`SignedTrustContext::ambient`). A key under `/user/alice` that is itself a
configured anchor still signs `/user/alice/…`. Names outside `/user` keep
the flat-anchor semantics: any key chaining to any configured anchor may
certify a key under the data's first component. That is the ambient
context's nature, not a gap of this rule — hold a context for a namespace
whose names need its own authority.

A chain walk terminates only at an anchor of the selected context.

### 6.2 Anchor matching

A name `K` (key name or certificate name) refers to an anchor of the context
when either:

- an anchor is stored under exactly `K`; or
- some anchor has the same key name as `K` (§3.3.2), or an anchor's
  certificate name is `K` plus two components (`K/<issuer>/<version>`).

Among several matches, ndn-rs prefers, in order: valid now, then newest
NotBefore, then the greatest name. When it judges Data (§6.3) no validity
is compared with a clock, so the first criterion does not apply.

### 6.3 Revocation

During a chain walk, every key and certificate name passed is checked against
§3.3.6. A covered name fails validation. This holds whichever form the
KeyLocator uses, and for certificates issued after the revocation.

A node judges a signed packet in one of two ways.

**Live uses** keep the rule above, and also refuse an anchor or certificate
outside its ValidityPeriod by the node's clock: signed Interests and command
Interests, management authorization, adopting a context (§4.4, §5.2: the
signer anchor valid now), enrollment, renewal and NDNCERT, link admission
and peer authentication, certificate issuance and serving, the prefix
announcements a forwarder installs routes from, and signal run headers
([signals.md](signals.md) §7: Data, but never kept, served or answered for,
admitted only to open a live run). These are
exchanges whose freshness is the point; a refusal is retried, never stored,
so a wrong clock there denies service, loudly, and decides nothing about
stored data.

**Data** is durable. A Data packet is judged as data on every path that
keeps, forwards or hands it to an application:

- a forwarder's data path: validation of arriving Data, including Data
  parked while a certificate or a manifest packet is fetched; the content
  store's re-check after a revoking adoption; the purge on adoption (§5.1);
- the data layer ([data-layer.md](data-layer.md) §8): every entry taken,
  re-judged on a revoking adoption and on restore;
- an application's verified fetch through ndn-app (`Consumer::fetch_verified`,
  the verified segmented fetch, `object(..).verify(..)`), which all verify
  through `Unverified::verify`.

One kind of Data stays live: the answer to a request a node just sent and
acts on at once, such as a remote procedure call's reply, for which the
application opts in by name (ndn-rs: `Unverified::verify_live`; the
reflexive-forwarding replies use it). Such a
reply is not kept; refusing it is a retried exchange.

The durable walk is the same as the live one — signatures, the schema and
hierarchy floor (§6.4), certificate authorization, anchors, revocation —
with these differences:

1. **No clock, except to refuse.** No anchor's or certificate's
   ValidityPeriod is compared with a clock, with one exception that can
   only refuse: the certificate of a key whose role the context lists in
   DataRequiresCut (§3.3.13). Any certificate of the key that verifies
   serves (ndn-rs prefers the newest NotBefore). A key's authority over
   Data ends by signed data: a Revocation entry, with or without a cut, or,
   for a listed role, the lapse of its certificate until the cut decides.
2. **The cut.** At depth 0 only — the key that signed the Data itself,
   whether the KeyLocator names the key or one of its certificates — a
   Revocation entry covering that key is excused iff the selected context
   (§6.1) holds a RevocationCut for exactly that key's name, the cut
   accepts the Data (§3.3.12), and, when the cut has a CutKeyDigest, the
   certificate whose public key verifies the Data has a public key of that
   digest. The key's certificate must still verify, chain to an anchor and
   be authorized as for any Data. Every other revoked name met in the walk
   — an issuer's key or certificate — refuses the Data as before: a cut
   never excuses an issuer.
3. **The manifest.** When the cut has a CutManifest and the Data's name is
   one a range lists, the walk needs the manifest packets that hold that
   name's digest. Until it has them, by full name, the verdict is pending,
   as for a missing certificate: the forwarder's validation stage parks the
   Data and fetches them as it fetches certificates, and gives the Data up
   if they do not come in time.

A revoked key with no cut, and one whose cut does not accept the packet,
are refused alike (ndn-rs: `TrustError::Revoked`). A key revoked with no
cut is refused at once, before any signature is checked, as before cuts:
nothing it signed is accepted, so there is nothing to wait for (and a
chain through issuers that are no longer served would otherwise end
unverifiable instead of revoked). A key revoked with a cut that does not
accept the packet is refused only once the packet's signature and its
key's chain check out, so a forgery under that key's name is refused for
what it is (a bad signature, an unreachable or unauthorized chain) and an
out-of-cut refusal proves the packet authentic. A data-layer reader
therefore keeps a refusal against a name (for re-admission) only for a
key revoked with a cut.

**Re-checking what is held.** A node that holds Data judged under an
earlier version judges it again after a revoking adoption (§5.1) with the
same walk, not with the signing key alone: Data whose issuer the new
version revokes is refused too. The content store's re-check resolves
every hop of the chain to the cached certificate, of any validity, whose
public key verifies that hop's signature (the newest NotBefore first),
never merely the newest certificate of the name; a hop with none is not
clear, and the Data is fetched and validated afresh. At depth 0 it applies
the same cut rule as the walk. So a certificate with another public key
under the same name cannot keep a packet it did not verify.

**Why Data ignores the clock.** A judgement "valid when it was signed" can
use only the date the signer writes, and a stolen key writes any date, or
the reader's clock, which refuses honest old Data once its certificate
lapses and lets whoever sets that clock decide. Instead, the certificate,
signed by its issuer, proves the key was authorized, and the cut, signed by
the root, proves where that authority stopped. Renewing a certificate of the
same key therefore continues everything the key signs; ending a key is a
revocation. DataRequiresCut lets a context use the clock for one thing
only, refusing a lapsed key of a role that does not renew until its cut is
signed; it never makes a clock accept anything. The residual — a key of
a role not listed, whose certificate expired and that nobody revoked,
still signs Data that is accepted — is in §10.

**Old contexts.** A context without cuts refuses every Data packet of a
revoked key, as it always did. What changed for every context is only that
an expired certificate or anchor no longer refuses Data, except for a role
the context lists in DataRequiresCut.

ndn-rs: `Validator::validate_durable` and `validate_durable_cached` judge
Data; `validate`, `validate_chain` and `validate_chain_cached` keep the live
rule; `SignedTrustContext::refuses_data(key, name, digest)` is the cut test
alone (false when no Revocation entry covers the key; otherwise true unless
the key's cut accepts the packet).

### 6.4 Authorization

**Signing a packet:** `(data name D, key name K)` is authorized iff both of
these hold:

- *Hierarchy floor*, only when SchemaAuthoritative is absent: the identity of
  `K` is a prefix of `D`. The identity is `K` truncated before the first
  GenericNameComponent `KEY` (§3.3.2); a typed component with value `KEY`
  does not end it.
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

### 6.5 Certificates a walk refuses

A validator's certificate cache holds two kinds of certificate
(`CertCache`): those **vouched for** — inserted by the node itself (its
own certificates, its anchors, what it provisioned or checked), or
admitted by a walk that reached a trust anchor through them — and
**unverified** ones, fetched over the network
(`CertCache::insert_unverified`, the `CertFetcher`), which no walk has
vouched for yet. Neither kind vouches for a packet: every walk still ends
at the anchors of the context judging it. The kinds decide only which copy
of a certificate answers for its key and which copy a failing signature
condemns. A copy is refused as a copy, not as a key: its bytes were
altered on the way (a faulty or hostile link flips a byte) or never
signed, and another copy of the same certificate may be honest. The
rules, which bind every validator (a forwarder's validation stage and a
device's data layer alike):

1. Only a walk that reached an anchor admits a fetched certificate to the
   certificates vouched for: every unverified one it verified up to it.
   A fetched copy never displaces a certificate vouched for under its
   name, and an unverified one never answers a KeyDigest lookup. A walk
   takes a key's certificate vouched for first, an unverified one only
   when none answers. Only a certificate vouched for renews a lapsed key
   whose role needs a cut (§3.3.13, case 1), for a walk that must reach an
   anchor: an unverified one is walked to the anchors first, as a
   certificate, and admitted or dropped by that walk.
2. A signature that does not verify under a key vouched for (or an
   anchor) is forged. The packet's own refuses the packet
   `InvalidSignature`. A certificate's makes that copy a refused copy: it
   is evicted at once, by its bytes, and a copy cached under the same name
   since, which may be the honest one, stays (`CertCache::evict`).
3. A signature that does not verify under an *unverified* certificate
   says nothing yet of which is forged, the certificate's copy or the
   signed bytes. A walk that must reach an anchor goes on with that key:
   reaching an anchor vouches for the key, so the signed bytes are forged
   (rule 2), and a later forged packet under that key is refused at once,
   at no fetch. Not reaching one makes the key's copy a refused copy,
   dropped. An `accept-signed` walk, which reaches for no anchor, makes it
   a refused copy at once.
4. A walk that ends without reaching an anchor — refused, or with a
   certificate it cannot have — drops every unverified certificate it
   took, so a forged copy never outlives the walk that met it, and a
   later walk fetches them again. A cache-only walk waiting for a missing
   certificate keeps them until the fetch of what is missing fails: it
   resumes once its caller fetches it.
5. The packet whose walk met a refused copy is not refused for it. A
   fetching walk (`validate_chain`, `validate_durable`) walks once more,
   which fetches the certificate again, and refuses the packet
   `InvalidSignature` only if that copy is refused too; a cache-only walk
   (`validate_chain_cached`, `validate_durable_cached`) answers `Pending`,
   naming the certificate, which the caller fetches before validating
   again (a forwarder's validation stage parks the Data and fetches it, as
   for a certificate never cached). A fetching walk that dropped
   certificates an earlier walk fetched (rule 4) also walks once more.
6. A certificate packet refused `InvalidSignature` is not remembered for its
   key (the validator's refused-certificate memory, which lets a final
   verdict on a certificate — its issuer revoked, its hop unauthorized —
   answer for the Data its key signed). A verdict on bytes says nothing of
   the key.

*Threat note.* Only a node's unvalidated paths can cache a forged copy (a
transit mark, `mgmt-trust.md`, or a validator whose fetches its forwarder
does not validate): a forwarder refuses a certificate packet that fails
its validation before its fetcher takes it. Before these rules a forged
copy, fetched once, stayed in the cache with the same standing as an
honest one and refused the key's genuine packets for as long as the cache
lived: a copy holding another *public key* refused every genuine packet
at its own hop (depth 0), and a forged *issuer* certificate refused the
honest certificate below it, which was evicted and fetched again at every
validation while the forged issuer stayed; a copy Mallory issued herself
(the honest public key, her key as its issuer) ended every walk at her
untrusted root. Now a forged copy costs at most the walk that meets it
and one more fetch, and a certificate vouched for is never condemned by a
packet's forged signature. Residual: an on-path attacker that answers
every fetch of a certificate with a forged copy denies that key's packets
there for as long as it does so — it could anyway — and costs a fetch per
packet it makes the node walk. Before the renewal clause of rule 1, an
unverified copy of a lapsed guest key with a later ValidityPeriod — which
anyone answering the renewal fetch could serve, signed by no CA — renewed
the key: the guest's Data was accepted after its invitation ended.

### 6.6 Face trust: which Data a forwarder validates

A forwarder classes each face twice, and the two classes answer different
questions.

- **Scope** (`FaceScope`: local or non-local) is NFD's notion and governs
  *reach*: a `/localhost` name never crosses a non-local face, a `/localhop`
  Interest egresses to a non-local face only if it arrived on a local one,
  `/ndn/local` stays on the link, and a refusal Nack (local-refusal.md) is told
  to local downstreams only. A TCP, UDP, WebSocket, WebTransport, WebRTC or
  QUIC face is local in scope iff its remote host is a loopback address or
  `localhost`; a face of an IPC kind is always local. Scope is unchanged by
  this section.
- **Trust** (`FaceTrust`: program or validated) governs *belief*: whether
  the Data a face delivers is validated (§6.1–§6.5) before it satisfies a
  PIT entry, drives self-learning, or enters the content store.

**Rules.**

1. A forwarder MUST validate the Data that arrives on every face that is not
   a **program face**, and MUST NOT admit to its content store, or answer
   from it, Data that was refused or that no validator checked (an opt-in
   for a node whose trust is enforced above the forwarder is the content
   store's `admit_unverified`, which never admits Data a validator ran and
   refused). Whatever scope the face has, and whatever address its peer has.
2. A **program face** is exactly one of: an in-process app face (a channel
   or callback between the forwarder and a program of its own process); a
   shared-memory face (its segment is created owner-only or as an anonymous
   capability; see rule 6 for one opened for a requester); a stream socket
   of the Unix domain whose peer the operating system identified
   (`SO_PEERCRED`, `getpeereid`) **and** whose peer is the daemon's own
   user, root, or a member of a group the operator listed in `[security]
   program_groups` (empty by default), whether the forwarder accepted the
   socket or dialled it (a dialled socket: the peer is this process's user or
   root), including a socketpair descriptor handed to it. Every other face
   is **validated**: TCP, UDP, WebSocket, WebTransport, WebRTC, QUIC and
   every other network transport, **even to a loopback address**; the Unix
   socket of any other user (it is accepted, since the socket file is
   world-connectable, and it keeps the peer credentials so management can
   tell who asked, but its Data is validated); a Unix socket the operating
   system reported no peer for; a Windows named pipe (it reports no peer
   credentials). A face standing in for a network peer in a test or a
   simulation is validated like it.
3. Trust is a property the face's constructor sets from how the face was
   opened (which OS facility produced it, what it attested) and from the
   node's own policy on whom it trusts, and a forwarder MUST NOT derive it
   from the peer's address, a host name, the face's scope or its configured
   URI. A transport that states nothing is validated. A program that wants
   the program standing opens a Unix socket as the daemon's user (or a member
   of a program group) or a shared-memory face, as `ndn-ipc` does; there is
   no setting that makes a network face a program face.
4. An operator MAY make program faces validate too (ndn-fwd
   `[engine] require_local_validation = true`; per face
   `set_require_data_validation`), for a host whose local programs distrust
   each other: a program face so marked is validated, and its Data is
   dropped if no validator is configured. Nothing makes a validated face
   skip validation. The one setting that widens who is a program peer is the
   forwarder's `[security] program_groups` (rule 2): membership of such a
   group skips Data validation for that user's sockets, so a node lists only
   groups whose members it trusts as it trusts the daemon's own user. It is
   separate from `trust_admin_groups`, who may change the node's trust
   (mgmt-trust.md): neither list implies the other.
5. A node whose Data is carried in transit (a served namespace it does not
   hold, mgmt-trust.md) forwards that Data unvalidated and uncached whatever
   face it arrives on; that is the transit mark's rule and is unchanged.
6. A face the forwarder opens *for a requester* (a shared-memory face a
   command asked for) has no more trust than the requester's own face: a
   validated requester gets a validated face whatever transport it asked
   for, and so does a requester that is gone by the time the face is
   opened. A face carries the requester's require-validation flag too. The
   NDNLPv2 LocalFields option, which lets a face choose the next hop of its
   Interests (`NextHopFaceId`), is for program faces only: management refuses
   to turn it on for any other face (`field=flags:local-fields
   reason=not-a-program-face`), and the forwarder ignores `NextHopFaceId`
   from a validated face whatever its flag says.

*Management and `/localhop`.* An operator of the forwarder is identified by
the kernel's peer credentials of a Unix socket (mgmt-trust.md), never by a
face's scope, address or kind: a loopback TCP face carries no credentials, so
a trust-changing verb over it is refused `trust-change-unidentified`, and
every other management command over it is decided by its signature. A
`/localhop` command is always a signed Interest checked against the
localhop anchors, and a trust-changing verb over `/localhop` is refused
outright. `/localhop` names are forwarded by scope (a local face's `/localhop`
Interest may leave on a non-local face; one from a non-local face stays on
local faces), and the Data that returns on a validated face is validated as
any Data is.

*Threat note.* Before this rule ndn-rs classed a face as local, and so
unvalidated and cached-from, by its remote address: a TCP, UDP or
WebTransport face to `127.0.0.1` skipped validation. Any process of any
user on the host can open such a face (a listener is a network socket, not
a file with an owner), so any process could feed the content store: a
forged Data for a name was cached and then answered every later Interest
for it, from every consumer of the forwarder — including another user's —
so a device never saw the genuine packet (data-layer.md §18.1; the case
was met by a member's own loopback face). A second hole was the same in
Unix form: the face socket is world-connectable (`0666`), and every peer
the kernel identified was a program, so another user's process could
connect and feed the content store; it could also ask for a shared-memory
face (a program face by its transport) and turn LocalFields on, which lets a
face pick the next hop of its Interests. Now only a face whose peer the
operating system or the process itself vouches for *and* the node trusts as
its own is believed (rule 2): the peer credentials tell who connected, and
the forwarder uses them to decide whether that user's Data is validated. What
a program face still lets through is what it always did: the program on it
is trusted by the host's access control, so on a host whose programs
distrust each other the operator turns on rule 4.
Residual: a refusal Nack is told to a loopback consumer (it is local in
scope), so a process of the host that opens a loopback face learns the
forwarder's verdict on Data it forged, as a local app does; a network
downstream learns nothing (local-refusal.md §4.3).

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
| `/<ns>/32=trust-context/32=cut/<h>/seg=<i>`, with or without its ImplicitSha256DigestComponent, a packet of a held cut's manifest | that stored manifest packet, byte-identical (§3.3.12) |
| anything else under the prefix | Nack, reason NoRoute (150) |

"Anything else" includes a version that is not held, a manifest packet not
held, `…/32=metadata/v=…`, and the bare prefix. Matching is on the
Interest name only:

- the metadata answer requires the name to equal the metadata name exactly;
- a versioned answer requires exactly one component after the prefix,
  decoded as a VersionNameComponent *in canonical form*. The same version
  number in another width (e.g. `v=1` as `36 02 00 01`) is Nacked, because
  the stored Data's name would differ from the Interest's.

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
- A node MUST also keep and serve the manifest packets of every cut of a
  version it keeps (§3.3.12). It fetches the ones it does not hold by full
  name when it keeps the version — from the forwarders that serve the
  namespace, not from its own publisher — checks each against the digest
  that names it, and stores and serves it, so that the manifest stays
  available when the root device is not. ndn-rs asks for a missing packet
  up to 5 times (waiting 2 s, then doubling) and then waits for the next
  version; it holds at most 4096 packets for one cut. The root device
  stores the packets of the cut file it signed before it hands the version
  over, and serves them from the moment it publishes the version. A reader
  that needs a packet nobody near holds fetches it as it fetches a missing
  certificate (§6.3).
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
5. Authenticate the Data under §4.4 (first adoption), §4.5.2 (the genesis
   of a self-certifying namespace) or §5.2 (update).

A forged pointer can only lead to one of these outcomes:

- a forged or foreign context, which fails the fingerprint or continuity
  check;
- an older genuine context, which anti-rollback refuses, or the link's
  minimum version refuses on first contact;
- a name nobody serves, which fails the fetch.

A copy of a context version whose signature does not verify under the anchor
it names was forged or altered on the way, and says nothing of the version:
another copy may be honest. A forwarder deciding it under an expectation
(`Validator::expect_context`, `expect_context_update`) refuses it as forged
(`InvalidSignature`, answered `bad-signature`), not as a context failing the
expectation (`ExpectedContextRefused`, answered `context`), and keeps its
reason for the adopter. A fetcher asks again for a `bad-signature` answer
(ndn-rs `EngineExchange::fetching`, up to 8 asks); only when no honest copy
arrives does the adoption or refresh end, saying why. Before this rule one
forged copy of a version under fault ended an adoption by name.

**Asking again under loss (normative for ndn-rs).** Each fetch of steps 1
and 4 — in an adoption by name, a scoped adoption and a refresh — is one
*ask* lasting the Interest's lifetime (at least the consumer's 4.5 s),
inside which the Interest is expressed again with a fresh nonce every
1 s while at least 250 ms of it is left; every earlier Interest stays
pending, so a late answer to it counts. An ask nothing answered is asked
again, at most **3** such asks; an ask answered `bad-signature` is asked
again at once; at most **8** asks in all. Then the fetch ends with no
answer (a refresh's **Unreachable**). On the faulty network of
data-layer.md §18.1 an ask goes unanswered under one time in twenty and
three asks under one in ten thousand, while a path that is down costs a
fetch three lifetimes (some 15 s) — before this rule, eight asks of one
Interest each, some 36 s, which outlasted a person waiting at a recovery
screen for the question that nothing answered (data-layer.md §17.1). A
command to a CA (parameters or a signature) is never asked again behind
its caller's back.

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

**Outcomes.** ndn-fwd and ndn-boltffi (mobile) run the same library
refresh (ndn-namespace) and report:

- **Source**: the node holds the root key;
- **Current**, **UpstreamOlder**, **Updated**, **Behind**;
- **Unreachable**: no answer to the metadata Interest;
- **Failed**: everything else.

ndn-boltffi reports them as lowercase strings (`source`, `current`,
`upstream-older`, `updated`, `behind`, `unreachable`, `failed`). It never
reports `source`, because the app holds no root key, nor `behind`, because
it joins no sync group. Like ndn-fwd it evicts cached metadata before asking
(§7.3). It publishes nothing, so it hands the host only the newest version
to persist and does not keep the walked versions.

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
   `H+1 … high`, using `P/seg=<n>` as the source. The walk is not tried
   when `H+1 ≥ high`.
3. Adopt the newest under §5.1 and keep it like a refreshed version: walked
   versions, then the newest.

**Retries.** When the newest version could not be fetched, or the held
version changed meanwhile, ndn-rs retries the announcement:

- after 1 s, doubling up to 60 s between tries;
- while the announcement is newer than the held version;
- keeping the highest sequence number of later announcements from the same
  member.

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

- Trust enters only through an expected fingerprint (§4.4), or the name of
  a self-certifying namespace, which is its genesis root's fingerprint
  (§4.5), and thereafter only through the continuity rule (§5.2).
  Metadata, group Data and sync
  announcements are unauthenticated pointers. Each is confined by name, and
  everything it leads to is checked by the context signature.
- Anti-rollback depends on the node persisting its held version. A node that
  loses its store can be offered an older genuine version on re-adoption,
  unless the link names a minimum version.
- A relay that serves a forged newest version and lets intermediate versions
  time out costs at most one walk (128 positions, 40 s; for a
  self-certifying namespace, 128 positions it cannot use beside the
  versions it reaches, and 40 s, §4.5.6). ndn-rs does not retry such a walk
  from sync.
- A self-certifying name binds version 1 only. A stolen root, while it is
  an anchor, can sign a branch continuous from the genesis, which a fresh
  adopter that reaches only that branch follows (§4.5.6).
- A recovery anchor is root-equivalent. A compromise recovery therefore
  removes every recovery anchor the operator does not vouch for (§5.3).
- AdvertisedRelay endpoints are public: the context is served unencrypted
  to anyone who asks by name, so they are visible beyond the namespace's
  members (§3.3.11). Direct-path addresses are never in the context; they
  go only to devices the LinkPolicy's pairs allow (§3.3.10).
- A cut keeps what its producer lists, so what it lists decides what a
  thief keeps. Whoever holds a stolen key writes as that key until the
  revocation; a producer that listed everything it held would make those
  writes valid for good. The data layer's producer therefore lists only
  entries the root device itself first verified before the moment the
  owner gives as the loss, and stops taking new entries of a key the owner
  marks suspected ([data-layer.md](data-layer.md) §8.1). Residual: a
  thief's writes the root verified before that moment stay accepted, so
  the moment should be the earliest the owner can name. That moment and
  the times of first verification are both read on the root device's own
  clock, never from a date the key wrote; a wrong root clock moves which
  entries are listed, and the producer prints every entry it leaves out.
- A cut with a manifest binds names and bytes (§3.3.12): whoever holds the
  revoked key cannot have other bytes accepted at a name a range lists,
  neither by a reader that holds the honest packet nor by one that holds
  neither, nor by a forwarder that met the thief's copy first. A cut made
  before manifests binds names only: there, a node that holds the honest
  packet keeps both and reports the equivocation (the data layer does,
  [data-layer.md](data-layer.md) invariant 2), and a node holding neither
  may take whichever answers first; that residual remains for such cuts
  only. Withholding manifest packets delays acceptance (the packet stays
  pending) and never makes a node accept other bytes.
- A cut with a CutKeyDigest excuses the key only through a certificate of
  that public key (§6.3). A certificate issued later under the key's name
  for another public key — by a compromised CA, or by a recovery fed a
  forged certificate file — admits nothing through the cut, and a
  recovery re-certifies a cut key only for that digest (§5.3). A cut made
  before the field is bound to the key name only, and a recovery does not
  re-certify its key.
- Re-admission is exact (§3.3.12): one name with one digest. It admits no
  neighbouring sequence number, no packet under another prefix and no other
  bytes at that name, so it cannot be turned into a range.
- Data ignores validity periods (§6.3), except that a role listed in
  DataRequiresCut (§3.3.13) is refused once its certificate lapsed until
  its cut is held. A guest's authority over Data therefore ends at its
  expiry by default, and the owner's root device then revokes it with a
  cut bounded at its NotAfter (§5.3); a key replaced by a new enrollment
  is ended the same way, and both are listed as keys to end until then (a
  replaced key's Data is accepted meanwhile). Residual: a key of a role
  not listed (member, admin, node, relay), never replaced, whose
  certificate expired and that nobody revoked, still signs Data that is
  accepted if it leaked; nothing lists it, and ending it is the owner's
  revocation, with a cut. Live uses (links, signed Interests, renewal) end
  at expiry for every role.
- No clock makes a node accept Data that signed data refuses. A signer's
  lying clock moves only the dates it writes. A reader's lying clock can
  make it refuse live exchanges (an anchor or certificate "not yet valid"
  or "expired"), which is loud and retried; and, for a role listed in
  DataRequiresCut, refuse that role's Data early (fast clock) or accept a
  lapsed key's Data a while longer (slow clock), as a node that has not yet
  adopted a revocation does, until it holds the key's cut.
- A version that accepts less than the one before — a cut removed or
  shrunk, a manifest or key digest changed, a role added to DataRequiresCut
  — is revoking (§5.1): caches judge their Data again, so a version made by
  a tool that drops cuts cannot leave refused Data servable from a cache.
- Held Data is judged again with the whole walk (§6.3): Data under an
  issuer a later version revokes is refused on re-check, in the content
  store and in the data layer, as a fresh fetch would refuse it. The
  content store's re-check follows, hop by hop, the certificate whose
  public key verifies the cached packet.
- Fetching by full name (a manifest packet, an in-cut entry) makes the
  forwarder match Data by implicit digest, which costs a hash of every
  Data while such an Interest is pending. ndn-rs bounds it per forwarder:
  the deadline is kept per PIT (per engine), not per process, and the
  InterestLifetime it uses, for PIT expiry too, is clamped to one hour, so
  one Interest cannot make a forwarder hash every Data for longer than
  that.
- Every path that keeps or hands Data to an application judges it as Data
  (§6.3), the ndn-app verified fetch included, so an application refuses
  and accepts exactly what the forwarder and the data layer do.
- A version's cuts are its anchor's word: an adopter does not check that a
  later version kept a cut's ranges (§3.3.12). A root can widen a cut as it
  can drop a revocation; a root in a thief's hands is a namespace in a
  thief's hands, which recovery ([recovery-kit.md](recovery-kit.md)) answers,
  checking again every cut it carries.
- A node that predates cuts refuses every packet of a revoked key, the
  in-cut ones too (§3.3.12): it fails safe. A node that knows cuts but
  predates CutKeyDigest, CutManifest and DataRequiresCut keeps the
  residuals those fields close, for its own judgements, until updated.
- A forwarder believes a face's Data unchecked only when the operating
  system or the process itself vouches for the program on it *and* the node
  trusts that program as its own (an in-process face, shared memory, a Unix
  socket of the daemon's user, root or a `program_groups` member); a TCP, UDP
  or WebTransport face to a loopback address, or the Unix socket of any
  other user, is validated and cached-from like any network face, because
  any process of any user on the host can open one (§6.6). A node that ran
  a forwarder before that rule held, for its forwarder, the old exposure:
  a forged Data from a loopback face in
  its content store, answered to every later Interest for the name.

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
LinkPolicy default, direct off  fd0412 1a 3b6e6f64653b656e726f6c6c6d656e743b6e6f2d646972656374
                                                                                     ";node;enrollment;no-direct"
LinkPolicy default pairs but    fd0412 25 3b6e6f64653b656e726f6c6c6d656e743b6469726563743b6d656d6265723a6d656d626572
  member:member only                                                                 ";node;enrollment;direct;member:member"
LinkPolicy no direct pair       fd0412 18 3b6e6f64653b656e726f6c6c6d656e743b6469726563743b
                                                                                     ";node;enrollment;direct;"
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
the decoder reject the context ("unknown critical TLV-TYPE 0x0499").

AdvertisedRelay `/home/bob/node/relay`, RelayKey = the fingerprint above,
endpoint `relay.example.net:6367`, preference 0 (97 octets):

```
fd04205d07180804686f6d650803626f6208046e6f6465080572656c6179fd04
222056475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107
708cfd04241672656c61792e6578616d706c652e6e65743a36333637fd042601
00

fd0420 5d                          AdvertisedRelay, length 93
  0718 0804686f6d65…080572656c6179 Name /home/bob/node/relay
  fd0422 20 56475aa7…b107708c      RelayKey
  fd0424 16 72656c61…36333637      RelayEndpoint "relay.example.net:6367"
  fd0426 01 00                     RelayPreference 0
```

AdvertisedRelay `/home/bob/node/r2`, no RelayKey, endpoints
`192.0.2.7:6367` then `[2001:db8::7]:6367`, preference 300 (73 octets):

```
fd04204507150804686f6d650803626f6208046e6f646508027232fd04240e31
39322e302e322e373a36333637fd0424125b323030313a6462383a3a375d3a36
333637fd042602012c
```

In a TrustContext the first entry precedes the second (preference 0 before
300). These encodings are asserted by
`trust_context::tests::spec_vectors_t5_direct_pairs_and_relays`; the
decoding rules of §3.3.11 (malformed entries dropped, unknown even child
skipped, a device outside the namespace without RelayKey dropped) by
`a_malformed_relay_entry_is_skipped`, both in
`ndn-security/src/trust_context/mod.rs`.

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
(`fd0208`), and an extra Revocation, written *before* the existing one
because Revocation entries are in canonical name order (§3.2; `guest`
sorts before `member`, being shorter):

```
fd041821071f0804686f6d650803626f62080567756573740802747608034b455908026b32
```

The full v2 Data is reproducible with the seed above (sign over the
NDN signed portion, same SignatureInfo as T3).

### T8 RevocationCut (233 octets)

The cut of key `/home/bob/member/phone/KEY/k1`, with:

- CutRange `/home/bob/member/phone/32=log`, run `1..1`;
- CutRange `/home/bob/member/phone/32=log/notes`, runs `1..3` and `7..7`
  (made by adding seq 7, then the run `1..3`: the order does not change the
  bytes);
- CutExact `/home/bob/member/phone/32=log/notes/seq=9` followed by the
  ImplicitSha256DigestComponent `000102…1f` (the octets `0x00` through
  `0x1f`).

The shorter prefix sorts first (§3.2), and the runs of the second range
stay two, `4..6` lying between them:

```
fd0428e507230804686f6d650803626f6208066d656d626572080570686f6e65
08034b455908026b31fd042a2b071f0804686f6d650803626f6208066d656d62
6572080570686f6e6520036c6f67fd042c063a01013a0101fd042a3c07260804
686f6d650803626f6208066d656d626572080570686f6e6520036c6f6708056e
6f746573fd042c063a01013a0103fd042c063a01073a0107fd042e4d074b0804
686f6d650803626f6208066d656d626572080570686f6e6520036c6f6708056e
6f7465733a01090120000102030405060708090a0b0c0d0e0f10111213141516
1718191a1b1c1d1e1f
```

The cut accepts `/home/bob/member/phone/32=log/notes/seq=2` (any bytes) and
the packet at `…/notes/seq=9` whose implicit digest is `000102…1f`; it does
not accept `…/notes/seq=4`, `…/32=log/seq=2`, or another packet at
`…/notes/seq=9`. Added to the T2 context, these 233 octets are written
right after its Revocation entry; nothing else moves, and only the outer
length changes.

### T9 RevocationCut with key digest and manifest (379 octets)

The T8 cut with a CutKeyDigest of the octets `0x40` through `0x5f` (a
stand-in: in a real cut it is the SHA-256 of the key's public key,
§3.3.12) and a CutManifest naming the T10 root packet. The two fields come
right after the key Name, before the ranges (§3.2); the rest is T8's:

```
fd0428fd017507230804686f6d650803626f6208066d656d626572080570686f
6e6508034b455908026b31fd043020404142434445464748494a4b4c4d4e4f50
5152535455565758595a5b5c5d5e5ffd04326807660804686f6d650803626f62
200d74727573742d636f6e7465787420036375740820b016d8ea2979c8cb799a
1819b433608c13e16299ae0a35e53c87f659c2490a60320100012094f6b9944d
ec675aec156eded41ba373d407e9f35ea6ac4168e8618a9357710afd042a2b07
1f0804686f6d650803626f6208066d656d626572080570686f6e6520036c6f67
fd042c063a01013a0101fd042a3c07260804686f6d650803626f6208066d656d
626572080570686f6e6520036c6f6708056e6f746573fd042c063a01013a0103
fd042c063a01073a0107fd042e4d074b0804686f6d650803626f6208066d656d
626572080570686f6e6520036c6f6708056e6f7465733a010901200001020304
05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

Under this cut, `…/notes/seq=2` is accepted only with the digest T10 lists
for it, no longer with any bytes. The T8 bytes, which have neither field,
still decode, as a cut made before them whose ranges bind names only.

### T10 Cut manifest packet (417 octets)

`ndn_security::cut_manifest::build(/home/bob, /home/bob/member/phone/KEY/k1,
entries)` with the entries of T8's ranges: `…/32=log/notes` seqs 1, 2, 3
and 7, and `…/32=log` seq 1, each with the stand-in digest of the 32
octets `s, s+1, …` for seq `s`. They fit one packet, a leaf, so it is the
root: `/home/bob/32=trust-context/32=cut/<h>/seg=0`, `<h>` the SHA-256 of
the key's Name TLV, FreshnessPeriod 3600000, DigestSha256:

```
06fd019d07440804686f6d650803626f62200d74727573742d636f6e74657874
20036375740820b016d8ea2979c8cb799a1819b433608c13e16299ae0a35e53c
87f659c2490a60320100140619040036ee8015fd0124fd0436fd011efd04384a
071f0804686f6d650803626f6208066d656d626572080570686f6e6520036c6f
67fd043a253a010101200102030405060708090a0b0c0d0e0f10111213141516
1718191a1b1c1d1e1f20fd0438cc07260804686f6d650803626f6208066d656d
626572080570686f6e6520036c6f6708056e6f746573fd043a253a0101012001
02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20fd
043a253a0102012002030405060708090a0b0c0d0e0f10111213141516171819
1a1b1c1d1e1f2021fd043a253a01030120030405060708090a0b0c0d0e0f1011
12131415161718191a1b1c1d1e1f202122fd043a253a010701200708090a0b0c
0d0e0f101112131415161718191a1b1c1d1e1f2021222324252616031b010017
208b88bc33ba60b31453c9457f2a9561713450540ef8c118be605d8b755f8009
05
```

Its full name, the value of T9's CutManifest:

```
07660804686f6d650803626f62200d74727573742d636f6e7465787420036375
740820b016d8ea2979c8cb799a1819b433608c13e16299ae0a35e53c87f659c2
490a60320100012094f6b9944dec675aec156eded41ba373d407e9f35ea6ac41
68e8618a9357710a
```

**DataRequiresCut.** The entry for `guest` is `fd0434056775657374`; a
context listing `guest` and `relay` writes them in that order, after its
RevocationCut entries (§3.2). T2 lists no role and is unchanged.

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
- `0x0434` (5 octets, `guest`);
- `0x0412` (16 octets).

The octet counts above were measured before DataRequiresCut. Since then
`build_namespace` also writes the `guest` entry (9 octets with its
header), which adds 9 octets to the Content and to the Data and changes
no other child; the totals have not been measured again.

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

T8 is a test that stays in the tree:
`ndn_security::trust_context::tests::spec_vector_t8_revocation_cut`
(`ndn-rs/crates/security/ndn-security/src/trust_context/mod.rs`) builds the
cut with `RevocationCut::{new, add_seq, add_run, readmit}` and compares
`encode` with the hex above; `a_cut_accepts_its_prefix_plus_one_sequence_number_in_a_run`
asserts what the same cut accepts and refuses (those named in T8, and a
padded seq encoding, the prefix itself and longer names refused);
`spec_vector_t2_is_unchanged` checks that T2 encodes as before and that T2
with this cut differs only by the inserted cut and the outer length.

T9 and T10 are tests in the same file:
`spec_vector_t9_cut_with_key_digest_and_manifest` and
`spec_vector_t10_manifest_packet` build them with the helpers `t9_cut()`
and `t10_manifest()` (`RevocationCut::{set_key_digest, set_manifest}`,
`cut_manifest::build`) and compare the hex above;
`t8_bytes_decode_as_an_old_form_cut` checks that T8 still decodes without
the two fields; `data_requires_cut_round_trips_in_canonical_order` checks
the DataRequiresCut encoding and its order.

## 12. Decisions

These points were ambiguous in the code or differed between copies. Each is
now decided, and the code and the sections above agree with it. No question
is open.

- **Q1 Anchor and revocation order.** A producer writes AnchorSet in
  canonical order of the certificate names and Revocation entries in
  canonical name order (§3.2); decoders accept any order. The anchor map
  and the recovery procedure's revocation list have no stable order, so
  without this the same version re-encoded to different bytes. Order is
  not semantic, so no decoder changes.
- **Q2 Duplicates.** A second Name, AnchorSet, SchemaAuthoritative,
  EnrollmentHint, SourceBundleHash or LinkPolicy rejects the context, and so
  does a second SchemaFormat or SchemaBody in a blob (§3.3.3, §3.4). No
  producer emits one twice, and "the later one wins" let a later malformed
  LinkPolicy reset a valid one to the broader default.
- **Q3 Equal-version re-adoption.** An equal version from a link is a no-op
  when it encodes identically to the held context, and refused as a fork
  otherwise (§5.1). Re-scanning the same link stays harmless, while a
  second, different context under the same number cannot silently replace
  the held one.
- **Q4 Anchor validity.** A received context is refused when its signing
  anchor is outside its ValidityPeriod now; a node's own stored copy is
  not checked, and §5.2 rule 4 matches the held anchor by key only (§4.3).
  This is the rule a chain walk already applies to anchors. It cannot brick
  a namespace: an expired root certificate is replaced by signing the next
  version with a re-issued certificate of the same key. ndn-rs anchors
  never expire before 2554.
- **Q5 Unknown SchemaFormat.** A blob in an unknown format is skipped and
  re-emitted verbatim; a context with no understood blob is refused
  (§3.3.3). Fewer blobs only authorize less, and format `1` is
  ndn-rs-specific, so refusing would lock out implementations that only read
  LVS.
- **Q6 Unknown sub-TLVs inside TrustSchemaBlob** follow the critical-bit
  rule: odd or `<= 31` rejects, even is skipped (§3.3.3). It is the same
  NDN evolvability rule as for the TrustContext children, and a SchemaFormat
  must be exactly one octet.
- **Q7 LinkPolicy extra fields.** Fields after the fourth are reserved and
  ignored, and an unknown word in the fourth keeps direct paths on
  (§3.3.10). Rejecting them would make an older node fall back to
  the default policy, which admits more than the stated one.
- **Q8 Sync walk lower bound.** The sync walk starts at `H+1`, as a refresh
  does (§5.4, §9.5). An SVS update's low sequence number reflects only what
  this member last heard: with a lower bound of `max(low, H+1)`, a dropped
  earlier announcement made the walk skip the version that links `H` to
  the newest.
- **Q9 ndn-fwd and ndn-boltffi.** Both now run the library refresh
  (`ndn_namespace::refresh::refresh_contexts`). That refresh reports every
  outcome and evicts cached metadata before asking for any node, publisher
  or not, so the earlier mobile differences are gone. The rest is by
  design (§8.2): the app holds no root key, joins no sync group, publishes
  nothing, and hands the host only the newest version.
- **Q10 Pattern grammar.** `<**v>` matches zero or more components and binds
  nothing (§3.3.3); the `NamePattern` documentation now says so. The
  generated namespace schema depends on zero: `/<ns>/<role>/<dev>/<!KEY>/<**data>`
  must admit a one-component data name.
- **Q11 Version decoding.** A NonNegativeInteger of any length other than 1,
  2, 4 or 8 octets does not decode (§1), so `as_version` and its siblings
  return nothing for it instead of dropping octets. The publisher answers a
  versioned Interest only when its version component is canonical (§7.1),
  so a Data is never returned under a name that differs from the
  Interest's.
- **Q12 KEY detection.** Only the GenericNameComponent `KEY` (TLV-TYPE 8)
  marks a key or certificate name, in `is_cert_name` and in the floor's
  identity (§3.3.2, §6.4). ndn-cxx's `Certificate::isValidName` compares it
  this way, and a typed `32=KEY` component is not a certificate marker.
- **Q13 LinkPolicy direct pairs.** The role matrix is a fifth LinkPolicy
  field rather than a new TLV, written only when it is not the default, so
  every existing encoding is unchanged and decodes to the default pairs.
  An older node ignores the field and reads direct paths as on for every
  pair; §3.3.10 says why that is accepted and how to keep an excluded pair
  off older nodes (`no-direct`). A malformed fifth field means the default
  pairs, as an unknown fourth word means on (Q7).
- **Q14 AdvertisedRelay numbering and validity.** Every even number of
  `0x0410–0x041F` was taken, so the relay TLV opens `0x0420–0x042F`; its
  children use the same block, even (skippable). An entry that cannot be
  used — no endpoint, or a device outside the namespace with no RelayKey —
  is dropped by the decoder rather than kept for the device to discover;
  the producer (`ndn-fwd`) refuses to write one.
- **Q15 Revocation cuts and time.** A revocation's end of a key's authority
  over Data is a cut in the context (§3.3.12), not a date: Data is judged
  without validity periods, and a revoked key's Data is kept exactly where
  its cut accepts it (§6.3). The cut is a new even (skippable) field beside
  the Revocation entry, not a change to it, so a context without cuts, and
  every node that predates them, keeps the old meaning: everything the key
  signed refused (fails safe). Its ranges are runs of sequence numbers under
  per-prefix names because a log's sequence numbers in one prefix have gaps
  (a limit would admit a thief's packet in a gap) and per-prefix runs stop a
  thief reusing an accepted number under another prefix; they carry no
  digest because a digest per packet does not fit one Data. Re-admission
  adds exact names with their digest and never a range, and ranges never
  change after the revoking version, so nothing a thief signed after the cut
  can be admitted by a later version unless the root names its exact bytes.
  A malformed cut rejects the context, as a duplicate field does (Q2): a
  partial reading would accept something another decoder refuses. The live
  uses keep the clock (§6.3) because their freshness is the point and their
  failure is retried, never stored.
- **Q16 Cut manifest.** A range of a new cut is bound to bytes by a
  manifest beside the context, not inside it: a digest per packet does not
  fit one Data, and a context that grew past one packet would break every
  fetch and walk of §5.4 and §8. The manifest is self-certifying
  (DigestSha256) because the root-signed context names its root packet by
  full name: no second signature is needed, any holder may serve it, and a
  reader fetches it as it fetches a certificate (pending until held). Cuts
  made before it keep name-only ranges rather than being rejected, since
  rejecting a version that already holds a revocation would undo the
  revocation on every node; producers refuse to make a new one without a
  manifest.
- **Q17 Cut key digest.** A cut names a key, and a key name can be
  certified again for another public key (by a compromised CA, or by a
  recovery fed the wrong certificate file). The cut therefore carries the
  digest of the public key whose packets it lists, and the walk excuses
  depth 0 only through a certificate of that key. It is the digest of the
  public key, not of a certificate, so a renewed or re-certified
  certificate of the same key still serves.
- **Q18 DataRequiresCut.** Ending a key's authority over Data by expiry
  needs a clock, which §6.3 keeps out of Data because a clock can refuse
  honest old Data and lets whoever sets it decide. The field allows the
  clock in one direction only — refusing — and only for roles the owner
  lists, by default `guest`, which does not renew: an honest guest's Data
  is refused after its expiry only until the root's cut, which keeps what
  it wrote while invited. Renewable roles are not listed, since a late
  renewal or a fast reader clock would otherwise refuse honest Data. It is
  a context field rather than a CA setting because every validator must
  apply it alike, and it is even (skippable) because a node that cannot
  read it then behaves as before rather than rejecting the version.
- **Q19 Shrinking is revoking.** An adopter treats any version that
  accepts less than the one it replaces as revoking (§5.1), although the
  producer rules forbid shrinking a cut: adopters do not enforce producer
  rules, and a cache that kept serving what the held version refuses would
  fail open where validators fail safe.
- **Q20 Every Data path is durable.** The ndn-app verified fetch judges
  Data as the forwarder and the data layer do (§6.3); only replies an
  application opts into as live keep the clock. Otherwise an application
  would refuse honest old Data and in-cut Data that the rest of the node
  accepts.
- **Q21 A link never replaces a held namespace.** Adoption from a link once
  replaced a held namespace whenever the offered version was higher. The
  expected fingerprint only proves who signed the offered context, so a
  stranger's link naming a namespace the node holds, carrying the
  stranger's own root and a high version, replaced the owner's anchors: the
  stranger then signed anything under it. A held namespace now moves on
  only by the update rule (§5.1, §5.2), the one the owner already uses for
  every version and a recovery; a link to a version that does not follow
  is refused with why and what to do (refresh the namespace).
- **Q22 Self-certifying names name the genesis root.** `/user/<h>` must
  keep its meaning when the root changes: a compromise recovery signs
  `N+1` with a new root, and a root moved to a hardware token may be
  P-256. Hashing the current root would rename the person at every
  recovery, so `<h>` names the key that signed version 1 and later
  versions follow by continuity alone (§4.5). The genesis rule checks the
  anchor that signed version 1, not the anchors it lists, because listing
  someone else's public key beside one's own root costs nothing. The
  component type `0xA1` is in NDN's application range for name component
  types (128–252), clear of every assigned type, and is the type ndf-rs
  uses for the same names. The catch-up bound of §5.4 is lifted for these
  namespaces: its remedy, adopting again from a current anchor link, leads
  back to the same walk from the genesis.

## Appendix A. Code references (non-normative)

Paths are relative to the workspace root. ndn-fwd code is being moved into
libraries by concurrent work; locations under `ndn-fwd/binaries/ndn-fwd/src`
may move.

**TLV registry and codec** — `ndn-rs/crates/security/ndn-security/src/trust_context/`

- `tlv.rs:29` TrustContext 0x0410; `:32` AnchorSet 0x0411; `:38` TrustSchemaBlob 0x0413; `:42` CaEndpoint 0x0414; `:48` SchemaFormat 0x0415 (unknown code not understood, `:44-47`); `:51` SchemaBody 0x0417; `:54` EnrollmentHint 0x0416; `:57` Revocation 0x0418; `:64` SourceBundleHash 0x041A; `:74` SchemaAuthoritative 0x041C; `:87` KeyRole 0x041E; `:98` LinkPolicy 0x0412; `:105` AdvertisedRelay 0x0420; `:110` RelayKey 0x0422; `:114` RelayEndpoint 0x0424; `:118` RelayPreference 0x0426; format codes 1/2 after them; `:3-28` provisional blocks and parity.
- `mod.rs:61` keyword `trust-context`; `:65-92` SchemaFormat (unknown code → `Unknown`, `:85-91`); `:118-137` native-text parsing (trim, skip empty lines); `:143-161` OR of understood blobs, none understood → error, multiple LVS → error.
- `mod.rs:204-207` hint flags; `:213-219` default hint; `:221-236` hint encode; `:238-268` hint decode (legacy rule `:260-265`).
- `mod.rs:281-291` KeyRole codes 1/2.
- `mod.rs:304-341` LinkPolicy and its default; `:373` allows_direct_path; `:384` default_direct_pairs; `:397` canonical_direct_pairs; `:450` encode (fourth field only when off, unless the pairs are not the default: then fourth and fifth); `:482` decode (unknown fourth word: on; missing or malformed fifth: default pairs; fields after the fifth ignored); `:530` parse_pairs.
- `mod.rs:547` AdvertisedRelay; `:563` canonical order; `:574` encode; `:593` decode (malformed entry → `None`); `:840` with_relays (sorted); `:903` relays; encode_content writes the entries after LinkPolicy (`:1134`); decode_content drops malformed entries (`:1358`) and entries outside the namespace without a key (`:1370`).
- `mod.rs:635-637` admits_enrollment_links; `:646-652` add_anchor validity check; `:666-682` anchor_for; `:689-691` is_revoked; `:714-725` authorizes (floor + schema); `:741-753` authorizes_hop; `:771-783` authorizes_certification.
- `mod.rs:808-861` encode_content (anchors sorted by name `:809-815`, revocations sorted `:816-817`); `:865-872` rdr_name; `:886-910` sign_into_data (KeyLocator = signer key name); `:916-931` async variant.
- `mod.rs:942-1112` decode_content: `:947-950` outer type; `:959-966` single-valued fields at most once; `:973-979` namespace; `:980-996` AnchorSet (skip non-Data `:985-987`); `:998-1037` blob (SchemaFormat one octet, no repeats `:1006-1023`; unknown critical inner → reject `:1025-1028`; missing fields `:1033-1035`); `:1038-1041` authoritative; `:1042-1047` CaEndpoint; `:1048-1051` hint; `:1055-1058` SourceBundleHash length 32; `:1059-1064` Revocation; `:1067-1071` KeyRole; `:1074-1077` LinkPolicy; `:1079-1081` unknown critical → reject; `:1086-1090` required fields; `:1101` floor unless authoritative.
- `mod.rs:1116-1128` derived native blob; `:1135-1138` anchor_fingerprint; `:1142-1156` context_namespace_of; `:1193-1236` open_signed (name equality `:1203`, signer must be own anchor `:1212-1215`, public-key sig types `:1219-1224`); `:1238-1254` open_received (signer valid now `:1250`); `:1302-1304` is_critical; `:1307-1319` read_tlv (trailing bytes ignored); `:1321-1332` key_identity (generic `KEY` only).
- Revocation cuts (by symbol; the line numbers above predate them): `tlv.rs` REVOCATION_CUT 0x0428, CUT_RANGE 0x042A, CUT_RUN 0x042C, CUT_EXACT 0x042E; `RevocationCut::{new, add_seq, add_run, readmit, accepts, encode, decode}`, `CutRange`; `SignedTrustContext::{with_revocation_cut, revocation_cuts, revocation_cut, refuses_data}`; encode_content writes the cuts after the Revocation entries; decode_content rejects a malformed cut and a second cut for one key; tests `spec_vector_t8_revocation_cut`, `spec_vector_t2_is_unchanged`.
- Cut key digest, manifest and DataRequiresCut (by symbol): `tlv.rs` CUT_KEY_DIGEST 0x0430, CUT_MANIFEST 0x0432, DATA_REQUIRES_CUT 0x0434, MANIFEST_NODE 0x0436 and the MANIFEST_* children 0x0438–0x043E; `RevocationCut::{set_key_digest, key_digest, set_manifest, manifest, range_seq, accepts_exactly, covers}` (`accepts` admits a range only when the cut has no manifest: fails closed); `ndn_security::public_key_digest` (SHA-256 of `Certificate::public_key` as stored); `SignedTrustContext::{with_data_requires_cut, without_data_requires_cut, data_requires_cut, role_of, requires_cut_for, without_revocation_cuts}`.
- `ndn-rs/crates/security/ndn-security/src/cut_manifest.rs`: `manifest_prefix`, `build` (→ `BuiltManifest { root, packets }`, root first), `build_under` (the same tree, its packets named `<prefix>/seg=<i>`: the data layer's removal cuts name theirs under the members record, `<R>/32=cut`, data-layer.md §8), `parse`, `children`, `CutManifests::{new, insert, contains, get, lookup, missing}`, `ManifestLookup::{Listed, NotListed, Missing}`, `MAX_PACKET_SIZE` 8000, `FRESHNESS` 1 h; held in `CertCache::cut_manifests` / `Validator::cut_manifests`; fetched by `CertFetcher::fetch_missing` (a certificate or a full-name manifest packet, `ndn_security::is_full_name`).
- `ndn-rs/crates/security/ndn-security/src/validator/`: `Validator::{validate_durable, validate_durable_cached}` (the walk without validity periods but DataRequiresCut's refusal; the depth-0 revocation excused in the key's cut when the key digest and the manifest agree, §6.3), `Validator::can_resolve_durable` (manifest full names too); `ndn_security::chain_clear` (the content store's durable re-check, shared with the validator); `TrustError::Revoked { name, why }` with `TrustError::{REVOKED, REVOKED_OUTSIDE_CUT, REVOKED_LAPSED}`; `Unverified::{verify, verify_live}` (`unverified.rs`).
- `ndn-rs/crates/security/ndn-security/src/validator/chain.rs` (§6.5): `Validator::walk_to_anchor` (one more walk after a refused copy, or after dropping certificates an earlier walk fetched, when fetching; `Pending` naming a refused copy when cache-only), `walk_once` with `reached_anchor` (admits the unverified certificates verified up to the anchor), `bad_signature` / `forged` (a signature failing under a key vouched for condemns the signed bytes; under an unverified one the walk goes on with it as the `Suspect`), `unvouched` (a walk not reaching an anchor drops what it took; a cache-only walk waiting on a fetch that has not failed, `CertFetcher::failed_recently`, keeps it), `durable_cached` (vouched for first), and the refused-certificate memory skipping `InvalidSignature` (`validate_chain_inner`); `CertCache::{insert, insert_unverified, evict}` and the crate's `resolve`, `get_any`, `all_by_kind`, `admit`, `drop_unverified` (`cert_cache.rs`: two kinds, a copy matched by its signed bytes and signature value); `CertFetcher::do_fetch` holds what it fetches unverified.
- §4.5.6 note 4 and §4.5.7, anchors under every profile: `Validator::anchor_required` (`validator/mod.rs`: a person's names, under `accept_signed` too), `Validator::scoped_view` (always requires anchors); ndn-engine `resolve_security_profile` (`builder.rs`: the accept-signed validator's chain depth is the default's, 5).
- §3.3.13 case 1 and §6.5 rule 1, a renewal vouched for: `signer_rule` / `valid_now` (`validator/durable.rs`: other certificates of the key count when vouched for, unverified ones only for a walk that reaches for no anchor; `chain_clear` counts vouched ones only), `Validator::durable_signer` and `vouch_renewal` (`validator/chain.rs`: an unverified renewal held or fetched is walked to the anchors as a certificate, `walk_to_anchor`'s `cert_walk`, then admitted or dropped).
- `ndn-rs/crates/security/ndn-security/src/keyring.rs`: the revocation epoch moves, and listeners are told, when a version revokes a new name, when a held cut is not `covers`-ed by the new one (the key's name), or when a DataRequiresCut role is added (`/<ns>/<role>`).
- `ndn-rs/crates/forwarding/ndn-engine/src/stages/pit.rs`: InterestLifetime clamped to one hour for PIT expiry and the per-PIT full-name deadline.

**Supporting library code**

- `ndn-rs/crates/security/ndn-security/src/keyring.rs:101-124` adopt (> replaces; = only when identical, `:108-111`); `:131-143` adopt_update (>); `:153-171` adopt_update_from (CAS); `:248-261` context_for (longest prefix).
- `ndn-rs/crates/security/ndn-security/src/cert_cache.rs:31-37` public key from Content (Ed25519 SPKI unwrapped).
- `ndn-rs/crates/security/ndn-security/src/spki.rs:31-33` Ed25519 SPKI prefix.
- `ndn-rs/crates/security/ndn-security/src/cert_name.rs:39-41` is_key_component (GenericNameComponent `KEY`); `:46-49` is_cert_name; `:54-60` key_name_of; `:77-83` cert_name.
- `ndn-rs/crates/security/ndn-security/src/manager.rs:514-594` certificate encoding (8-octet MetaInfo integers, ValidityPeriod).
- `ndn-rs/crates/security/ndn-security/src/trust_schema.rs:41-93` pattern grammar; `:123-125` MultiCapture matches zero or more, binds nothing; `:147-165` rule parse/check.
- `ndn-rs/crates/security/ndn-security/src/validator/expected.rs:281` forwarder expectation opens with open_received; `:288-291` a copy whose signature does not verify is refused `InvalidSignature` (§8.1).
- `ndn-rs/crates/core/ndn-packet/src/signature.rs:36-40` signature type codes.
- `ndn-rs/crates/core/ndn-packet/src/encode/data.rs:411-416` `build` = DigestSha256; `:535-588` sign_sync (MetaInfo only if set).
- `ndn-rs/crates/core/ndn-packet/src/lib.rs:105-108` SEGMENT 0x32, KEYWORD 0x20, VERSION 0x36.
- `ndn-rs/crates/core/ndn-foundation-types/src/name.rs:99-111` keyword/version components; `:123-158` as_segment/as_version/… (NNI widths only); `:161-169` NNI encode (shortest); `:175-184` NNI decode (1, 2, 4 or 8 octets, else none).
- `ndn-rs/crates/app/ndn-app/src/rdr.rs:83-107` MetaData encode (Name only when other fields absent).
- `ndn-rs/crates/app/ndn-app/src/consumer.rs:196` DEFAULT_TIMEOUT 4.5 s; `ndn-rs/crates/security/ndn-identity/src/engine_exchange.rs:38-40` wait = max(lifetime, default).
- `ndn-rs/crates/core/ndn-packet/src/encode/interest.rs:194,236` InterestLifetime defaults to 4000 ms; `:199-210,240-241` ApplicationParameters + ParametersSha256Digest component.

**ndn-cert**

- `ndn-rs/crates/security/ndn-cert/src/onboarding.rs:41` `metadata`; `:52` CONTEXT_EXPECTATION_TTL 30 s; `:57-69` rdr_prefix, rdr_metadata_name; `:195-211` authenticate (open_received, namespace, expected fingerprint); `:300-308` minimum version; `:361-415` adopt_anchor_link; `:454-470` adopt_arc_into (Rollback vs Fork); `:524-530` fetch_context; `:595` context_pointer confinement.
- `ndn-rs/crates/security/ndn-cert/src/context_update.rs:83-93` key_name_of; `:178-200` revocations_to_add; `:211-237` bump_context_revoking; `:241-255` ensure_anchor; `:257-261` next_version; `:345-398` schema_grants (unknown-format blob `:386-395`); `:522` MAX_CATCH_UP_VERSIONS 128; `:531` MAX_CATCH_UP_TIME 40 s; `:742-771` open_context_update (open_received `:746`, public-key equality `:764`); `:798-826` fetch_update; `:841-858` ByName source; `:884-953` follow_versions; `:979-1106` refresh_context (pointer compare `:1020-1028`, walk condition `:1057-1058`, CAS `:1082-1091`).
- `ndn-rs/crates/security/ndn-cert/src/namespace.rs:55-57` root key name; `:60-62` CA key name; `:137-156` build_namespace (version 1, hint, link policy, blobs, authoritative, CA endpoint, root-device KeyRoles).
- `ndn-rs/crates/security/ndn-cert/src/recovery.rs:740-756` add recovery anchor; `:762-790` remove; `:800-806` reissue; `:921-988` recovery_version.
- `ndn-rs/crates/security/ndn-cert/src/context_store.rs:5-8` on-disk layout (newest + every version).

**Self-certifying namespaces** (by symbol; §4.5)

- `ndn-rs/crates/core/ndn-packet/src/lib.rs`: `tlv_type::SELF_CERTIFYING` = 0xA1.
- `ndn-rs/crates/security/ndn-security/src/self_certifying.rs`: `key_digest`, `self_certifying_name`, `self_certifying_digest` (`SelfCertifyingNameError::{Misplaced, Under}`), `in_personal_namespace`, `Genesis::{open_received, open_stored}` (`GenesisError::{NotSelfCertifying, NotVersionOne, NotEd25519, Mismatch}`).
- `ndn-rs/crates/security/ndn-security/src/keyring.rs`: `Keyring::adopt` (`AdoptRefusal::{GenesisRequired, Name}`), `Keyring::adopt_genesis` (`AdoptRefusal::NotFromGenesis`), `Keyring::of_claim`, `Keyring::context_for` (the `/user/<h>` floor).
- `ndn-rs/crates/security/ndn-cert/src/context_update.rs`: `adopt_by_name`, `adopt_by_name_checking` (an inline version 1 compared with the fetched one), `reach_newest`, `follow_versions`.
- `ndn-rs/crates/security/ndn-cert/src/onboarding.rs`: `AnchorLink::{by_name, from_envelope, is_self_certifying, fetches}`, `adopt_anchor_link`, `adopt_anchor_envelope` (offline), `adopt_checked`, `LinkAdoption::{earlier, offline_genesis, OFFLINE_GENESIS_NOTE}`, `AdoptError::{GenesisRequired, GenesisFork, GenesisUnreachable, NotReached}`.
- `ndn-rs/crates/security/ndn-namespace/src/keep.rs`: `adopt_link` (the publisher bypass and cached-metadata eviction for every link that fetches); `ndn-rs/crates/security/ndn-identity/src/adopt.rs` `adopt_anchor_link_via_engine`.
- `ndn-rs/crates/security/ndn-cert/src/context_store.rs`: `adopt_stored_context`, `adopt_stored_genesis` (`ContextStoreError::GenesisMissing`), `persist_adoption`.
- `ndn-rs/crates/security/ndn-cert/src/namespace.rs`: `GenesisKey::{generate, from_seed, check}`, `ExistingGenesisKey::{probe, offline}`, `GenesisCheck::{NewKey, NoneReachable, Unchecked}`, `sign_genesis` (`GENESIS_ROOT_CERT_VERSION`, `GENESIS_ROOT_VALID_FROM_NS`, `GENESIS_ROOT_VALID_UNTIL_NS`), `init_self_certifying`, `init_self_certifying_in_pib`, `init_self_certifying_in_pib_with`, `NamespaceInit::{genesis, genesis_check}`, `NamespaceInitError::{SelfCertifying, GenesisOnToken, GenesisExists, GenesisReachable, GenesisKeyNotEd25519}`; `invite.rs` `ensure_invite_context`.
- `ndn-rs/crates/security/ndn-namespace/src/root/init.rs`: `InitNamespace::{Named, SelfCertifying}` (refusals before anything is asked); `ndn-fwd/binaries/ndn-fwd/src/onboard.rs` `run_init` (`--self-certifying`, `genesis`, `anchor_uri_name`).

**ndn-identity**

- `ndn-rs/crates/security/ndn-identity/src/adopt.rs:51-59` refresh_context_via_engine.
- `ndn-rs/crates/security/ndn-identity/src/context_sync.rs:144-148` group_prefix; `:155-162` group_data (seg=version, DigestSha256); `:252-372` check_and_adopt (fetch `:258`, walk from `H+1` `:301-304`); `:377-413` GroupVersions; `:421-434` Retry 1 s/60 s; `:440` UNPROVEN_TRIES 6; `:444` UNPROVEN_PENDING 8; `:477-592` run (highest sequence kept `:506`); `:609-` obtain.

**ndn-namespace**

- `ndn-rs/crates/security/ndn-namespace/src/publish/contexts.rs:199-217` answer (canonical version component only, `:210-214`).
- `ndn-rs/crates/security/ndn-namespace/src/refresh.rs:86` refresh_contexts (used by ndn-fwd and ndn-boltffi); `:133` cached metadata evicted before every refresh.

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

- `ndn-mobile/crates/ndn-boltffi/src/identity_core.rs:213-260` refresh_contexts (the library refresh; every outcome mapped `:241-249`; only the newest returned to the host `:232-239`).
