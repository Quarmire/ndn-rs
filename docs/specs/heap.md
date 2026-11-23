# Heap: a signed, hash-chained log per writer and space

- **Status:** Normative. The data layer of `ndn-heap`: spaces, entries and
  their chains, membership as an operation fold, seals and grants, durability
  by sequence reservation, and the names and TLVs that carry them. It replaces
  [data-layer.md](data-layer.md) (`ndn-data`) for the `ndn-heap` crate. The two
  formats are incompatible (TLV block 0x0600–0x063F, store prefix
  `/localhost/ndn-heap/`); no `ndn-data` space or store is migrated.
- **Scope:** the data model every file, database and exchange of a group of
  people shares: a **space** with its members, the **entries** its writers sign,
  the **chain** that binds each writer's entries, the **seal** that keeps a
  space's content to its readers, and the **durability** that keeps a restart
  from making an honest device contradict itself. The Rust contract and its
  reference implementation are the `ndn-heap` crate
  (`crates/app/ndn-heap`: `Node`, `Heap`); conformance cases are
  `ndn-data-conformance` in ndn-sim (§13).
- **Out of scope:** views and lenses above the layer; trust-context encoding
  ([trust-context.md](trust-context.md)); link admission
  ([ndn-link.md](ndn-link.md)); State Vector Sync itself (ndn-svs v2, as
  `ndn-sync` implements it); invitations (`ndn-invite`); the clock of live
  signals (`ndn-surface`).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174)
when, and only when, they appear in all capitals, as shown here.

## 1. Model and invariants

### 1.1 Principle: end to end

The ends are the signing key and the reader. Caching, combining requests,
relaying and holding are performance or protection only. Whether an entry is
genuine, newest, readable or still valid MUST be decided by the reader, from
the entry, its name, the trust context and the chain. A reader's correctness
MUST NOT depend on any forwarder, cache, repository, relay or sync notice.

### 1.2 The model

- A **namespace** `O` is the name of a trust context
  ([trust-context.md](trust-context.md)): one or more components (`/alice`,
  `/home/bob`), none of them a KeywordNameComponent (TLV-TYPE 0x20), a digest
  component or a SequenceNumNameComponent. A **person** is a namespace. Members
  of a space are persons, **matched exactly**: there are no writer prefixes and
  no hierarchical admission (`/home` does not admit `/home/bob`). A person's
  **self-certifying namespace** `/user/<h>` (`<h>` a component of type `0xA1`,
  trust-context.md §4.5) is a namespace like any other here.
- A **device** `D` is the identity of one key; the key is named
  `<D>/KEY/<key-id>` (NDN key naming). `D` has one or more components, none a
  KeywordNameComponent or a digest component. The **person of a device** (of a
  key) is the namespace of the trust context that validates its key (§9). A
  device is never a person.
- A **space** `S` is the one unit of sharing, membership, sealing, sync and
  follow. Its name is `<O>/32=data/<c1>[/<c2>…]` (§2); its **owner** is `O`,
  the components before `32=data`. An **owner device** is a device whose name
  lies under `O` and whose key the trust context of `O` itself validates (§3.8,
  rule 4). A space has **writers** and **readers** (persons); the owner is an
  implicit writer and, unless the space is public, an implicit reader.
  A space is **public** when its creation says `ANYONE` (§5), and **sealed**
  otherwise.
- An **entry** is one Data packet named `<D>/32=log/<S>/seq=<n>` and signed by
  a key of `D` (§3). The entries of one device in one space are its **log**,
  numbered by `seq` from 1. Each entry carries the signed-region digest of the
  one before it (`PREV`, §3.6), so a log is a **hash chain**; the entry named by
  the highest seq a node holds of a device is that device's **tip** there. A
  device's **own head** is the highest seq of its own log.
- An entry is **plain** (`Put`: one path and its value), **sealed** (a `Put`
  whose path and value are ciphertext), or **structural**: `Members` (the
  space's creation, additions and removals) or `Epoch` (a new sealing epoch).
  Structural entries are signed by owner devices only and are published only
  once durable (§4).
- A **register** keeps, per path, the newest value (§10). Nothing else is
  merged: no rule is named, no host decides.
- A **node** holds any number of spaces on one store, over one transport, as
  one device (the host object `Node`, §10). Its in-memory state of one space is
  `Heap`.

### 1.3 Invariants

Every implementation MUST hold all of these.

1. **Checkable anywhere.** Any entry verifies from its bytes, its name, the
   trust context and the chain: never from a server, never because of a clock
   (§1.4), never because a notice said so.
2. **One name, one content.** One entry name `<D>/32=log/<S>/seq=<n>` has one
   signed content. Two packets under one name whose **signed regions** differ
   are proof of misbehaviour attributable to that key (equivocation); a node
   MUST keep both and MUST tell its host (`Alert::Equivocation`), for entries of
   every kind including `Members` and `Epoch`. Two packets whose signed regions
   are equal are one object (§1.5).
3. **Monotonic.** A device's seq never goes back and never repeats, a power
   loss, a crash and a restart included: a device MUST NOT sign at a seq above
   its durable reservation and MUST resume above everything it may have
   published (§4). A node never takes a lower head than it holds, and an own
   head after a restart is read from the names of every stored own entry (§4.3).
4. **Completeness is relative.** "I have everything" always means "everything
   on the chain up to this tip".
5. **Stale, never wrong.** Failures degrade to older verified data, and the
   reader is told it is older; an unreachable network is not an error of a
   read.
6. **Authority is in the data.** Writing follows the members entries and the
   trust context; reading follows the seal; a removal ends writing from a tip
   on (§3.8, §5).
7. **Retention is forever.** No node drops an entry for its age. There is no
   compaction.
8. **Nothing is lost by not understanding it.** An entry carrying fields a
   node does not know is stored and served exactly as received (a packet is
   never re-encoded), and a writer MUST keep every field it does not know when
   it writes about it (§3.4).
9. **Forward-only, said plainly.** Removal, revocation and deletion stop future
   reads and writes; an implementation MUST NOT claim to recall copies already
   made or keys already granted.
10. **The chain.** An entry of a removed person counts only if the tip the
    removal names reaches it by following `PREV`; entries off that chain, or
    above its tip, never count, in any arrival order. A device's chain is also
    what lets a reader skip a hole the device declared (§3.6) and no other.

### 1.4 No clock decides

No validity decision accepts anything because of a wall clock, nor compares a
certificate's validity period with one, with one exception that can only
refuse: a key of a role the trust context lists in DataRequiresCut (every role,
by default) whose certificate lapsed is refused until its revocation cut is held
(§9). Such a refusal (`Lapsed`) is not recorded as a verdict on the entry: the
entry is judged again whenever it is fetched again. Time stamps in this layer
(`at` of a `verified/` record, §4.3) are for display and for bounding a
revocation cut a node makes; no reader reads them to decide.

### 1.5 Digests are signed-region digests

The **signed-region digest** of a Data packet is SHA-256 over its signed region:
the bytes the signature covers, from the Name through the SignatureInfo,
excluding the SignatureValue. It is the only digest this layer uses for
ordering, tie-breaks, parent and chain links (`PREV`), `ENTRY_REF` digests, cut
tips, equivocation comparison, markers, and the choice between duplicate
membership facts (§5). The **implicit digest** (SHA-256 over the whole wire
encoding) addresses exact bytes and is used only for DigestSha256 packets:
pieces and manifest nodes (§8).

A packet that does not decode as Data has no signed region and never verifies;
its digest is its implicit digest, which no verified packet shares by accident.

*Threat note (malleable signatures).* An ECDSA signature is malleable: `(r, s)`
and `(r, n − s)` both verify, and a signer that randomises signs the same
content to another value each time. A relay's high-S copy, or a re-signed copy,
has the same signed region and therefore the same digest: it is the same object
and changes nothing (no equivocation, no new chain link, no different tip).
Comparing whole packets would let any relay frame an honest key.

### 1.6 Where each property of the design is held

| # | Property | Where |
|---|---|---|
| 1 | A removed writer cannot sign a new entry at a gap seq below a limit: the chain of the removal's tip decides, not a seq limit | §1.3 (10), §3.8 |
| 2 | A removed writer cannot sign other bytes at a kept seq: the tip's digest binds every entry below it | §3.8 |
| 3 | Concurrent membership edits converge; removal wins | §5 |
| 4 | A late removal or revocation withdraws what was applied | §3.8, §9, §10 |
| 5 | A writer never seals in an epoch whose audience still holds a removed reader | §5, §6 |
| 6 | An epoch key is delivered only to whom the records admit, and checked against the owner-signed key check | §6 |
| 7 | An unsealed entry in a sealed space is refused | §3.8, §6 |
| 8 | Equivocation compares signed regions | §1.5, §3.7 |
| 9 | The highest head survives restart; a replayed lower one changes nothing | §4 |
| 10 | No decision accepts anything because of a clock | §1.4 |
| 11 | A sync notice is bounded and decides nothing | §7 |
| 12 | A miss decides nothing: ask again while owed | §7 |
| 13 | A space replicates exactly its members' logs | §3.8, §7 |
| 14 | A big payload verifies piece by piece and a sealed one shows only its size | §8 |
| 15 | Errors say why and what to do; `put` never waits on the network | §4.7, §10 |

### 1.7 Non-goals

- **No partial replication inside a space.** Whole spaces replicate; large
  payloads fetch lazily by their pieces (§8). Narrowing access is a second
  space.
- **No per-path access control, no writer prefixes, no groups.** Members are
  persons matched exactly (§1.2).
- **No merge engine and no host rule.** The register keeps the newest value per
  path (§10); a value a host merges is a value a host writes.
- **No time ordering.** No last-writer-wins by date, no expiry, no
  retention classes, no streams.
- **No compaction.** Every entry is kept forever (invariant 7). The cost is the
  size of the history; it is accepted (§4.10).
- **No custody, no answers.** No node holds data for another against its will;
  no request/response exchange is part of the layer.
- **No confidentiality of the log's shape.** A relay sees names, kinds,
  writers, seqs, chain links, the digests an entry supersedes, sizes and epoch
  ids; sealing hides paths and values only (§6.7).
- **No recall.** Invariant 9.
- **No migration.** An `ndn-data` space is not read.

## 2. Names

`D` is a device name, `O` a namespace, `S` a space, `E` an entry's name, `G`
and `H` device names. `32=` is a KeywordNameComponent (TLV-TYPE 0x20, `32`),
`seq=` a SequenceNumNameComponent (0x3A, 58), `seg=` a SegmentNameComponent
(0x32, 50), all from the NDN naming conventions; a sequence number or segment
number is a NonNegativeInteger below 2⁶⁴. Every other component here is a
GenericNameComponent (0x08).

### 2.1 Name classes

| Class | Form |
|---|---|
| namespace `O` | one or more components; none a keyword, a digest (ImplicitSha256Digest, ParametersSha256Digest) or `seq=` |
| device `D` | one or more components; none a keyword or a digest |
| key name | `<D>/KEY/<key-id>`: the last two components are the GenericNameComponent `KEY` and the key id; what precedes them (one or more components) is the device |
| space `S` | `<O>/32=data/<c1>[/<c2>…]`: `O` a namespace, then the one keyword `data`, then 1 to 4 GenericNameComponents |
| path | a name **relative to the space**: 1 to 8 GenericNameComponents, at most 200 octets in all (§3.3) |

The **owner rule.** A key `<D>/KEY/<id>` is a key of an owner device of space
`S = <O>/32=data/…` only if the components of `O` are a prefix of those of `D`,
and the trust context that validates the key is `O`'s own (§9). The first half
depends on the two names alone, so every node judges it alike in any order; the
second is the trust layer's. A device under a longer held namespace is that
namespace's device: with `/home` and `/home/bob` held, `/home/bob/member/laptop`
is a device of `/home/bob`, not of `/home`, although `/home` is a prefix of its
name.

### 2.2 Packets

Every packet a device signs MUST be named under that device, so any
forwarder's hierarchical schema admits it and Interests for it route to the
device.

| Packet | Name | Content | Signature |
|---|---|---|---|
| entry | `<D>/32=log/<S>/seq=<n>`, `n ≥ 1` | one `ENTRY` TLV (§3) | a key of device `D` |
| chunk of the payload of entry `E` | `<E>/32=piece/seg=<i>` | the chunk's octets (§8) | DigestSha256 |
| manifest node `k` of entry `E` | `<E>/32=piece/32=manifest/seg=<k>` | `DIGEST`* (§8) | DigestSha256 |
| seal key of device `D` | `<D>/32=seal/<public key>`, the last component 32 octets | one `SEAL_KEY` TLV (§6.2) | a key of device `D` |
| grant | `<G>/32=grant/<GrantAsk TLV>`, the last component one GenericNameComponent holding the `GRANT_ASK` TLV | one `GRANT` TLV (§6.5) | a key of the granter `G` |
| held copy | `<H>/32=held/<Name TLV of the original>`, the last component one GenericNameComponent | the complete wire of the original packet | DigestSha256 |
| sync group | `<O>/32=sync/<c1>[/<c2>…]` | State Vector Sync Interests and Data (§7) | as `ndn-sync` |

A space is not a packet: it exists as the entries under its name. Entries are
named after the **writer's** device, not the space, because a writer of another
namespace can only sign under its own
(`/bob/laptop/32=log/alice/32=data/docs/seq=3`). A **held copy** is how a node
serves the packet of another device that it holds and has verified (§7): the
Content is the original packet exactly as held, the outer DigestSha256 only
makes it a valid Data, and a receiver MUST verify the **inner** packet as if it
had been fetched from its own name, whose Name MUST equal the Name TLV the held
name carries.

Names under `/localhost/ndn-heap/` are the keys of a node's store (§4.3). They
MUST NOT be served, announced, or accepted as the name of any packet received.

### 2.3 Parse rules

Every name parses one way, and a node MUST refuse a name that does not parse.

- **Space.** The owner is the components before the first `32=data`; the rest,
  the 1 to 4 components after it. The owner MUST be a namespace; the rest MUST
  all be GenericNameComponents (no keyword, no digest, no other type). A name
  with no marker, an empty owner, an empty or longer rest, or any other
  keyword or digest component is no space.
- **Entry.** `D` is the components before the first `32=log` (so `D` has no
  keyword); the last component is `seq=<n>`; what lies between is a space name.
  `n` is 1 or more: a name with `seq=0` names no entry.
- **Piece.** The last component is `seg=<n>`; if the one before it is
  `32=manifest` the piece is manifest node `n`, otherwise chunk `n`; the next
  component is `32=piece`; what precedes is an entry name.
- **Seal key.** `D` is the components before the first `32=seal` (a device
  name); exactly one component follows, a GenericNameComponent of 32 octets:
  the X25519 public key, equal to the key the packet's Content carries.
- **Grant.** `G` is the components before the first `32=grant` (a device
  name); exactly one GenericNameComponent follows whose value is one `GRANT_ASK`
  TLV: two `Name` TLVs in this order, the asker's **seal key name**
  `<D>/32=seal/<public key>` (which MUST parse as a seal key name) and the
  space (which MUST parse as a space name), then one `EPOCH_ID`. The ask names
  the seal key by its packet name, not by its octets, so a granter learns which
  device to fetch it from and whose person to test (§6.5). The encoding MUST be
  canonical: re-encoding the decoded ask MUST give the same octets, so one ask
  has one name.
- **Held copy.** `H` is the components before the first `32=held` (a device
  name); exactly one GenericNameComponent follows whose value is the Name TLV
  of the original.
- **Sync group.** `<O>/32=sync` followed by the 1 to 4 components of a space's
  rest (§2.5).

### 2.4 The keyword router

A node answers an Interest by the keyword right after the device part of its
name. By one look: the **first component that is a keyword or a digest** of the
name decides, since a device name holds neither. If it is not a keyword the
name is none of these. If it is a keyword:

| keyword | served kind |
|---|---|
| `log` | an entry, or a piece under one |
| `held` | a held copy |
| `seal` | a seal key packet |
| `grant` | a grant answer |
| any other | not served |

The parser of the kind still judges the name; the router only chooses which
parser to run. A node MUST NOT serve any other name, and MUST NOT serve a
name under `/localhost`.

### 2.5 The sync group of a space

Each space has one sync group, `<O>/32=sync/<c1>[/<c2>…]`: the owner's group
name (`<O>/32=sync`, `ndn_security::sync_group(O)`) followed by the components
of the space name after `32=data`. The name is a pure function of the space
name; nothing else names a group. A node joins the group of every space it
holds as one SVS producer named by its device name; the producer's counter is
its own seq in that space, so a state-vector entry `(D, n)` of the group names
exactly the entry `<D>/32=log/<S>/seq=<n>` (§7). A forwarder that routes
`<O>/32=sync` by prefix routes every group of `O`'s spaces.

## 3. The entry

### 3.1 The packet

An entry is a Data packet named `<D>/32=log/<S>/seq=<n>` (§2.2) whose Content
is exactly one `ENTRY` TLV (0x0601) and whose signature is made by a key of
device `D`: the KeyLocator is a key name `<D'>/KEY/<id>` and `D'` MUST equal
`D`. A node MUST refuse an entry whose key names another device.

The encoding of the `ENTRY` TLV MUST NOT exceed **8,000 octets** (`ENTRY_MAX`:
the 8,800-octet maximum NDN packet size less 800 octets that the name, the
signature information with its key locator and the signature value take).
A writer MUST NOT emit a packet over 8,800 octets and refuses a write that
would (`TooLarge`). A decoder refuses a longer `ENTRY` (`TooLarge`). What does
not fit in an entry travels in pieces under it (§8).

### 3.2 Layout

```
ENTRY      = 0x0601 { KIND [PREV [PREV_SEQ]] ENTRY_REF{0..8} body }
body       = PATH (INLINE | BLOB)         ; Put, plain
           | SEALED                       ; Put, sealed
           | MEMBERS                      ; Members
           | EPOCH_BODY                   ; Epoch
```

A writer emits the fields in the order shown; a reader accepts them in any
order (the packet is never re-encoded, so order does not affect identity).
`KIND` is NonNegativeInteger 0 (**Put**), 1 (**Members**) or 2 (**Epoch**) and
is derived from the body, never chosen: a plain or sealed Put is 0, `MEMBERS`
is 1, `EPOCH_BODY` is 2. A decoder refuses an entry whose `KIND` disagrees with
its body (`KindMismatch`), a `KIND` above 2 (`UnknownKind`), an entry with no
`KIND` and an entry with no body. Exactly one body is present: two bodies, or
both `INLINE` and `BLOB`, refuse the entry. `ENTRY_REF` appears only in a Put
(it lists the heads that the write supersedes, §3.5): in a Members or Epoch
entry it refuses the entry. One path per Put entry. A **removal** is a Put with
an `INLINE` of zero octets.

### 3.3 The TLVs

Every TLV below is odd, hence critical (§3.4). A TLV that is not defined in
the record that holds it is unknown there, whatever number it has.
`NNI` is a NonNegativeInteger: 1, 2, 4 or 8 octets, big-endian; a writer uses
the shortest, a reader accepts any of the four lengths. A `Name` is the NDN
`Name` TLV (0x07) holding the components. A *device name* is a name that
passes the device class of §2.1, a *person* one that passes the namespace
class.

| TLV | # | In | Content | Count and limits |
|---|---|---|---|---|
| `ENTRY` | 0x0601 | Content | the fields of §3.2 | exactly one; ≤ 8,000 octets |
| `KIND` | 0x0603 | `ENTRY` | NNI 0, 1 or 2 | exactly one |
| `PREV` | 0x0605 | `ENTRY` | 32 octets: the signed-region digest of the previous entry (§3.6) | at most one; absent exactly at seq 1 |
| `PREV_SEQ` | 0x0607 | `ENTRY` | NNI: the previous entry's seq (§3.6) | at most one; only with `PREV`; present iff the previous entry's seq is not `seq − 1` |
| `ENTRY_REF` | 0x0609 | `ENTRY`, `REMOVE` | `Name` (a device name), `SEQ`, `DIGEST` | in `ENTRY`: 0 to 8, Put only; in `REMOVE`: 0 to 64 |
| `SEQ` | 0x060B | `ENTRY_REF`, `EPOCH_ID` | NNI: a seq | exactly one per container |
| `DIGEST` | 0x060D | `ENTRY_REF`; manifest node | 32 octets: a signed-region digest (in an `ENTRY_REF`); an implicit digest (in a manifest node, §8) | exactly one in an `ENTRY_REF` |
| `PATH` | 0x060F | `ENTRY` (plain Put); sealed plaintext (§6.4) | the components of a path, each TLV directly | exactly one; 1 to 8 GenericNameComponents, ≤ 200 octets in all (each component counted with its TLV header) |
| `INLINE` | 0x0611 | `ENTRY` (plain Put); sealed plaintext | the value's octets; empty is a removal | at most one; ≤ 6,144 octets (`INLINE_MAX`) |
| `BLOB` | 0x0613 | `ENTRY` (plain Put); sealed plaintext | `SIZE`, `ROOT` | at most one; instead of `INLINE` |
| `SIZE` | 0x0615 | `BLOB` | NNI: the octets of the payload as carried | exactly one; ≤ 67,108,864 (`PAYLOAD_MAX`, 64 MiB) |
| `ROOT` | 0x0617 | `BLOB` | 32 octets: the implicit digest of the root manifest node packet (§8) | exactly one |
| `SEALED` | 0x0619 | `ENTRY` | `EPOCH_ID`, `CIPHERTEXT`; replaces `PATH` and the payload | at most one |
| `EPOCH_ID` | 0x061B | `SEALED`, `ADD`, `GRANT_ASK` | `Name` (the creator, a device name), `SEQ` | exactly one `Name` and one `SEQ` |
| `CIPHERTEXT` | 0x061D | `SEALED`, `GRANT` | `nonce (12) ‖ tag (16) ‖ ciphertext` | exactly one; in `SEALED` 28 to 6,400 octets (`SEALED_MAX`) |
| `EPHEMERAL_KEY` | 0x061F | `GRANT` | 32 octets: the granter's X25519 public key | exactly one |
| `MEMBERS` | 0x0621 | `ENTRY` | `CREATE`?, (`ADD` \| `REMOVE`)* | at most one `CREATE`; `ADD` and `REMOVE` together ≤ 32 operations |
| `CREATE` | 0x0623 | `MEMBERS` | `ANYONE` | exactly one `ANYONE` |
| `ANYONE` | 0x0625 | `CREATE` | NNI 0 or 1: whether readers are everybody | exactly one |
| `ADD` | 0x0627 | `MEMBERS` | `ID`, `Name` (a person), `ROLE`, `EPOCH_ID`? | `ID`, person and `ROLE` exactly one each |
| `ID` | 0x0629 | `ADD`, `REMOVE` | 16 octets: names an addition | exactly one |
| `ROLE` | 0x062B | `ADD` | NNI 0 (writer) or 1 (reader) | exactly one |
| `REMOVE` | 0x062D | `MEMBERS` | `ID`, `ENTRY_REF`* (the tips) | `ID` exactly one; ≤ 64 tips |
| `EPOCH_BODY` | 0x062F | `ENTRY` | `KEY_CHECK`, `AUDIENCE` | at most one |
| `KEY_CHECK` | 0x0631 | `EPOCH_BODY` | 32 octets (§6.2) | exactly one |
| `AUDIENCE` | 0x0633 | `EPOCH_BODY` | `Name`* (persons) | exactly one; 0 to 256 persons |
| `GRANT_ASK` | 0x0635 | the last name component of a grant | `Name` (seal key), `Name` (space), `EPOCH_ID` | see §2.3 |
| `SEAL_KEY` | 0x0637 | Content of a seal key packet | 32 octets: an X25519 public key | exactly one |
| `GRANT` | 0x0639 | Content of a grant packet | `EPHEMERAL_KEY`, `CIPHERTEXT` | exactly one of each |

`SEAL_KEY` and `GRANT` are packet Contents, not parts of an entry; `GRANT_ASK`
lives in a name. 0x063B–0x063F and every even number of the block are free
(§15).

### 3.4 Decoding

One set of limits holds on both sides: a decoder validates what it parses
exactly as an encoder validates what it is given, so nothing that encodes
fails to decode and nothing that decodes fails to encode.

- **Critical and skippable.** Inside any record of §3.3, an unknown **odd**
  TLV-TYPE refuses the record (`UnknownCritical`: the writer is newer than
  this reader; upgrade). An unknown **even** TLV-TYPE is skipped. The block
  reserves the even numbers for additive fields. Because a served packet is
  never re-encoded, a skipped field stays in the stored and served packet.
  A node MUST keep every packet exactly as received (invariant 8).
- **Duplicates.** A field that may appear once and appears again refuses the
  record (`Duplicate`). `ENTRY_REF`, `ADD`, `REMOVE` and the `Name`s of an
  `AUDIENCE` repeat, within their limits. Operations keep their order.
- **Required fields.** An absent required field refuses the record
  (`Missing`). A `PREV_SEQ` without a `PREV` refuses the entry.
- **Sizes.** A `Name` that does not decode into well-formed components, a
  digest or key of other than 32 octets, an `ID` of other than 16, an NNI of
  other than 1, 2, 4 or 8 octets, an `ANYONE` other than 0 or 1, a `ROLE`
  other than 0 or 1, a person that is no namespace, a device that is no device
  name, a path that is not 1 to 8 GenericNameComponents within 200 octets: each
  refuses the record (`Malformed`). A list over its limit refuses it
  (`TooMany`), a value over its limit refuses it (`TooLarge`).
- **A refused entry is never applied or served as data**, and a decoder never
  panics on any octets.

### 3.5 Bodies

**Plain Put.** `PATH` and `INLINE` or `BLOB`. A payload of 6,144 octets or
fewer MUST be written `INLINE`; a larger one is cut into pieces (§8) and the
entry holds `BLOB { SIZE, ROOT }`. A `SIZE` over `PAYLOAD_MAX` refuses the
entry. `ENTRY_REF*` (the entry's `after`) lists the current heads of this
entry's path that the write supersedes, at most 8: a writer that sees more
lists the 8 with the highest digests, and the others remain heads (§10). Each
reference is `(device, seq, signed-region digest)` of an entry in the same
space.

**Sealed Put.** `SEALED { EPOCH_ID, CIPHERTEXT }`. The path and the value are
inside the ciphertext (§6.4); `ENTRY_REF*` stay plain. No path appears in the
packet.

**Members.** `MEMBERS { CREATE?, (ADD | REMOVE)* }`, at most 32 operations
(§5). An `ADD` is `{ ID, Name(person), ROLE, EPOCH_ID? }`; the `EPOCH_ID` of an
addition of a reader names the epoch whose history the reader reads (§6.6).
A `REMOVE` is `{ ID, ENTRY_REF* }`.

**Epoch.** `EPOCH_BODY { KEY_CHECK, AUDIENCE { Name* } }`: the check of the
epoch key (§6.2) and up to 256 persons the epoch is for. Its `EpochId` is
`(the device that signed the entry, the entry's seq)`.

### 3.6 The chain

Each entry links to the one before it in the same (device, space) log:

- `PREV` is the **signed-region digest** (§1.5) of the previous entry. An
  entry at seq 1 carries no `PREV`; every entry at seq 2 or more MUST carry
  one, and a receiver refuses one that does not.
- `PREV_SEQ` is present **iff the previous entry's seq is not `seq − 1`**: it
  is the signed gap statement. A writer MUST NOT write a `PREV_SEQ` equal to
  `seq − 1`, and a receiver refuses a `PREV_SEQ` that is not below `seq − 1`.
- **The zero form.** `PREV` of 32 zero octets with `PREV_SEQ` 0 means "this
  device lost everything before". `PREV` is 32 zero octets **exactly when**
  `PREV_SEQ` is 0; a decoder refuses one without the other.

A **gap statement** (an entry at `seq` with `PREV_SEQ = p < seq − 1`) says: "I
(this key) have signed nothing in `(p, seq)` that I know of, and I will sign
nothing there again". It is attributable and it is **not a retraction**: an
entry inside `(p, seq)` that exists and verifies is a valid **orphan**, kept
and applied (invariant 9). A device makes it after an unclean start (§4.5) and
after losing its log. Because a gap is declared, a reader never asks for the
seqs inside it (§7); an undeclared hole costs misses until a later entry
declares it.

A node keeps for each verified entry a **marker** `verified/<entry name>` (§4.3)
holding the entry's signed-region digest, `PREV`, and the absolute seq of the
previous entry (0 with a zero `PREV`). A **chain walk** from a tip follows
these markers only — no entry body is read or decoded — and ends at **genesis**
(an entry with no `PREV`, or the zero form), at a **missing** marker (the seq
to fetch), at a marker whose digest differs from the one the chain names
(**divergence**: other bytes at a name), or at a marker that cannot be read or
links to a seq not below its own (corrupt).

### 3.7 Equivocation

Two packets under one entry name with different signed regions are
equivocation. Two entries of one (device, space) that name the same previous
entry are equivocation too, unless the one with the higher seq states a gap
whose `PREV_SEQ` is below the other's seq (the other is then an orphan, §3.6).
On either, a node MUST keep **both** packets (the second at
`equivocal/<entry name>`, §4.3), MUST raise `Alert::Equivocation { device, seq }`
to its host, and MUST mark the signing key **suspected**: no new entry of a
suspected key is taken (`Suspected`) until its revocation is held or the host
unsuspects it; entries held from before stay. A node MUST NOT prefer either
packet silently. The alert is raised for entries of every kind; for `Members`
and `Epoch` entries it is the host's cue to use an owner device (`UseOwnerDevice`).

An honest device never produces equivocation by a crash or a restart (§4); a
copy of its key, a restored backup or two live processes with one key do.

### 3.8 Admission of a received entry

A node takes an entry received by any route (a fetch, a held copy, a recovery)
only through these steps in order. Each refusal says why and what to do
(`Refusal` and `NextStep`, §10).

1. **Name and key.** The name parses as an entry name of a space this node
   holds, `n ≥ 1`, and the key's device is `D` (§3.1).
2. **Validation.** The packet validates under the durable rule (§9) — one
   verification — yielding the signer's key digest and its person `P`. A packet
   whose signer's certificate chain or person is not yet held is **pending**
   (it waits, it is not refused). `Lapsed` is not recorded as refused (§1.4).
3. **Decoding.** The content decodes (§3.4). An entry that verifies but does
   not decode is **refused for what it carries**: its marker is written with
   the refusal so a chain walk through it completes, and it is never applied.
4. **Carrier.** A `Members` or `Epoch` entry MUST be signed by an owner device
   (§2.1) or it is refused (`NotMember`).
5. **Membership.** The signer's person `P` is the owner, or is a writer of the
   space (§5), or `P` was removed and the entry is **inside the cut**: there is
   a tip `t` among the removal tips for `P` with `t.device == D`, the entry's
   `seq ≤ t.seq`, and the entry is a **chain ancestor of `t`** (below).
   Otherwise it is refused: `OutsideCut` when the fold holds a removed writer
   addition of `P`, `NotMember` when it does not.
6. **Seal.** In a sealed space the body MUST be sealed and open under the key
   of its epoch; if the key is not held it is held closed (`Sealed`, the node
   asks for the key, §6.5) and its path stays unknown. An unsealed Put in a
   sealed space is refused (`Unsealed`); a sealed Put in a public space is
   refused (`Sealed`).
7. **Chain.** If the entry at `PREV_SEQ` (or `seq − 1`) is held, its signed
   digest MUST equal `PREV`; if not, there are two packets at that name: both
   are kept, `Alert::Equivocation`, the key `Suspected` (§3.7). Entries inside
   a declared gap are valid orphans and are kept and applied.
8. **Own name.** An entry under this node's own device name at a seq above its
   `R_durable` is refused (`AboveReservation`), kept as evidence and reported
   (§4.8).
9. **Apply.** The register and the fold take it, and everything is written as
   one batch (§4.4).

**Chain ancestry (cuts as tips).** For a tip `t = (D, s, d)` the set *kept* by
`t` is the set of seqs reachable from `t` by following `PREV` / `PREV_SEQ`
through the markers (§3.6), with `d` the signed digest of the entry at `s`. An
entry at seq `q` is kept iff `q` is in the set **and** its signed digest equals
the digest the chain names at `q`, so other bytes at a kept seq are refused.
An orphan inside a gap that the chain jumps over is not kept; nor is anything
above the tip, nor anything before a zero form. A missing link makes the answer
**pending** and the seqs are fetched (§7): the effect of a removal on entries
not yet chain-connected waits, it never accepts.

**Re-check and withdrawal.** Every `Members` or `Epoch` entry, adopted
context or revocation re-judges the held entries of the persons affected. An
entry applied and now refused is taken out of the register — its place is
taken by the entries in its `after` that nothing else applied names — and the
host is told (`Change::Withdrawn`, §10).

### 3.9 Threat notes

- **Equivocation visibility.** It is visible to the host for every entry kind,
  not only data (invariant 2). A silent choice between two `Members` entries
  would let one owner device un-sign a removal for some readers and not others.
- **What a relay learns.** Without sealing, everything. With sealing: the
  writer, seq, chain links, the digests the entry supersedes, the epoch id and
  the size of the ciphertext — **not the path** (§6.7).
- **A forged `after`.** `after` is honoured literally, across paths too: a
  writer that names another path's head in its `after` hides that head, which
  gives it no more power than a removal it could write at that path (§10).
- **Unknown critical TLV.** A newer writer's critical field refuses the entry
  at an old reader rather than being misread; the entry is not applied, and
  the reader is told to upgrade.
- **A hole is not a retraction.** A gap statement lets readers stop waiting;
  it removes nothing a peer holds (§3.6).

## 4. Durability, normative

A node signs an entry, stores it and publishes it **before** it is on disk.
What keeps a crash from making an honest device sign a different entry at a
seq a peer already saw (invariant 2, with its consequence: a suspected key and
a re-enrolled device) is a **durable reservation** of seqs, recovery of the
device's own entries from its peers, and a **signed gap statement** for what a
crash leaves unissued. This replaces "flush before every publication": the put
path carries no flush.

### 4.1 Words

- **Process-durable:** a store write returned. It survives the process being
  killed (`kill -9`, an out-of-memory kill, a crash of the application).
- **Power-durable:** a store write made before a `DataStore::sync` that
  returned. It survives a power loss.
- **The store.** A node keeps everything in one `ndn_sync::DataStore`. Each
  store instance keeps, on its own: a write that returned survives the process
  being killed; a write before a returned `sync` survives a power loss; after a
  power loss the store opens at a whole state at or after its last returned
  `sync`, never part of a write (for an atomic `apply`), and a torn tail rolls
  back without error and without refusing to open. `sync` returns once every
  write that returned before the call is durable, or with the error saying why
  it may not, and coalesces concurrent calls. A store that keeps nothing across
  a restart (the memory store) reports every write durable at once and keeps
  nothing; a node on one starts again with an empty log and signs from seq 1
  under the same key: it is for tests and for identities that never restart.
- **`R`**, the **reservation** of a (device, space): the highest seq the device
  may sign once `R` is durable. **`R_durable`**: the largest `R` whose write a
  returned `sync` covered (or that the store held at open). The device signs no
  seq above `R_durable`; always `own head ≤ R_durable ≤ R`.
- **Own head:** the highest seq of the device's own entries in the space held
  in the store, read from the **names** of every stored own entry
  (`<D>/32=log/<S>/seq=<n>`) before and regardless of whether any decodes (a
  head taken from decoded packets would miss an entry that does not decode, and
  the device would sign again at its seq). Pieces of an entry, other devices'
  entries and entries of a space that extends this one move nothing.
- **Structural entry:** a `Members` or `Epoch` entry.

### 4.2 The rules

1. A device MUST NOT sign at a seq above its durable reservation `R_durable`,
   and MUST resume at `max(own head, R) + 1` after an unclean start (§4.5).
2. A device MAY serve and announce an entry as soon as it is stored and
   applied (the store write returned).
3. A device MUST flush before serving or announcing a `Members` or `Epoch`
   entry, and before it signs under a reservation extension: a seq above
   `R_durable` waits for the flush that covers the extension.
4. `put` returns when the entry is signed, stored and applied; with `durable`
   it returns after the flush that covers it (§4.7).
5. After an unclean start that leaves a hole (the first seq is not `own head +
   1`), the first entry MUST carry the signed gap statement (§4.5).
6. A device that hears its own name above its own head MUST NOT raise its head
   on that counter alone; it MUST fetch and verify the entries behind the
   counter and MUST tell its host (§4.8).
7. A failed flush stops signing past `R_durable` and the error says which
   disk; nothing already signed is retracted and reads continue (§4.6).
8. An own-name entry above `R_durable` is evidence of a key copy or a
   rollback: it MUST NOT be applied, MUST be stored, and MUST be reported
   (§4.8).

### 4.3 The store layout

Entries are stored **at their own names** (`<D>/32=log/<S>/seq=<n>`, value the
Data wire) and pieces at theirs. Everything else is under
`/localhost/ndn-heap/`, a prefix no device serves. A `<S>`, `<device>` or
`<creator>` shown as a *TLV component* is **one GenericNameComponent holding the
`Name` TLV** of that name: a space name is a prefix of the names of spaces that
extend it, so spelled out as components a scan of one space's keys would list
another's. A `seq` shown as *seq 8* is one GenericNameComponent of 8 octets,
big-endian, so keys order numerically. Other names are appended as components.

| Key under `/localhost/ndn-heap/` | Value | Written |
|---|---|---|
| `verified/<entry name>` | the **marker**, 112 octets: signed-region digest 32 ‖ key digest 32 ‖ `PREV` 32 (zero when none) ‖ previous seq 8 (absolute; 0 with a zero `PREV`) ‖ `at` 8 (first-seen time, `Config.clock` in milliseconds; display and cut bounds only) | with the entry |
| `head/<S>` | own `seq` 8 ‖ its signed-region digest 32 (40 octets) | with every own entry |
| `reserve/<S>` | `R` 8 (big-endian) ‖ clean 1 (0 or 1): 9 octets | at open, at each extension, at clean close |
| `space/<S>` | 1 octet | when the space is created or opened |
| `joined/<S>` | a marker that the node was told it joined `<S>` | when joined |
| `structural/<S as TLV component>/<device as TLV component>/<seq 8>` | empty | with a `Members` or `Epoch` entry (start replays only these) |
| `heads/<S as TLV component>/<SHA-256 of the PATH TLV>` | the `PATH` TLV ‖ `ENTRY_REF`* | with the apply |
| `supers/<S as TLV component>/<device as TLV component>/<seq 8>` | `ENTRY_REF`* of the entries that name `<device>/<seq>` in their `after` | with the apply |
| `epoch/<S as TLV component>/<creator as TLV component>/<seq 8>` | the epoch key wrapped to this device's own seal key: a `GRANT` TLV (§6.5), the wrap's AAD the `Name` TLV of this very store key | before the Epoch entry is signed |
| `equivocal/<entry name>` | the second packet | on equivocation |
| `suspected/<key name>` | 1 octet | when a key is suspected |
| `scoped/<person>` | the adopted trust context of a person for a space (§9) | on adoption |
| `ledger/<S as TLV component>/<device as TLV component>` | an index of what the node holds of one device: its person, the seqs held as ranges and the gaps its entries declared; read at open in place of every `verified/` marker | with the entries |
| `kept/<S as TLV component>/<device as TLV component>` | the seqs a removal cut keeps of one device (the chain ancestry of its tips, §3.8), as ranges | when a removal is applied |
| `status/<S as TLV component>/<device as TLV component>/<seq 8>` | why a held entry is not applied (its refusal); absent for an applied entry | with the entry |

A record the store holds that cannot be read (wrong length, a clean flag other
than 0 or 1) is **never taken for an absent one**: a node that cannot tell what
it reserved could sign a seq a peer saw. It refuses to open the space and says
what to do (restore the store from a copy, or remove it and recover from peers).

### 4.4 Batches

Every write of one entry — the entry, its marker, `head`, `heads`, `supers`,
`structural`, and for a large payload its pieces — is one `DataStore::apply`.
A node MUST hand the batch to the store before the `put` that made it returns
and MUST NOT defer it to a background writer: a write that returned survives
`kill -9`. A read by prefix that a node makes while a batch is open MUST answer
as the store would with the batch applied (what the batch stores appears, what
it removes does not) and MUST NOT hand a part of the batch to the store. A node
MUST apply the batches of puts in the order their seqs were numbered, so
publication follows put order. A store MAY apply a batch atomically (all of it
survives a kill and a power loss, or none: the persistent backends do) and one
that cannot applies it one write at a time in order; a state left by a
prefix of a batch MUST be one a restart accepts, and a record that is not an
entry (a marker, a head, a structural record) has meaning only with its entry:
the **entry's name** is the authority for the own head. A store that returns
from `apply` having kept only some of it, or reports a batch durable before it
is, defeats the barrier as a disk that lies does (§4.10).

The epoch key of a new epoch is written (`epoch/…`) **before** the `Epoch`
entry that names it is signed (§6.3). A stored key is no authority without its
entry: a node takes a stored key only if a held `Epoch` entry names its epoch
and the key matches that entry's key check (§6.2).

### 4.5 Reservation, open and resume

1. **Reservation.** Per (this device, space) the device keeps `R` durable. It
   MUST NOT sign a seq above `R_durable`. When the seq about to be signed
   exceeds `R − ⌊reserve_block / 2⌋`, the node writes `reserve/<S> =
   (max(R, seq) + reserve_block, clean 0)` straight to the store and asks the
   flusher for a flush; a seq above `R_durable` waits for it, and only a disk
   that stalls makes a put wait. `Config.reserve_block` is 1,024 by default.
2. **Open.** To open a space the node reads `reserve/<S>` and `head/<S>` and
   the own head from the names (§4.1), recovering from peers first when the
   start is unclean and peers are known (§4.8). The start is **clean** iff the
   record says clean, `R` equals the seq of the `head/<S>` record, **and** the
   own head from the names equals that seq. The first seq to sign is **always**
   `max(own head, R) + 1`. Before anything is signed the node writes
   `reserve/<S> = (max(R, first seq − 1) + reserve_block, clean 0)`, clean
   start included, and asks for its flush; the first put waits for that flush
   only if it arrives before it completes. One flush at open covers every open
   space.
3. **A clean start has no hole:** it resumes at `head + 1`. A start whose `R`
   is above the head leaves a **hole** `(head, first seq)`, and the first entry
   signed after it carries the **signed gap statement**: `PREV` the
   signed-region digest of the entry at the own head and `PREV_SEQ` that head;
   when nothing is held, `PREV` 32 zero octets and `PREV_SEQ` 0 (§3.6). The node
   tells its host (`Alert::GapSigned { after, resumed }`). An unclean start
   with no hole (the first seq is `own head + 1`) states nothing.
4. **Clean close.** `Node::close` refuses new puts, drains the publisher,
   flushes, writes `reserve/<S> = (own head, clean 1)` for every open space,
   flushes again and stops its tasks. The next start is clean. `Node::shutdown`
   (what `Drop` calls) stops at once and leaves `R` above the head: the next
   start is unclean, with a hole and a gap statement.

### 4.6 The flusher and the publisher

- **One flusher per node.** While any write is unsynced it calls
  `DataStore::sync`, which covers every write that returned before the call;
  writes arriving meanwhile share the next flush; no timer. Natively the call
  runs on a blocking thread, except for a store whose `sync` returns at once; on
  `wasm32` it runs inline. A write is made durable when a flush that began after
  it returned has returned: a node takes its flush ticket **after** the write
  returned, never before.
- **Failure is sticky.** Once a `sync` fails, no flush is begun again. Signing
  past `R_durable`, every wait for a flush that has not covered a write, and
  every structural change answer `Local` (next step `FixLocal`; the reason is
  the disk's own: "the store could not make this node's writes durable:
  …"), `Alert::StoreFailed { why }` is raised, nothing already signed is
  retracted, writes covered before the failure stay durable, entries at seqs
  up to `R_durable` may still be signed, and reads continue. The repair is to
  fix the disk and restart the node.
- **The in-order publisher.** Each own entry results in exactly one
  announcement (`SyncHandle::publish`, §7), in seq order, one at a time. A
  structural entry — and every entry after it — is **held** until a flush
  covering the structural entry returned. If that flush fails the held entries
  are never announced.

### 4.7 `put`, `durable`, `flush`, `close`

- **`put`** signs the entry, writes one batch, applies it and returns. The
  entry is served and announced at once (rule 2) — except a structural entry
  (rule 3). A `put` MUST NOT wait for the network; it waits for the disk only
  when its seq is above `R_durable`.
- **`PutOptions { durable: Option<bool> }`.** With `durable` true, `put` returns
  after the flush covering the entry. The default is `durable = structural ||
  no_peers`, where `no_peers` holds when the space's observed sync state
  holds no name other than this device's. A structural change (`change`,
  `create`) always returns after the flush that covers it and the entry's
  publication.
- **`Node::flush()`** waits for a flush covering everything written so far and
  returns the sticky error if there is one.
- **`Node::close`** and **`Node::shutdown`** are §4.5, rule 4.
- **Counter = seq.** The producer counter of the space's sync group at join is
  the own head after recovery; every entry results in one publication (§4.6).

### 4.8 Recovery from peers, and counters heard

An unbacked counter never raises a head. A state vector names no sender and its
validator is insecure by default, so a forged `(D, 2⁴⁰)` could push a device's
seq up; counters only decide **what to fetch**.

1. **At an unclean start with peers known** (any other device's entry held in
   this space, or heard in the group) the node waits up to `Config.settle`
   (1 s by default) for the first vector of the group before signing, and
   fetches its own-name entries `head + 1 …` from the members heard, through
   `32=held` (§2.2), at most `4 × reserve_block` above its head. With no peer
   known it proceeds at once: there is nothing to learn.
2. **Adoption.** An entry is adopted only if it verifies under this device's
   key, carries the right name, chains to the previous (`PREV` equals the signed
   digest of the entry before it) and its seq is at most `R_durable`. The node
   adopts the longest such prefix, raises its own head to it, and signs above
   it. Entries of the hole that are not in that prefix stay valid orphans.
3. **Evidence.** An own-name entry above `R_durable` that verifies is evidence
   of a rollback or a key copy: the node stores it, does **not** apply it,
   raises `Alert::RolledBack { reserved, seen }`, and resumes above it.
4. **Unbacked.** A heard counter for this device above its own head with no
   fetched, verified entry behind it raises `Alert::UnbackedCounter { device,
   seen }` and changes nothing.
5. **Later.** A heard own-name counter above the head at any later time
   triggers the same fetch, adoption and alerts.

If peers are known but no vector arrives within `settle`, the node proceeds,
the hole is signed and nothing is recovered (§4.10). Raising `settle` to the
sync layer's suppression period plus jitter is the remedy; weakening rule 6 is
not.

### 4.9 The durability matrix

`h` is the durable own head after a restart; "the window" is the entries signed
since the last completed flush; a peer "held" an entry if it fetched it.

| Event | After restart | Outcome |
|---|---|---|
| Process killed (`kill -9`, no power loss) | every returned write is in the store; own head from the names; `R` above it | nothing lost; hole `(head, R]` declared by the gap statement; no seq re-signed |
| Power cut in the window; **no peer held** the entries | the window's entries are gone; `R_durable ≥` every seq ever signed | the entries are lost at this device though `put` returned (unless `durable`); hole signed; no seq re-signed; readers do not wait |
| Power cut in the window; **a peer held** an entry; peer reachable | recovery (§4.8) fetches it | recovered **whole**: adopted, head above it, no hole for what was recovered |
| Same, **no peer reachable** within `settle` | the entry is not at this device | hole signed above `R`; the peer's copy stays a valid orphan; never re-signed |
| `put` with `durable` true, power cut after it returned | the entry is in the durable image | nothing acknowledged is lost |
| Members or Epoch entry, power cut before its flush | the entry is gone, and was never served or announced | nothing a peer saw is lost |
| Reservation flush fails (disk) | — | puts past `R_durable` refused with the disk's reason; `StoreFailed`; reads continue |
| Restored old image, peers online | the first vector shows this device's counter above its head | `RolledBack` raised; the entries above are stored, not applied; seq jumps above them; nothing re-signed |
| Restored old image that says **clean**, a put before the first vector | no wait is made on a clean start | may sign a seq a peer holds: equivocation, detected at the first vector (§4.10) |
| Cloned or restored, no peer, later meets a peer | — | equivocation, attributable; key suspected; re-enrol the device (§4.10) |
| Own-name entry above `R_durable` seen | — | rule 8: evidence of a copy or rollback |
| `Node::close` | `reserve = (head, clean 1)` | next start clean; no hole, no gap statement |
| Single device, no peers | — | no re-sign; the window is lost unless `durable`, which defaults on |
| Removed device's entries recovered | — | count only inside the removal cut (§3.8); outside never |
| Disk acknowledges a flush it did not make | — | defeated: a power loss can still make an honest device equivocate (§4.10) |

### 4.10 Threat notes and residuals

Residuals are stated plainly; the layer does not hide them.

- **D17: an unbacked counter never raises a head.** A state vector decides
  what to fetch, never a seq (§4.8).
- **The window.** On a power loss, the entries signed since the last completed
  flush (about the duration of one flush, 1–3 ms of puts at default) are lost
  at this device though `put` returned, unless `durable` was set. This is the
  loss window of any application that does not flush per write. The layer does
  not widen it.
- **Restore from backup offline, with no peer reachable.** The device may sign
  a seq a peer holds. This is detected and attributed (`Equivocation`), and
  handled as a compromise of the key: "this device's key signed two things at
  one seq; it was restored or copied; re-enrol it". Restoring a device from a
  backup is unsupported; enrol anew. A backup taken at a clean close and
  restored carries `clean`, for which no wait for a peer vector is made; the
  first vector the device hears still raises `RolledBack`.
- **History forever.** No entry is dropped (invariant 7); the log grows. The
  cost is accepted; there is no compaction.
- **A disk that lies about a flush** (a write cache without power-loss
  protection, a virtual disk with unsafe caching, some removable media) defeats
  the barrier: a power loss can then make an honest device equivocate. Readers
  treat that as any equivocation; it is a residual of such hardware.
- **Orphans above a cut's tip.** A removal binds what the removing owner device
  held of the removed person's devices. What it never held, and every entry
  above a tip, is outside the cut and never counts, in any arrival order. An
  entry the person signed after the removal is not retracted from copies
  already made.
- **Holes.** A crash leaves up to `reserve_block` seqs unissued. Readers skip a
  hole a gap statement declares; an undeclared hole costs misses until a later
  entry declares it (§7).
- **Equivocation by this device** is evidence of a copy (rule 8) or of two live
  processes; it is never produced by a crash.
- **A store that keeps nothing across a restart** (the memory store) reports
  every write durable at once and keeps nothing (§4.1).
- **A process killed without a power loss** loses nothing that returned.

## 5. Membership: an operation fold

What a space's members are is stored nowhere: it is **computed** from the
`Members` and `Epoch` entries the owner's devices signed. Those entries are
facts in grow-only sets, every query is a pure function of the sets, so two
nodes holding the same entries agree whatever order the entries reached them in
and however often they were applied. Removal wins over an addition of the same
id; a person removed and admitted again needs a fresh id.

### 5.1 The entries

`Members` entries are signed by **owner devices** only (§2.1, §3.8 rule 4).
A `Members` entry holds at most one `CREATE` and at most 32 operations (an owner
device splits a larger change across entries):

- **`CREATE { ANYONE }`** is the space's creation, once. `ANYONE` 1 makes the
  space **public**: readers are everybody and nothing is sealed (§6). `ANYONE` 0
  makes it sealed.
- **`ADD { ID, person, ROLE, EPOCH_ID? }`** admits `person` (a namespace, matched
  exactly) as a writer (0) or a reader (1). `ID` is 16 octets that a writer
  chooses at random and that name this addition. A reader's `EPOCH_ID` names
  the epoch whose history it reads (§6.6).
- **`REMOVE { ID, ENTRY_REF* }`** removes every addition under `ID`. The
  `ENTRY_REF`s are the **tips**: what the removing owner device held, verified,
  of the removed person's devices (§5.6).

An `Epoch` entry (§6.3) is applied to the same fold.

### 5.2 The state

The fold keeps four sets and the entries that carry them:

1. **`adds`**: `ID → Add`. If several carriers claim one `ID`, the fold keeps the
   `Add` of the carrier of lowest **rank**: its signed-region digest, then its
   device name, then its seq (the digest decides; the rest only make the order
   total).
2. **`removed`**: `ID → ⋃ tips`: the union of the tips of **every** `REMOVE` that
   names `ID`, in any entry. A `REMOVE` of an `ID` whose `ADD` is not held yet
   stands: the `ADD` is removed when it arrives. (A removal that needs more than
   64 tips repeats its `ID` in further `REMOVE` operations.)
3. **`epochs`**: `EpochId → EpochBody`. If an owner device signed two bodies for
   one id (equivocation, which the log reports), the fold keeps the **least** by
   `(KEY_CHECK, AUDIENCE)`.
4. **`create`**: the `CREATE` of the carrier of lowest rank (and, for one
   carrier, the lower `ANYONE`). Until a `CREATE` is known the space is read as
   **not public**.

A carrier is identified by `(device, seq, signed-region digest)`: two
equivocating packets are two carriers.

### 5.3 Rules

1. **Facts.** The state is the sets of §5.2. Applying a `Members` entry or an
   `Epoch` entry is **idempotent and commutative**; the fold trusts its caller:
   only entries signed by owner devices are applied (§3.8 rule 4).
2. **The owner.** The owner `O` (the first components of the space name) is an
   implicit writer and, unless the space is public, an implicit reader. A
   `REMOVE` of an `ADD` that names `O` is ignored.
3. **Writers and readers.** `writers()` is `{ who | ADD(writer) stands }`,
   `readers()` likewise for the role reader, where an `ADD` **stands** iff its
   `ID` is not in `removed` (or it names the owner). **Removal wins over an
   addition of the same `ID`**, in any order. A person removed and later
   re-admitted needs an `ADD` under a **fresh `ID`**; an `ADD` under another
   `ID` that is concurrent with a removal is a re-admission and stands. Both
   lists are sorted with the owner first and the rest in NDN canonical name
   order; `readers()` is "everybody" for a public space.
4. **Removal tips.** `removal_tips(P)` is the union of the tips of every
   removed writer `ADD` whose person is `P`, sorted; never any for the owner.
   (A reader's removal carries no tips that count.)
5. **Audience.** `audience(E)` is the persons the epoch's `EPOCH_BODY` lists
   **plus** every standing reader whose `ADD` names `E`. A person the epoch lists
   who is no longer a reader stays in it: this is what keeps the epoch out of
   force.
6. **In force.** `in_force()` is the epoch with the greatest `(creator name,
   seq)` (NDN canonical order of the creator, then the seq) among the known
   epochs whose `audience(E)` is a subset of `readers()` (the owner counted
   among them); none if there is none, and none for a public space. `complete()`
   holds iff `audience(in_force)` equals `readers()` exactly; a public space is
   always complete.
7. **Repair.** Owner devices MUST sign a new `Epoch` entry, whose audience is
   `readers()`, whenever a sealed space is **not** `complete()` (§6.3). A writer
   MUST NOT seal in any epoch but `in_force()` (§6.4). Concurrent owner devices
   may sign duplicates: all have equal audience, `in_force` picks the greatest
   id, and nothing is lost.

### 5.4 Queries

| Query | Answer |
|---|---|
| `writers()` | the persons that may write, owner first, then sorted |
| `readers()` | everybody (public), or the persons that may read, owner first, then sorted |
| `is_writer(P)` | `P` is the owner or a standing writer |
| `is_reader(P)` | public, or `P` is the owner or a standing reader |
| `persons()` | every person a standing `ADD` lists, owner first |
| `removal_tips(P)` | rule 4 |
| `standing_ids(P)` | the `ID`s of the standing `ADD`s that name `P`, in either role, sorted; none for the owner: what a removal of `P` names |
| `audience(E)` | rule 5 |
| `in_force()`, `complete()` | rule 6 |
| `create()` | whether the space is public, once a `CREATE` is known |

### 5.5 Convergence

Every set above is a join-semilattice and every query is a function of the sets;
so any two nodes that have applied the same carriers hold the same state,
whatever the arrival order and duplicates. A carrier later **withdrawn** (its
signer's key revoked, a context changed: §3.8) is taken out of the fold by
**recomputing** the sets from the carriers that remain — facts cannot be
subtracted — which is the same function; an `Epoch` withdrawn is dropped by its
id.

### 5.6 Writing a removal

A removing owner device lists, **per device of the removed person that it knows
and holds verified entries of**, one `ENTRY_REF`: the highest verified seq of
that device in this space and its signed-region digest, collected within
`Config.first_look` (4 s by default). What it never held is **outside the cut**:
an entry of that device above the tip, or one the owner never saw, never counts
(the existing, stated trade-off; §4.10). A person who is both writer and reader
has two `ADD`s with two ids; removing "from both roles" removes both ids, and
only the writer's tips count (rule 4). The cut is applied by every reader as
chain ancestry of the tips (§3.8, rule 5): the tip's digest binds every entry
below it.

An **owner device** is not removed by a members operation: its key is revoked by
the owner namespace's trust context (§9). The trust layer revokes a key; a
members operation removes a person.

### 5.7 Threat notes

- **Concurrent owner devices** may each sign an `ADD`, a `REMOVE` or an `Epoch`
  at once; the sets union, removal wins, and `in_force` / `complete` repair
  an epoch whose audience outgrew the readers. Nothing is lost.
- **A removal is not a retraction.** The removed person keeps what it already
  opened and the copies it made (invariant 9).
- **The owner cannot be removed** by a members operation, so an owner device
  that signs `REMOVE` of the owner changes nothing.
- **Equivocating owner devices.** Both carriers are applied; their `ADD`s under
  one `ID` resolve by the lowest digest, and the host is told (§3.7).
- **Writers that are not readers** of a sealed space cannot be granted an epoch
  key (§6.5) and so cannot seal (§6.4): the owner SHOULD list every writer of a
  sealed space as a reader too.

## 6. Seal and grants

### 6.1 Public and sealed spaces

A **public** space (`CREATE` with `ANYONE` 1) has no epochs and no sealed
entries: a sealed Put in it is refused (`Sealed`, §3.8 rule 6). Every other
space is **sealed**: every Put in it carries its path and value as ciphertext
under the key of an **epoch**, and an unsealed Put in it is refused
(`Unsealed`).

An **epoch** is named by the `Epoch` entry that started it: `EpochId { creator,
seq }`, the device that signed the entry and its seq. Its key is 32 random
octets made by that device. The entry carries the key's **check** and the
**audience**: the persons the epoch is for. The epoch **in force** (§5.3 rule 6)
is the one writers seal in. A space with a reader added or removed since its
last epoch is not `complete()` until an owner device signs a new epoch (§5.3
rule 7).

### 6.2 Keys and primitives

All cryptography is ChaCha20-Poly1305, HKDF-SHA256 and X25519 as `ndn-security`'s
confidentiality module implements them. Every secret is held in a type that
zeroizes on drop.

- **Epoch key.** 32 octets from the system CSPRNG.
- **Key check.** `KEY_CHECK = HKDF-SHA256(IKM = the epoch key, salt = none, info
  = "ndn-heap/seal/check/1" ‖ the Name TLV of S ‖ the Name TLV of the creator ‖
  the epoch's seq, 8 octets big-endian)`, 32 octets of output. The ASCII label
  has no terminator. A key is taken for an epoch only if its check equals the
  `KEY_CHECK` of a **held, owner-signed `Epoch` entry** naming that epoch of
  that space; otherwise it is dropped (zeroized).
- **Sealing.** `ChaCha20-Poly1305(key = the epoch key, nonce = 96 fresh random
  bits, aad = the Name TLV of the entry's name)`; stored as `nonce (12) ‖ tag
  (16) ‖ ciphertext`. Opening fails for another key, another entry name (the
  AAD binds the ciphertext to its entry), an altered or a truncated value.
- **Recipient key.** An X25519 key pair per device, the secret 32 random
  octets kept in the node's key store under `/localhost/ndn-heap/seal/<device>`
  and made once. A key store that keeps something other than 32 octets there is
  never overwritten (grants wrapped to the old key would be lost): the node
  says so and the operator removes it by hand. The public half is published as
  the device's **seal key packet** `<D>/32=seal/<pk>` (§2.2), Content one
  `SEAL_KEY` TLV, signed by a key of `D`. A node takes a key from such a packet
  only if the name equals `<D>/32=seal/<pk>`, the Content is that same `pk`, and
  the validator accepts the packet as signed by a key of `D` (§9).
- **Wrapping a key to a seal key `to`** under `aad` (a Name TLV): a fresh
  ephemeral X25519 pair; shared secret `X25519(ephemeral secret, to)` (an
  all-zero shared secret refuses); `KEK = HKDF-SHA256(IKM = shared, salt = none,
  info = "ndn-security/confidentiality/x25519-kek/1" ‖ ephemeral public ‖ to)`,
  32 octets; the wrapped key is `ChaCha20-Poly1305(KEK, 96 fresh random bits,
  aad, the 32 epoch-key octets)` stored `nonce ‖ tag ‖ ciphertext` (60 octets).
  The result is the Content of a grant: `GRANT { EPHEMERAL_KEY, CIPHERTEXT }`.

### 6.3 Epoch entries

An `Epoch` entry is **structural**: it is served and announced only after a
flush covering it (§4.2 rule 3), and the call that made it returns after that
flush. An owner device makes one:

- at the creation of a sealed space (`create`): audience the owner and the
  listed readers; none for a public space;
- whenever a change leaves the space not `complete()`, and whenever it learns
  from received entries that it is not (§5.3 rule 7).

The ceremony is, in this order: allocate the seq the entry will have (under the
reservation, §4.5); generate the key; wrap it to this device's own seal key and
write it at `epoch/<S>/<creator>/<seq>` (§4.3); compute the key check; sign the
entry with `AUDIENCE = readers()` (owner first, then sorted); store it; flush;
publish. A sealed space has **at most 256 readers**, the owner counted, because
an `AUDIENCE` holds at most 256 persons; a change that would exceed it is
refused (`BadRequest`).

### 6.4 Sealing a write

A writer to a sealed space MUST seal in `in_force()` and in no other epoch; if
none is in force, or it does not hold the key of the one in force, the write
answers `NotReady` (next step `RetryLater`) and the node asks for the key (§6.5).
The **plaintext** sealed is the TLV bytes of a `PATH` followed by exactly one of
`INLINE` or `BLOB` (§3.3), so the path, a removal (an empty `INLINE`) and the
blob's root are inside the ciphertext. The entry is
`SEALED { EPOCH_ID, CIPHERTEXT }` with `ENTRY_REF*` left plain. A payload over
6,144 octets travels in pieces (§8); a sealed payload is sealed whole before it
is cut, so holders of the pieces see only its size.

A reader opens a sealed entry with the key of the epoch it names; without the
key the entry is **held closed**: kept, chained, its path unknown. `get` on a
space with any entry held closed answers `Sealed` (the path of a closed entry
is unknown, so no answer would be complete; §10).

### 6.5 Grants

An epoch key reaches a reader by a **pull**, not inside an entry: the devices of
a person cannot be enumerated by the signer of an entry, so a new device of an
admitted person could never be a recipient of a wrap. A grant is one packet per
(asker seal key, space, epoch): `<G>/32=grant/<GrantAsk>` (§2.3), Content `GRANT`.

**Reader side.** To obtain the key of epoch `E` a device asks the epoch's
creator first and then the other devices heard in the space (at most 8,
`RELAYS_ASKED`), round after round with a capped back-off, until the key is held
or no longer owed. It MUST NOT ask a name that only a Sync Interest carried (a
notice names nothing it decides, §7). A granted key is taken only if it
matches the key check of a held owner-signed `Epoch` entry naming `E`;
otherwise it is dropped. It unwraps with its recipient key and the grant's name
as AAD.

**Granter side.** A device `G` answers `<G>/32=grant/<GrantAsk>` **only when all
four hold**, checked in this order:

1. a held owner-signed `Epoch` entry names `E` (`EpochNotNamed`);
2. `audience(E)` contains the asker's **person** — the person of the device
   `D` of the seal key name in the ask (`NotInAudience`);
3. `readers()` contains that person **now** (`NotReaderNow`): a removed
   reader fails here for every later ask;
4. `G` holds the epoch's key (`KeyNotHeld`).

Anything else gets **no answer**, and `G` fetches nothing for it. Only then does
`G` fetch the seal key packet named by the ask — `<D>/32=seal/<pk>` — and
verify it (§6.2: signed by a key of `D`, the Content equal to `pk`, one run per
seal key, kept once verified); the four conditions are checked **again** after
the fetch, since the records may have moved. It answers with the key wrapped to
`pk` (§6.2) under the **grant's own name** as AAD, signed by its device key.
One name has one packet while it is kept; a granter keeps its last 4,096 grants.

### 6.6 Forward only

Said plainly (invariant 9): a **removed reader is refused every later grant**
(condition 3), and the new epoch that its removal forces has a key that did not
exist before; **what it already opened it keeps**, and a key it was already
granted still opens what it sealed. A reader added by an `ADD` that names the
current epoch reads that epoch's history; an epoch that ended before a reader
was listed stays **closed** to it. To open an earlier epoch to a reader the
owner adds it with that epoch's `EPOCH_ID`; the reader still joins the epoch in
force through the new `Epoch` entry the addition requires (§5.3 rule 7).

### 6.7 What a relay sees, and threat notes

A relay (a forwarder cache, a repository) of a sealed space sees names, kinds,
writers, seqs, chain links, epoch ids, the digests an entry supersedes and the
size of the ciphertext. It does **not** see the path or the value: the path is
inside the sealed body.

- **Outgrown epoch.** A writer that sealed in an epoch whose audience still held
  a removed reader would give that reader the new data; hence §6.4.
- **Unsealed entry in a sealed space.** A relay that strips encryption would make
  a reader take plaintext; it is refused (`Unsealed`).
- **Key to the wrong device.** A grant is wrapped only to a seal key that a key
  of the asker's device signed, and only to a person the records admit; the key
  that arrives is checked against the owner-signed check.
- **Stolen epoch key.** An epoch key a thief holds opens what it was sealed in;
  revoking the device rotates the epoch for what follows (§5.3 rule 7), it does
  not recall (invariant 9).
- **A forged ask.** An ask names no sender; a stranger's ask costs the granter
  no fetch (conditions 1–4 are checked first).

## 15. TLV registry

The data layer owns **0x0600–0x063F** (64 numbers), registered in
[README.md](README.md#tlv-type-numbers). **Odd** numbers are critical: a decoder
refuses a record holding one it does not know. **Even** numbers are skippable
and reserved for additive fields (§3.4). Every number in use is odd; 0x063B–0x063F
and every even number of the block are free.

| TLV-TYPE | Name | Value | § |
|---|---|---|---|
| 0x0601 | `ENTRY` | the Content of every log packet | 3.2 |
| 0x0603 | `KIND` | NNI: 0 Put, 1 Members, 2 Epoch | 3.2 |
| 0x0605 | `PREV` | 32 octets: signed-region digest of the previous entry; 32 zero octets with `PREV_SEQ` 0: "lost everything before" | 3.6 |
| 0x0607 | `PREV_SEQ` | NNI: the previous entry's seq; present iff it is not `seq − 1` | 3.6 |
| 0x0609 | `ENTRY_REF` | `Name` (device), `SEQ`, `DIGEST` | 3.3 |
| 0x060B | `SEQ` | NNI | 3.3 |
| 0x060D | `DIGEST` | 32 octets | 3.3 |
| 0x060F | `PATH` | a name relative to the space: 1 to 8 generic components, ≤ 200 octets | 3.3 |
| 0x0611 | `INLINE` | the value's octets, ≤ 6,144; empty is a removal | 3.3 |
| 0x0613 | `BLOB` | `SIZE`, `ROOT` | 3.3, 8 |
| 0x0615 | `SIZE` | NNI ≤ 67,108,864 | 3.3 |
| 0x0617 | `ROOT` | 32 octets | 3.3 |
| 0x0619 | `SEALED` | `EPOCH_ID`, `CIPHERTEXT` | 3.5, 6.4 |
| 0x061B | `EPOCH_ID` | `Name` (creator device), `SEQ` | 3.3 |
| 0x061D | `CIPHERTEXT` | `nonce ‖ tag ‖ ciphertext` | 6.2 |
| 0x061F | `EPHEMERAL_KEY` | 32 octets: the granter's ephemeral X25519 public key | 6.5 |
| 0x0621 | `MEMBERS` | `CREATE`?, (`ADD` \| `REMOVE`)*, ≤ 32 operations | 5.1 |
| 0x0623 | `CREATE` | `ANYONE` | 5.1 |
| 0x0625 | `ANYONE` | NNI 0 or 1 | 5.1 |
| 0x0627 | `ADD` | `ID`, `Name` (person), `ROLE`, `EPOCH_ID`? | 5.1 |
| 0x0629 | `ID` | 16 octets | 5.1 |
| 0x062B | `ROLE` | NNI: 0 writer, 1 reader | 5.1 |
| 0x062D | `REMOVE` | `ID`, `ENTRY_REF`* (≤ 64 tips) | 5.1 |
| 0x062F | `EPOCH_BODY` | `KEY_CHECK`, `AUDIENCE` | 3.5, 6.3 |
| 0x0631 | `KEY_CHECK` | 32 octets | 6.2 |
| 0x0633 | `AUDIENCE` | `Name`* (≤ 256 persons) | 3.5 |
| 0x0635 | `GRANT_ASK` | `Name` (seal key packet), `Name` (space), `EPOCH_ID`: the last component of a grant's name | 2.3, 6.5 |
| 0x0637 | `SEAL_KEY` | 32 octets: an X25519 public key; the Content of a seal key packet | 6.2 |
| 0x0639 | `GRANT` | `EPHEMERAL_KEY`, `CIPHERTEXT`: the Content of a grant packet | 6.2, 6.5 |

Name keywords this specification owns (KeywordNameComponent, TLV-TYPE 0x20): `data`,
`log`, `piece`, `manifest`, `seal`, `grant`, `held`, `sync` (§2). The numbers
that the deletions of the previous design freed (inside 0x0520–0x057F, and
0x05C0–0x05FE) stay quarantined, so no stale `ndn-data` packet ever decodes as
new content; the block 0x0640–0x0653 belongs to the custodian remote signer of
`ndn-security`, not to this specification.
