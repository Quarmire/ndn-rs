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
  lies under `O`, whose key the trust context of `O` itself validates, and whose
  role is `admin` or `member` where `O` declares the role layout (§2.1, §3.8
  step 6). A space has **writers** and **readers** (persons); the owner is an
  implicit writer (through its owner devices) and, unless the space is public,
  an implicit reader.
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
   head after a restart is read from the own device's `ledger/` record, which
   lists every stored own entry (§4.1, §4.3).
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
the trust context that validates the key is `O`'s own (§9), **and** its role is
`admin` or `member` where `O` declares the role layout. The first half
depends on the two names alone, so every node judges it alike in any order; the
second is the **person** of the key (the namespace of the held context that
governs the device's name, §9.1), which must be `O` itself; the third is the
key's **role** (the component after `O` in the device name), judged by the
governing context and carried with the verdict (`Verified::owner_capable`).
Admission checks all three for a `Members` or `Epoch` entry (§3.8 step 6). A
device under a longer held namespace
is that namespace's device: with `/home` and `/home/bob` held,
`/home/bob/member/laptop` is a device of `/home/bob`, not of `/home`, although
`/home` is a prefix of its name, and so it carries no `Members` or `Epoch` entry
of a space of `/home`. **The role layout** is declared by a marker the root
signs into the context: its schema is *authoritative* (the generated namespace
schema of every `ndn-cert` namespace). Where it is declared, a `guest`, a `node`,
any other role and a device with no role are not owner devices; where it is not
(a flat namespace), every device of `O` is. The `DataRequiresCut` list is not
the marker: an owner can narrow it to nothing without declaring a flat layout.

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
| grant | `<G>/32=grant/<GrantAsk TLV>`, the last component one GenericNameComponent holding the `GRANT_ASK` TLV, which carries the asker's seal key packet | one `GRANT` TLV (§6.5) | a key of the granter `G` |
| held copy | `<H>/32=held/<Name TLV of the original>`, the last component one GenericNameComponent | the complete wire of the original packet | DigestSha256 |
| signal run header (§11; never stored, served or fetched) | `<D>/32=signal/<S>/32=run/<run id>`, the run id one GenericNameComponent of 16 octets | the run's body | a key of device `D` |
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
  TLV: the space as one `Name` TLV (which MUST parse as a space name), one
  `EPOCH_ID`, and one `SEAL_KEY_PACKET`, the asker's **seal key packet** — the
  whole signed Data `<D>/32=seal/<public key>` (its name MUST parse as a seal key
  name, and it is at most 2,048 octets, `SEAL_KEY_PACKET_MAX`). The ask carries
  the packet itself, not its name, so the granter learns the asker's device and
  key, and judges the packet, from the ask alone and sends no Interest (§6.5).
  The encoding MUST be canonical: re-encoding the decoded ask MUST give the same
  octets, so one ask has one name. A name of the older form (the seal key named,
  not carried) names no grant.
- **Held copy.** `H` is the components before the first `32=held` (a device
  name); exactly one GenericNameComponent follows whose value is the Name TLV
  of the original.
- **Signal run header.** `D` is the components before the first `32=signal` (a
  device name); the last component is a GenericNameComponent of exactly 16
  octets, the next-to-last `32=run`; what lies between is a space name (§11).
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
| any other, **registered by an extension** (§10.9) | that extension's answer |
| any other | not served |

The parser of the kind still judges the name; the router only chooses which
parser to run. A node MUST NOT serve any other name, and MUST NOT serve a
name under `/localhost`. The keywords above, and `data`, `piece`, `manifest`,
`sync`, `signal` and `run` (the other keywords this layer's names carry), are
**core**: an extension MUST NOT be given an Interest under one (§10.9).

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
The codec checks the `ENTRY` encoding only: a decoder refuses a longer `ENTRY`
(`TooLarge`) and a writer's `encode` refuses to produce one. The reserve covers
the name, the key locator and the signature of ordinary devices; a writer whose
device and space names or signature exceed it can sign a packet above 8,800
octets, which no bare face carries, and a node SHOULD keep its names short enough
that it does not. What does not fit in an entry travels in pieces under it (§8).

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
(it lists the heads that the write supersedes, §3.5) and in an Epoch (the
epochs it replaces, §3.5): in a Members entry it refuses the entry. One path
per Put entry. A **removal** is a Put with
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
| `ENTRY_REF` | 0x0609 | `ENTRY`, `REMOVE` | `Name` (a device name), `SEQ`, `DIGEST` | in `ENTRY`: 0 to 8, Put (heads superseded) or Epoch (epochs replaced) only; in `REMOVE`: 0 to 64 |
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
| `GRANT_ASK` | 0x0635 | the last name component of a grant | `Name` (space), `EPOCH_ID`, `SEAL_KEY_PACKET` | see §2.3 |
| `SEAL_KEY` | 0x0637 | Content of a seal key packet | 32 octets: an X25519 public key | exactly one |
| `GRANT` | 0x0639 | Content of a grant packet | `EPHEMERAL_KEY`, `CIPHERTEXT` | exactly one of each |
| `SEAL_KEY_PACKET` | 0x063B | `GRANT_ASK` | the wire of the asker's seal key packet, a whole Data | exactly one; ≤ 2,048 octets (`SEAL_KEY_PACKET_MAX`) |

`SEAL_KEY` and `GRANT` are packet Contents, not parts of an entry; `GRANT_ASK`
and `SEAL_KEY_PACKET` live in a name. 0x063D–0x063F and every even number of the
block are free (§15).

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
`(the device that signed the entry, the entry's seq)`. The entry's
`ENTRY_REF*` (at most 8) name the epochs it **replaces**: the owner device lists
the epochs no held epoch replaces when it signs (§5.3 rules 6–8); a reader of
the entry takes only each reference's `(device, seq)` as an `EpochId`.

### 3.6 The chain

Each entry links to the one before it in the same (device, space) log:

- `PREV` is the **signed-region digest** (§1.5) of the previous entry. An
  entry at seq 1 carries no `PREV`; every entry at seq 2 or more MUST carry
  one.
- `PREV_SEQ` is present **iff the previous entry's seq is not `seq − 1`**: it
  is the signed gap statement, and it MUST be below `seq`. A writer MUST NOT
  write a `PREV_SEQ` equal to `seq − 1`; a receiver reads one as the dense link.
- **The zero form.** `PREV` of 32 zero octets with `PREV_SEQ` 0 means "this
  device lost everything before". `PREV` is 32 zero octets **exactly when**
  `PREV_SEQ` is 0; a decoder refuses one without the other.

A receiver that finds an entry violating these (a `PREV` at seq 1, none above
it, a `PREV_SEQ` not below `seq`) reads it as **verified but not readable**
(§3.8 step 4): it records the refusal and applies nothing.

A **gap statement** (an entry at `seq` with `PREV_SEQ = p < seq − 1`) says: "I
(this key) have signed nothing in `(p, seq)` that I know of, and I will sign
nothing there again". It is attributable and it is **not a retraction**: an
entry inside `(p, seq)` that exists and verifies is a valid **orphan**, kept
and applied (invariant 9). A device makes it after an unclean start (§4.5) and
after losing its log. Because a gap is declared, a reader never asks for the
seqs inside it (§7); an undeclared hole costs misses until a later entry
declares it. A gap statement **counts** only while its entry is admitted
(applied, or closed for want of a key) and its name is not equivocal: the
gap of a refused entry, of an entry whose chain forks (`Chain`), or of an
entry found equivocal (§3.7) declares nothing, and when an entry stops
counting what only it declared absent is asked for again. *Threat (fixed,
review L5):* a writer whose fork arrived first made a reader skip its real
entries inside the fork's gap for good.

A node keeps for each verified entry a **marker** `verified/<entry name>` (§4.3)
holding the entry's signed-region digest, `PREV`, and the absolute seq of the
previous entry (0 with a zero `PREV`). A **chain walk** from a tip follows
these markers only — no entry body is read or decoded — and ends at **genesis**
(an entry with no `PREV`, or the zero form), at a **missing** marker (the seq
to fetch), at a marker whose digest differs from the one the chain names
(**divergence**: other bytes at a name), or at a marker that cannot be read or
links to a seq not below its own (corrupt).

### 3.7 Equivocation

A node finds equivocation in three ways:

- **Two packets at one entry name** whose signed regions differ.
- **A fork in the chain.** An entry's `PREV` names other bytes than the entry
  held at `PREV_SEQ` (or `seq − 1`), or the nearest held entry above it links to
  this seq with another digest. The conflict is at that seq.
- **A displaced packet.** Other bytes were refused at a name as outside a
  removal cut, and the bytes the cut names then arrive (§3.8 step 7): both are
  kept.

On any of them a node keeps **both** packets (the one held first at the entry
name, the other at `equivocal/<entry name>`, §4.3), raises
`Alert::Equivocation { device, seq }` to its host, and marks the signing key
**suspected**. An entry that forks the chain is also refused (`Chain`); a second
packet at a name is kept as evidence (not applied), **except** that a second
`Members` or `Epoch` packet is applied to the fold as the first is, because a
fold is a set of facts and every holder must agree whichever packet came first
(§5). A node MUST NOT prefer either packet silently. The alert is raised for
entries of every kind; for `Members` and `Epoch` entries it is the host's cue to
use an owner device (`UseOwnerDevice`).

A **suspected** key's new entries are not taken (`Suspected`) while its person
is a writer, until its revocation is held (§9) or the host unsuspects it;
entries held from before stay. A removed person's entries are judged by the
removal cut alone, so suspicion does not touch them, and a fork in the chain among
them is not refused as one: the cut decides what is kept. The fork is still the
evidence of a key that signed two chains, so it raises `Alert::Equivocation` (no refusal
and no suspicion) and the host sees a copied key even when the cut decides. `Suspected` is never kept
as an entry's verdict: the entry is taken when the mark ends and it is offered
again.

An honest device never produces equivocation by a crash or a restart (§4); a
copy of its key, a restored backup or two live processes with one key do.

### 3.8 Admission of a received entry

A node takes an entry received by any route (a fetch, a held copy, a recovery)
only through these steps in order. Each refusal says why and what to do
(`Refusal` and `NextStep`, §10).

1. **Name and key.** The name parses as an entry name of the space this node
   holds, `n ≥ 1`, and the key's device is `D` (§3.1); otherwise it is refused
   (`BadSignature`).
2. **Validation.** The packet validates under the durable rule (§9) — one
   verification — yielding the signer's key digest and its person `P`. A packet
   whose signer's certificate chain or person is not yet held is **pending**
   (it waits, it is not refused). `Lapsed` is not recorded as refused (§1.4).
   A key suspected here, while its person is a writer, is refused (`Suspected`,
   §3.7).
3. **Own name.** An entry under this node's own device name is taken only if
   this device's current key signed it (otherwise `BadSignature`, not
   stored). It is applied once it **chains to what is applied of this device's
   own log** (its `PREV` names the entry held at `PREV_SEQ`, which was
   admitted; a `PREV_SEQ` of 0 chains), and until then it is **held, waiting**
   (§4.3 status 2): not applied, not asked for again, judged again whenever an
   own entry is applied, so own entries that come back out of order are applied
   in order. Above the reservation the store held when this node opened the
   space (`R_durable` at open: the extensions this run wrote do not count) it
   is a restored old image or a copy of the key: `Alert::RolledBack { reserved,
   seen }` is raised and the next seq to sign moves above it (§4.8), and it is
   applied all the same when it chains, as every peer applied it, so this
   device and its peers read the same value. *Threat:* before this an own
   entry above the reservation was refused for good on the device that signed
   it while its peers applied it, and the two diverged.
4. **Decoding.** The content decodes (§3.4) and its chain link is well formed
   (§3.6). An entry that verifies but does not decode is **refused for what it
   carries**: it is stored, its marker is written with the chain link it
   states (`PREV` / `PREV_SEQ` are read even when the body fails; zero and 0
   only if it states none that can be read) and a status record says so, so a
   chain walk through it follows its real link, completes, nobody fetches it
   again, and it is never applied.
5. **Chain.** A fork (§3.7) refuses the entry (`Chain`) and raises the alert.
   Entries inside a declared gap are valid orphans and are kept and applied.
6. **Carrier.** A `Members` or `Epoch` entry MUST be signed by a key whose
   device lies under the owner's namespace by name (§2.1), whose person
   (the namespace of the held context that governs its name, §9.1) is the owner,
   **and** whose role is `admin` or `member` where the owner declares the role
   layout (`Verified::owner_capable`, §2.1); otherwise it is refused
   (`NotMember`; `NotOwnerDevice` for a device of the owner that is no owner
   device). The owner's person writes the same way: an entry of any kind
   signed by a guest, node or role-less device of the owner is refused
   (`NotOwnerDevice`), since the owner's implicit write is its owner devices'.
7. **Membership.** The signer's person `P` is the owner, or is a writer of the
   space (§5), or `P` was removed and the entry is **inside the cut**: there is
   a tip `t` among the removal tips for `P` with `t.device == D`, and the entry
   is **kept** by the tips of `D` (chain ancestry, below). Otherwise: no tip
   names `D` (`P` never was a writer, or the removal bound none of its devices)
   is `NotMember`; a tip names `D` and the entry is not kept is `OutsideCut`
   (naming `D` and the highest seq the cut keeps); a tip names `D` and the chain
   to it is not whole yet is **waiting**: stored, not applied, judged again
   whenever a missing link arrives, never accepted meanwhile.
8. **Seal.** A Put is judged by the space's creation (§5): `CREATE` known and
   public, a sealed Put is refused (`Sealed`); known and sealed, a plain Put is
   refused (`Unsealed`); a sealed Put whose epoch key is not held is **held
   closed** (stored, chained, not applied, its path unknown; the node asks for
   the key, §6.5) and opens when the key arrives; a sealed Put whose epoch's
   creator is no owner device of the space (its name is not under the owner's,
   or the log holds the device as no owner device, §2.1) is refused
   (`NotOwnerEpoch`: no Epoch entry can ever name that epoch, and holding it
   closed would have every reader wait for its key for good); a sealed Put that
   does not open under the key it names is refused (`BadSignature`). **Until a `CREATE` is
   known** neither is refused for it: a plain Put is applied, a sealed one waits
   as above, and every held entry is judged again when the creation arrives.
9. **Apply.** The register and the fold take it, and everything is written as
   one batch (§4.4).

The decision of steps 3 and 6 to 8 is a pure function of what is held (the
fold, the keys, the cuts, this device's own log), so it is made again by the
same function whenever any of them changes, and an entry never depends on the
order things arrived in. A verdict that depends on what is held can change
(`NotMember`, `OutsideCut`, `Unsealed`, `Sealed`, `Untrusted`, closed,
waiting); one about the entry itself cannot (`BadSignature`, `Chain`, not
readable). A second copy of an entry already held (the same signed bytes) is a
duplicate and writes nothing, but is judged again if its verdict can change.

**Fragmentation is capped.** The `ledger/` record of a device is rewritten with
every entry of it, so a node keeps at most 1,024 separate runs of held seqs and
1,024 counting gap statements (§3.6) of one other device. An entry that would
start a 1,025th run or state a 1,025th gap is **not stored** and is refused
`Fragmented` (next step: ask the owner: a writer that signs with gaps on
purpose is removed); one that extends a run is taken. An honest device stays
far below this (one gap per unclean start). *Threat:* before the cap a member
that alternated gap statements fragmented its runs and made a node write
O(N²) octets for N entries.

**Chain ancestry (cuts as tips).** A removal names, per device `D` of the removed
person, tips `(D, s, d)`. The set *kept* for `D` is the set of seqs reachable
from its tips by following `PREV` / `PREV_SEQ` through the markers (§3.6), each
link reached only if the marker holds the digest the chain names. An entry at
seq `q` is kept iff `q` is in the set **and** its signed digest equals the
digest the chain names at `q`, so other bytes at a kept seq are refused. The
walk stops at a **frontier**: a link whose entry is not held (or is held as
other bytes). The entry the chain names at a frontier is kept when it arrives
with exactly those bytes, and it is asked for by that exact digest (§7);
everything below a frontier is **waiting**, never accepted. Once a walk has
reached genesis, what it did not reach is not kept: an orphan inside a gap
that the chain jumps over, anything above a tip, anything before a zero form.
The kept set is computed once per removal, extended as the entries of its
chain arrive, and recomputed when the tips change. It is **not stored**: a
node computes it again at open, from the tips the fold says and the `verified/`
markers alone, which gives the same set and the same frontier (§4.3).

**Re-check and withdrawal.** Every change of what decides admission (a
`Members` or `Epoch` entry, an adopted trust context or person, a revocation, a
key that arrives, an entry that completes a cut's chain) judges again the held
entries it may affect, read from the store, not from memory. An entry applied
and now refused is taken out of the register or the fold — its place in the
register is taken by the entries in its `after` that nothing else applied
names, loaded by name — and the host is told (`Change::Withdrawn { id, why }`,
§10). An entry the trust layer refused after the fact stays refused until it is
offered again and verifies.

### 3.9 Threat notes

- **Equivocation visibility.** It is visible to the host for every entry kind,
  not only data (invariant 2). A silent choice between two `Members` entries
  would let one owner device un-sign a removal for some readers and not others.
- **What a relay learns.** Without sealing, everything. With sealing: the
  writer, seq, chain links, the digests the entry supersedes, the epoch id and
  the size of the ciphertext — **not the path** (§6.7).
- **A forged `after`.** A ref that names a digest the entry at that name does
  not have, or an entry of another path, supersedes nothing (§10.1, §10.8).
- **Unknown critical TLV.** A newer writer's critical field refuses the entry
  at an old reader rather than being misread; the entry is not applied, and
  the reader is told to upgrade.
- **A hole is not a retraction.** A gap statement lets readers stop waiting;
  it removes nothing a peer holds (§3.6).

### 3.10 The public wire module

The crate exports its wire format as `ndn_heap::wire`, so that a program that is
not a node (the conformance suite, §13) can build, name, read and digest
entries exactly as a node does. Nothing else of the module is public (the
names of grants, held copies, seal keys and signal runs, the pieces, the record
codecs, the TLV registry, the function that signs an entry are the layer's own).
There is no switch and no feature behind it: it is the format this section and §2
specify.

```rust
pub mod wire {
    pub struct Entry { pub prev: Option<Prev>, pub after: Vec<EntryRef>, pub body: Body }
    impl Entry {
        pub fn kind(&self) -> Kind;
        pub fn encode(&self) -> Result<Bytes, WireError>;      // the ENTRY TLV (§3.2)
        pub fn decode(content: &[u8]) -> Result<Entry, WireError>;   // §3.4
    }
    pub struct Prev { pub digest: [u8; 32], pub seq: Option<u64> }      // §3.6
    pub struct EntryRef { pub device: Name, pub seq: u64, pub digest: [u8; 32] }
    pub enum Kind { Put, Members, Epoch }
    pub enum Body { Put(PutBody), Sealed(SealedBody), Members(MembersBody), Epoch(EpochBody) }
    pub struct PutBody { pub path: Name, pub payload: Payload }
    pub enum Payload { Inline(Bytes), Blob { size: u64, root: [u8; 32] } }
    // SealedBody, EpochId, MembersBody, Op, Role, EpochBody: the shapes of §5, §6.
    pub enum WireError { /* §3.4 refusals */ }
    pub fn log_name(device: &Name, space: &Name, seq: u64) -> Name;       // §2.2
    pub fn signed_digest(wire: &Bytes) -> [u8; 32];                      // §1.5
    pub fn signed_digest_of(data: &Data) -> [u8; 32];
}
```

There is no public function that signs an entry. One that signed `entry` at any
`(device, space, seq)` with a `Signer` the caller passes would let a host make a device
equivocate (two entries at one name: its key is suspected everywhere, invariant 8), and
nothing outside the crate needs it: a node signs its own entries with its own key through
`Heap::put` and `Heap::change`, under the reservation of §4, and the conformance suite makes
a device write through them. A doctest of the crate fails if it is made public again.
`Entry::decode` reads the Content of a stored packet back (`Data::decode`, then
`content()`) into the fields it was built from, `log_name` names where it is stored, and
`signed_digest` is the id of its bytes.

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
  in the store, read from the own device's `ledger/` record (§4.3), which is
  written in the batch of every entry taken, decoding or not (a head taken from
  decoded packets would miss an entry that does not decode, and the device
  would sign again at its seq). It is one read at open: no entry and no piece
  is listed or read to find it, so a device with gigabytes of its own values
  starts in memory proportional to its devices and ranges (threat note M5).
  Pieces of an entry, other devices' entries and entries of a space that
  extend this one move nothing.
- **Structural entry:** a `Members` or `Epoch` entry.

### 4.2 The rules

1. A device MUST NOT sign at a seq above its durable reservation `R_durable`,
   and MUST resume at `max(own head, R) + 1` after an unclean start (§4.5).
2. A device MAY serve and announce an entry as soon as it is stored and
   applied (the store write returned).
3. A device MUST flush before serving or announcing a `Members` or `Epoch`
   entry, and before it signs under a reservation extension: a seq above
   `R_durable` waits for the flush that covers the extension. Whether an own
   entry may be served, and whether its epoch key may be granted, is decided
   under the space's lock, where the signing call that stores the entry also
   records it as held back: an Interest that arrives meanwhile cannot find it
   stored and not yet held back. The owner checks of `change` and of the epoch
   repair apply the same rule admission does (the name is under the owner's
   **and** the key is vouched for as the owner's person), so a device of
   another person under the owner's name is refused at once with `NotOwner`
   and starts no repair.
4. `put` returns when the entry is signed, stored and applied; with `durable`
   it returns after the flush that covers it (§4.7).
5. After an unclean start that leaves a hole (the first seq is not `own head +
   1`), the first entry MUST carry the signed gap statement (§4.5).
6. A device that hears its own name above its own head MUST NOT raise its head
   on that counter alone; it MUST fetch and verify the entries behind the
   counter and MUST tell its host (§4.8).
7. A failed flush stops signing past `R_durable` and the error says which
   disk; nothing already signed is retracted and reads continue (§4.6).
8. An own-name entry above the reservation the store held at open
   (`R_durable` then; this run's extensions do not count) is evidence of a key
   copy or a rollback: it MUST NOT be applied, MUST be stored, and MUST be
   reported (§4.8).

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
| `assembled/<entry name>` | 1 octet: every piece of the entry's value in pieces is held and proved (§8.5); a value not marked is not read | after the last piece arrives; in the entry's batch for a value this device wrote |
| `head/<S>` | own `seq` 8 ‖ its signed-region digest 32 (40 octets) | with every own entry |
| `reserve/<S>` | `R` 8 (big-endian) ‖ clean 1 (0 or 1): 9 octets | at open, at each extension, at clean close |
| `revoked/<S>` | 32 octets: the digest of the revocations of the readers' devices (§5.3 rule 8) that the last `Epoch` entry this device signed accounted for | after each Epoch entry this device signs |
| `rule/<S>` | 1 octet: the version of the owner rule (§2.1, §9.9) the space's entries were last judged by here; 1 is the role rule | at the first open of a space with no entries, and after the one judgement at start (and the fresh epoch an owner device of a sealed space signs) of a space stored under an earlier rule |
| `space/<S>` | 1 octet: 1 a space this node is a member of, 2 a space it only follows (§10) | when the space is created, opened or followed |
| `joined/<S>` | 1 octet, 1, then the 32-octet signed-region digest of each `Members` entry held that removes the device's person: an offer's answer admitted this device to the space and the fold does not list its person yet (§10.9); while it stands, a refusal for want of a listing is a wait | at `note_joined`, when the fold does not list the person; removed when it does, and when a removal of her arrives that it does not name |
| `structural/<S as TLV component>/<device as TLV component>/<seq 8>` | empty | with a `Members` or `Epoch` entry (start replays only these) |
| `heads/<S as TLV component>/<SHA-256 of the PATH TLV>` | the `PATH` TLV ‖ `ENTRY_REF`* | with the apply |
| `supers/<S as TLV component>/<device as TLV component>/<seq 8>/<digest 32>` | `ENTRY_REF`* of the applied entries that name the entry `<device>/<seq>` of that signed-region digest in their `after` (not recorded for a target held at another path than the namer's) | with the apply |
| `epoch/<S as TLV component>/<creator as TLV component>/<seq 8>` | the epoch key wrapped to this device's own seal key: a `GRANT` TLV (§6.5), the wrap's AAD the `Name` TLV of this very store key | in the batch of the Epoch entry, ahead of it |
| `equivocal/<entry name>` | the second packet | on equivocation |
| `suspected/<key name>` | `since` 8 octets, big-endian, ms (`Config.clock`) | when a key is suspected; one record per key, for the whole node: one map shared by every space's log, read once at start |
| `scoped/<person>` | the adopted trust context of a person (§9.4) | on adoption |
| `ledger/<S as TLV component>/<device as TLV component>` | what the node holds of one device: the length (2 octets) and the `Name` TLV of its person ‖ the seqs held as a count (4 octets) then `(low 8, high 8)` ranges, ascending, disjoint, non-adjacent ‖ the **counting gap statements** (§3.6) as a count (4 octets) then `(seq 8, prev seq 8)`, ascending; the seqs declared void are derived from them ‖ one octet, the device's **standing**: 1 an owner device where its person owns the space, 0 not (§2.1; a record without it reads as 1 until the one judgement at start, §9.9). At most 1,024 ranges and 1,024 gap statements (§3.8) | with every entry taken, when a gap statement stops or starts counting, and when the judge says a device's standing changed |
| `status/<S as TLV component>/<device as TLV component>/<seq 8>` | why a held entry is not applied, one octet, the kind and nothing more: 1 closed, 2 waiting, 3 not readable, 4 `NotMember`, 5 `OutsideCut`, 6 `Unsealed`, 7 `Sealed`, 8 `Untrusted`, 10 `Chain`, 11 any other (read back as `BadSignature`), 12 `NotOwnerDevice`; absent for an applied entry. What a refusal says besides its kind (the seq a cut keeps to, the judge's reason) is told to the host when the refusal is made, and is not stored: nothing reads it back | with the entry |

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
the **ledger**, written in the entry's batch, is the authority for the own head
(it lists the entry whether or not it decodes). A store that returns
from `apply` having kept only some of it, or reports a batch durable before it
is, defeats the barrier as a disk that lies does (§4.10).

The epoch key of a new epoch is written (`epoch/…`) in the **same batch** as
the `Epoch` entry that names it, ahead of it (§6.3), so a restart finds both or
neither. A stored key is no authority without its entry: a node takes a stored
key only if a held `Epoch` entry names its epoch and the key matches that
entry's key check (§6.2); otherwise it is dropped.

### 4.5 Reservation, open and resume

1. **Reservation.** Per (this device, space) the device keeps `R` durable. It
   MUST NOT sign a seq above `R_durable`. When the seq about to be signed
   exceeds `R − ⌊reserve_block / 2⌋`, the node writes `reserve/<S> =
   (max(R, seq) + reserve_block, clean 0)` straight to the store and asks the
   flusher for a flush; a seq above `R_durable` waits for it, and only a disk
   that stalls makes a put wait. `Config.reserve_block` is 1,024 by default.
2. **Open.** To open a space the node reads `reserve/<S>` and `head/<S>` and
   the own head from the own device's `ledger/` record (§4.1: one read; an
   own record that cannot be read refuses the open), recovering from peers
   first when the start is unclean and peers are known (§4.8). The start is
   **clean** iff the record says clean, `R` equals the seq of the `head/<S>`
   record, **and** the own head from the ledger equals that seq. The first seq
   to sign is **always**
   `max(own head, R) + 1`. Before anything is signed the node writes
   `reserve/<S> = (max(R, first seq − 1) + reserve_block, clean 0)`, clean
   start included, and asks for its flush; the first put waits for that flush
   only if it arrives before it completes. One flush at open covers every open
   space. The `R` the store answers with is durable only if every write made
   before it was read is: a node that left the space and opens it again in the
   same process reads the first run's `R` before any flush covered it. It
   counts as `R_durable` only when the flush that covers the writes so far has
   returned; until then nothing is signed under it (a seq the gate says Ok for
   is covered by the image a power cut leaves).
3. **A clean start has no hole:** it resumes at `head + 1`. A start whose `R`
   is above the head leaves a **hole** `(head, first seq)`, and the first entry
   signed after it carries the **signed gap statement**: `PREV` the
   signed-region digest of the entry at the own head and `PREV_SEQ` that head;
   when nothing is held, `PREV` 32 zero octets and `PREV_SEQ` 0 (§3.6). The node
   tells its host (`Alert::GapSigned { after, resumed }`). An unclean start
   with no hole (the first seq is `own head + 1`) states nothing.
4. **Clean close.** `Node::close` refuses new puts, drains the publisher,
   flushes, writes `reserve/<S> = (own head, clean 1)` for every open space
   whose next seq is `own head + 1`, flushes again and stops its tasks. The next
   start is clean. A space that started unclean and has signed nothing since
   keeps its `R` above the head (an earlier run may have shown those seqs), so
   its next start is unclean again. `Node::shutdown` (what `Drop` calls) stops
   at once and leaves `R` above the head: the next start is unclean, with a
   hole and a gap statement.

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
  no_peers`, where `no_peers` holds when no device other than this one is
  vouched for (an admitted entry of it is held in the log): the group's
  unsigned vector decides nothing, so a forged name cannot flip it. A
  structural change (`change`, `create`) always returns after the
  flush that covers it; the entry is then free for the publisher to release
  (§4.6).
- **`Node::flush()`** waits for a flush covering everything written so far and
  returns the sticky error if there is one.
- **`Node::close`** and **`Node::shutdown`** are §4.5, rule 4.
- **Counter = seq.** The producer counter of the space's sync group at join is
  the own head after recovery; every entry results in one publication (§4.6).

### 4.8 Recovery from peers, and counters heard

An unbacked counter never raises a head. A state vector names no sender and its
validator is insecure by default, so a forged `(D, 2⁴⁰)` could push a device's
seq up; counters only decide **what to fetch**.

1. **At every start with peers known** (an admitted entry of another device is
   held: clean or not, §4.5; an old image closed cleanly looks complete) the node
   waits up to `Config.settle` (1 s by default) for the first vector of the
   group, and then until the own-name entries it wants are fetched or each has
   been asked for in vain `FETCH_TRIES` (3) times. It fetches `head + 1 …` from
   the members heard (never from itself), through `32=held` (§2.2), at most
   `4 × reserve_block` above its head. **When any other device's entry is held
   in this space the node does this before its first publication**, waiting at
   most `settle` + 3 `lifetime`; with no such peer it does not wait: the same
   recovery runs in the background and what it fetches is handed to the log as
   it arrives.
2. **Adoption.** An entry is adopted only if it verifies under this device's
   key, carries the right name, chains to the previous (`PREV` equals the signed
   digest of the entry before it) and its seq is at most the reservation the
   store held at open (`R_durable` then). The node
   adopts the longest such prefix, raises its own head to it, and signs above
   it. Entries of the hole that are not in that prefix stay valid orphans.
3. **Evidence.** An own-name entry above that reservation that verifies is evidence
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
| Restored old image, peers online | the first vector shows this device's counter above its head | `RolledBack` raised; the own entries above that chain are applied; seq jumps above them; nothing re-signed |
| Restored old image that says **clean**, peers known | the node waits for the first vector (bounded by `settle`, liveness only) | `RolledBack`, seq jumps above what peers hold; nothing re-signed |
| Same, **no peer known** in the image | no wait is made | may sign a seq a peer holds: equivocation, detected at the first vector (§4.10) |
| Cloned or restored, no peer, later meets a peer | — | equivocation, attributable; key suspected; re-enrol the device (§4.10) |
| Own-name entry above `R_durable` seen | — | rule 8: `RolledBack`; applied when it chains |
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
  restored carries `clean`; with peers known (an admitted entry of another
  device held) the node still waits for their first vector and for the own
  entries it shows before its first publication (§4.8, rule 1), and then
  raises `RolledBack` and signs above. The wait ends on that signed data; its
  timeout (`Config.settle`) is liveness only, never a rule. **Residual:** with
  **no peer known** at that start (none held in the image) nothing is waited
  for, and the device may sign a seq a peer holds (equivocation, attributable,
  §3.7).
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

`Members` entries are signed by **owner devices** only (§2.1, §3.8 step 6).
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
3. **`epochs`**: `EpochId → (EpochBody, replaces)`, where `replaces` is the
   epoch ids the entry's `ENTRY_REF*` name. If an owner device signed two
   packets for one id (equivocation, which the log reports), the fold keeps the
   **least** by `(KEY_CHECK, AUDIENCE, replaces)`.
4. **`create`**: the `CREATE` of the carrier of lowest rank (and, for one
   carrier, the lower `ANYONE`). Until a `CREATE` is known the fold reports
   none; the log then neither accepts nor refuses a write for the space's
   seal (§3.8 step 8) and an own write answers `NotReady`.

A carrier is identified by `(device, seq, signed-region digest)`: two
equivocating packets are two carriers.

### 5.3 Rules

1. **Facts.** The state is the sets of §5.2. Applying a `Members` entry or an
   `Epoch` entry is **idempotent and commutative**; the fold trusts its caller:
   only entries signed by owner devices are applied (§3.8 step 6).
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
5. **Audience and holders.** Two sets are kept per epoch `E`, because removing a
   person takes back a promise and not a key.
   - `audience(E)` is whom `E`'s key is **to be given** now: the persons the
     epoch's `EPOCH_BODY` lists **plus** every **standing** reader whose `ADD`
     names `E`. A person the epoch lists who is no longer a reader stays in it.
     Grant condition 2 (§6.5) reads this set.
   - `holders(E)` is who **holds, or was admitted to hold**, `E`'s key: the
     persons the epoch's `EPOCH_BODY` lists **plus** every reader any `ADD` ever
     named to `E`, **removed or not**. A removal never shrinks it. (A reader
     added by `change` is written with `EPOCH_ID` = the epoch in force, is
     granted its key at once, and keeps it when removed: its removal leaves
     `audience(E)` as it was and `holders(E)` as it grew.)
6. **In force.** An epoch is **replaced** when a held `Epoch` entry names it in
   its `ENTRY_REF*` (§3.5, §6.3). `in_force()` is the epoch with the greatest
   `(creator name, seq)` (NDN canonical order of the creator, then the seq)
   among the known epochs that no held epoch replaces and whose `holders(E)` is
   a subset of `readers()` (the owner counted among them); none if there is
   none, and none for a public space. `complete()` holds iff `holders(in_force)`
   equals `readers()` exactly; a public space is always complete.
7. **Repair.** Owner devices MUST sign a new `Epoch` entry, whose audience is
   `readers()` and whose `ENTRY_REF*` are the epochs no held epoch replaces
   (the **tips**, at most 8, the greatest ids), whenever a sealed space is
   **not** `complete()` (§6.3), and whenever a key of a reader's device is
   revoked and no epoch the device signed accounts for it (rule 8). A writer
   MUST NOT seal in any epoch but `in_force()` (§6.4). Concurrent owner devices
   may sign duplicates: all have equal audience, `in_force` picks the greatest
   id, and nothing is lost.
8. **Revocation of a reader's device key.** A revocation changes no member, so
   the fold alone cannot tell that the key in force is out of hand. An owner
   device therefore keeps, per space, the digest of the revocations (of keys
   under the namespace of a person `readers()` lists) that its last `Epoch`
   entry accounted for (`revoked/<S>`, §4.3), and signs a new epoch (rule 7)
   whenever the revocations it holds now are not those: at start, and whenever
   a trust context or person is adopted. The new epoch **replaces** the epoch
   in force, so it is the one in force whatever the order of the creators'
   names. Two owner devices may each sign one; a restart signs none more.

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
| `audience(E)`, `holders(E)` | rule 5 |
| `epoch_tips()` | the epochs no held epoch replaces, ascending (rule 6) |
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

A removing owner device lists, **per device of the removed person that it holds
verified entries of** (devices whose person is the removed person), one
`ENTRY_REF`: the highest seq it holds of that device in this space, applied or
not, and its signed-region digest, collected within `Config.first_look` (4 s by
default). A writer lists at most 64 tips (`TIPS_MAX`); a person with more
devices than that is cut at 64, and the devices left out are **outside the cut**
(the fold itself unions the tips of repeated `REMOVE`s of one `ID`, §5.2). What
an owner never held is likewise outside the cut: an entry of a device above its
tip, or one the owner never saw, never counts (the stated trade-off; §4.10). A
person who is both writer and reader has two `ADD`s with two ids; removing "from
both roles" is one `REMOVE` per standing `ID` of the person (`standing_ids`),
each carrying the same tips, and only the writer `ADD`'s tips count (rule 4).
The cut is applied by every reader as chain ancestry of the tips (§3.8): the
tip's digest binds every entry below it.

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
  key (§6.5) and so cannot seal (§6.4): their `put` answers `NotAllowed`, and
  the owner SHOULD list every writer of a sealed space as a reader too.

## 6. Seal and grants

### 6.1 Public and sealed spaces

A **public** space (`CREATE` with `ANYONE` 1) has no epochs and no sealed
entries: a sealed Put in it is refused (`Sealed`, §3.8 step 8). Every other
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
  from received entries that it is not (§5.3 rule 7);
- whenever a key of a reader's device is revoked and no epoch it signed accounts
  for it (§5.3 rule 8).

The entry's `ENTRY_REF*` are the epochs no held epoch replaces (§5.3 rule 7).

The ceremony is, in this order: allocate the seq the entry will have (under the
reservation, §4.5); generate the key; hold it; compute the key check; wrap it to
this device's own seal key; sign the entry with the audience the owner device
gives (`readers()`, owner first, then sorted); write, in **one batch**, the
wrapped key at `epoch/<S>/<creator>/<seq>` (§4.3) and then the entry with its
records; flush; publish. A sealed space has **at most 256 readers**, the owner
counted, because an `AUDIENCE` holds at most 256 persons; `create` and
`change` check it **before anything is signed** and refuse with `BadRequest`
(a sealed space lists at most 256 readers, the owner included).

### 6.4 Sealing a write

A writer to a sealed space MUST seal in `in_force()` and in no other epoch; if
none is in force, or it does not hold the key of the one in force, the write
answers `NotReady` (next step `RetryLater`) and the node asks for the key (§6.5).
A writer whose person is not in the audience (no reader, §5.7) is told at once
`NotAllowed` (`AskOwner`), since its key never comes.
The **plaintext** sealed is the TLV bytes of a `PATH` followed by exactly one of
`INLINE` or `BLOB` (§3.3), so the path, a removal (an empty `INLINE`) and the
blob's root are inside the ciphertext. The entry is
`SEALED { EPOCH_ID, CIPHERTEXT }` with `ENTRY_REF*` left plain. A payload over
6,144 octets travels in pieces (§8); a sealed payload is sealed whole before it
is cut, so holders of the pieces see only its size.

A reader opens a sealed entry with the key of the epoch it names; without the
key the entry is **held closed**: kept, chained, its path unknown. `get` on a
space with any entry held closed answers `NotReady` (`RetryLater`) to a reader
whose key is on its way by grant, and `Sealed` otherwise (the path of a closed
entry is unknown, so no answer would be complete; §10.3).

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
as AAD. Every ask carries the device's own seal key packet as it signed it.

**Granter side.** A device `G` answers `<G>/32=grant/<GrantAsk>` **only when all
six hold**, checked in this order:

1. a held owner-signed `Epoch` entry names `E` (`EpochNotNamed`);
2. the asker is no guest, node or role-less device of the owner: where the
   asker's person is the owner, the asking device's role is `admin` or `member`
   (`NotOwnerDevice`; §2.1, §9.9) — the owner's person is in every audience, but
   only its `admin` and `member` devices hold the owner's powers;
3. `audience(E)` contains the asker's **person** — the person of the device
   `D` of the seal key name in the ask (`NotInAudience`);
4. `readers()` contains that person **now** (`NotReaderNow`): a removed
   reader fails here for every later ask;
5. `G` holds the epoch's key (`KeyNotHeld`);
6. the key that signed the asker's seal key packet is **not revoked** by a trust
   context `G` holds (`AskerKeyRevoked`): known only once the packet is judged,
   so it is checked after the judging.

Anything else gets **no answer**, and `G` sends no Interest for any ask: the
exchange is one Interest and one Data. Conditions 1–5 are decided first, from the
ask's names alone, before the packet in it is decoded. Then `G` decodes the seal
key packet the ask carries — `<D>/32=seal/<pk>` — and verifies it (§6.2: signed
by a key of `D`, chained to `D`'s person's trust context as any packet of a
device is, the Content equal to `pk`; kept once verified); all six conditions
are checked **again** after the judging, with the key that signed it, since the
records may have moved. It answers with the key wrapped to `pk` (§6.2) under the
**grant's own name** as AAD, signed by its device key. `pk` is the key of the
packet `D`'s device signed, never a key the ask names on its own: a grant ask
made by anyone but `D` cannot make `G` wrap the key to any key but `D`'s.
One name has one packet while it is kept; a granter keeps its last
4,096 grants and the last 4,096 seal keys it verified (with the key that signed
each), **for one generation of its judge**: a counter that moves whenever a
revoking context is adopted or a person's newer version refuses more
(`Judge::generation`). What was kept under another generation is not served;
the packet is judged again. It works on at most 32 asks of one asker device at a
time; a packet that does not verify gets no answer, and the asker's next round
asks again. An epoch that
this device itself made is not granted until its `Epoch` entry has been
flushed (it is not servable before), so that a power loss cannot take the entry
and leave the key granted. Every ask a device does not answer is Nacked, never
left to time out.

Why the exchange is one: an ask that made the granter fetch the asker's seal key
packet put two exchanges inside one Interest lifetime (the ask, the granter's
Interest for the packet, the packet, then the grant: four legs, two of them Data).
On a path that delays and drops Data (the suite's faulty profile holds a Data up
to 1.9 s on every link and drops one packet in five) the four legs together
outlast the lifetime almost always: in the suite's k2 under `--faulty --fault-seed
2`, none of the phone's 34 grant asks was answered in time and 2 of the 17 seal
key fetches arrived, so the key never came within the case's 120 s. The asker
has the packet, signed, and is the one party that must send it; the granter's
judging of it is local.

### 6.6 Forward only

Said plainly (invariant 9): a **removed reader is refused every later grant**
(condition 3), and the new epoch that its removal forces has a key that did not
exist before; a **device whose key is revoked is refused every later grant**
(condition 5), whatever its person may read, and the epoch the revocation forces
(§5.3 rule 8) has a key it was never given. **What a removed reader or a revoked
device already opened it keeps**, and a key it was already granted still opens
what it sealed. A reader added by an `ADD` that names the
current epoch reads that epoch's history; an epoch that ended before a reader
was listed stays **closed** to it. To open an earlier epoch to a reader the
owner adds it with that epoch's `EPOCH_ID`; the reader still joins the epoch in
force through the new `Epoch` entry the addition requires (§5.3 rule 7). The
same reader, once removed, makes that epoch **outgrown** though its audience did
not change: the epoch stays in the readers' history and leaves force (§5.3
rule 5).

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
- **A captured ask replayed.** A grant ask is a name, and a name can be sent
  again by anyone who saw it. It gives the replayer nothing: the reply is
  wrapped to the seal key inside the packet the ask carries, which the asker's
  device signed, so only the holder of that recipient key opens it, and the
  granter takes the key to wrap to from nowhere else (the ask names no key of
  its own). A replayer cannot put its own key in the ask either: the packet must
  verify as signed by the asker's device. Every ask is decided afresh, so a
  replay after the asker's person was removed from the readers, or after its key
  was revoked, is refused as the asker's own ask would be (§6.6), and the kept
  grant answers only within the judge's generation it was made in.
- **Stolen epoch key.** An epoch key a thief holds opens what it was sealed in;
  revoking the device's key rotates the epoch for what follows (§5.3 rules 7–8),
  it does not recall (invariant 9). Between the theft and the revocation the
  thief reads what is written, and nothing here narrows that window.
- **A reader added after the creation, then removed.** The reader holds the key
  of the epoch it was added to, though that epoch's body never listed it. An
  epoch stays out of force while anyone who ever held its key is no reader
  (`holders`, §5.3 rule 5), so a new epoch is signed and the removed reader
  does not read what follows.
- **A kept answer outliving a revocation.** A granter's kept seal keys and
  grants are valid only for the judge's generation they were made in (§6.5): a
  revocation clears them, so a revoked device is judged again, never served from
  what was kept before.
- **A forged ask.** An ask names no sender; a stranger's ask costs the granter
  no signature check (conditions 1–4 are checked first, from the names alone),
  and one that passes them for a real reader's device costs at most one
  judging of a packet of at most 2,048 octets, under the per-asker bound of 32.

## 7. Sync and fetch

How a node learns that a device wrote, fetches what it wrote, catches up, serves
what it holds and pulls an epoch key. Nothing here decides what is true: every
packet fetched goes through admission (§3.8), and a sync notice decides nothing
(§7.2).

### 7.1 One group per space

A node joins the sync group of each space it holds (§2.5) as one State Vector
Sync producer named by its device name, through **one** SVS driver for all its
groups. The groups' configuration is the node's `SvsConfig` with three fields set
per group: `local_seq`, the producer counter at join; `max_producers`,
`HEARD_MAX` (64) devices besides this one; and `vouch`, a device is vouched for
exactly when an admitted entry of it is held in the space. The dialect is SVS
version 2 as `ndn-sync` implements it; this layer adds no wire to it and uses no
two-phase acknowledgement. The sync face registers the owner's prefix
`<O>/32=sync` once, however many of `O`'s spaces the node joins; the forwarder's
own routes carry the Sync Interests (§7.9).

- **Counter = seq.** A producer's counter in a space is its own seq there, so
  the vector entry `(D, n)` names exactly `<D>/32=log/<S>/seq=<n>`. Every own
  entry results in exactly one publication of the group, in seq order (§4.6).
  The counter at join is the own head (`Log::head()`): a publication sets the
  counter to its entry's seq (`MultiSvs::publish_at`), so a seq that was never
  signed (a hole a crash left, §4.5; a rollback's jump) is announced only with
  the entry that declares it, and readers ask nothing in `(head, R]` (M1)
  (above a hole that a crash left, §4.5, the hole is declared by the next
  entry's gap statement); a **follower** (§10) joins with counter
  0 and publishes nothing. A peer asking for the entry at a counter above a hole
  gets no answer until a later entry declares the hole (§3.6); the asks pause and
  grow (§7.4).
- **A notice is unauthenticated.** A Sync Interest names no sender and its
  validator is insecure by default.

### 7.2 The notice decides nothing

An update `(D, high)` of a group is handled so:

1. **Counter 0** names no entry and is ignored: the device is not heard, takes no
   room and displaces no one.
2. **This node's own name** is never fetched from itself: a counter above the
   own head raises `Alert::UnbackedCounter` and nothing else (§4.8), and wakes the
   recovery's fetch from other members.
3. **Another device** is *heard*: kept in a list of at most `HEARD_MAX` (64) per
   group, each with when it was last heard. Past the bound the device heard
   longest ago that **nothing held vouches for** is dropped (the device just
   heard when every other is vouched for), else the one heard longest ago: a
   name a Sync Interest carried never displaces a device that signed data held
   here. A dropped name is walked no further.
4. The log is told nothing of another device's counter (M4): the entry the
   counter names is **probed** when the log neither holds it nor asks for it,
   alone for a stranger, `FETCH_TRIES` (3) asks and then asks after a pause that climbs
   from 4 s, doubling, to 16 s (`PROBE_PAUSE_MAX`; r5 under loss: a device away for a minute
   and back must not wait 64 s after one lost ask; a forged counter's steady cost is one
   ask per 16 s per name); the holes below it are wanted once it is held and verified.
   **The ladder belongs to the device**: a higher counter changes the entry the probe
   names and never its pauses, and at most 8 (`PROBES_MAX`) probes of a group are in
   flight (the devices with the fewest misses first, vouched ones before strangers, then by
   name), so counters that rise at every Sync Interest cost one ladder each, not an ask
   each. A device the log vouches for has up to 4 (`PROBE_FLIGHTS`) of its counters asked
   at once (a writer that never pauses names a new entry every few milliseconds, and the
   entry a notice names is often not to be had when asked; o4 under loss): the asks that
   nothing answered pause a quarter second, 16 in a row (`REFRESH_TRIES`) then a minute,
   and a packet that took nothing (a forgery) pauses as a want's does, growing; an ask
   of any of its counters that takes something ends the run. A forged counter for such a
   device costs 16 asks and then one a minute. A probe that is answered ends the
   run: the device's next counter is asked at
   once. This device's own counter is told
   (`note_own_counter`: `UnbackedCounter` above the head, and the entries within
   `R` wanted). A device nothing vouches for yet costs the same one probe; the
   log hears its entry only once admitted.

A notice only **names an entry to probe**; nothing it says is believed: a
forged vector entry changes no wants and no state, and a replayed old one never
ends an ask (§7.4).

### 7.3 The hot path: one notice, one fetch

The entry a notice names is `<D>/32=log/<S>/seq=<high>`. It is fetched
**directly** from `D`, **first and alone** while nothing at or above it is held
(its own gap statement may declare everything below it void), as one Interest
with a lifetime of `Config.lifetime` (4 s by default), verified and taken
(§3.8). Only after that is the rest below it asked for (§7.4). One new entry
therefore costs one Interest.

An ask is made by an **expressed** Interest: if nothing answers within the
retransmission timeout, the same Interest is expressed again under a fresh
nonce, up to 3 times within the lifetime; the timeout is the smoothed round
trip plus four times its variation (RFC 6298; only an ask answered by its first
Interest gives a sample; none before the first sample: then the timeout is one
second, RFC 6298 §2.1, so a lost first Interest is expressed again within the
lifetime), doubled for every ask since the last sample that needed a
re-expression or missed, at least 250 ms (a forwarder holds back a fresh-nonce
Interest from the same face for about that long), at most the lifetime, and
doubled again at each re-expression of one ask. A Nack with reason Congestion
is asked again by the consumer after a short jittered pause, and cuts the device's window (§7.4). The node has `Config.in_flight` (256) slots for asks, shared by
kind so that nobody's asks starve the others': the asks of the wanted entries and
pieces (**walks**) hold at most three quarters of them, one device's walks at most
half; the probes (§7.2) at most an eighth; a grant pull takes from what is
left, so it finds a slot whoever floods the
walks. An ask waits for its slots at most one lifetime and is then a miss.

A **miss** is: nothing answered in time; a Congestion Nack that asking again
soon did not mend; a packet refused as not genuine (a forwarder's
`bad-signature` is final for that packet, never for the name); no slot. A miss
is *again*. Any other Nack, or the connection ending, is *gone*: asking another
source may still get it. **A miss decides nothing** (§7.4).

### 7.4 What is wanted, and asking again

The log says what is **wanted** of the space, and the fetch asks for it until
the log holds it; nothing else ends an ask. This is *level-triggered*: a notice,
a restart, a lost packet or a refusal changes nothing about what is owed.

- **The holes.** For each device walked (an admitted entry of it is held, or it
  is this device, or a removed one), every seq from 1 up to the highest *held*
  that is neither held nor **void** (declared absent by a held gap statement,
  §3.6). A heard counter adds nothing here (it is unsigned): the entry it names
  is probed alone (§7.3), and only once it is held and verified are the holes
  below it wanted. Entries inside a declared void are **never asked for**; an
  undeclared hole of another device is asked a block at a time: the seq below a hole
  is held or void, so only the first `reserve_block` seqs of each hole are asked,
  that is at most `reserve_block` above what is held, and the next ones once those
  are held (the hole's start moves up) or a later entry declares the rest void. A
  device that signs an entry at seq 10^9 and nothing between therefore costs a
  few asks (its window), never the walk of 10^9 seqs. For this device the heard
  counter is also believed up to `R` (what an earlier run could have signed),
  `(head, min(seen, R)]`.
  The prefix a device is held to is the largest `n` with every seq of `1..n`
  held or void.
- **The entries a cut names.** A revocation cut a held trust context lists (§9.5) wants the
  seqs it keeps that are neither held nor void, whatever counter the group shows, and the
  entries it re-admits one by one, by their implicit digest: the bytes must be those. Only
  the cuts of keys the context itself governs count, those under its own namespace: a
  context another person signed that lists a cut for someone else's device says nothing
  here, and wants nothing (an adopted friend's context cannot make a node walk another
  person's log). An exact entry is held only when the packet at its name (the first one
  taken) has those bytes: the same bytes kept as evidence beside others (§3.7) are not the
  entry, and are asked for, and §9.7 takes them in place of the others when the judge
  accepts them. The exact asks are windowed as the holes are, below.
- **Windowing.** The asks of one device in flight, or pausing after a miss, are at most
  its **window**, which the node keeps per device (not per space or value: the asks of
  every space and every value in pieces count against it). It starts at 16, grows by
  one for every ask answered (it doubles each round), is at most `Config.window` (128)
  and half of `Config.in_flight`, and halves, to at least 2, after a round (as many
  asks answered or timed out as the window is wide) in which more asks timed out than
  were answered. **A Congestion Nack cuts it too:** the path says it is over a rate (a link's
  quota of what one key may ask or be answered), so the window halves, to at least 2, at
  once, **once for all the asks that were in flight** (an ask carries the number of cuts its
  device's window had when it began; the Nack of an ask that began before the last cut says
  what that cut already answered), and from then on it grows by one a round, not by one for
  every ask answered, until it is cut again. A window that doubled back every round would
  meet the rate again at every transfer, with a Nack for each ask over it, and a link Nacks
  only so many a second (`CONGESTION_NACKS`, 256 at once and 128 a second per link: what is
  Nacked past it is dropped silently, and its asker left to its timer). An ask that was
  asked again after Nacks only (none by the timer) gives no round-trip sample and does not
  double the timeout. Loss is not silence: a path that loses a third of its asks answers
  more than it misses and keeps its window, so 1,200 owed entries over a path of over
  a second's round trip that loses a third of its asks are still held within a minute
  of virtual time (with a window of 32 they took 87 s), what a reader of an
  entry-per-save writer (o4) needs to keep up; a device that answers nothing is down to
  2 after a few rounds, however many seqs lie below its newest entry. A reply that is not
  genuine counts neither way. An ask that missed holds its place in
  the window while it pauses (until it has missed 16 times in a row, when it waits a
  minute at a time and holds a place only while asked), so the walk does not slide on
  over the seqs nothing answers. The asks go in seq order, the entry at the highest
  seq first and alone while it is not held (§7.3).
- **Own entries** are wanted only up to `4 × reserve_block` above the own head
  (§4.8).
- **Sources.** The ask goes to the **writer** by its own name; after a miss to
  the next source: the **heard members** vouched for, through
  `<H>/32=held/<Name TLV of the original>` (§2.2), at most `RELAYS_ASKED` (8) of
  them, those of which this node holds an unbroken prefix of their own log
  leading, never this node or the
  writer. Miss number `m` goes to the writer when `m` is even, and to the `⌊m/2⌋ mod k`-th
  of the `k` heard members when it is odd (the writer holds what it signed; a member
  holds a hole only if it got it, and the members that heard of a hole are as many as
  miss it too, so a ring over all of them left a hole only the writer held for minutes
  at 20 % loss). A relay's answer is the
  original packet, whose name MUST equal the name asked for; the original is
  verified as if it had come from the writer. An own entry is asked of relays
  only (miss `m` goes to the `m mod k`-th).
- **Asking again.** After an ask resolved, the next look at the same entry waits
  250 ms. After `m` misses in a row an ask waits 250 ms × 2^`m`, at most 4 s;
  from 16 misses in a row, 64 s: a source away for long costs one ask a minute,
  until the entry comes or is no longer wanted. A refused packet (a forged copy,
  an entry whose judgement is pending) is not held, so it stays wanted and is
  asked again the same way; a genuine copy from another source ends it. An
  answer that resolved nothing counts as a miss too (L2): a packet the log
  already knew while it still wants the entry, or evidence; and for an exact
  entry a removal cut names, other bytes than the cut's signed digest are not
  handed to the log at all, so the next source is asked.

Pieces of a value not yet whole (§8), epoch keys that are owed (§7.8) and the
certificates and cut manifests a judgement waits for are owed the same way.

### 7.5 Catch-up at open

At open the log holds what the store held, so what it wants at once is the holes
below the highest seq of each device it holds. Every `(device, high)` the group's
vectors then carry is a notice, and for each one above the prefix the node holds
the same plan runs. A returning device fetches only what changed. Its own entries
are recovered first, by §4.8.

### 7.6 Serving

A node answers an Interest by the keyword after its own name (§2.4); every
Interest it does not answer is **Nacked** (`NoRoute`), never left to time out.
A name under `/localhost` is never served.

| Name | Answer |
|---|---|
| `<D>/32=log/<S>/seq=<n>` with `D` this device | its own entry at that seq, if held, verified and not held back (a structural entry not yet flushed, §4.2 rule 3) |
| `<E>/32=piece/…` with `E` this device's entry | the piece, if the entry is served |
| `<H>/32=held/<Name TLV>` with `H` this device | the packet named — another device's entry, or a piece — **only if it is held and admitted** (a follower serves what it verified), wrapped as the Content of a DigestSha256 packet, so it carries no claim of having been signed by this device |
| `<D>/32=seal/<pk>` with `D` this device and `pk` its recipient public key | its seal key packet |
| `<G>/32=grant/<ask>` with `G` this device | by §6.5 |
| `<D>/32=<keyword>/…` with `D` this device and `keyword` registered by an extension | by §10.9: what the extension answers, else Nacked |

An entry is served from the entry's own record: held and verified, and either
applied or held closed; one refused, waiting or unreadable is not served.

### 7.7 Face up

A link coming up is when someone can hear what was announced while none was. The
forwarder's routes are the trigger: a route whose prefix covers a joined group,
added to its FIB on a face that is not a local application's, makes the node
announce that group's state vector at once instead of at the group's next period.
The announcement is the one a join makes; nothing about the devices heard is set
by it. It is bounded: at most one announcement per group a second, and at most 32
a second over all groups (a batch is deferred, never dropped). A connection that
cannot tell routes gives none, and the periodic announcement alone runs.

### 7.8 The grant pull, network halves

The conditions and the cryptography are §6.5. As implemented:

- **Reader.** A device owes the key of an epoch when a held owner-signed `Epoch`
  entry names it, this device's person may hold it, it does not, and an entry
  waits for it or it is the epoch in force. It asks `<G>/32=grant/<ask>` of the
  epoch's creator (unless it is this device) and then of the heard members
  vouched for (at most 8), one after another, round after round with the pause
  of §7.4, for as long as the key is owed. It never asks a name that only a Sync
  Interest carried. A grant is judged as a packet of the granter's device
  (§9.1), unwrapped with the recipient key under the grant's name, and taken
  only if the log accepts it (§6.2); one that fails is dropped and the asking
  goes on. The ask is built once per epoch owed from this device's own seal key
  packet, which the node signed at start (`SEAL_KEY_PACKET`).
- **Granter.** §6.5, with its bounds (asks per asker, grants kept).

### 7.9 Routing is the forwarder's

This layer installs no routes. A deployment makes the owner's sync prefix
`<O>/32=sync` reach the other devices (the forwarder's group strategy and routes
for the namespace), and the entries' and pieces' names route to their devices by
their own prefix (§2.2). A sync face that registers `<O>/32=sync` receives the
Sync Interests of every group of every space of `O`.

### 7.10 What the previous design did that this one does not, and what it has back

The previous design **hailed** (it asked a group again for its members' state,
with a growing pause, when a first look found no device heard) and **heralded**
(it announced its newest change again while no member was heard to have taken
it). This layer does not hail without bound: a group's own period and the
announcement at every link coming up (§7.7) repeat what is announced, and
because the fetch is level-triggered by what the log wants (§7.4), no peer's
progress depends on hearing a notice a second time once a peer is heard at all.
It hails once per join, in the bounded form below.

It heralds, in a form the faulty runs of the conformance suite (§13, `o5` at
seeds 3 to 6) required. A notice is what makes a peer want an entry at all (a
counter names it), so a notice lost on its way to the only peer that wants the
entry cost that peer a whole group period (half a minute by default; `o5` took 32
and 62 s against a bound of 10 s). A device therefore announces its newest own
entry again after each pause of the capped doubling of §7.4 (250 ms, 500 ms, 1 s,
2 s, then 4 s) until a peer is seen to have taken it: a peer's vector carries this
device's counter at that seq, or a peer asked this device for that entry or a
later one. Three announcements are made whatever is seen (a group has several
peers, and the one that took the entry says nothing of the others), and at most
eight for one change; a newer own entry starts the pauses again. Nothing is kept
per peer, and what is announced is unchanged: a counter names an entry to be
fetched and judged, never a head (D17), so an absent peer or a forged counter
costs a bounded handful of Sync Interests per change, never one per period.

What ends the announcing early is not signed, and that is a **bounded residual**: any
requester of the newest entry (an Interest names no sender) or a vector that carries
this device's counter (a Sync Interest is unsigned) stops it after the three
announcements made whatever is seen. A stranger can thus cut a change's re-announcing
to three; a lost notice is then heard at the group's next period, a delay and never
a wrong state (a counter names an entry to be fetched and judged, D17). No signed signal
closes it: the only evidence of a peer holding the entry that a peer signs is an entry
of its own that supersedes this one on the same path (`after`), which most puts never
get, so waiting for it would make every put announce eight times to save a stranger
three.

It hails, in a form the faulty runs of the conformance suite (`p1` at seed 1)
required. A device that joins a group announces itself at once, and a peer that
is ahead answers with its vector; both Sync Interests must cross the link, and
when one is lost nothing else comes before the group's next period (`p1`'s
laptop joined a space its phone wrote into, the phone's answers were lost three
times in a row, and the first notice of the phone came 95 s after the join, when
the 120 s a host retries a refusal for were nearly spent). A device
therefore announces a group it joined again after each pause of the same capped
doubling until a notice of the group is heard (a counter of any device,
this one included), at most eight times; peers that wrote nothing never answer,
and cost the bounded handful and no more.

### 7.11 Timeline events

For measurement, a node emits `tracing` events at level `trace` under the target
`ndn_heap::timeline`, one per seam a put crosses to another device's watch:
`put_returns`, `flush_begin`, `flush_end`, `announce`, `sync_update`,
`fetch_out`, `fetch_in`, `fetch_miss`, `verify_begin`, `verify_end`, `judged`
(the judge decided a fetched entry), `admitted` (the log took it), `routed`
(its changes were told and its effects routed) and `watch_send`. They change
nothing a node does; the `put_watch` example records them (§13.8).

### 7.12 Threat notes

- **Forged notices.** A stranger can name any device at any counter. It costs a
  list of at most 64 names per group, vouched-for devices never displaced, and,
  per device, entries probed: of a stranger one at a time, `FETCH_TRIES` (3) asks, then
  asks after a pause climbing from 4 s, doubling, to 16 s (liveness: a device that was
  away for a minute and speaks again is asked within 16 s; a forged counter's steady
  cost is one ask per 16 s per name, however often it rises: the ladder is the device's,
  not the counter's, §7.2); of a device the log vouches for, see §7.2 item 4.
  At most 8 probes of a group are in
  flight and at most an eighth of the node's slots hold probes, so counters that rise
  at every Sync Interest of 64 names (M2) take no slot an owed ask or a grant pull
  waits for. It raises no head, no
  want and no head of `ready()` (a counter wants nothing of the log: M4), ends
  no ask (D17, §4.8), and cannot flip `put`'s `durable` default (`no_peers` is
  decided by vouched devices in the log, not by the unsigned vector).
- **One device pins the slots (M3).** A writer's device that signs an entry at a huge
  seq with no gap statement, and answers nothing, leaves a hole of that size that
  every member is owed. What is asked of it is its window (starts at 16, down to 2
  while nothing answers, §7.4), the first `reserve_block` seqs of the hole only, at
  most half of the node's slots whatever the spaces, and the asks that missed keep
  their place in the window instead of letting the walk slide on. The same holds for
  pieces nothing serves (they take the device's window and slots). A grant pull, a
  seal key and the probe of a device not asked yet find a slot (§7.3).
- **Strangers' entries (L7).** A device certified in a held context that is no
  member has at most one refused entry stored and one alert per device: a
  probe of it (`Host::take(.., probe = true)`) is neither stored nor told when
  that device already holds one and nothing of it is vouched for. Its holes are
  not walked. An entry the log asked for is stored as before.
- **A stranger never answers for another or grants.** Only devices vouched for by
  an admitted entry are asked as relays or granters.
- **A poisoned cache** or a forged relay: the inner packet fails verification or
  carries another name; it is dropped, nothing is kept against the name, and the
  next source is asked (§7.4).
- **Replayed notices** never make a reader stop asking for a newer entry: the
  notice names the entry by construction and the want never shrinks except by
  holding (§7.4).

## 8. Large payloads: pieces

A value over 6,144 octets is **cut into pieces** under its entry's name; the
entry holds only the value's size and the digest of the root of the pieces'
manifest tree. Each piece verifies alone, from whichever holder it came from.

### 8.1 Shape

A payload of `size` octets (at most `PAYLOAD_MAX`, 67,108,864 octets) is cut into
`chunks = max(1, ⌈size / 4096⌉)` chunks of `CHUNK` = 4,096 octets (the last
carries the rest). The chunks are listed by a **manifest tree** of fan-out
`FANOUT` = 128: `depth` is the least `d ≥ 1` with `128^d ≥ chunks`; level `l`
(the root is level 1) has `⌈chunks / 128^(depth − l + 1)⌉` nodes; nodes are numbered
**in heap order** from the root, node 0, the first node of level `l` being
`(128^(l−1) − 1) / 127`. A node of the bottom level lists up to 128 chunks; any
other lists up to 128 nodes of the level below. The tree's shape follows from
`size` alone.

### 8.2 Pieces

| Piece | Name | Content |
|---|---|---|
| chunk `i` | `<E>/32=piece/seg=<i>` | the chunk's octets: exactly 4,096, but the last, which carries `size − 4096 × (chunks − 1)` |
| manifest node `k` | `<E>/32=piece/32=manifest/seg=<k>` | `DIGEST`*, 1 to 128 of them: the **implicit digests** (§1.5) of the packets of the children it lists, in order |

Every piece is a Data packet signed DigestSha256, so no key signs a piece and
its implicit digest names exactly its bytes. The entry's `ROOT` is the implicit
digest of node 0.

### 8.3 Sealing

A sealed value is **sealed whole first** (§6.2, `nonce ‖ tag ‖ ciphertext`, the
AAD the entry's `Name` TLV) and the ciphertext is cut: `SIZE` is the ciphertext's
octets, and a holder of the pieces learns the value's size and nothing else. In a
sealed space the entry is `SEALED`, whose plaintext holds the path and the
`BLOB { SIZE, ROOT }` (§6.4).

### 8.4 Writing

A writer cuts the payload (sealed first, if sealed) for the entry name of the seq
it is about to sign, and writes **all the pieces and the `assembled/<entry
name>` record in the one batch of the entry** (§4.4), the pieces ahead of the entry's records. Because the seq and the epoch
are fixed before the work is done, a writer that finds either moved before it
signs does the work again. A value over `PAYLOAD_MAX` is refused (`TooLarge`,
limit `PAYLOAD_MAX`).

### 8.5 Reading

A reader gathers the pieces of one value with these rules:

1. It asks for the **manifest nodes first** (each unlocks up to 128 more), then
   chunks in order, at most the writer's window (§7.4: it starts at 16 and is at most
   `Config.window` (128); the asks of the values gathered at once, up to 4, share it)
   at a time, from the writer and then the heard members (§7.4); the root's digest is
   the entry's `ROOT`.
2. It names and accepts a piece **only** if its parent, already held, lists its
   implicit digest, its name is the piece's, a node lists as many digests as its
   place in the tree holds and a chunk has as many octets as its place holds. A
   copy that is not the listed one is dropped alone and the piece is still
   wanted; a piece that is no piece of this payload is ignored.
3. **A proved piece is stored at once**, in one batch with the others its round
   proved (a piece is only ever read through the tree, from the digest the
   entry carries, so a stored piece of an unfinished value proves nothing and
   harms nothing). When the last piece is held the node writes
   `assembled/<entry name>` and the value becomes readable; the marker follows
   the pieces in write order, and a value written by this device carries the
   marker in its entry's batch (§8.4). A restart resumes an unfinished value
   from the pieces the store holds, each proved again before it counts. At most
   4 values gather at once (`ASSEMBLIES_MAX`); a turn ends when the value is
   whole or a round brought nothing, and the next turn is waited for after a
   pause, so a value whose holders are away never keeps the others from
   theirs.

Pieces still owed are asked for again while the node lists the value as owed
(§7.4) and the entry is still wanted.

### 8.6 Reading a blob head

`get` of a path whose head is a blob answers the item only when the value is
recorded whole (`assembled/<entry name>`, §4.3) and the root, every node and
every chunk verify as it is read and, if sealed, the value opens; otherwise
`Unavailable` (`RetryLater`) and a background fetch of the missing pieces. A
value that is not recorded whole is not read: nothing is allocated for it. If
the store lost or damaged a piece it recorded whole, the record is dropped and
the value is gathered again. A value that is sealed and does not open under the
epoch key it names is a local failure, not an empty value. A change to a
watcher (`Change::Put`) for a blob is emitted when it is whole; the watcher's
queue holds a reference and the value is read when the watcher reaches it, and
skipped if its entry is no longer the head of its path. Pieces are served with
their entry (§7.6).

### 8.7 Threat notes

- **A piece from a stranger** verifies by its digest alone: it is the listed bytes
  or it is nothing.
- **A writer that signs an entry whose root the pieces do not match** leaves the
  value `Unavailable`; nothing else of the space is held back.
- **What holders of a sealed value's pieces see** is its ciphertext's size.
- **Memory.** Nothing of a payload is held in memory but what is being read
  out: an assembly keeps the digests its proved nodes listed (about 40 octets
  per chunk, so under 1 MiB for a 64 MiB value), never a piece; at most
  `ASSEMBLIES_MAX` (4) values gather at once on the node and the others wait
  for a turn with nothing in memory; a value is allocated, once, when it is
  read, and only after every piece is known to be held; a watcher's queue holds
  a reference to a value, never the value (§10.4). An entry that claims more
  than `PAYLOAD_MAX` is refused. A device with many large values of its own
  starts reading no entry and no piece (§4.5).

## 9. Trust, revocation and suspicion

### 9.1 The judge

One place checks an entry's signature: the **judge**, which runs the durable rule
of the node's validator (`validate_durable`: the certificate chain to the trust
anchors of the trust context that governs the packet's name, no clock except
where a role needs a cut, the key's revocation and role rules; certificates and
cut manifests are fetched through the validator's fetcher). It answers, for the
log: **valid** (who signed, by which key), **refused** (why) or **pending** (what
it waits for). A verdict is data the log keeps; the judge keeps none.

The **person** of a valid packet is the namespace of the held trust context that
governs its **name** (the longest held prefix; for a name under a
self-certifying `/user/<h>`, only that person's own context, held or adopted,
§9.4), not of any claim in the packet. The verification happens **once**: the
digest of the public key that verified comes from the certificate whose key
verified, and a revocation cut binds to it (§9.5) without verifying again.

A node judges a packet that is not an entry (a seal key packet, a grant) as
`validate_device_packet`: as above, by the view adopted for the person only when
the space lists her as a **writer or reader** (not as a person only a cut keeps),
and valid only if the key belongs to the device the packet's name is under.

While a judgement runs the trust layer may change (a context adopted, a version
that refuses more): the judge keeps a **generation** (the keyring's revocation
epoch plus the count of person versions that refused more), and a verdict "valid"
reached while it moved is reached again, up to three times.

### 9.2 The mapping

| The validator says | The judge says |
|---|---|
| valid, signed by a key, the key locator naming `<D>/KEY/<id>` | **valid**: key, device `D`, the person, the key digest |
| valid, but the trust path is a DigestSha256 | refused `Untrusted` (a digest names no signer) |
| valid without a key digest or key locator | refused `BadSignature` |
| valid, the key not named `<device>/KEY/<id>` | refused `Untrusted` |
| pending (a certificate or a cut manifest not to be had now) | **pending** on the chain: judged again when it is held |
| the signing key itself is revoked, and the cut does not accept the packet | refused `OutsideCut` naming `D` and the highest seq the revocation's cut keeps of `<D>/32=log/<S>` (0 if it has none) |
| a certificate of the key, or an issuer above it, is revoked | refused `Untrusted` (no cut excuses it) |
| the key's certificates lapsed (§9.3) | refused `Lapsed { not_after, now }` |
| the person's namespace is self-certifying and not held | **pending** on the adoption of that person (§9.4) |
| invalid signature, invalid key, unsupported signature type, not a public-key signature, certificate not found, key store error, no signing identity | refused `BadSignature` (it may verify from another holder, or once a certificate arrives) |
| anything else | refused `Untrusted` with the validator's reason |

### 9.3 The lapsed rule

No decision accepts anything because of a clock (§1.4). The one exception can
only refuse: for **every role the trust context lists in DataRequiresCut** (every
role, by default, in a context `ndn-fwd init` makes) a key whose certificates
have all lapsed by this node's clock is **refused until the lapse is ended for
that key**: by a renewed certificate, or by the revocation cut of the key being
held (the cut then decides). No role is exempt that the context lists; a device
that renews before its expiry is never refused. The refusal (`Lapsed`) is **not
kept as an entry's verdict**: only this node's clock says it, so the entry is
judged again whenever it is fetched again, and a re-judgement after a change of
trust leaves it as it is (§9.7). The host is told **once per entry**
(`Alert::Refused`, §10.6).

### 9.4 Adoption of persons, per space

A person's self-certifying namespace `/user/<0xA1: hash>` (exactly two
components) that this node does not hold is judged only by that person's own trust
context (trust-context.md §4.5). The host **adopts it for a space** — by name,
through the `Adopter` it gives the node — and the adoption judges, through a
*view* of the node's validator that no other path sees, exactly the packets about
the spaces that list her. It goes into no keyring the node judges by.

- **Whom.** From a space's listing: its writers, then its readers, then the
  persons only a removal cut keeps, in that order, that are self-certifying and
  not held: the first **64** for one space (`SCOPE_PER_SPACE`) and at most **256**
  persons in all spaces (`SCOPE_NAMESPACES`, spaces taken in name order so the cap
  falls the same way in any order). The rest are not adopted for it, and the
  node logs **one warning** (when the number left out changes) that says how many,
  why, and what to do.
- **The host's side.** `trait Adopter { fn adopt_scoped(&self, namespace, held:
  Option<&ScopedContext>) -> Scoping; fn release_scoped(&self, namespace); }`.
  `adopt_scoped` fetches her genesis (version 1, checked as the genesis her name
  hashes) and reaches her newest version from it, or, when `held` is the version
  the node already judges her by, from that version by continuity. It judges
  nothing itself. `release_scoped` is told when no space lists her any more or the
  node holds her context itself; it MUST neither block nor call back into the
  layer. A node with no adopter never adopts, and the entries of such persons
  wait (`Pending`).
- **Pacing.** At most 4 adoptions are in flight; a person the host could not adopt
  is asked for again after 2 s, doubling to 64 s; a person already adopted is
  **refreshed** (from the version held, by continuity) when a new listing names
  her, and a failed refresh keeps the version judging and is asked again after the
  same growing pause.
- **Which packets.** A packet whose person's namespace is held by no keyring
  context is judged by the person's adopted view only when a listing of the space
  it is about names her; otherwise the node's own validator refuses it as not
  held, which is **pending** on her adoption.
- **Kept across restarts.** The newest version adopted of each person is kept at
  `scoped/<person>` (§4.3): its version (8 octets), the SHA-256 of its content
  (32), and, when the host gave signed Data, the genesis' length (4) and Data and
  the newest version's Data (none for version 1). After a restart each listed
  person is held again at that version at once (the genesis checked as stored,
  signature and genesis rule, no clock; the newest version's signature), judges
  without any host reachable, and is refreshed by continuity, never walked to from
  her genesis again. An **older** version than the newest adopted, or that
  version number with other content (a fork), is refused; a record that cannot be
  opened is reported and she is adopted from her genesis, no older than the version
  it names. No ask goes to the host before the records are opened.
- **Release.** A person no listing names, or whom the node now holds itself (its
  keyring adopted her context), is released.
- **What the log is told.** `Adoption::Person { person, spaces, refuses }`: whether
  the version now held may refuse more than the one before it (it revokes a name
  the older did not, shrinks a cut, lists a role whose Data needs a cut that the
  older did not, or drops an anchor; a first adoption does). When it may, the held
  entries of her devices are judged again and what is refused is withdrawn; when
  not, only what waited for her is judged. `Adoption::Context` says the keyring
  adopted a context (§9.7).

Named, non-self-certifying namespaces (`/alice`) are never adopted this way; the
host holds them (`Introducer::adopt`, in `ndn-invite`).

### 9.5 Revocation cuts

A key lost to a thief is revoked by the owner of **its namespace**, in that
namespace's trust context, and the revocation carries a **cut**: the entries of
the key that still count (trust-context.md §3.3.12, the manifest form). A node can
vouch for a cut because for every entry it verified it keeps a marker with the
digest of the public key that verified it and the time it first saw it (§4.3).
`revocation_cut(key, bound)` reads those markers and nothing else:

1. `bound` is a `CutBound { held_before: Option<Timestamp>, upto: BTreeMap<space,
   seq> }`; **at least one** is given (else `BadRequest`, saying so and, when the
   key is suspected, since when). They are this node's own observations, never
   anything the revoked key signed.
2. For every space the node holds, for every entry held of the key's device that
   is **applied or held closed** and whose packet names the key as its signer,
   keep it if it was first verified here **strictly before** `held_before` (the
   marker's `at`) and its seq is at most `upto` of its space (when `upto` is
   given, a space it does not name keeps nothing).
3. The cut lists `(<D>/32=log/<S>, seq)` runs and a **manifest** of the implicit
   digest of every kept packet, made under the namespace of the context that
   governs the key; the key digest comes from the markers (no second
   verification), and the cut is **refused** if the kept entries were verified
   under more than one public key certified under the key's name; with no kept
   entry it binds the one public key the node holds a certificate of, or is
   refused.
4. **Everything the bound leaves out**, and every entry that verified but cannot
   be read, is returned as `left_out`, each by its full name ending in its
   implicit digest, for the owner to re-admit one by one (`ndn-fwd readmit`).
5. The names `<D>/32=log/<S>/seq=<n>` are under `<D>/32=log`, which is all
   `ndn-cert` requires of a cut's names (`check_cut_names`): `ndn-fwd revoke` and
   the cut file need no change. A node hands the manifest it made to its own
   validator, so it judges its held entries by the cut once adopted without
   fetching what it made.

What a revoked key's entries are, once its revocation is held: those the cut
accepts, by seq **and** digest, stay; the rest are refused `OutsideCut`
(`Standing::Revoked` while the person still writes), withdrawn if applied, and
listed by `refused_by_revocation(key)` by their full names with implicit digest
for the owner to re-admit. An entry refused as outside the *removal* cut of a
person who no longer writes is not listed: no re-admission of the key brings it
back.

### 9.6 Removal cuts are tips, not manifests

A person removed from the space (§5) is cut by the **tips** in the `REMOVE`
operation, applied by every reader as chain ancestry (§3.8, §5.6): the trust
context is untouched, and the cut's digests are signed-region digests of entries,
not implicit digests of packets. A revocation (§9.5) is the key's namespace's
decision about a key everywhere; a removal is the space's decision about a
person there.

### 9.7 Re-judgement

When a trust context is adopted by the keyring (`Adoption::Context`) the node
first lifts the suspicion of every suspected key the held contexts now revoke
(§9.8), then judges again the held entries of the persons whose namespace is that
context's, in every space, by the durable rule, with the whole walk: an entry
refused now — a revoked issuer in its chain, a cut that no longer accepts it —
is **withdrawn** (§3.8) with the refusal as its reason. A `Lapsed` verdict is left
as it is. A person's newer version that refuses more does the same for her
devices' entries in the spaces that list her.

**What is refused may have a second packet.** A device that signed two packets at one name
(§3.7: a thief heard first, the owner's bytes second) has the first held at the entry name and
the second at `equivocal/<entry name>`. When the first is refused for what a cut or a trust
context can change (`OutsideCut`, `Untrusted`) and the judge accepts the second, the second
**takes the name**: the refused bytes go to `equivocal/` as the evidence, the entry is judged
again as a fresh one (§3.8), and nothing is raised again as an equivocation. This is how the
owner's re-admission of the honest bytes of a name (§9.5) works at a node that heard the
thief first: it applies the honest entry it held, without asking for it again. The cut's wants
(§7.4) count an exact entry as held only when the packet at the name has those bytes.

### 9.8 Suspicion

A node marks a key it fears is in a thief's hands **suspected**: no new entry of
it is taken while its person is a writer (`Suspected`); what is held stays.

- **Where it lives.** In memory, in each space's log (a map from key to
  `since`), and as one shared store record `suspected/<key>` (8 octets, `since`
  in ms by this node's clock; §4.3) that every space's log reads at open. The
  host marks a key in every open space at once (`suspect(key, since)`); an
  equivocation (§3.7) marks it in the space where it was found at once and,
  as soon as that call's effects are routed, in every other open space; a
  space opened later reads the shared record. A device whose **own** key is
  revoked by a context held here, or marked suspected, signs nothing: `put` and
  `change` answer `Refused` (`Untrusted` or `Suspected`, `AskOwner`).
- **`since`** is by this node's clock and is the default `held_before` bound of
  the key's cut.
- **`suspected(key)`** is the earliest `since` among the open spaces' marks.
  **`unsuspect(key)`** clears it in every space; the host does this when the key
  is safe.
- **`lift_revoked`.** Whenever a trust context is adopted, a suspected key that
  the context now revokes is unmarked in every space: from then its **cut decides**
  (§9.5) and the mark would only refuse what the cut keeps.
- **A removed person is not suspected out of the cut:** her entries are judged by
  the removal cut alone (§3.7).

### 9.9 Threat notes

- **A revocation cut lists entries by implicit digest (residual, L10).** The
  manifest format belongs to the trust context (`ndn-security`
  `cut_manifest`): it binds `<prefix>/seq=<n>` to the *implicit* (full-wire)
  digest, so a relay's high-S copy of an ECDSA writer's entry falls outside the
  cut although it is the same signed object. Listing signed-region digests
  alongside needs a manifest format change and a validator rule, which is the
  tip carrier of the trust stage, not an interim here; until then the owner
  re-admits such an entry by its full name (§9.5, `ndn-fwd readmit`). Removal
  cuts (§9.6) are tips of signed-region digests and are not affected.
- **Writes between theft and revocation.** What the owner's node first verified
  before the loss time it states stays accepted (a residual); later entries are
  left out of the cut, listed, and refused everywhere; once the key is suspected,
  the owner's node takes none.
- **A thief backdates, fills a gap, signs other bytes at an accepted name, reuses
  an accepted seq in another space.** Refused: the cut lists names and digests per
  space prefix, and no date or seq outside it counts.
- **A withheld manifest.** The entries it lists wait, never accepted with other
  bytes, and are fetched from another holder.
- **A leaked key whose certificate expired and was never revoked** is a residual
  for a role not in DataRequiresCut; every role is, by default.
- **A person's context in an older version after a restart** is refused (§9.4):
  a key a newer version revoked never writes again.
- **The owner rule's second half is checked.** An owner device is a key whose
  device lies under the owner's namespace by name **and** whose person is the
  owner (§2.1). A `Members` or `Epoch` entry is refused (`NotMember`) unless its
  signing key meets both (§3.8 step 6), and a device's own signing of one is
  refused the same way (`NotOwner`, next step `UseOwnerDevice`). A device whose
  name lies under `O` but which a deeper held context validates
  (`/home/bob/member/laptop` under `/home`) is a device of the person
  `/home/bob`: it writes `Put` entries of `/home/32=data/…` if `/home` lists
  `/home/bob` as a writer, and it can **never** carry a `Members` or `Epoch`
  entry of that space, listed or not.
- **A guest or relay device of the owner holds none of the owner's powers (the
  owner rule's third half, review H1).** In a namespace that declares the role
  layout, the owner's person acts only through devices whose role is `admin` or
  `member`. Before, "owner device" meant a name under `O` and a key `O`'s context
  validates, so a `guest` device (a friend's, for a weekend) or a `node` relay
  of the owner could sign `Members` (add itself or a stranger as reader, remove
  members) and `Epoch` entries, wrote with the owner's implicit write, and was
  granted the key of every epoch, which defeats sealing against the relay. Now
  the judge decides it once, from the context that governs the key
  (`owner_capable` in `Verified`), and the log uses that one predicate for
  admission step 6, the owner's implicit write (a refused entry says
  `NotOwnerDevice` and what to do), a device's own signing (`NotOwner`; a put
  says `NotAllowed`), the owner-log hole check, epoch repair, `change`, the
  grant (`GrantRefusal::NotOwnerDevice`) and the signal scope. A device with no
  role at all in a role-layout namespace is no owner device either (fail
  closed). **The role layout is read from a signed marker, not inferred:** the
  governing trust context's schema is *authoritative* — the generated namespace
  schema every namespace `ndn-cert` creates carries, signed into the context by
  the root and kept by every update. The `DataRequiresCut` list is not used for
  it: an owner may narrow that list to nothing, which would turn role-less names
  back into owner devices. A namespace without the marker (a flat namespace of
  devices, as small hosts and tests make) has no roles to tell devices apart by,
  and all its devices are owner devices, as before.
- **Migration.** A space stored under the earlier rule has no `rule/<S>` record
  (§4.3). At start, the first time, every held entry of the owner's devices is
  judged again under the new rule: what a guest or node device signed leaves the
  fold and the register (`Withdrawn`, `NotOwnerDevice`), and each device's
  standing is stored in its ledger record (a record without the flag reads as an
  owner device until this judgement runs). An owner device of a sealed space then
  signs a **fresh epoch** before the record is written (guests may already hold
  keys of the epochs in force), and a device that cannot sign one records the
  rule at once. Each owner device that opens the space signs one; they merge as
  concurrent epochs do (§5.3).
- **A writer that holds an owner entry above a hole still seals in the fold's
  epoch (FA6, a residual).** A device that holds a later owner entry above a hole
  in the owner's log judges whether it may write by the fold it holds (a put
  never waits on other devices, `p1`) and seals in the epoch that fold names in
  force: a reader an entry in the hole removes can read what that device writes
  until the hole is filled and the epoch repaired, as with any removal that has
  not reached a device yet (`o1`). The removal binds every device that holds it,
  and no key goes to the removed reader once the removal is held (§6.5).

## 10. Register and API

What a space shows is its **register** (§10.1). The host holds two objects: a
`Node`, one device's layer over one store and one transport (§10.2), and a
`Heap`, one space of a node (§10.3). A watcher is told what changed (§10.4);
every call that cannot be done says why and what to do (§10.5); the alerts are
what the host decides about (§10.6); a sealed space has rules of its own
(§10.7). The Rust API is the one `crates/app/ndn-heap` exports at its root; a
call's name and signature below are those of that crate.

### 10.1 The register

For each path the register keeps its **heads**: the applied entries that no
other applied entry names in its `after` (§3.5). The **value** of a path is the
head of highest **rank** unless that head is a removal (a Put whose `INLINE` is
empty), and then the path has no value. The rank of a head is its signed-region
digest, then its device name, then its seq; the digest decides and the other two
only make the order total (§1.5).

- **Named last, else highest digest.** A Put whose `after` names the heads of
  its path replaces them whatever their digests are. Two Puts that do not name
  each other, written by two devices offline, are both heads, and every node
  picks the one of highest rank. No date takes part (§1.4); nothing is merged.
- **A removal is a Put** and competes as any head does. A removal that names
  the heads it saw ends them; a removal concurrent with another Put wins or
  loses by rank; a Put written after seeing the removal replaces it whatever
  its digest.
- **`after`.** A Put lists the current heads of its own path, the 8 of highest
  rank when there are more; the rest remain heads until a later Put names them.
  A reader honours a ref only for the entry it names by digest and only at the
  Put's own path (§10.8).
- **A function of the set of applied entries.** Arrival order, duplicates and a
  restart change no head. An entry that an applied entry already names when it
  arrives is never a head. An entry withdrawn (§3.8) leaves what never having
  applied it would have left: the entries it named that no other applied entry
  names are heads again, read from the store by name.
- **Memory and store.** The register holds, per head, a reference, the person of
  its writer, whether it removes and the size of its payload: O(heads), never
  a value. A value is read from the store by its head's entry name when a call
  needs it. It is kept as the `heads/` and `supers/` records of every apply
  (§4.3, §4.4), read back at open.
- **What the host is told.** Whenever the head that decides a path changes, a
  watcher is told it: `Change::Put` with the new item, or `Change::Removed` with
  an item of empty value when the deciding head is a removal or the path has
  none left (§10.4).

### 10.2 The node

```rust
impl Node {
    pub async fn start(transport: Transport, device: Name, keys: Arc<SecurityManager>,
                       validator: Arc<Validator>, store: Arc<dyn DataStore>,
                       config: Config) -> Result<Node, HeapError>;
    pub async fn create(&self, space: &Name, share: Share) -> Result<Heap, HeapError>;
    pub async fn open(&self, space: &Name) -> Result<Heap, HeapError>;
    pub fn space(&self, space: &Name) -> Option<Heap>;
    pub fn spaces(&self) -> Vec<Name>;
    pub async fn follow(&self, space: &Name) -> Result<Follower, HeapError>;
    pub async fn flush(&self) -> Result<(), HeapError>;
    pub async fn close(self);
    pub fn shutdown(&self);
    pub fn name(&self) -> &Name;
    pub fn namespace(&self) -> &Name;
    pub fn writer(&self) -> &Name;
    pub fn signatures(&self) -> u64;
    pub fn held(&self) -> u64;
    pub fn revocation_cut(&self, key: &Name, bound: &CutBound)
                          -> Result<CutProposal, HeapError>;
    pub fn suspect(&self, key: &Name, since: Timestamp) -> Result<(), HeapError>;
    pub fn unsuspect(&self, key: &Name) -> bool;
    pub fn suspected(&self, key: &Name) -> Option<Timestamp>;
    pub fn refused_by_revocation(&self, key: &Name) -> Vec<Name>;
    pub fn signal_scope(&self, space: &Name) -> Result<SignalScope, HeapError>;
    pub fn signal_header(&self, scope: &Name, run_id: &[u8; RUN_ID_LEN], body: &[u8])
                         -> Result<Bytes, HeapError>;
    pub fn signal_sender(&self, scope: &Name, data: &Data)
                         -> Result<SignalSender, SignalRefusal>;
    pub async fn signal_admit(&self, scope: &Name, data: &Data)
                              -> Result<SignalSender, SignalRefusal>;
    pub fn signal_member(&self, scope: &Name, key: &Name) -> bool;
    pub fn revocations(&self) -> u64;
}
```

The crate exports exactly these, the types they use (`Transport`, `Config`,
`Clock`, `Share`, `Readers`, `MembersChange`, `Members`, `PutOptions`,
`Frontier`, `Item`, `EntryId`, `Change`, `Changes`, `Alert`, `Follower`,
`HeapError`, `NextStep`, `Refusal`, `Cut`, `Timestamp`, `CutBound`,
`CutProposal`, `RUN_ID_LEN`, `SignalScope`, `SignalKey`, `SignalSender`,
`SignalRefusal`) and the host's trust seam (`Adopter`, `Scoping`, §9.4), and,
for `ndn-invite` and `ndn-surface` alone, the sibling surface of §10.9. The
signal methods are the gate of §11 (`revocations` is its count of revocations;
each answers `NotReady` for a space not open here as a member). The node
offers no raw signing: nothing signs octets a caller names with the device key
(a signature over bytes of the host's choosing would be an oracle for any
protocol that frames them like an entry); a run header is signed by
`signal_header` under a name this gate defines. The one exception is the
sibling surface (§10.9), which signs a packet only under a keyword an extension
registered and never under one of the core keywords above.

**`Config`** tunes a node; each field's default is what the spec's numbers are:

| Field | Default | Meaning |
|---|---|---|
| `svs` | SVS's reference timing | State Vector Sync settings of every group (§7.1) |
| `clock` | the system clock, ms since the Unix epoch | the time of a marker's `at` and of a cut bound; display only (§1.4) |
| `lifetime` | 4 s (the NDN default) | Interest lifetime of every fetch: the budget of an ask, within which its Interests are expressed again and a late reply to any of them answers (§7.3); under the faulty profile (round trips of up to 3 s) 2 s misses a reply that was on its way |
| `first_look` | 4 s | how long a removal looks for entries heard of and not yet held (§5.6) |
| `window` | 128 | the most asks of one device in flight, node-wide, whatever space or value they are for; at most half of `in_flight`; it starts at 16 and follows what the device answers (§7.4) |
| `in_flight` | 256 (at least `window`) | asks of the whole node in flight, by kind: walks at most three quarters, probes an eighth (§7.3) |
| `settle` | 1 s | the wait for the first group vector at an unclean start (§4.8) |
| `reserve_block` | 1,024 | seqs one durable reservation covers (§4.5) |
| `watch_queue` | 4,096 (at least 1) | changes a watcher may leave unread before it lags (§10.4) |
| `adopter` | none | adopts persons for the spaces that list them (§9.4); with none, their entries wait |

**`start`** gives a device its layer: it signs with the key `keys` holds for
`device`, keeps the X25519 recipient secret there too (made on the first start,
§6.2), verifies with `validator`, keeps everything in `store`, serves
`device`'s prefix and registers `<O>/32=sync` (§7.1). The namespace of the node
is the one of the trust context governing `device` in `validator`'s keyring: the
person every one of its entries is by. It answers `Local` (next step `FixLocal`,
saying what to fix) for a device with no key to sign as, one whose key is not
named `<device>/KEY/<id>`, one whose name has a keyword or digest component, one
that no held context covers, one whose namespace is not a namespace of plain
components (§1.2), and a store that cannot make what it holds durable. It then
restores every space the store holds, in the order of §4.5, flushes once, and only
then publishes anything. It never waits for another device.

**`create(space, share)`** makes a space whose owner is this node's namespace:
`NotOwner` (`UseOwnerDevice`) for any other owner, `BadName` for a name that is
no space name, `BadRequest` when the space is open here already or when a
sealed space would list more than 256 readers, the owner counted (checked before
anything is signed, §6.3). It signs the
creation (`CREATE`, with `ANYONE` 1 for `Readers::Anyone`) and one `ADD` per
listed person (the owner is implicit, a person listed twice in one role once;
more than 32 operations go in further `Members` entries), then, unless the space
is public, its first epoch (§6.3), signed by the call itself (no task is left
behind to sign it later), and returns after the flush that covers
them (§4.7). An error after the first of them was signed leaves what was signed
in the store, as nothing signed is retracted (§4.6); the space is left. Two
owner devices that both `create` one name make two creations, and the fold keeps
the one of lowest rank (§5.2): a second device `open`s and waits for `ready`.
`Readers::Persons(vec![])` is the owner alone.

**`open(space)`** joins a space made elsewhere, or answers the handle of one
held: it is idempotent, never waits for the network, and a node's start has
opened every space it held already. A space the node follows (below) is
`BadRequest`, saying to close the follower first. **`space(name)`** and
**`spaces()`** answer the spaces open as a member (never a followed one).

**`follow(space)`** makes the node a **carrier**: it joins the group with
counter 0, publishes no vector entry, verifies and stores what it receives,
serves it as held copies (§7.6) and needs no read key; it hands out no `Heap`,
so it reads nothing, a sealed space's entries staying closed to it.
`Follower::held()` is the entries
held of the space; `Follower::close()` leaves the space (what was stored stays,
and the node does not carry it after a restart). A space open as a member is
`BadRequest`: a member carries it already.

**`flush`** waits for a flush covering everything written so far and answers the
sticky store error, if any, as `Local` (§4.6, §4.7). **`close`** is §4.5 rule 4:
it refuses puts that begin after it, drains each publisher, flushes, records
the head of each space that has signed since its start (or started clean) as a
clean close, flushes, and stops; the next start has no hole. **`shutdown`**,
and `Drop`, stop at once: every watch ends, whatever the
flusher had not made durable is not, and the next start is unclean (§4.9).

`name()`, `namespace()` and `writer()` are the device, its person and the name of
the key it signs with. `signatures()` counts the signatures the node
made (entries and grants); `held()` the entries it holds in every space, copies
of others' and its own; the suite's cost columns read them (§13).
`revocation_cut`, `suspect`, `unsuspect`, `suspected` and
`refused_by_revocation` are §9.5 and §9.8; they act over every space the node
holds.

### 10.3 The space

```rust
impl Heap {
    pub fn name(&self) -> &Name;
    pub async fn put(&self, path: &Name, bytes: Bytes, opts: PutOptions)
                     -> Result<EntryId, HeapError>;
    pub async fn get(&self, path: &Name) -> Result<Option<Item>, HeapError>;
    pub async fn watch(&self, since: &Frontier) -> Result<Changes, HeapError>;
    // `Frontier::everything()`: everything held now is seen, so no head is replayed and no value read; only what follows is told.
    pub fn members(&self) -> Members;
    pub fn ready(&self) -> bool;
    pub fn holds_epoch_key(&self) -> bool;
    pub fn applied(&self, id: &EntryId) -> bool;
    pub async fn change(&self, c: MembersChange) -> Result<EntryId, HeapError>;
}
pub struct PutOptions { pub durable: Option<bool> }
pub struct Item { pub path: Name, pub bytes: Bytes, pub by: Name, pub writer: Name,
                  pub id: EntryId, pub as_of: Option<Duration> }
pub struct EntryId { pub device: Name, pub seq: u64, pub digest: [u8; 32] }
pub struct Share { pub readers: Readers, pub writers: Vec<Name> }
pub enum Readers { Anyone, Persons(Vec<Name>) }
pub struct MembersChange { pub add_writers: Vec<Name>, pub add_readers: Vec<Name>,
                           pub remove: Vec<Name> }
pub struct Members { pub owner: Name, pub writers: Vec<Name>, pub readers: Readers }
```

A `Heap` is a cheap handle, `Clone`, on one space of one node. `Item.by` is the
person of the writer (the namespace of the held context that governs its device's name, §9.1),
`Item.writer` its device, `Item.id` the entry (its digest is the signed-region
digest, §1.5). `Item.as_of` is `None` in every item this layer hands out; a read
of a past state does not exist. `Readers::Persons` and `Members.writers` list
the owner first and the rest in NDN canonical order.

**`put(path, bytes, opts)`** is the one write. Its promises:

1. *What `Ok` says.* The entry is signed by this device's key, chained to the
   one before (§3.6), stored in **one** batch with its records and, for a value
   in pieces, its pieces (§4.4), applied to the register, and handed to the
   in-order publisher: `get` on this node answers the value and every watcher
   of this node has been told (a value in pieces: once its pieces are whole
   here), before `put` returns, and the entry is served and announced as
   soon as the publisher releases it (§4.6, §7.6). The `EntryId` names the
   entry.
2. *It never waits for the network.* No peer, group, fetch or notice is
   waited for, ever. It waits for the disk in two cases only: the seq it signs
   is above `R_durable` (the reservation's flush is awaited, §4.5), and
   `durable` (below).
3. *`durable`.* With `Some(true)` it returns after a flush that began after the
   write returned (§4.6); with `Some(false)` it does not wait; with `None`
   it is `true` exactly when the space's observed sync state holds no device but
   this one (nobody else can hold the entry yet) and `false` otherwise (§4.7). An
   `Ok` without `durable` does **not** say the entry survives a power loss, nor
   that any device holds it: a power cut can take the entries signed since the
   last completed flush that no peer fetched (§4.9), and a process kill takes
   none that returned.
4. *`Err` before the entry is signed* signs nothing. `Err` from the flush that a
   `durable` put waits for (`Local`, the disk's reason, §4.6) comes **after**
   the entry was signed, stored, applied and announced: it is not retracted, the
   caller simply has no `EntryId`, and a put again writes a second entry.
5. *Empty `bytes` removes the path* (§3.2). A value of 6,144 octets or fewer
   travels inline; a larger one up to `PAYLOAD_MAX` (64 MiB) is sealed whole if
   the space is sealed, cut into pieces and written with its entry (§8.4); a
   put that moves the seq or the epoch in force while it cuts does it again.
   `Local` after `Node::close` began.
6. *A sealed space seals* in the epoch in force and in no other (§6.4).

It refuses with: `BadName` (a path that is not 1 to 8 generic components of 200
octets in all, counted with their TLV headers: the codec's one definition,
§3.3), `TooLarge` (over `PAYLOAD_MAX`; the entry's own limits, §3.1), `NotReady`
(the space's creation is not held yet; or, sealed, no epoch is in force or its
key is not held, §6.4: ask again), `NotAllowed` (carrying `why`, `AskOwner`:
this device's person is no writer, or, in a sealed space, a writer that is no
reader and so can never hold the key, §10.7), `Refused` (`AskOwner`: this
device's own key is revoked by a context held here, `Untrusted`, or marked
suspected, `Suspected`, §9.8: it signs nothing), `Local` (the disk, the keys, or
a closing node). It never refuses for what a peer holds.

**`get(path)`** reads what this node holds and never waits for the network:
`Some(item)` the value, `None` for a path that has none or was removed. Stale,
never wrong (§1.3 invariant 5): a path the node has not caught up on answers
what it holds. `Unavailable` (`RetryLater`) answers for a value in pieces that is
not whole here yet (§8.6); it is being fetched. `Sealed` (`AskOwner`) answers
when the space is sealed and this node's person is neither the owner nor a
listed reader. While any entry of a sealed space is held closed (its epoch key
has not arrived, so its path is unknown and no answer would be complete, §6.4)
`get` answers `NotReady` (`RetryLater`) to a reader that is entitled to every
key it lacks, the keys being on their way by the grant pull (§7.8), and `Sealed`
otherwise.

**`watch(since)`** is §10.4. **`members()`** answers who the space lists now,
from the fold (§5.4), the owner first; it never waits. **`ready()`** says the
first catch-up is done: the space's creation is held and everything heard of
is held (§7.4). A host that opens a space made elsewhere waits for it before it
reads `members()`, and before any call that answers `NotReady` for the creation.

**`holds_epoch_key()`** says whether a `put` seals now instead of answering
`NotReady` while the key of the epoch in force is asked for (§6.4, §6.5): the
node holds that key, or the space is public and needs none. It is `false` while
the creation is not held and, in a sealed space, while no epoch is in force. The
owner's devices each sign an epoch for the readers they see, and the greatest is
in force (§5.3 rule 6), so the epoch in force of a device can change when it
learns of another owner device's epoch, and the key of the new one comes by a
grant (one exchange). A host that is to write while cut off from the others waits
for this before it goes offline, and a `put` made when it is `true` is not
answered `NotReady` for the key unless the epoch in force changed since. It reads
the space's records under the space's lock and never waits.

**`applied(id)`** says whether this node has applied the entry `id` (an
`EntryId` from `put`, `change`, an `Item` or a peer): it holds exactly those
signed bytes (the digest is the signed-region digest, §1.5), verified and
chained to its writer's log, and admitted it (§3.8): the writer's person was a
member, inside the cut if removed, and the entry was neither refused, waiting
on a removal cut, held closed for want of its epoch's key, unreadable, nor
withdrawn since (§3.8, re-check). An entry never held, or held as other bytes
at its name, is not applied. Every applied entry counts, one a later write
superseded too: `get` shows only the heads, `applied` is how a host (or the
suite's "device D holds entry E") sees the entries below them. It reads the
space's records under the space's lock, never waits for the network or the
disk's flush, and is not a durability statement (§4.9).

**`change(c)`** edits who the space lists and only an owner device signs it:
`NotOwner` (`UseOwnerDevice`) from any other, including a device under the
owner's name that is of another person (§9.9). The operations are the
removals, one `REMOVE` per standing `ID` of each person removed (from both
roles), carrying the tips this device holds of that person's devices, collected
within `first_look` (§5.6), then the additions, a person already standing in a
role skipped; at most 32 operations to an entry, more in further entries. When the
change leaves a sealed space without an epoch for exactly its readers a new
`Epoch` is signed (§6.3). It returns the last entry's `EntryId` after the flush
that covers everything signed (§4.7), `BadRequest` when nothing was to be
signed or when a sealed space would list more than 256 readers, the owner
counted (checked before anything is signed, §6.3), and `Refused` as `put` does
for a revoked or suspected own key. A reader's addition names the epoch in
force (§6.6, `ADD`'s `EPOCH_ID`): the reader is in that epoch's audience, is
granted its key and
reads its history, and the space stays complete with no new epoch; a writer's
addition names none. The call has no way to name an earlier epoch.

### 10.4 Watching

```rust
pub enum Change {
    Put(Item), Removed(Item),
    Withdrawn { id: EntryId, why: Refusal },
    Members(Members), Alert(Alert), Lagged { missed: u64 },
}
pub struct Frontier(/* device → seq */);   // new(), everything(), get(&Name) -> u64, set(Name, u64): `set` is what `get` answers, also after `everything()` (the devices not set stay seen to the end)
pub struct Changes;  // async fn next(&mut self) -> Option<Result<Change, HeapError>>; a Stream
```

`watch(since)` answers `Sealed` as `get` does for a person outside the
audience, then registers a queue **and** takes its first listing under one lock,
so no change falls between them and none is told twice. A watcher is told, in
this order:

1. **What is held.** Every head that has a value and whose entry is above
   `since` (`id.seq > since.get(id.device)`), as `Change::Put`, in path order.
   A removed path is not listed. A value in pieces is queued by reference after
   the inline heads and read from the store when the watcher reaches it: it is
   told only if it is still the head of its path and whole here (it may
   therefore come after later changes; a watcher that reads slowly holds a few
   hundred octets per value, never the value). The first listing is never
   lagged and does not count against `watch_queue`.
2. **The standing alerts.** `Equivocation` and `RolledBack` that were raised in
   this space (at most 32), then the `Refused` alerts told of the last 256
   refused entries (§10.6), then `StoreFailed` if the store has failed.
3. **The changes**, in the order the log made them: `Put`, `Removed` (an
   item with empty `bytes`), `Withdrawn { id, why }` (an applied entry was
   refused after the fact, §3.8: drop what was derived from `id`; the
   paths whose deciding head moved follow as `Put` or `Removed`), `Members`
   (what the fold decides changed: the writers, the readers, a removal, the
   creation, the epoch in force or whether it is complete; the payload is the
   members after, so a host reads `members()` again for the rest), and `Alert`.

A host starts from `Frontier::new()` to be told everything held; a host that
kept what an earlier watch told it passes the frontier it keeps, built with
`set(device, seq)` from the `Item.id`s it saw. Dropping the `Changes` ends the
registration; it ends by itself (`next` answers `None`) once the queue is read
and the node stopped or the space left.

**`Lagged`.** A watcher may leave `Config.watch_queue` live changes unread. A
change that does not fit is dropped and counted, and so is every later one until
the watcher has read what was queued; it is then told `Lagged { missed }`, and
the changes after that arrive again. A host that is told `Lagged` MUST discard
what it derived from the stream and `watch(&Frontier::new())` again (or `get`
what it shows): the dropped changes are not recoverable one by one, and alerts
may be among them (a new watch is told the standing ones again, §10.6). A slow
watcher never slows a put, a fetch or another watcher.

The item of `Changes::next` is a `Result` so that the stream and the calls share
one error type; the stream defines no failure of its own and yields only `Ok`.

### 10.5 Errors

Every error says why in its message and what to do in `HeapError::next()`, and
`retry()` says the same call can succeed later (`next() == RetryLater`).

| `HeapError` | Raised when | `next()` |
|---|---|---|
| `Unavailable { name }` | a value in pieces is not whole here; a name is not held and no holder answered | `RetryLater` |
| `NotReady { name, why }` | the creation is not held; no epoch in force or its key not held; `why` says what it waits for | `RetryLater` |
| `BadName { name, why }` | a space or a path that does not parse (§2.3) | `FixName` |
| `TooLarge { name, limit }` | a value over `PAYLOAD_MAX`, an entry over its limit | `FixName` |
| `NotAllowed { space, why }` | this device's person is no writer; or a writer that is no reader of a sealed space (`why` says which and what to ask); or, for signals, neither writer nor reader, or its key revoked (§11) | `AskOwner` |
| `Sealed { space }` | a read of a sealed space by a person outside its audience, or while an entry is held closed in an epoch the person is not entitled to (§10.3) | `AskOwner` |
| `NotOwner { space }` | a structural call from a device that is not an owner device (§9.9) | `UseOwnerDevice` |
| `Refused { name, why }` | `put`, `change` or an epoch by a device whose own key is revoked by a context held here (`Untrusted`) or marked suspected (`Suspected`) (§9.8) | that of `why` (`AskOwner`) |
| `BadRequest { why }` | a request no device does as given (§10.2, §10.7) | `FixRequest` |
| `Local { reason }` | the store, the keys, a closing node | `FixLocal` |

`Refusal` is the verdict on an entry (§3.8): `OutsideCut`, `Lapsed`, `NotMember`,
`Suspected`, `Untrusted` and `Fragmented` say `AskOwner`; `BadSignature` says
`RetryLater` (another holder's copy may verify); `Unsealed`,
`Sealed` and `Chain` say `None` (final, and its writer writes again).
An entry **received** and refused is not a call the host made:
it reaches the host as `Alert::Refused`, `Alert::OutsideCut` or
`Change::Withdrawn` (§10.6), never as a failed call.

### 10.6 Alerts and what the host does

An alert is a `Change::Alert` on a watch, and a `warn` event of the node's log.
Two kinds are **standing** and told to every watcher that begins later, after
the heads: `Equivocation` and `RolledBack` (a space keeps up to 32), and the
`Refused` alerts of entries the judge refused (below), of which a space
remembers the names of the last 256. Every other alert is told to the
watchers there are when it is raised (`StoreFailed` also to one that begins
after the store failed). A host that wants to see alerts therefore holds a
watch for as long as it runs.

| Alert | Raised when | The host |
|---|---|---|
| `Equivocation { device, seq }` | one key signed two things at one name, or forked its chain (§3.7), for an entry of any kind | treats the key as copied or compromised; the node has already suspected it (§9.8); the host unsuspects it only when it knows the key is safe; for a `Members` or `Epoch` entry it uses an owner device and tells the owner; revokes with a cut (§9.5) |
| `OutsideCut { id }` | an entry is refused as outside a removed person's removal cut (§3.8 step 7); a refusal by the judge of a revoked key's cut or of a bad signature is no alert of this kind: the entry is not taken and is asked for again, and `refused_by_revocation` lists what a revocation refused | shows it; nothing re-admits an entry outside a removal cut, and the owner re-admits a revoked key's entries by name and digest (§9.5) |
| `Refused { id, why, next }` | an entry that verified is refused for the chain, the carrier, the membership or the seal (§3.8 steps 5 to 8); and, **once per entry**, an entry the judge refused as `Lapsed` or `Untrusted` or that a suspected key signed (`Suspected`) (§9.2, §9.3, §3.7) | shows `why` and does `next`; nothing the layer needs |
| `RolledBack { reserved, seen }` | an entry under this device's own name lies above the reservation the store held when the node opened the space (§3.8 step 3, §4.8) | marks the key suspected on this node, asks the owner to revoke it with a cut and enrols the device again: a restored image or a copy of the key signs; the entries above are applied when they chain |
| `GapSigned { after, resumed }` | the first entry after an unclean start stated the gap it skipped (§4.5) | informs; nothing is lost beyond the entries no peer held (§4.9) |
| `UnbackedCounter { device, seen }` | a peer's counter for this device's own name lies above its head with no entry behind it (§4.8) | informs, and watches for `RolledBack`: nothing was applied or signed because of it |
| `StoreFailed { why }` | the store could not make writes durable (§4.6) | stops offering writes, shows the disk's reason, repairs the disk and restarts the node; reads continue and nothing signed is retracted |

A `Withdrawn` change is not an alert but is what a late removal or revocation
does to the host's picture: what was derived from `id` is dropped, the paths it
decided show what they decided before.

### 10.7 Sealed spaces

- **A reader is an audience member.** `get` and `watch` of a sealed space answer
  `Sealed` to a node whose person is neither the owner nor a standing reader.
  Opening what the audience may read needs the key of the epoch an entry
  names, which arrives by grant (§6.5); until it has, `get` answers `NotReady`
  (`RetryLater`) to a reader entitled to the key and `Sealed` to one that is not
  (§10.3).
- **A writer that is not a reader cannot seal.** Writing needs the key of the
  epoch in force, and a key is granted only to a person in the epoch's audience
  and a standing reader (§6.5). A person listed as a writer only never holds the
  key, so `put` answers `NotAllowed` (`AskOwner`, `why` saying so) until the
  owner adds the person as a reader too. The owner SHOULD list every writer of a
  sealed space as a reader (§5.7).
- **At most 256 persons in an epoch's audience, the owner counted** (§6.3).
  `create` and `change` refuse with `BadRequest` (a sealed space lists at most
  256 readers, the owner included; list fewer, or make the space public)
  **before anything is signed**, so a refused call leaves nothing behind. A
  reader added to a space with an epoch in force names it and needs no new
  epoch.
- **A reader added later** names the epoch in force and reads its history; an
  epoch that ended before it was added stays closed to it (§6.6).
- **A public space** seals nothing: `Readers::Anyone`, no epochs, `get` and
  `watch` answer everybody.
- **Signals.** `signal_scope` (the signal keys and the groups, §11.2) is
  available to writers **and readers** of the space; sending a header and being
  admitted as a sender stay with writers.

### 10.8 Threat notes

- **A forged `after`.** `put` lists only the heads of the path it writes, but
  the wire lets a Put name any entry of the space in its `after`, with any
  digest. A reader supersedes only what the ref names **exactly**: an entry
  of the named device and seq whose signed-region digest is the ref's (the
  `supers/` record is keyed by that digest), and only an entry **at the Put's
  own path** (a ref whose target is held at another path is ignored; one whose
  target arrives later is ignored when it does). So a writer cannot hide
  another writer's entry, present or future, by naming its (device, seq) with
  a wrong digest, nor a head of another path by naming it. *Threat (fixed,
  review H2):* before this, `supers/` was keyed by (device, seq) alone and a
  writer could name the next eight seqs of another device under any digest:
  their real entries never became heads at any reader, including that device
  itself, and withdrawing the forged entry did not repair it. A host still
  MUST NOT rely on a path's value being untouched by what the other writers of
  the space write at that path (§1.7, no per-path access control).
- **A slow or hostile watcher** is bounded by `watch_queue`: it lags, it does not
  grow without bound and does not slow any other (§10.4).
- **`Item.by` is the namespace of the held context governing the writer's
  device name** (§9.1), not a claim in the entry: a host that shows who wrote a
  value shows `by` and `writer`, and not the entry's bytes.

### 10.9 The sibling surface

`ndn_heap::host` is the interface for `ndn-invite` and `ndn-surface` and for
no other program; a host that reads and writes spaces never uses it. It lets a
sibling crate add a protocol of its own to a device (introductions, invite.md)
that rides the device's key, trust, store and serving, without this layer
growing a case for it. `Node` dereferences to a `NodeHandle`, the same
surface held by a task or an extension: a `Node` stops when it is dropped, a
handle does not, and a stopped node makes every method that needs the network
answer `HeapError::Local` and the rest read what it held.

```rust
pub trait Extension: Send + Sync {
    fn keywords(&self) -> &'static [&'static str];
    fn answer<'a>(&'a self, interest: &'a Interest) -> AnswerFuture<'a>; // Option<Bytes>
}

impl Node { pub fn handle(&self) -> NodeHandle; }          // and Deref<Target = NodeHandle>
impl NodeHandle {                                          // Clone; every method is Node's too
    pub fn sign_packet(&self, packet: DataBuilder) -> Result<Bytes, HeapError>;
    pub fn extend(&self, extension: Arc<dyn Extension>) -> Result<(), HeapError>;
    pub fn consumer(&self) -> Consumer;
    pub fn validator(&self) -> &Arc<Validator>;
    pub fn keys(&self) -> &Arc<SecurityManager>;
    pub fn store(&self) -> &Arc<dyn DataStore>;
    pub fn recipient(&self) -> &RecipientKey;
    pub fn note_joined(&self, space: &Name);
    pub async fn fetch_entry(&self, name: &Name) -> Result<EntryId, HeapError>;
    pub fn now(&self) -> Timestamp;
    pub fn config(&self) -> &Config;
    pub fn person_of(&self, device: &Name) -> Name;
    pub fn adopted_persons(&self) -> Vec<Name>;
    pub fn name(&self) -> &Name;  pub fn namespace(&self) -> &Name;  pub fn writer(&self) -> &Name;
    pub async fn open(&self, space: &Name) -> Result<Heap, HeapError>;
    pub fn space(&self, space: &Name) -> Option<Heap>;
    pub async fn flush(&self) -> Result<(), HeapError>;
}
impl Heap { pub fn removed_by(&self, person: &Name) -> Option<EntryId>; }
```

**Extensions.** `extend` registers an extension for **all** its keywords or for
none, and answers `HeapError::BadRequest` (next step `FixRequest`) when it
claims no keyword; a word that is not a keyword (lowercase ASCII letters,
digits and `-`, at least one); a core keyword (§2.4: `data`, `log`, `seal`,
`grant`, `held`, `piece`, `manifest`, `sync`, `signal`, `run`); or a keyword
claimed already, by another extension or twice by itself. An Interest whose
name is under this device's own name and whose keyword right after it is
registered is **given to that extension, and to no other code**: it answers
in a task of its own (it may sign, wait for the store or ask the network), a
`None` is **Nacked** like any Interest nothing answers, and a name under
`/localhost`, a name of another device, and a name of a core kind never
reach it. The router of §2.4 is otherwise unchanged. A sibling's records live
in the store under `/localhost/ndn-<crate>/`, which no device serves and this
layer neither scans nor writes; `flush` makes them durable.

**Signing.** `sign_packet` signs with the device's key, and **only** a Data
named `<D>/32=<keyword>/…` where `D` is this device, the keyword is the
component right after it, and an extension has registered it. The name is read
from the very bytes about to be signed, before the key is used, so nothing
signs a name the caller builds around it. Every other name (an entry
`32=log`, a seal key, a grant, a signal run, a certificate or key name
`<D>/KEY/…`, another device's, one with no keyword or the keyword not right
after the device, an unregistered keyword) is `HeapError::BadRequest` naming why
and what to register, signs nothing and counts no signature. A name with a
generic `KEY` component anywhere, even under a registered keyword
(`<D>/32=<keyword>/KEY/<id>/<issuer>/v=<n>` is a certificate's shape), is
refused too, so a keyword is no way to have the device key certify a key. So the
node is no signing oracle: it cannot be made to sign an entry at a chosen name (the
device would equivocate, §3.7), speak for the namespace, or frame octets as
an entry. A packet signed under a registered keyword parses as none of the
core kinds (§2.3: the first keyword decides), so a peer never takes it for an
entry, a seal key or a grant.

**Joining.** `note_joined(space)` records at `joined/<S>` (§4.3) that an offer's
answer admitted this device to `space`. While the record stands and the fold of
`space` held here does not list this device's person (the owner, a standing
writer or a standing reader), a `put` that would answer `NotAllowed` (the
person is not a writer) answers **`NotReady`**, next step `RetryLater`, and says
the entry that lists the person has not arrived: the entry is on its way, not
refused. Nothing else changes: the judge is as strict as before, the put still
writes nothing until the fold lists the person, and an error other than
`NotAllowed` is returned as it is (`NotOwner`, `Sealed`, a refused key). The
record is removed when the fold lists the person (checked when a members entry
is applied and when the space is opened), and when a removal of her arrives
that the record did not name while no Add of hers stands (the admission was
undone before this device ever saw it listed: the record keeps the digests of
the removals held when it was made, so a removal of an earlier invitation is not
mistaken for one of this): then the entry it waited for is never to come, and
the refusal is `NotAllowed` again. It is not made for a space that lists the
person already. It survives a restart, so a device that stopped between the
answer and the entry still waits instead of being told to ask the owner. A
device that really is no member, with no record, is told `NotAllowed`. No
clock takes part: what ends the wait is a listing or a removal, both signed
entries.

**One entry by name.** `fetch_entry(name)` takes the log name of one entry,
`<device>/32=log/<S>/seq=<n>`, of a space **open here** (`BadName` for any
other name, `BadRequest` for a space not open). It asks the writer and the
heard members that vouch for its log, in turn (two asks of each, within one
Interest lifetime each), and hands what arrives to the same admission every
fetched entry passes (§3.8, through the judge of §9.1 and the log): **no
bypass, and nothing else is fetched**. It answers the entry's id (`device`,
`seq`, signed-region digest) when the entry is held, a duplicate included;
whether it was applied is `Heap::applied`'s to say (a refused entry is
`HeapError::Refused` with the judge's reason; one that waits for a context or
a certificate is `NotReady`; none answered is `Unavailable`). It is the call a
removed person's node makes for the entry that removed it, the name `removed_by`
gave its inviter.

**Who removed a person.** `Heap::removed_by(person)` is `None` for a person
the fold lists (as owner, writer or reader), one it never listed, and the
owner. For a person it lists no more it is the id of the applied `Members`
entry that carries a `Remove` naming an `Add` of hers, and of those the one of
the lowest rank (signed-region digest, then device, then seq: the order that
picks between entries claiming one fact, §5.2), so every node holding the same
entries names the same one. A withdrawn entry names nobody.

**What else a sibling reads.** `consumer` is a consumer on the node's own face
(its Interests go where the node's go, a new one per call; it may carry a
forwarding hint and parameters). `validator` and `keys` are the node's own
(the keyring of trust contexts held, the certificate caches, the key store).
`recipient` is this device's X25519 key: the secret stays in the key store,
never in the data store, so a sibling derives the keys that protect its own
notes from it with an HKDF label of its own. `now` is `Config.clock`, as the
times the node writes are read. `config` gives the node's `lifetime` and
`first_look`, the bounds of a sibling's waits. `person_of(device)` is the
namespace of the context that governs the device here (the self-certifying
namespace its name hashes to, while no context of it is held).
`adopted_persons` is the sorted set of persons whose context the host's
`Adopter` adopted here for the spaces that list them (§9.4), not those the
keyring holds and not those still being adopted.

**Waiting for a join** needs no other call: a sibling opens the space, notes
the join, and waits, bounded, for `Heap::members` to list the person
(`watch` yields `Change::Members`; re-check on a bounded tick as well), for
`Heap::holds_epoch_key`, and for `Heap::applied` of the id `Heap::change`
returned to the inviter (the last entry that change signed: its Members entry,
or the Epoch entry it owed a sealed space, which follows it in the same log).

Threat notes:

- **A registered keyword cannot reach the core, nor the core an extension.** The
  core keywords are refused at registration, and a name is routed by its first
  keyword alone (§2.4), so an extension that registers `ping` cannot be asked
  for `<D>/32=log/…` and cannot make a node sign one.
- **A sibling is trusted with the device's name under its keywords**, and with
  nothing else: the signing it is lent is bounded as above, the validator and
  the store it reads are the node's, and a sibling that signs a wrong answer
  under `<D>/32=<its keyword>` harms only the protocol of that keyword.
- **`note_joined` admits no one.** It changes the words of one refusal, and only
  while the fold does not list the person; a forged or stale record keeps a
  device waiting, never lets it write.
- **`fetch_entry` is no admission path.** An entry a caller names is judged
  by the rules of §3.8 and §9; a name of a space not open here is refused
  before anything is asked.

## 11. Signals: the gate

A **signal** is ephemeral live data — presence, cursors, a drag — pushed to the
members of a space and never an entry: nothing of it is stored, served or counted
by this layer. The transport that carries signals (`ndn-surface`, signals.md)
asks the node six things, and nothing else leaves this layer. The scope of a
signal is **one space**. The clock and sequence reservation of signals belong to
the transport, not to this layer.

### 11.1 Members

A **member** of a space, for signals, is a key of a device whose **person** is a
writer of the space (the owner always is) and which the trust context governing
that key does not revoke. The person is the namespace of the context that
governs the key, taken from the view the node judges the key's packets about the
space by (§9.4): the node's own for a person it holds, else the view adopted for
her while a listing of the space names her as a writer or a reader. The answer is
read **offline, from what is held at the call**: the fold of the `Members` entries
held and the contexts held, so it flips on the first call after the entry that
removes a person, or the context that revokes a key, is held. Readers of a
space that are not writers are **not** members: they cannot send and their
headers are not admitted, but they are given the scope and, in a sealed space,
the signal keys (§11.2), since they hold the epoch key and must be able to
receive what members send.

### 11.2 The six calls

| Call | What it says |
|---|---|
| `signal_scope(space)` | this device's `SignalScope { space, keys, groups, listen }`, to a writer **or a reader** of the space: its signal keys when the space is sealed, the group to push into (`sync_group_of(space)`) and the group to listen on (the same one) |
| `signal_header(scope, run id, body)` | a run header signed by this device's key |
| `signal_sender(scope, header)` | the header's signer if it is a member, before anything is verified |
| `signal_admit(scope, header)` (async) | admit another device's run header, or say why not |
| `signal_member(scope, key)` | whether a key is a member now; asked for every packet |
| `revocations()` | a count that moves when a trust context that revokes keys is adopted (the judge's generation, §9.1), so a transport walks the chains of the runs it admitted again |

**This device may take the scope** when the space's creation is held and this
device's key is a writer's or a reader's and not revoked; it may **send** (sign
a header, `signal_header`) only as a writer, that is, as a member. Otherwise
`signal_scope` and `signal_header` answer `NotReady` (the space is not open here
as a member, or its creation is not held;
or, sealed, no epoch is in force, or the key of the epoch in force is not held
yet and this device is in the audience: ask again after the grant; the gate
starts no ask), `NotAllowed` (neither writer nor reader, or, for
`signal_header`, not a writer; or its own key is revoked) or `Sealed` (a person
outside the sealed space's audience, which may not hold its key; the owner
counts as inside). A header can be signed without the epoch's key. The checks
that judge another device's key (`signal_member`, `signal_sender`,
`signal_admit`) count writers only, whoever asks.

### 11.3 Run headers

A run header is the Data `<D>/32=signal/<S>/32=run/<run id>` (§2.2): the run id
one GenericNameComponent of 16 octets, no FreshnessPeriod, Content the body,
signed by a key of `D`. It is never stored, served or fetched here.

`signal_sender` refuses with: `Malformed` (a scope other than the space, a name
that is not a run header of it, no key locator, a key of another device than the
name's), `NotReady` (the creation is not held), `NotMember`, or `BadSignature`
(for a key the context governing it revokes). Its answer is
`SignalSender { key, device, namespace }`, the **namespace being the person**: a
transport bounds a sender's admissions and runs by it, since a person can make as
many keys and devices as it likes and never more persons.

`signal_admit` asks `signal_sender` first (a stranger's header costs nothing
more), then verifies the header by the validator that judges the signer's person
by the **live** rule: its certificates valid now, a revoked key refused. The
chain is walked from the certificates held first; one not held is fetched, but
only while fewer than **2** headers of the signer's person wait for certificates,
not for a device whose last fetch brought none within **30 s**, and at most **4**
certificates for one header; otherwise `Unverified` (ask again when the header
rides again). Once it verified, the signer is checked a member again, so a removal
or revocation held while the chain was fetched ends it (`NotMember`,
`BadSignature`). A refused header is dropped with its run; none is kept.

### 11.4 Signal keys

A sealed space's **signal key** for an epoch is `HKDF-SHA256(IKM = the epoch's
content key, salt = none, info = "ndn-heap/signal/1" ‖ the Name TLV of S ‖ the
Name TLV of the epoch's creator ‖ the epoch's seq, 8 octets big-endian)`, 32
octets (an XChaCha20-Poly1305 key, signals.md). Its **id** is the first 8 octets
of `HKDF-SHA256(IKM = the signal key, salt = none, info =
"ndn-heap/signal/id/1")`, carried beside what it seals so a receiver knows which
key opens it. `SignalScope.keys` lists the epoch in force's key **first** (the
one to seal with), then the keys of the other epochs whose content keys are held,
by epoch seq highest first (to open what members still seal in them). The keys
are zeroed when dropped and never shown by `Debug`.

### 11.5 Differences from the previous gate

- The scope is a space; the previous gate's scope was a collection or folder with
  per-namespace groups for every writer and reader namespace, and a share. The
  groups to push into and to listen on are the space's one group.
- Members are the space's **writers** (and the owner), by person; the previous
  gate also admitted the readers of the record's audience. The decision is that
  `signal_scope` (the keys and the groups) is available to writers **and
  readers**, so a reader of a sealed space can receive what members send,
  while sending and admitting a sender remain writers' only.
- The gate asks the node's judge for persons and revocations; `revocations()`
  is the judge's generation, with no counter of its own.
- The clock, the sequence floor and their store keys are not in this layer.

### 11.6 Threat notes

- **A removed member** keeps sending until the removal is held here: the answer
  is exact by what is held, never by time.
- **A stranger's headers** cost no certificate fetch, and a member's cost at most
  2 waiting per person and one fetch run per device per 30 s.
- **A revoked issuer** ends the runs it certified: the count of §11.2 moves and a
  transport walks the chains again.

## 12. Failure model

| Failure | Required behaviour | Rests on |
|---|---|---|
| Partition / offline | Reads and writes continue locally under each device's key; the group reconciles when a path returns: what a returning device is missing is fetched by what the log wants. | §4, §7 |
| Lost device | The devices that hold its entries keep serving them as held copies; the owner marks its key suspected on the node it revokes from, says when it was lost, and revokes it in the trust context with a cut of what that node first verified before then; the entries left out are listed and any honest one is re-admitted by exact name and digest. | §7.6, §9.5, §9.8 |
| Compromised key | The revocation cut keeps exactly the entries it lists, by seq and digest, and refuses the rest whatever they claim; the key's seal keys and grants are refused; sealed data re-keys forward. | §9.5, §6 |
| Bad or lying clock | Never makes an entry accepted: Data is judged without certificate validity periods and a cut, not a date, ends a key; a reader's clock only decides when a lapsed key's entries start being refused until its renewal or its cut. A writer's clock moves only the display time of its markers. | §1.4, §9.3 |
| Thief writes between the theft and the revocation | Entries the owner's node first verified before the loss time stay accepted (residual); later ones are left out of the cut and refused everywhere; once the key is suspected, that node takes none. | §9.5, §9.8 |
| Thief backdates, or fills a gap, with a revoked key | Refused wherever the revocation is held: the cut lists names and digests, and no date or seq outside it counts. | §9.5 |
| Thief reuses an accepted seq in another space | Refused: the cut's runs are per `<D>/32=log/<S>` prefix. | §9.5 |
| Thief signs other bytes at an accepted name | Refused: only the digests the manifest lists are accepted, and in-cut entries are fetched by their exact digest. | §9.5 |
| Manifest packets withheld | The entries they list stay pending, never accepted with other bytes; they are fetched from another holder. | §9.5, §7.4 |
| Revocation arrives after a thief's entry was accepted | On adopting the revoking context the node withdraws it and tells every watcher (`Change::Withdrawn`); in-cut entries stay. | §3.8, §9.7 |
| Issuer revoked after its keys' entries were held | On adopting the revoking context, and on restore, every held entry of the persons affected is judged again with the whole walk; those whose chain passes the revoked issuer are withdrawn. | §9.7 |
| Honest work outside the cut | Refused and listed with its full name and digest; the owner re-admits it by exact name and digest, and every node holding it then applies it. | §9.5 |
| Certificate renewed, or expired | The key's entries verify alike under the old and the new certificate; the log continues. A key whose certificate lapsed without renewal is the exception, for every role the context lists in DataRequiresCut: refused (`Lapsed`, not kept) until its renewal or its cut. | §9.3 |
| Device key replaced by a new enrolment | Its entries stay accepted until the owner ends it with a cut bounded at the replacement. | §9.5 |
| Copy of the device's own key writes under its name | An own-name entry above `R_durable` raises `RolledBack` and the next seq goes above it; it is applied once it chains to this device's own log (and waits, held, until then), so the device and its peers agree; the head moves only for what was fetched, verified and chains, and never for a counter. | §3.8, §4.8 |
| Power loss | The device loses at most the entries since its last completed flush that no peer held; it never signs a different entry at a seq a peer holds, because it resumes above its durable reservation and says so in a signed gap statement; entries a peer held return from the peer. | §4 |
| Process killed (no power loss) | Every write that returned is kept; the restarted device resumes above `R` and signs the hole it left. | §4.9 |
| Disk flush fails | Signing past `R_durable` and every Members or Epoch change are refused with the disk's reason; nothing signed is retracted; reads continue; `StoreFailed` is raised. | §4.6 |
| Disk acknowledges a flush it did not make | Residual: a power loss can then make an honest device equivocate, and readers report it as any equivocation. | §4.10, §3.7 |
| Restored or cloned device | Detected at the first peer vector (`RolledBack`): the own entries above the reservation that chain are applied, as every peer applied them, and nothing is re-signed; with no peer reachable it can sign a seq a peer holds: equivocation, attributable (residual). | §4.8, §4.10 |
| Member removed mid-edit | Entries inside the removal cut merge; later ones are refused, and a reader that applied one before the cut arrived withdraws it and says so. | §3.8, §5 |
| Holder withholds, or rolls back | A relay's answer is the original, verified; an older or replayed notice never ends an ask; another source is asked. | §7.4 |
| Writer equivocates | Both packets are kept and reported (`Alert::Equivocation`), at one name or as a fork of the chain, for every entry kind; the key is suspected. | §3.7 |
| Writer names a previous entry by other bytes than the one held | The entry is refused (`Chain`), reported as a fork; nothing waits for it. | §3.7, §3.8 |
| Old software writes | Unknown even TLVs survive (the packet is never re-encoded); an unknown critical TLV refuses the entry and says to upgrade. | §3.4 |
| Poisoned cache | Verification fails, or the packet is signed by another device's key or does not decode: it is dropped, nothing is kept against its name, and it is fetched elsewhere. | §3.8, §7.4 |
| Stranger in a sync group | Costs a bounded list (64 names) and three asks per name nothing vouches for; never asked to answer for another device or to grant; its entries are refused. | §7.2, §7.12 |
| Removed reader | Refused every grant; the key of the epoch its removal starts did not exist before it, so the new epoch's entries stay closed to it; what it opened before it keeps. | §6.5, §6.6 |
| Owner's devices edit members at once | The facts union, removal wins, and each owner device repairs the epoch; the state depends on the entries held alone, not on their order. | §5 |
| Removed writer signs a new entry at a seq below its tip, or other bytes at a kept seq | Refused (`OutsideCut`) at every reader, in any arrival order: the chain of the tips decides and binds each kept entry's digest. | §3.8 |
| Removal cut's chain withheld | The entries it keeps wait, neither applied nor refused, the missing link asked for by its exact digest from any holder; never accepted unbound. | §3.8, §7.4 |
| Wrong key granted | Refused against the epoch's key check; the right key from any device is taken. | §6.2, §6.5 |
| Writer behind on a seal | Its unsealed entry is refused (`Unsealed`) in a sealed space; its later sealed entries do not wait for it. | §3.8, §6 |
| Relay or repository of another person | Carries ciphertext and grants wrapped to one device each; reads no payload and no key, and sees the metadata §6.7 lists. | §6.7 |
| Lossy link (packets dropped, delayed past the lifetime) | Every fetch that missed is asked again while the log still wants it — pausing 250 ms doubling to 4 s, then a minute after 16 misses — never waiting for a new notice; within one ask an unanswered Interest is expressed again under a fresh nonce; a notice naming nothing held costs bounded asks. | §7.3, §7.4 |
| Owner lists thousands of persons | A node adopts, refreshes and judges at most 64 self-certifying persons for one space and 256 in all; the rest are logged and told, their entries waiting. | §9.4 |
| After a restart a path serves only an older version of a member's context | The newest version adopted is kept signed, held again at start and refreshed from by continuity; an older version, that number with other content, or a branch not descending from it is refused. | §9.4 |
| Value in pieces, a piece forged or missing | A piece verifies by the digest its parent lists or is dropped; the value is `Unavailable` until whole; nothing is stored of a partial value. | §8 |
| Space created by an outsider under an owner's name | Its `Members` entries are refused (`NotMember`): only keys of devices of the owner's person, under its namespace by name, carry them. | §3.8, §9.9 |
| Signal sender removed or revoked | The gate flips on the first packet after the removal or revocation is held. | §11 |

The durability cases — a crash at each point, with and without a peer, with and
without `durable`, a restored image, a failing disk — are the matrix of §4.9.

## 13. Conformance

The conformance suite is `ndn-data-conformance` in ndn-sim. Each case has an id,
a title, the **property it guards** and a body written once over a neutral
trait (`Spaces`: `create`, `change`, `members`, `put`, `get`, `watch`, `open`,
with plain data types, and per-provider hooks for crashes, images, keys and the
network); the same body runs on every provider. A case MUST NOT be weakened to
pass: a failure is a defect of the implementation, or a mistaken re-expression
of the case, and is corrected there. Every case also runs over lossy and
reordering networks (seeds 0 to 39, `--faulty`), and the faulty runs are
deterministic for one seed (`--check-determinism`); the cost columns the suite
prints (`round_trips`, `bytes`, `signatures`, `converge_ms`, from `Node::signatures`
and `Node::held`) are a measurement, never a verdict.

The tables name the property each case guards, in this layer's terms, and the
tests of the `ndn-heap` crate that already hold it (names as in the crate; "suite
only" says the case is shown by the suite alone). A property the layer no longer
has is said so.

### 13.1 The core cases (both providers)

| Case | Property | Crate tests |
|---|---|---|
| c1 | Two devices' offline writes to one path are distinct entries that converge on every device to one value, the head of highest digest, and are never reported as equivocation | `two_offline_writers_converge_on_the_highest_digest`, `concurrent_versions_give_one_winner_in_any_order`, `register_state_is_independent_of_arrival_order`, `d9_a_crash_between_put_and_flush_never_re_signs_a_seq_a_peer_saw` |
| c2 | Removing a person is a chain cut: the entries inside it stay, a later one by her is refused at every reader whatever date it claims | `a_removed_writers_entry_inside_the_cut_is_kept_and_outside_it_refused`, `an_entry_by_a_removed_person_after_the_tip_never_counts_in_any_arrival_order`, `an_owners_removal_binds_what_it_holds_and_the_cut_survives_a_restart` |
| c3 | Revoking a stolen key is a cut: what others had seen from it stays, nothing the thief signs later is accepted, whatever date it claims; a device whose own key is revoked here signs nothing | `a_cut_keeps_exactly_what_the_device_holds_verified`, `a_thiefs_entry_first_verified_after_the_loss_is_left_out`, `a_revoked_key_is_outside_its_cut`, `a_device_whose_key_is_revoked_here_is_refused_by_name` |
| c4 | Seal audiences are persons (devices and groups are not audiences here): a reader opens what its person may read, and a person outside the audience cannot; a writer outside the audience is told so; a relay sees no path | `a_writer_in_a_private_space_seals_and_a_reader_outside_the_audience_gets_sealed`, `a_writer_outside_the_audience_is_told_so_not_to_retry`, `an_audience_member_waiting_for_its_key_is_told_to_retry_not_sealed`, `may_grant_refuses_each_condition_and_names_which`, `a_non_reader_gets_no_answer_and_the_granter_fetches_nothing`, `a_relay_sees_no_path` |
| c8 | A device back after a long absence fetches only what changed and reports exactly the changed paths, in far fewer round trips than one per entry | `a_returning_device_fetches_only_what_changed` (in `sync_tests` and over a forwarder in `mesh_net_tests`), `a_gap_in_the_notice_is_backfilled_in_a_window`, `a_cold_open_reads_one_marker_per_device_not_one_per_entry` |
| c9 | A space replicates exactly its members' logs: every member's entry reaches the others, and a non-member's entry under the same path reaches no one | `an_entry_before_the_members_entry_that_admits_its_writer_waits_for_it`, `a_listed_writers_own_device_packets_verify_and_nothing_else_of_hers_does`, `a_person_no_listing_names_has_nothing_judged`, `a_non_writer_put_is_refused_not_allowed` |
| k1 | No validity depends on a reader's clock: a key whose certificate lapsed is refused until the owner ends it, and after the cut a reader a year ahead still accepts what was signed before the lapse | `a_key_lapsed_by_this_clock_is_lapsed` (the cut half: suite only) |
| k2 | A revoked key's entry outside its cut is refused at every honest device, one that joins after the revocation included, while the entries inside stay readable | `a_revoked_key_is_outside_its_cut`, `what_a_revocation_refused_is_listed_and_not_kept` |
| k3 | Re-admitting an entry outside a cut brings back that entry only: not the key's next entry, nor the same seq in another space | `a_withdrawn_entry_is_taken_back_only_when_offered_again_and_verified`, `the_cut_names_satisfy_check_cut_names` (the re-admission itself is a trust-context operation: suite only) |
| k4 | A revocation that reaches a device is re-checked against what it accepted: an entry outside the cut is withdrawn and told to watchers, the entries inside stay | `a_late_cut_withdraws_what_it_does_not_keep`, `a_context_the_keyring_adopts_is_announced`, `a_key_revoked_while_the_node_was_off_is_withdrawn_at_start` |
| k5 | A renewed certificate continues the key's log: entries signed before and after stay valid at every reader, also once the old certificate expired | suite only (the judge's mapping, §9.2, is in `a_signer_of_a_held_namespace_is_valid_and_named`) |
| k6 | After the namespace recovers from a compromised root a revoked key's cut still holds everywhere, a device joining later included, and honest data verifies under renewed certificates | `the_authority_is_the_context_the_node_holds_for_the_key` (the recovery flow: suite only) |
| k7 | A thief's entries between the theft and the owner's report stay out of the cut though the owner's node held them: the cut keeps only what was first verified before the stated loss, the node takes nothing new of a suspected key, and the honest entries left out come back one by one | `a_thiefs_entry_first_verified_after_the_loss_is_left_out`, `a_suspected_keys_new_entries_are_not_taken_until_its_revocation`, `an_unreadable_entry_is_left_out_and_listed`, `unsuspect_lifts_every_space_and_a_non_key_is_refused` |
| k8 | A friend's guest key's authority over data ends with its certificate (the writer is `/bob/guest/phone`, a device of the listed writer Bob: a guest of the owner's own namespace holds none of the owner's powers, §1.2): what it signs after the lapse is refused by a reader whose clock says so, and the host is told once per entry; after the cut of Bob's root, what it wrote before is accepted and what it wrote after stays out | `a_key_lapsed_by_this_clock_is_lapsed`, `a_refusal_the_judge_or_the_mark_makes_is_alerted_once_and_replayed`, `only_the_cuts_of_keys_a_context_governs_raise_wants` (the cut half: suite only) |
| k9 | A cut binds the bytes it keeps: a device joining after the revocation reads the honest entry at every name in the cut, and the thief's other bytes at one are refused, also when a forwarder saw the thief's copy first | `the_cut_binds_the_digest_of_the_key_that_verified_each_entry_without_a_second_verification`, `other_bytes_at_a_kept_seq_are_refused` (the forwarder half: suite only) |
| k10 | A later trust-context version that revokes an issuer re-judges what a device holds through it: the entry is withdrawn and told, on adoption and after a restart, and an honest entry returns once its key is certified anew | `a_key_revoked_while_the_node_was_off_is_withdrawn_at_start`, `a_context_the_keyring_adopts_is_announced` |
| o1 | A cut that arrives is re-checked against what was already accepted: an entry accepted before and refused by the cut is withdrawn and told as withdrawn | `a_late_cut_withdraws_what_it_does_not_keep`, `withdrawing_a_head_restores_the_entry_it_superseded`, `withdrawal_leaves_what_never_applying_would_have_left` |
| o2 | Entries outside a revocation cut are refused until the owner re-admits specific ones by name and digest; exactly those return, the thief's stay out, even one at the same name, also at a node that heard the thief first and kept the honest entry as evidence | `what_a_revocation_refused_is_listed_and_not_kept`, `a_withdrawn_entry_is_taken_back_only_when_offered_again_and_verified`, `the_second_packet_kept_as_evidence_takes_the_name_when_the_first_is_refused`, `the_honest_copy_kept_as_evidence_is_applied_when_the_owner_readmits_it` |
| o3 | Completeness is per writer: a reader holds exactly each other member's chain up to its tip, and an offline member is a tip that has not moved, not a gap the reader cannot see | `a_gap_in_the_notice_is_backfilled_in_a_window`, `one_new_entry_is_one_fetch`, `a_restart_finds_the_fold_the_register_and_the_held_ranges` |
| o4 | A reader keeps up with a writer that never pauses: it comes to hold everything written before it looked, then every entry up to any later moment | `a_replayed_stale_notice_never_stops_the_fetch_of_a_newer_entry`, `a_gap_in_the_notice_is_backfilled_in_a_window`, `one_new_entry_is_one_fetch` |
| o5 | With one packet in five lost on its way to each device, the first entry a writer seals reaches a reader's watch opened within seconds, not minutes: a grant, an epoch key, an entry that missed is asked again with a capped back-off until held | `a_forged_entry_is_asked_again_with_growing_pauses`, `the_grant_pull_walks_creator_then_relays_with_backoff` (the loss profile: suite only) |
| p1 | A put never waits on another device | `a_put_never_waits_on_the_network`, `put_visible_at_once_is_served_before_the_flush_returns` |
| r1 | Two owner devices remove readers at once: the facts merge, removal wins, each repairs, writers seal in one complete epoch, and a removed reader reads nothing written after both are known | `concurrent_removals_leave_a_complete_epoch_after_each_owner_device_repairs`, `concurrent_removals_end_with_one_complete_epoch`, `a_removed_reader_leaves_no_epoch_in_force_until_the_owner_repairs`, `an_owner_device_signs_the_epoch_a_members_entry_of_another_leaves_incomplete`, `a_writer_never_seals_in_an_outgrown_epoch` |
| r3 | A device under the owner's name reads only while its **person** is in the audience: the premise of the old case, a device of the owner locked out of a space its person still reads, does not exist here (the audience is persons), so the case is re-expressed over a device of another person under the owner's name | `a_writer_device_under_the_owners_name_but_of_another_person_cannot_carry_members_or_epoch_entries`, `a_device_of_another_person_under_the_owners_name_does_not_sign_members_or_epoch_entries`, `a_writer_in_a_private_space_seals_and_a_reader_outside_the_audience_gets_sealed` |
| r4 | An addition on one owner device and a removal on another, concurrent, both stand: the added person writes and reads everywhere, the removed one stays removed, his later entries refused and nothing sealed after both is opened by him | `fold_state_is_independent_of_arrival_order`, `removal_beats_an_add_of_the_same_id`, `an_entry_by_a_removed_person_after_the_tip_never_counts_in_any_arrival_order` |
| r5 | A removal cut binds the entries it keeps to their bytes: a reader that never held a kept entry refuses other bytes the removed writer signed at its name (`OutsideCut`) and reads the honest entry once a holder answers | `other_bytes_at_a_kept_seq_are_refused`, `two_packets_at_one_name_are_evidence_and_the_key_is_suspected` |
| r7 | A person removed in one entry stays removed when a device that had not seen it signs the next listing of her: every device ends with one membership, the removed person neither writer nor reader, her later entries refused | `removal_beats_an_add_of_the_same_id`, `fold_state_is_independent_of_arrival_order`, `removed_writers_lists_each_person_removed_and_not_readmitted` |
| h1 | A payload larger than an entry travels in pieces under its entry's name, each verified by the digest its parent lists: a reader reads exactly the bytes written, and it stays sealed to its audience all the way (a relay sees only its size) | `a_1_mib_payload_round_trips_through_pieces`, `a_1_mib_payload_reaches_the_peer_in_pieces`, `a_payload_over_the_inline_limit_round_trips_in_pieces_in_one_entry_batch`, `a_tampered_piece_is_refused_alone`, `a_sealed_payload_shows_only_its_size`, `a_blob_head_is_unavailable_until_assembled` |
| h10 | An entry reaches a reader from another member that holds it, the writer offline and no cache holding it: the holder answers with the writer's own signed entry (sealed, as ciphertext) and the reader verifies it against the writer's key | `a_held_copy_is_served_only_if_admitted`, `a_notice_naming_this_device_is_fetched_from_relays_never_from_itself`, `a_bad_piece_is_never_taken_and_another_holder_is_asked` |
| f1 | One `Members` entry and one grant per reader per epoch let a reader read every path of a space, however many there are (the per-path way of the old layer does not exist here) | `a_new_device_of_an_admitted_person_gets_the_key_by_a_grant` |
| w1 | One watch of a space reports every path under it, those created after it began included, whoever writes them, each tagged with its path, and never hands one watch the same entry twice | `create_put_get_watch_remove_round_trip`, `watch_lists_held_then_live_and_lags_past_the_queue` |
| n1 | A person named by her genesis key is adopted by name alone, version 1 fetched and checked as signed by the key the name hashes, and another key's version 1 for that name is refused and left held nowhere; once adopted, a space shared with her is read and written both ways | `a_person_listed_by_a_members_entry_is_adopted_for_that_space_only`, `an_unheld_person_is_judged_pending_until_adopted`, `adoption_survives_a_restart` |
| n2 | Members of one space named by their keys read each other with no gesture beyond the owner's listing: a device adopts, for that space's data alone, every self-certifying writer an owner-signed entry lists, and drops her when the listing does, her old entries kept by the cut | `a_person_listed_by_a_members_entry_is_adopted_for_that_space_only`, `a_person_no_fold_lists_is_released`, `a_listed_writers_own_device_packets_verify_and_nothing_else_of_hers_does`, `a_listing_past_the_caps_adopts_the_first_and_reports_the_rest` |
| d8 | The writes of a put reach the store as one batch without changing what a peer sees: sixty back-to-back puts take consecutive seqs and all arrive in order; after `close` and a start on the store the next put signs the next seq | `batches_reach_the_store_as_one_apply`, `an_own_put_is_signed_chained_stored_in_one_batch_and_applied`, `a_clean_close_leaves_no_hole_and_no_gap_statement`, `start_restores_held_spaces`, `each_structural_entry_holds_everything_after_it_until_its_own_flush` |

### 13.2 Durability (this layer only)

Over the hooks `crash` (the store's image at the last returned `sync`, the node
dropped, a start from the image), `image`, `restore` and `block_flush`.

| Case | Property | Crate tests |
|---|---|---|
| d9 | A crash between a put and its flush never makes the device sign a different entry at a seq a peer saw | `d9_a_crash_between_put_and_flush_never_re_signs_a_seq_a_peer_saw`, `no_two_entries_at_one_seq_for_random_crash_points`, `never_signs_above_r_durable` |
| d10 | The same with the peer reachable: the entries the peer held come back whole, adopted, with no hole for them | `d10_a_crash_between_put_and_flush_with_the_peer_reachable_returns_the_entries_whole`, `recovery_adopts_only_own_entries_that_verify_chain_and_lie_within_r_durable` |
| d11 | With no peer, the hole is signed and readers do not wait for it | `d11_with_no_peer_the_hole_is_signed_and_readers_do_not_wait`, `the_first_entry_after_an_unclean_open_states_the_gap`, `a_void_declared_by_a_gap_statement_is_never_asked` |
| d12 | A restored old image with peers online raises `RolledBack`, applies the own entries above the reservation that chain (so this device and its peers read the same value), and signs above them: nothing is re-signed | `d12_a_restored_old_image_with_peers_online_raises_rolledback_and_reuses_nothing`, `an_old_image_applies_every_own_entry_that_chains_and_resumes_above_them`, `an_own_entry_above_r_durable_that_chains_to_nothing_held_raises_rolledback_and_waits`, `recovery_adopts_only_own_entries_that_verify_chain_and_lie_within_r_durable` |
| d13 | A killed process loses nothing that returned | `d13_kill_9_loses_nothing_on_fjall`, `d13_kill_9_loses_nothing_on_redb`, `kill_9_loses_nothing_on_fjall`, `kill_9_loses_nothing_on_redb` |
| d14 | A failed reservation flush refuses puts past `R_durable` with the disk's reason, raises `StoreFailed`, and reads continue | `d14_a_failed_reservation_flush_refuses_puts_past_r_with_the_disks_reason_and_reads_continue`, `a_failed_flush_is_sticky_and_refuses_signing_past_r_durable_with_the_disks_reason_and_reads_continue` |
| d15 | A durable put survives a power cut, whenever the power goes, also while the disk image of an earlier flush is being replaced | `d15_a_durable_put_survives_crash`, `a_power_cut_keeps_what_a_returned_flush_covered_on_fjall`, `a_power_cut_keeps_what_a_returned_flush_covered_on_redb`, `a_power_cut_at_any_moment_leaves_a_whole_image_on_fjall`, `a_power_cut_at_any_moment_leaves_a_whole_image_on_redb` |
| d16 | A `Members` or `Epoch` operation is invisible to peers before its flush | `d16_a_members_operation_is_not_served_or_announced_before_its_flush`, `a_structural_entry_is_released_only_after_a_flush_that_covers_it`, `a_structural_entry_is_never_released_when_its_flush_fails` |

### 13.3 Chain, fold, grant (this layer only)

| Case | Property | Crate tests |
|---|---|---|
| q1 | Equivocation evidence: two packets at one name from a copied key are both kept, `Alert::Equivocation` is raised for an entry of any kind, the key is suspected and its new entries are not applied | `two_packets_at_one_name_are_evidence_and_the_key_is_suspected`, `equivocation_in_a_members_or_epoch_entry_is_reported_to_the_host`, `a_suspected_keys_new_entries_are_not_taken_until_its_revocation` |
| q2 | A removal keeps exactly the chain ancestors of its tips: an orphan inside a declared gap is kept, other bytes at a kept seq refused, an entry above the tip refused; a fork among a removed writer's entries is the cut's to settle and is still told as an equivocation | `an_orphan_inside_a_gap_is_kept`, `other_bytes_at_a_kept_seq_are_refused`, `a_removed_writers_entry_inside_the_cut_is_kept_and_outside_it_refused`, `an_entry_by_a_removed_person_after_the_tip_never_counts_in_any_arrival_order`, `a_removed_writers_fork_below_the_tip_is_told_and_not_refused_as_a_chain_fork` |
| q3 | The membership fold depends on the entries held alone: three devices applying the same `Members` entries in different arrival orders while offline hold the same members and epoch | `fold_state_is_independent_of_arrival_order`, `withdrawing_a_members_entry_equals_never_having_seen_it` |
| q4 | A cold device joining a space whose writer crashed twice fetches every entry and asks for no seq inside a declared gap beyond the miss bound | `a_void_declared_by_a_gap_statement_is_never_asked`, `a_gap_in_the_notice_is_backfilled_in_a_window` |
| q5 | Two owner devices remove two readers at once: after the repair writers seal in one complete epoch and neither removed reader opens later entries | `concurrent_removals_leave_a_complete_epoch_after_each_owner_device_repairs`, `concurrent_removals_end_with_one_complete_epoch`, `a_writer_never_seals_in_an_outgrown_epoch` |
| q6 | A new device of an admitted person gets the epoch key by grant and reads that epoch's history; a removed person's new device is refused | `a_new_device_of_an_admitted_person_gets_the_key_by_a_grant`, `a_reader_added_by_an_add_reads_the_history_of_that_epoch`, `a_removed_reader_is_refused_every_later_grant` |
| q7 | A reader added after the creation and removed again leaves its epoch out of force though the epoch's audience never changed: a new epoch is signed and the removed reader opens nothing written after | `a_reader_added_to_an_epoch_and_removed_leaves_it_out_of_force`, `holders_keep_every_reader_ever_named_to_an_epoch_and_the_audience_only_the_standing`, `holders_never_shrink_and_bound_the_epoch_in_force`, `a_reader_added_by_change_and_removed_again_cannot_open_the_next_put`, `a_reader_added_by_an_add_and_removed_reads_nothing_written_after` |
| q8 | An epoch a held epoch replaces is never in force, whatever the order of the creators' names, and returns when the replacing entry is withdrawn | `an_epoch_a_held_epoch_replaces_is_never_in_force_whatever_their_order`, `withdrawing_an_epoch_equals_never_having_seen_it`, `only_a_put_or_an_epoch_names_what_it_supersedes` |
| q9 | A reader's device whose key is revoked is granted no key and the epoch it held goes out of force: an owner device signs one new epoch that replaces it, a restart none more; a granter's kept seal key and grant never outlive a revocation | `may_grant_refuses_each_condition_and_names_which`, `an_asker_with_a_revoked_key_gets_no_grant`, `a_reader_device_with_a_revoked_key_is_refused_every_grant`, `a_kept_seal_key_and_grant_are_not_served_after_the_judge_moves`, `revoking_a_reader_devices_key_makes_an_owner_device_sign_a_new_epoch_once` |

### 13.4 Signals (with the signal transport, one provider)

The transport that carries signals (`ndn-surface`) owns most of these; this layer
owns the gate (§11): who is a member, the signal keys, admission of a header,
and the count that walks admitted runs again. The suite runs them on this layer
only.

| Case | Property | Crate tests |
|---|---|---|
| e1 | A member's signals reach every other member, attributed to the device whose key vouched for the run, each delivered once and never older than one before it; a reader of a sealed space holds the scope and keys to receive them and cannot send | `a_members_header_is_admitted_at_a_peer_node_and_a_removed_writers_is_not`, `a_reader_of_a_sealed_space_gets_scope_and_keys_but_cannot_send_and_its_headers_are_not_admitted` (delivery: suite only) |
| e2 | A device no entry in force names is refused `NotMember` when it opens a run, and its hand-made packets are refused by every member | `a_header_signed_by_a_non_member_is_refused_with_the_reason`, `a_device_that_is_no_member_uses_no_signals`, `a_spaces_members_are_its_writers_by_person_and_no_stranger` |
| e3 | A member cannot pass signals off as another's: a run is another's only if its run key signed | suite only (the run key is the transport's) |
| e4 | A replayed packet is refused as a sequence its run already delivered | suite only |
| e5 | From the moment a device holds the entry that removes a member, or the revocation of a key, every packet of that member or key is refused, signals of the new epoch cannot be opened by the removed member, and its own send answers `NotMember` | `signal_member_flips_after_a_removal`, `a_revoked_key_is_no_member_once_its_revocation_is_held`, `a_sealed_space_gives_its_audience_the_keys_of_its_epochs`, `a_members_header_is_admitted_at_a_peer_node_and_a_removed_writers_is_not` |
| e6 | A relay of a sealed space's signals sees only ciphertext, a key id, a size and timing | `a_signal_key_is_the_hkdf_the_spec_fixes`, `signal_keys_are_per_epoch_and_zeroized` (the packets: suite only) |
| e7 | No store keeps a signal: nothing under `32=signal` is stored, served or fetched | `signal_run_names_round_trip_and_refuse_what_they_are_not`, `the_keyword_router_names_each_served_kind_in_one_look`, `localhost_and_other_devices_names_are_never_served` |
| e8 | The newest signal per address survives loss, duplication and reordering | suite only (the transport's) |
| e9 | Live edits never become entries: a stream of signals ending in one put adds exactly one entry | suite only (this layer never stores a signal, §11) |
| e10 | Four senders at 60 Hz in one sealed space: every receiver gets each sender's last signal per address, once, in order | suite only |
| e11 | A run header is taken only with proof that its signer holds the run key | suite only; the signer's membership and signature: `a_header_signed_by_a_non_member_is_refused_with_the_reason` |
| e12 | A flood of unfetchable run headers never shuts out a member's run | `the_fetch_budget_bounds_waiting_headers`, `a_device_whose_certificate_could_not_be_had_is_not_asked_again_for_30_seconds`, `a_member_header_admitted_after_the_chain_fetch` |
| e13 | Forged packets of a held run do not starve its genuine ones | suite only |
| e14 | One member cannot take a space's run slots, and a removal frees them at once | `signal_member_flips_after_a_removal` (the slots: suite only) |
| e15 | A packet at the largest sequence is taken or refused like any other | suite only |
| e16 | Revoking a sender's issuer ends its held run without waiting for its next header | `a_revoked_key_is_no_member_once_its_revocation_is_held` (the count `revocations()` moves), `a_header_under_an_expired_certificate_is_refused` |
| e17 | A signal of 512 octets is delivered whole under the longest space names, and a name over the limit is refused with the limit stated | `space_names_of_one_to_four_components_parse_and_five_do_not` (the signal's size: suite only) |
| e18 | A member whose clock stepped back across a restart is heard again | suite only; the clock is not in this layer (§11) |
| e19 | A crash loop and a corrected clock leave a member's signal clock at real time | suite only; the clock is not in this layer (§11) |

### 13.5 Invitations (with `ndn-invite`, both providers)

The protocol of an invitation (offers, secrets, proofs, short codes) is
`ndn-invite`'s and uses this layer through `change`, `Change::Members`, `open`
and `ready`, and the grant pull. The cases keep their ids and run on both
providers; this layer's own tests of the part they use are named, and the rest
is suite only.

| Case | Property | Crate tests |
|---|---|---|
| i1 | A stranger with only a code becomes a member with the role the offer names and each side reads what the other writes | `a_new_device_of_an_admitted_person_gets_the_key_by_a_grant` |
| i2 | A code once used admits nobody else; its user asking again is answered again | suite only |
| i3 | A code past its expiry admits nobody | suite only |
| i4 | Wrong tries count durably across a restart, then the offer closes for good | suite only |
| i5 | A code replayed by a third party admits one key, never two | suite only |
| i6 | An ask forged without the secret is counted and grants nothing | suite only |
| i7 | A join while the inviter is unreachable is refused as not ready and spends nothing | suite only |
| i8 | A joiner cannot claim a namespace that overlaps one the inviter trusts | suite only |
| i9 | A code cannot make the joiner trust a namespace overlapping one it trusts | suite only |
| i10 | Removing a member who joined by a code lasts: asking again with the code never makes it a member again | `removal_beats_an_add_of_the_same_id`, `a_removed_reader_is_refused_every_later_grant` |
| i11 | A stranger cannot close someone else's offer; a used offer counts no tries | suite only |
| i12 | A member removed from another device of the owner never comes back by its code | `removal_beats_an_add_of_the_same_id`, `a_fresh_id_readmits` |
| i13 | A closed offer admits no one new yet answers the writer it admitted until it expires | suite only |
| i14 | A join returns once the joiner may write and says what it waits for | `a_non_writer_put_is_refused_not_allowed`, `a_sealed_entry_without_the_key_is_held_closed_and_opens_when_the_key_arrives` (`ready`, `NotReady`: §10.3) |
| i15 | An offer's admission makes one grant to link, for the admitted key only | suite only |
| i16 | A held entry that leaves the person out ends the grant, and a restart keeps the rest | `a_members_entry_that_only_removes_a_reader_is_a_membership_change` (the `Change::Members` the grant follows) |
| i17 | A held entry that demotes the person changes the grant's role, and a restart keeps it | `a_members_entry_that_only_removes_a_reader_is_a_membership_change` |
| i18 | Two offers to one person are two grants, and an entry ends one space's alone | suite only |
| i19 | A person let go takes the entry that lets them go and says so | suite only (needs the host surface of `ndn-invite` to fetch an entry) |
| i20 | Writers invited by separate invitations read each other through the inviter's copy | `relays_are_vouched_for_ranked_and_bounded`, `a_held_copy_is_served_only_if_admitted` |
| i21 | A member let go and invited again joins the sealed space and writes again | `a_fresh_id_readmits` |
| i22 | The joiner's list of joined spaces follows the members in force | suite only |
| i23 | The joiner holds a grant for the inviter, told once and re-derived from the entries | suite only |
| i24 | Mutual invitations make an inviter's entry and a mirror entry that end one by one | suite only |
| i25 | A short code joins: one line, a first contact dialled once, a hint record fetched | suite only |
| i26 | A short code is refused saying why: a typo, a wrong count, a closed, expired or unanswered offer, an altered record | suite only |

### 13.6 Cases that are not carried over

| Case | Why |
|---|---|
| p2 | its premise, narrowing a folder by a collection's own record, does not exist; its sealing half is `a_writer_never_seals_in_an_outgrown_epoch` |
| r2 | an audience of people-groups has no counterpart here |
| r6 | the upgrade of an old-form (unbound) cut has no counterpart: a removal cut is tips from the start (§9.6) |
| f3, f4 | a collection's first own record and a host's list of a folder's members have no counterpart; what a host reads of members is `members()` and `Change::Members` (§10.3, §10.4) |

### 13.7 What a conforming implementation shows

An implementation conforms when every case of §13.1 to §13.5 that applies to it
passes on it, clean and under each faulty seed, with the same body as on every
other provider, and the differential of the shared cases (§13.1) shows no id
whose status differs from the other provider's. Every property of §1.6 is held
by named crate tests (§14.2) and shown again by cases of this section; a case
that fails where its crate tests pass is a missing crate test, added first.

### 13.8 Measured: put to watch

What the reference implementation measured, **on one shared machine** (load
average 12 to 13 on 64 CPUs, four cores with idle SMT siblings picked per run, a
release build at ndn-rs `24ea1e95`). It is a measurement, not a conformance
condition: the numbers move with the machine and are recorded so that a later
change can be compared, and the targets are the ones the design was held to.

The setup is the `put_watch` example of the crate: two `Node`s, one device each of
`/alice`, on two app faces of **one** forwarder, a fjall store each on disk;
every validator holds every certificate, so each entry the second node takes
goes through the whole durable judgement (one signature verification). A's `put`
starts the clock and B's `watch` yielding that `Put` stops it; 10 warm-ups, then
200 runs of each size back to back, in each of 16 process runs. The flush is
off the path: it runs while the notice travels.

| Size | p50 of a process run: min / median / max, ms | p95, median, ms | Target p50, hard fail | Verdict |
|---|---|---|---|---|
| 1 KiB | 0.344 / 0.479 / 0.759 | 0.757 | ≤ 0.7 ms, above 1.0 ms | median within the target; **2 of 16 process runs above 0.7 ms** (0.725 and 0.759), none above 1.0 ms |
| 16 KiB | 0.788 / 0.993 / 1.353 | 1.521 | ≤ 1.6 ms, above 3 ms | within the target in 16 of 16 |
| 1 MiB | 19.3 / 23.1 / 27.2 | 32.9 | ≤ 45 ms, above 70 ms | within the target in 16 of 16 |

One run in the form of the ladder's rows (p50 / p95, ms): the put on A to B's
watch yielding, 1 KiB 0.428 / 0.811, 16 KiB 1.156 / 1.572, 1 MiB 22.849 / 33.622;
A's `put` returning, p50, 0.137, 0.234 and 5.571. No run took over 150 ms. At 1
MiB, 100 traced runs made 260 fetches each: none answered after a
re-expression, none missed.

**Where a 1 KiB put's time goes** (hot, p50 ms after the put began): `put_returns`
0.077, `announce` 0.080, `sync_update` 0.121 (the notice, +0.041), `fetch_out`
0.159, `fetch_in` 0.230 (the round trip, +0.072), `verify_begin` 0.234,
`judged` 0.348 (+0.114: the durable judgement, one Ed25519 verification), `watch_send`
0.389 (+0.04: admit and tell), the watch yields at 0.397. The 1 MiB put spends
about 17 of its 23 ms fetching its 260 pieces (window 32) and A about 4 to 6 ms
cutting, hashing and writing it.

**The machine moves it.** With 10 ms of idle between runs the medians were 0.82,
1.81 and 26.9 ms (1 KiB, 16 KiB, 1 MiB) and with 100 ms 0.93, 1.82 and 34.7: a
put that follows silence misses the 1 KiB and 16 KiB targets on this machine,
and every stage of the timeline grows alike, which the measurer reads as CPU
frequency and idle-state exit rather than one stage of the code. A sealed space
measured 0.64, 1.17 and 28.9 ms, two worker threads 0.43, 0.81 and 19.3.

**Cold open of 100,000 entries** (fjall, 120 MiB on disk, 100,000 paths, 15,300
puts a second to build): the store opens in 0.83 to 0.91 s, `Node::start` takes
2.1 to 2.4 s after a clean close and 2.5 to 3.1 s after `shutdown` (an unclean
start), the first `get` answers in 0.04 to 1.2 ms, and a watcher's first
listing takes 0.63 to 0.69 s. Start plus first `get` (0.9 s of store open
included) is under 5 s; the layer has no checkpoint, and a start over 5 s is to
be reported to the owner of the layer, checkpoints being a later work. With
1,000 paths of 100 versions each: store open 57 ms, `Node::start` 0.28
to 0.40 s, first `get` 0.014 ms, listing 5.4 ms.

### 13.9 The sibling surface (this layer only)

| Case | Property | Crate tests |
|---|---|---|
| s1 | An extension answers the Interests under the keyword it registered, signed by the device's key and verified by a peer, and no others: an unregistered keyword and a core one are Nacked and never reach it; the core router serves as before | `an_extension_answers_its_keyword_only` |
| s2 | The node signs for its extensions only `<D>/32=<keyword>/…` of a registered keyword; every other name is refused and signs nothing | `sign_packet_refuses_a_name_no_extension_owns` |
| s3 | An extension claiming a core keyword, a keyword already claimed, none, or a word that is no keyword is refused, and a refused claim registers none of its keywords | `extend_refuses_a_core_keyword_and_a_duplicate`, `every_keyword_the_layers_names_carry_is_a_core_keyword` |
| s4 | A device an offer admitted is told `NotReady` (retry), not `NotAllowed`, until the fold lists its person; the note is removed when it does, survives a restart, is not made for a listed person, and ends (`NotAllowed` again) when the admission was undone before the device ever saw it listed | `note_joined_turns_not_allowed_into_not_ready_until_listed`, `a_joined_note_survives_a_restart`, `a_joined_note_ends_when_the_listing_it_waited_for_was_undone` |
| s5 | One entry is fetched by its log name and admitted by the ordinary judge: held and applied, nothing else fetched; a refused entry is refused to the caller; none answered is `Unavailable` | `fetch_entry_admits_one_entry_by_name`, `fetch_entry_does_not_admit_what_the_judge_refuses` |
| s6 | The Members entry that removed a person is named identically by every node holding the same entries, and by none for a person listed, never listed, or the owner | `removed_by_names_the_members_entry_that_removed_a_person`, `removal_record_names_the_lowest_entry_that_removed_a_person_listed_no_more` |
| s7 | The node lends its key store, validator, store, clock, config, persons and the persons adopted for spaces | `the_node_lends_its_keys_validator_store_clock_and_persons`, `a_person_listed_by_a_members_entry_is_adopted_for_that_space_only` |

## 14. Threat notes

### 14.1 The notes

- **D17: an unbacked counter never raises a head.** A state vector names no
  sender; a counter only decides what to fetch. A head moves only for an entry
  fetched, verified under this device's key and chained, and a counter above the
  head with nothing behind it is reported (`UnbackedCounter`) and changes nothing
  (§4.8, §7.2).
- **Malleable signatures.** Every digest that orders, links or compares is a
  signed-region digest, so a relay's re-signed copy of an ECDSA entry is one
  object (§1.5).
- **Orphans above a cut's tip.** An entry of a removed person above its tip, or
  off the chain of its tip, or of a device the removing owner never held, never
  counts, in any arrival order; a copy already made is not retracted (§3.8, §4.10,
  §5.6).
- **Restore offline with no peer reachable.** A restored backup can sign a seq a
  peer holds; it is detected, attributed and handled as a compromise: re-enrol the
  device (§4.10).
- **A disk that lies about a flush** defeats the barrier: a power loss can then
  make an honest device equivocate (§4.10).
- **History kept forever.** There is no compaction (§1.7, §4.10).
- **Cross-path `after`.** An entry's `after` is honoured literally even across
  paths: a writer can hide another path's head by naming it, with no more power
  than a removal written at that path (§3.9, §10).
- **Equivocation visibility.** It is reported for entries of every kind,
  `Members` and `Epoch` included; both packets are kept and neither is silently
  preferred (§3.7).
- **What a relay sees.** Names, kinds, writers, seqs, chain links, epoch ids, the
  digests an entry supersedes and sizes; with sealing, not the path or the value
  (§6.7). Pieces show only the ciphertext's size (§8.7).
- **The owner rule's second and third halves are checked.** A `Members` or
  `Epoch` carrier must be a device of the owner's *person* (a device under the
  owner's name whose key a deeper context validates cannot carry them) **and**
  an `admin` or `member` device where the owner declares the role layout (a
  `guest`, a `node` relay and a role-less device cannot), at admission, when
  signing, when granting a key and for signals (§2.1, §3.8 step 6, §9.9).
- **Writers that are not readers** of a sealed space cannot hold a key and cannot
  seal (§5.7, §10.7): their `put` answers `NotAllowed`. A sealed space listing
  more than 256 readers is refused before anything is signed (§10.7).

### 14.2 The properties of §1.6 and what holds each

Each property of §1.6 is held by one module and shown by named tests (the
`ndn-heap` crate, under `src/`).

| # | Property | Module | Tests |
|---|---|---|---|
| 1 | A removed writer's new entry never counts: the chain of the tip decides | `log/admit.rs`, `log/chain.rs` | `an_entry_by_a_removed_person_after_the_tip_never_counts_in_any_arrival_order`, `a_removed_writers_entry_inside_the_cut_is_kept_and_outside_it_refused`, `an_orphan_inside_a_gap_is_kept` |
| 2 | Other bytes at a kept seq are refused | `log/chain.rs` | `other_bytes_at_a_kept_seq_are_refused` |
| 3 | Membership converges; removal wins | `fold.rs` | `fold_state_is_independent_of_arrival_order`, `removal_beats_an_add_of_the_same_id`, `a_fresh_id_readmits`, `concurrent_removals_leave_a_complete_epoch_after_each_owner_device_repairs` |
| 4 | A late removal or revocation withdraws what was applied | `log/admit.rs`, `node.rs` | `a_late_cut_withdraws_what_it_does_not_keep`, `withdrawing_a_head_restores_the_entry_it_superseded` (log, register), `a_context_the_keyring_adopts_is_announced` |
| 5 | A writer never seals in an outgrown epoch: one a removed reader holds, or a revoked reader device may hold | `fold.rs`, `log/own.rs`, `space.rs` | `a_writer_never_seals_in_an_outgrown_epoch`, `an_own_members_entry_spawns_no_task_to_sign_its_epoch`, `a_removed_reader_leaves_no_epoch_in_force_until_the_owner_repairs`, `a_reader_added_to_an_epoch_and_removed_leaves_it_out_of_force`, `a_reader_added_by_change_and_removed_again_cannot_open_the_next_put`, `revoking_a_reader_devices_key_makes_an_owner_device_sign_a_new_epoch_once` |
| 6 | An epoch key goes only to whom the records admit, and is checked | `seal.rs`, `serve.rs` | `may_grant_refuses_each_condition_and_names_which`, `a_key_that_fails_the_key_check_is_dropped`, `a_non_reader_gets_no_answer_and_the_granter_fetches_nothing`, `a_removed_reader_is_refused_every_later_grant`, `an_asker_with_a_revoked_key_gets_no_grant`, `a_kept_seal_key_and_grant_are_not_served_after_the_judge_moves` |
| 7 | An unsealed entry in a sealed space is refused | `log/admit.rs` | `an_unsealed_entry_in_a_sealed_space_is_refused`, `a_sealed_entry_in_a_public_space_is_refused` |
| 8 | Digests are signed-region digests | `wire/digest.rs`, `log/admit.rs` | `a_reencoded_copy_has_the_same_signed_digest`, `a_relays_high_s_copy_changes_nothing` |
| 9 | The head survives restart; a replayed lower one changes nothing | `store.rs`, `reserve.rs`, `log.rs` | `a_devices_own_head_after_restart_comes_from_its_ledger_even_if_an_entry_does_not_decode`, `a_device_that_cannot_read_its_own_ledger_does_not_open_the_space`, `a_reopen_in_the_same_process_trusts_only_an_r_a_flush_covered`, `an_own_entry_above_r_durable_raises_rolledback_and_is_not_applied`, `d9_a_crash_between_put_and_flush_never_re_signs_a_seq_a_peer_saw`, `no_two_entries_at_one_seq_for_random_crash_points` |
| 10 | No decision accepts anything because of a clock | `trust.rs` | `a_key_lapsed_by_this_clock_is_lapsed` |
| 11 | A notice is bounded and decides nothing | `heard.rs`, `sync.rs` | `heard_never_displaces_a_vouched_device`, `a_sync_interest_naming_many_devices_leaves_the_list_bounded`, `a_vector_naming_a_device_at_counter_zero_is_ignored`, `a_notice_names_nothing_it_decides` |
| 12 | A miss decides nothing; ask again while owed | `fetch.rs` | `a_forged_entry_is_asked_again_with_growing_pauses`, `a_replayed_stale_notice_never_stops_the_fetch_of_a_newer_entry` |
| 13 | A space replicates exactly its members' logs | `log/admit.rs`, `node.rs` | `a_members_entry_from_a_device_outside_the_owner_namespace_is_refused`, `an_entry_before_the_members_entry_that_admits_its_writer_waits_for_it`, `follow_stores_and_serves_but_publishes_no_vector_entry_and_reads_nothing_sealed` |
| 14 | A big payload verifies piece by piece; a sealed one shows only its size; memory does not grow with the blobs held | `pieces.rs`, `wire/pieces.rs`, `fetch.rs`, `space.rs` | `a_piece_from_a_stranger_verifies_by_digest_alone`, `a_sealed_payload_shows_only_its_size`, `pieces_are_written_in_one_batch_by_the_writer_and_kept_as_the_reader_proves_them`, `a_payload_with_a_piece_missing_reads_no_chunk`, `only_a_few_values_are_gathered_at_once_and_every_one_in_turn`, `opening_a_space_reads_no_payload_and_no_piece`, `a_watch_reads_a_value_in_pieces_only_when_it_reaches_it`, `a_value_whose_piece_the_store_lost_is_unavailable_and_gathered_again` |
| 15 | Errors say why and what to do; `put` never waits on the network | `error.rs`, `space.rs` | `every_refusal_names_a_next_step`, `a_put_never_waits_on_the_network` |

## 15. TLV registry

The data layer owns **0x0600–0x063F** (64 numbers), registered in
[README.md](README.md#tlv-type-numbers). **Odd** numbers are critical: a decoder
refuses a record holding one it does not know. **Even** numbers are skippable
and reserved for additive fields (§3.4). Every number in use is odd; 0x063D–0x063F
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
| 0x0635 | `GRANT_ASK` | `Name` (space), `EPOCH_ID`, `SEAL_KEY_PACKET`: the last component of a grant's name | 2.3, 6.5 |
| 0x0637 | `SEAL_KEY` | 32 octets: an X25519 public key; the Content of a seal key packet | 6.2 |
| 0x0639 | `GRANT` | `EPHEMERAL_KEY`, `CIPHERTEXT`: the Content of a grant packet | 6.2, 6.5 |
| 0x063B | `SEAL_KEY_PACKET` | the wire of the asker's seal key packet (a whole Data), at most 2,048 octets | 2.3, 3.3, 6.5 |

Name keywords this specification owns (KeywordNameComponent, TLV-TYPE 0x20): `data`,
`log`, `piece`, `manifest`, `seal`, `grant`, `held`, `sync`, `signal`, `run` (§2, §11). The numbers
that the deletions of the previous design freed (inside 0x0520–0x057F, and
0x05C0–0x05FE) stay quarantined, so no stale `ndn-data` packet ever decodes as
new content; the block 0x0640–0x0653 belongs to the custodian remote signer of
`ndn-security`, not to this specification.
