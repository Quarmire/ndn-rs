# Data layer: named, signed, versioned data

- **Status:** Slice 1 normative: versions, collections with owner-signed
  members records, the merge rule and its function `/merge/yrs`, types,
  signed nested summaries, snapshots, the sync notice, the verbs `get`, `put`,
  `watch`, `snapshot` and `share` (adding), and their wire format (§14).
  Sections marked with a later slice are not yet normative beyond what they
  state; a section marked *open* has no normative content beyond its text.
- **Scope:** the data model shared by files, databases and network
  exchanges — versions, collections, members, summaries, cuts, snapshots,
  custody, prune, seals and types — and the seven verbs over it. The Rust
  contract and its reference implementation are the `ndn-data` crate
  (`crates/app/ndn-data`: `DataLayer`, `Device`); conformance cases are
  `ndn-data-conformance` in ndn-sim.
- **Out of scope:** views and lenses above the layer; trust-context encoding
  ([trust-context.md](trust-context.md)); link admission
  ([ndn-link.md](ndn-link.md)); State Vector Sync itself (ndn-svs v2, as
  `ndn-sync` implements it).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174)
when, and only when, they appear in all capitals, as shown here.

## 1. Principle: end to end

The ends are the signing key and the reader. Caching, combining requests,
relaying and holding are performance or protection only. Whether data is
correct, newest, readable or still valid MUST be decided by the reader, from
the data, its name, the trust context and the cuts. A reader's correctness
MUST NOT depend on any forwarder, cache, repository or relay.

## 2. Invariants

Every implementation MUST hold all of these.

1. **Checkable anywhere.** Any version verifies from its bytes, its name,
   the trust context and the cuts — never from a server or a clock.
2. **Immutable per writer.** One `(writer, seq)` has one set of bytes. Two
   different versions with the same `(writer, seq)` are proof of
   misbehaviour attributable to that key; a reader MUST keep both and report
   them.
3. **Monotonic.** A writer's sequence and a collection's summary never go
   back. A reader MUST refuse a summary or members record older than one it
   has seen from the same signer.
4. **Completeness is relative.** "I have everything" always means
   "everything in this signed summary".
5. **Stale, never wrong.** Failures MUST degrade to older verified data, and
   the reader MUST be told how old.
6. **Authority is in the data.** Writing follows the trust schema and the
   collection's members; reading follows the seal; a cut ends both from a
   point on.
7. **Retention is chosen at write.** Custody MUST NOT extend keep; prune
   only narrows, and only over the pruner's own writes.
8. **Nothing is lost by not understanding it.** A writer MUST keep every
   field it does not know.
9. **Forward-only, said plainly.** Revocation and deletion stop future
   reads; an implementation MUST NOT claim to recall copies already made.

No validity decision may read a wall clock. Dates are display and
retention only.

## 3. Names, devices, namespaces — slice 1

- A **device** `D` is the identity of one key: the key is named
  `<D>/KEY/<key-id>` (NDN key naming). `D` is the device's name in seals
  and the prefix it serves.
- The **namespace** of a name is its first component (`/alice`). It is the
  unit of the hierarchical trust schema (data and signing key share their
  first component), so it is the person a collection belongs to: the
  **owner** of collection `C` is the namespace of `C`.
- Every packet a device signs MUST be named under `D`, so any forwarder's
  hierarchical schema admits it and Interests for it route to the device.
- A **collection name** MUST NOT contain a KeywordNameComponent (type
  0x20) or an ImplicitSha256DigestComponent: keyword components mark the
  layer's own names (§14.1). A verb given such a name answers `NotFound`.

## 4. Version and log — slice 1 (blocks: slice 4)

A version is an immutable record signed by one key. It carries
`(writer, seq)`, parents, type, seal, keep, a date and a payload.

- A writer is one key, never a person. Each key keeps **one log**: every
  entry it signs about any collection — versions, members records (§6),
  snapshots (§11) — takes the next sequence number of that log. `seq` MUST
  increase by one with every entry and never goes back; entries of one key
  MUST NOT share a sequence space with any other key. A collection holds a
  subset of each writer's log, so its entries of one writer have gaps.
- Parents are the frontier (writer → highest seq) of the collection's state
  the writer had applied when it wrote (§5.2).
- The date is the writer's clock reading in milliseconds since the Unix
  epoch. A reader MUST NOT use it to accept or refuse anything.
- The payload of a slice-1 version is one entry: the fields the writer set
  (§10), and the merge function's operation (§5.1). A block of entries under
  one signature is slice 4.
- The seal a slice-1 version carries is the collection's readers at the
  time of writing, as the writer declares it; slice 1 does not encrypt
  (§9). Keep is recorded; enforcing it is slices 3 and 4.

A version is the Data packet `<D>/32=log/<C>/seq=<n>` whose Content is a
`VersionRecord` (§14.3), signed by the key `<D>/KEY/<id>`. A reader MUST
refuse (and MUST NOT apply) a log entry whose signature does not verify
against its trust context, whose signing key is not a key of the `D` its
name starts with, or whose record's collection is not the `C` in its name.

## 5. Collection and rule — slice 1 (log: slice 2, one key: slice 4)

A collection is a named, growing set of versions with a rule and a members
record. It exists when its first members record is signed (§6): `share`, or
a writer's first `put` into a collection of its own namespace, which signs
the host's default record (merge with `/merge/yrs`, the namespace writing
and reading).

| Rule | Meaning |
|---|---|
| one key | One key writes; the newest is its signed head with a freshness bound. Slice 4. |
| log | Each member key appends; the collection is the union of exactly its members' logs. Slice 2. |
| merge | Member logs plus a named merge function every reader runs alike. `get` returns the merged state at a frontier. |

The collection, not the application, decides what "newest" means. A
collection's rule is fixed by its first members record.

### 5.1 Merge functions

A merge function turns a writer's edit into an **operation** carried in the
version (`MergeOp`) and folds operations into a state. Every reader that
applies the same versions MUST obtain the same state. A reader that does not
know a collection's function MUST NOT claim a state for it and says so.

`/merge/yrs` is a Yjs document. Its root map `fields` holds one entry per
field, each value a binary (`Uint8Array`). The operation of a version is the
Yjs update (lib0 v1 encoding) of its edit: set every field the version sets,
delete every field it sets to an empty value. Concurrent sets of one field
resolve as Yjs resolves them; different fields never conflict. A writer's
Yjs client id is the low 53 bits of SHA-256 over the TLV encoding of its key
name, and a reader MUST refuse an operation that inserts content under any
other client id. A Yjs peer may therefore apply the same updates (it sees
the fields as binaries). A reader ignores root-map entries of other Yjs
shapes; they stay in the document.

### 5.2 Applying versions

A reader applies an admitted version `v = (w, s)` of collection `C` only
when

1. every entry of `w` in `C` below `s` — as `w`'s summary (§7) lists them —
   is applied, and
2. for every `(y, t)` in `v`'s parents, the reader has applied `y`'s entries
   in `C` up to `t`.

Until then `v` waits. The state's frontier `at` is, per writer, the highest
seq applied; by these rules every entry at or below it is applied, so `at`
names exactly the versions the value is computed from.

## 6. Members — slice 1 (owner, adding), slice 2 (removal, readers' keys)

The members record is signed by a key of the collection's owner namespace.
It lists the rule, the key-name prefixes that may write — of any namespace
(`/bob` writes into `/alice/docs/plan`) — and the audience that may read.

- A members record is an entry of its signer's log, `<D>/32=log/<C>/seq=<n>`
  with Content `MembersRecord` (§14.3). Its `Revision` is one more than the
  highest revision its signer had accepted for `C` (1 for the first).
- A reader MUST ignore a members record whose signer's namespace is not
  `C`'s. Of the records it holds for `C` it uses the one with the highest
  `(Revision, signer key name)`; a lower one never replaces it.
- A reader MUST apply to `C` only versions by keys under a prefix of the
  record's writers (and, as for every entry, admitted by the trust schema
  under the writer's own name). Versions that arrive before any members
  record wait for one; versions by other keys are refused `NotMember`.
- Slice 1 signs records that keep every writer of the previous revision and
  the rule. Removing a writer MUST add a cut (§8): slice 2.

## 7. Summary — slice 1

A writer's summary of a namespace `O` is its own log's index over `O`: a
tree of **nodes**, one per name under `O` the writer wrote into (and every
name on the way there). Completeness is per writer: with many writers each
publishes its own, and a reader gathers them from the members it hears in
the namespace's sync group (§12).

A node of name `X` carries:

- `Head`: the writer's highest seq in the subtree of `X`;
- `Entries`: the seqs of the writer's versions directly in `X`, as ranges —
  the seq → name mapping, since an entry's name is `<D>/32=log/<X>/seq=<n>`;
- `MembersEntries`: the seqs of its members records of `X`;
- its children: for each next name component under `X` with entries in its
  subtree, the child's component, `Head` and the implicit digest (SHA-256 of
  the whole Data packet) of the child's node. A node with more than 64
  children lists them on **pages** instead: 16 buckets by the first nibble
  of SHA-256 over the child component's TLV, each a page node listing its
  children, or (beyond 64 again) 16 sub-pages by the next nibble.

A node's content is fixed by the writer's log up to its head, so one node
name (`<D>/32=summary/<X>/seq=<head>`, a page
`<D>/32=summary/<X>/32=page/<path>/seq=<head>`) has one packet. Inner nodes
and pages are DigestSha256 packets; a reader MUST check each against the
digest its parent lists. The **root**, the node of `O` itself, is the only
signed one: `<D>/32=summary/<O>/seq=<head>`, signed by the device key,
FreshnessPeriod 0 so that discovery always reaches the writer. A writer
SHOULD sign a new root only when one is asked for and the tree changed;
SHOULD keep recently superseded nodes servable so a reader descending a
slightly older root completes; and MUST answer an Interest for a node it no
longer serves with a Nack, so the reader starts from a newer root.

A reader:

- discovers a writer's root with `<D>/32=summary/<O>` (CanBePrefix,
  MustBeFresh), verifies it as a log entry is verified (§4), and checks
  that its subject is `O`, its writer field its signing key and its name's
  seq its `Head`;
- MUST refuse a root whose `Head` is lower than one it verified from that
  writer for `O`, or than the highest seq it holds of that writer under `O`
  (invariant 3, "rollback");
- descends only into what it follows (the collections and folders it has
  put into, read or watched, and the names on the way to them), and only
  into children and pages whose digest differs from the one it last
  processed in full: an unchanged branch costs nothing. Watching a folder
  of 10,000 notes of which 37 changed costs the root, the folder node, the
  changed pages, the 37 notes and their new entries;
- fetches the entries the visited nodes list that it does not hold.

`watch` reports a `Summary` for each verified node of the watched name or
below it that it descends into: the collection, the signing writer,
frontier `{writer: Head}` and the node's inline children by digest (a paged
node lists none; its pages are not sub-collections).

## 8. Cut — slice 2 (removal), slice 5 (revocation)

A cut is a signed "up to here" for a key or for a member's keys: everything
inside its accepted frontier stays valid; anything else by those keys MUST
be refused, whatever date it claims.

- A cut replaces clock-based signing-time validity.
- *Open (slice 2):* when a cut arrives, a reader MUST re-check everything it
  already accepted from the cut's keys and withdraw what the cut refuses.
- *Open (slice 5):* a cut can drop honest work (a stolen device's unseen
  offline edits). The owner MAY re-admit specific versions by signing them
  into the members record.

## 9. Seal — slice 2

A seal is a read policy over people, devices and groups. An application is
never a seal audience: lenses hold no keys, and the host opens only what the
person pointed at. Holders without the key store and forward. Erasure is the
destruction of the key. Removing a reader moves reading to a new epoch.
Slice 1 records the seal a version declares (§4) and does not encrypt.

## 10. Type — slice 1

A type is a named, versioned content schema (`/types/note`, revision 2).
Revisions only add fields. Content is a set of named fields with opaque
values.

- A version sets fields: each field it carries is set to its value, a field
  carried with an empty value is removed, and every field it does not carry
  keeps its value. So a writer that knows only revision 1 keeps revision-2
  fields by construction (invariant 8); there is no "replace all" write.
- The type is recorded in the version for readers and lenses; it never
  changes how the merge function folds fields. A type MAY later declare
  richer field kinds (text merged by character); slice 1 has none.

## 11. Snapshot and state names — slice 1

A **state name** `<C>/32=state/<F>` names the merged value of merge
collection `C` at frontier `F` (the last component is a
GenericNameComponent whose value is a `Frontier` TLV). It is computed, never
fetched: a reader answers it by applying exactly the versions of `C` inside
`F` (§5.2) and MUST answer the same value on every device and however `C`
grows. A reader that does not hold every version inside `F` (as the
writers' summaries list them) MUST NOT answer a partial value.

A **snapshot** is an entry of its signer's log, `<D>/32=log/seq=<n>` (no
collection), Content `SnapshotRecord`: the names it pins, each an exact log
entry name or a state name. Publishing it is the atomic multi-object change
and makes a merged state citable: a link carries the snapshot's name.

## 12. Sync notice — slice 1

Each namespace `O` has a **sync group** `<O>/32=sync`, run as State Vector
Sync (ndn-svs v2 dialect). A device joins its own namespace's group, and the
group of every other namespace whose collections it puts into, reads or
watches. Each member's state-vector entry is named by its device name `D`;
the device publishes into `O`'s group after every entry it signs about a
collection under `O`.

The group only says "`D` moved". It carries no data and decides nothing: a
reader that hears it fetches `D`'s root for `O` (§7). Sync Interests are
unsigned; a stranger in the group costs a reader a root fetch, never a
wrong answer. A device's counter in a group starts at its log head when it
joins, so it stays above anything an earlier run of the same key announced.

Forwarders between devices MUST route `<O>/32=sync` to the other members
with the multicast strategy: a device registers the group prefix for its own
sync face, which shadows any shorter route.

## 13. Custody — slice 3

A custody lease is a holder's signed promise to keep what matches a prefix
until a date.

- A lease MUST NOT extend beyond the data's keep.
- A lease ends for anything an authorised prune covers.
- The owner audits leases by fetching random pieces; a lease nobody can
  serve counts as broken and repair starts.

## 14. Prune — slice 3

A prune is a signed record dropping the pruner's own versions under a prefix
up to a point. It spreads like data.

- A prune MUST cover only versions the pruner may write. Removing another
  writer's data in a shared collection is a merge edit every reader applies.
- A reader that knows a prune MUST report "pruned" for what it covers, not
  the data. Copies already made are the forward-only limit (invariant 9).

## 15. Verbs — slices 1–3, host surface slice 7

| Verb | Shape | Slice |
|---|---|---|
| `get` | `get(name) → version or state + age` | 1 |
| `put` | `put(collection, content, {type, keep}) → (writer, seq)` | 1 (`batch`: 4) |
| `watch` | `watch(collection, since F) → summary, new versions…` | 1 |
| `snapshot` | `snapshot(names \| collections) → snapshot` | 1 |
| `hold` | `hold(prefix, {copies, until}) → custody` | 3 |
| `prune` | `prune(prefix, upto)` | 3 |
| `share` | `share(collection, {readers, writers})` | 1 (adding), 2 (removing) |

Code mostly uses `get`, `put` and `watch`. `hold`, `prune` and `share` run
on host policy, or on the person's gesture. A function's answer is a `get` on
its name (slice 6). Exposure over forwarder management and the mobile FFI is
slice 7. A device answers a verb or option of a later slice with an error
that names the slice.

- **`get(C)`** of a merge collection answers its state now — `State` with a
  state name, `at` and the value — and `Age::Newest` with the time since the
  device last knew nothing newer was outstanding in `C`'s sync group (it
  heard the group with no refresh pending, or finished one), measured on its
  monotonic clock. The first `get` of a collection the device does not
  follow looks at what the group's known members hold first. Nothing held:
  `Unavailable`.
- **`get(state name)`** answers that exact state (`Age::Exact`), §11.
- **`get(log entry name)`** answers the version or snapshot (`Age::Exact`),
  fetching it when not held; a members record is not a version
  (`NotFound`); a refused entry answers `Refused` with the reason.
- **`put(C, content, {type, keep})`** signs the next entry of the device's
  log with parents = the state's `at`, applies it, and publishes into the
  group. It requires a members record that lists the device's key; for a
  collection of another namespace the device first looks for one, and
  answers `Unavailable` when no member of that group was heard, else
  `NotAllowed`.
- **`watch(C, since F)`** reports every held version of `C` (or of the
  collections under folder `C`) outside `F`, then every version applied
  later and the summaries of §7, each outside `F`; it starts a refresh of
  every member known in the group. The stream ends when the device stops.
- **`snapshot(names)`** pins, for each name, the current state name of a
  merge collection or the exact name of a version or snapshot, and signs
  the `SnapshotRecord`.
- **`share(C, members)`** signs the next members revision (owner namespace
  only: else `NotOwner`).

## 16. Wire format — slice 1

### 16.1 Names

`D` is the device name, `C` a collection, `O` a namespace, `X` any
collection or folder name under `O`. `32=` is a KeywordNameComponent,
`seq=` a SequenceNumNameComponent (0x3A), both from the NDN naming
conventions.

| Packet | Name | Signature |
|---|---|---|
| version, members record | `<D>/32=log/<C>/seq=<n>` | device key |
| snapshot | `<D>/32=log/seq=<n>` | device key |
| summary root of `O` | `<D>/32=summary/<O>/seq=<head>`, FreshnessPeriod 0 | device key |
| summary node of `X` | `<D>/32=summary/<X>/seq=<head>` | DigestSha256 |
| summary page of `X` | `<D>/32=summary/<X>/32=page/<path>/seq=<head>` | DigestSha256 |
| state (never fetched) | `<C>/32=state/<Frontier TLV>` | — |
| sync group | `<O>/32=sync` (State Vector Sync Interests) | — |

`<path>` is a GenericNameComponent whose octets are the buckets taken from
the node, one octet (0–15) each. Log entries are named after the writer's
device, not the collection, because a writer of another namespace can only
sign under its own (`/bob/laptop/32=log/alice/docs/plan/seq=3`). Data
packets carry no MetaInfo besides the root's FreshnessPeriod; ContentType is
BLOB.

### 16.2 TLV-TYPE numbers

The data layer uses 0x0520–0x057F (registered in
[README.md](README.md#tlv-type-numbers)). Every number is even: a decoder
MUST skip an unknown even TLV inside these records and MUST refuse an
unknown odd one, so a later revision can add fields old readers pass over
(and fields they must not).

| Type | Name | Value |
|---|---|---|
| 0x0520 | VersionRecord | Name (collection), Frontier (parents), TypeId, Seal, Keep, Dated, Fields, MergeOp |
| 0x0522 | Frontier | FrontierEntry*, by writer |
| 0x0524 | FrontierEntry | Name (writer key), Seq |
| 0x0526 | Seq | NonNegativeInteger |
| 0x0528 | TypeId | Name, Revision |
| 0x052A | Revision | NonNegativeInteger |
| 0x052C | Keep | one of KeepUntil, KeepLastN, KeepForever |
| 0x052E | KeepUntil | NonNegativeInteger, ms since the Unix epoch |
| 0x0530 | KeepLastN | NonNegativeInteger |
| 0x0532 | KeepForever | empty |
| 0x0534 | Seal | Audience* |
| 0x0536 | Audience | AudienceKind, Name |
| 0x0538 | AudienceKind | NonNegativeInteger: 0 person, 1 device, 2 group |
| 0x053A | Dated | NonNegativeInteger, ms since the Unix epoch |
| 0x053C | Fields | Field*, by name |
| 0x053E | Field | FieldName, FieldValue |
| 0x0540 | FieldName | UTF-8 |
| 0x0542 | FieldValue | octets; empty removes the field |
| 0x0544 | MergeOp | octets: the merge function's operation |
| 0x0546 | MembersRecord | Name (collection), Revision, Rule, Writers, Readers |
| 0x0548 | Rule | RuleKind [Name (merge function)] |
| 0x054A | RuleKind | NonNegativeInteger: 0 one key, 1 log, 2 merge |
| 0x054C | Writers | Name* (key-name prefixes) |
| 0x054E | Readers | Audience* |
| 0x0550 | SnapshotRecord | Name* (pins) |
| 0x0552 | SummaryNode | Name (subject), Writer, Seq (head), [PagePath], [Entries], [MembersEntries], [Children \| Pages] |
| 0x0554 | Entries | SeqRange* |
| 0x0556 | MembersEntries | SeqRange* |
| 0x0558 | SeqRange | Seq (low), Seq (high), low ≤ high |
| 0x055A | Children | Child*, by component |
| 0x055C | Child | Name (one component), Seq (head), Digest |
| 0x055E | Digest | 32 octets: SHA-256 of the child's whole Data packet |
| 0x0560 | Pages | Page*, by bucket |
| 0x0562 | Page | Bucket, Seq (head), Digest |
| 0x0564 | Bucket | NonNegativeInteger 0–15 |
| 0x0566 | PagePath | octets, one bucket each (pages only) |
| 0x0568 | Writer | Name (the writer's key) |

Names are the Name TLV (0x07). Inside a record, fields appear in the order
the table lists them; lists are sorted as stated, so equal content encodes
to equal bytes and equal nodes have equal digests.

### 16.3 Why these encodings

- **Reused:** the Name TLV, NonNegativeInteger, typed name components
  (keyword, SequenceNum), DigestSha256 and the implicit digest, ndn-svs v2
  for the notice, the hierarchical trust schema and the existing validator.
- **New records** because nothing existing carries them: a frontier (no NDN
  encoding of a version vector exists outside SVS's unsigned state vector),
  a version's parents/type/seal/keep/fields/operation, a members record, a
  snapshot's pins, and a Merkle summary node. SVS-PS mapping data was not
  reused: it maps one group's own sequence numbers to names, while a
  writer's log here spans many collections and its index must be signed and
  nested.
- **Pages** keep every summary packet small (at most 64 references) so a
  changed note in a folder of any size costs a logarithmic number of packets.

## 17. Failure model

| Failure | Required behaviour | Rests on |
|---|---|---|
| Partition / offline | Reads and writes continue locally under each device's key; collections reconcile from summaries when a path returns. | §4, §7 |
| Lost device | Its leases lapse; repair copies elsewhere; a cut ends its key at what others had seen. | §8, §13 |
| Compromised key | The cut keeps what was signed before it and refuses the rest; sealed data re-keys forward. | §8, §9 |
| Bad or lying clock | No effect on validity. | invariant 1 |
| Member removed mid-edit | Edits inside the removal cut merge; later ones are refused. | §6, §8 |
| Holder withholds | The summary shows what is missing; fetch from another holder. | invariant 4 |
| Holder rolls back | A summary older than one already seen is refused. | invariant 3, §7 |
| Writer equivocates | Both versions are kept and reported. | invariant 2 |
| Old software writes | Unknown fields survive its edit. | invariant 8, §10 |
| Poisoned cache | Verification fails; the version is dropped and fetched elsewhere. | invariant 1, §4 |
| Stranger in a sync group | Costs a root fetch; its entries are refused `NotMember`. | §6, §12 |

## 18. Conformance

`ndn-data-conformance` (ndn-sim) runs the study's use cases against an
implementation. Each case names the features it needs; a provider that
lacks one is reported "not implemented", naming it. The slice-1 cases are
c1 (offline notes on two devices), c7 (an older lens keeps a newer field),
c8 (a laptop back after four months: 10,000 notes, 37 changed) and c11
(citing a merged state).
