# Data layer: named, signed, versioned data

- **Status:** Slices 1–6 normative (slice 6, the substrate for ndf-rs, B
  and C: merge rules by exact versioned name and the rule interface,
  operations the application builds, versions held but not counted,
  checkpoints covering by frontier, pieces in merge collections and the
  release of merge pieces only on an audited covering checkpoint, groups
  of versions counted all or none, folder members records narrowing every
  collection under a folder with one seal epoch per folder epoch, §5.1,
  §5.2, §5.5, §6.1, §6.2, §9, §13, §15, §16); slice 5: a revoked key's versions kept
  exactly where the root's revocation cut in the trust context accepts
  them, the cut bounded by when the owner says the key was lost and bound
  to the key and to each version's bytes, Data judged without clocks or
  validity periods except that a lapsed guest fails closed until its cut,
  re-admission of exact versions, late revocation withdrawn, issuers
  re-checked, renewal, rotation and recovery, §8.1–§8.6); slice 4: signed blocks of small
  entries carried inline, the one-key rule with its signed head, rollback
  check and freshness bound, retention by expiry and listing by keep, range
  reads by seq and by time, `put`'s batch, §4.1, §5.3, §5.4, §7, §14.1,
  §14.2); slice 3: large payloads in
  pieces, hold records naming their holders, leases capped by keep, signed
  asks, audits, repair and release on whole proofs, `prune` of one's own
  writes and the erasure of fully pruned epochs, §13, §14);
  slices 1 and 2: versions, collections with
  owner-signed members records whose writers and readers are of any
  namespace, the merge rule and its function `/merge/yrs`, the log rule,
  removal cuts and the re-check when a cut arrives, seals (epoch keys and
  grants), types, signed nested summaries, snapshots, the sync notice and
  its reach across namespaces, the verbs `get`, `put`, `watch`, `snapshot`
  and `share` (adding, removing, changing the rule), `prune`'s scope, and
  their wire format (§16). Sections marked with a later slice are not yet
  normative beyond what they state; a section marked *open* has no
  normative content beyond its text.
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
   the trust context and the cuts — never from a server, and never
   accepted because of a clock (below).
2. **Immutable per writer.** One `(writer, seq)` has one set of bytes. Two
   different versions with the same `(writer, seq)` are proof of
   misbehaviour attributable to that key; a reader MUST keep both and report
   them.
3. **Monotonic.** A writer's sequence and a collection's summary never go
   back. A reader MUST refuse a summary or members record older than one it
   has seen from the same signer, also after the reader restarts.
4. **Completeness is relative.** "I have everything" always means
   "everything in this signed summary".
5. **Stale, never wrong.** Failures MUST degrade to older verified data, and
   the reader MUST be told how old.
6. **Authority is in the data.** Writing follows the trust schema and the
   collection's members; reading follows the seal; a cut ends both from a
   point on.
7. **Retention is chosen at write.** Custody MUST NOT extend keep; prune
   only narrows, and only over the pruner's own writes; every device drops
   what has passed its keep, by its own clock (§14.1).
8. **Nothing is lost by not understanding it.** A writer MUST keep every
   field it does not know.
9. **Forward-only, said plainly.** Revocation and deletion stop future
   reads; an implementation MUST NOT claim to recall copies already made.

No validity decision may accept anything because of a wall clock, nor
compare a certificate's validity period with one, with one exception that
can only refuse: a key of a role the trust context lists in DataRequiresCut
(a guest's, by default) whose certificate lapsed is refused until its
revocation cut is held (§8.5). Dates are display, indexing (range reads,
§5.4) and retention (§14.1) only. The root device's own clock also bounds
which entries it puts in a cut it makes (§8.1); a reader never reads it.

## 3. Names, devices, namespaces — slices 1, 2

- A **namespace** `O` is the name of a trust context
  ([trust-context.md](trust-context.md)): one or more components (`/alice`,
  `/home/bob`), none of them a KeywordNameComponent (type 0x20), a digest
  component or a SequenceNumNameComponent. It is the unit of the
  hierarchical trust schema, so it is the person data belongs to.
- A **collection name** is `<O>/32=data/<path>`: the namespace, the
  KeywordNameComponent `data` (the **marker**, which says where `O` ends),
  and a path of one or more components. No component of it besides the
  marker is a KeywordNameComponent or a digest component: keyword
  components mark the layer's own names (§16.1). A **folder** is
  `<O>/32=data/<path>` with a path that other collections extend, and
  `<O>/32=data` is the folder of every collection of `O`. The **owner** of
  collection `C` is its namespace, the components before its marker.
- `put`, `get`, `share` and `snapshot` take collection names; `watch` takes
  a collection or folder name (`<O>/32=data[/<path>]`). A verb given a name
  that is none of these — no marker, nothing before it, nothing after it
  where a collection is asked for, or another keyword or digest component —
  answers `BadName`, saying which and how the name must be formed
  (`NextStep::FixName`). `get` also takes log entry and state names
  (§11), and entry and range names (§4.1, §5.4).
- A **device** `D` is the identity of one key: the key is named
  `<D>/KEY/<key-id>` (NDN key naming). `D` is the device's name in seals
  and the prefix it serves; it has no KeywordNameComponent or digest
  component (`<O>/<role>/<device>`, as ndn-cert names it).
- **A device's own namespace** is the namespace of the trust context that
  governs `D` in the device's validator: the held context whose namespace
  is the longest prefix of `D`. It is the group a device joins (§12), the
  namespace of the host's default members record (§5) and the only one
  whose collections it may `share` (§15). A device that no held context
  governs (only the ambient, root context matches it) MUST NOT start, and
  says so.
- **The owner rule.** A members record `<D>/32=log/<C>/seq=<n>` is signed
  by a device of `C`'s namespace `O` exactly when `D` lies under `O` and
  the trust context that governs the record's name in the reader's
  validator — the one its signature verified under, the held context whose
  namespace is the longest prefix of the name — is `O`'s own. A device of a
  longer held namespace is that namespace's device: with `/home` and
  `/home/bob` held, `/home/bob/member/laptop` owns `/home/bob/32=data/x` and
  not `/home/32=data/x`, although `/home` is a prefix of its name. A reader
  holding `/home` alone verifies that device's records under `/home` (its
  chain ends at `/home`'s anchor), so to it the device is `/home`'s.
- **The namespace of a name** here (a writer prefix, a device, a person)
  is that of the held trust context governing it, the one whose namespace
  is its longest prefix; a name no held context governs has none. A
  device that writes into or reads another person's collections holds that
  person's trust context — it verifies their entries with it — so the
  person's namespace is held wherever their data is used. Holding it is
  the person's gesture of pointing at someone (adopting their anchor
  link); nothing else names people.
- Every packet a device signs MUST be named under `D`, so any forwarder's
  hierarchical schema admits it and Interests for it route to the device.

## 4. Version and log — slices 1, 2, 4 (blocks)

A version is an immutable record signed by one key. It carries
`(writer, seq)`, parents, type, seal, keep, a date and a payload, and, when
it is one of a group of versions counted all or none, its group (§5.5).

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
- The payload of a version is one entry — the fields the writer set
  (§10), and the merge function's operation (§5.1), empty under the log
  rule — or, in a log or one-key collection, a **block**: many small
  entries under the version's one signature (§4.1).
- The seal a version carries is the collection's readers at the time of
  writing, as the writer declares it. In a sealed collection (§9) the
  payload travels encrypted (`Sealed`, §16.2) under the key of the epoch
  the writer's newest members record names; everything else in the record
  stays readable. Keep is recorded at write; leases are capped by it
  (§13.2) and every device drops what has expired by it (§14.1).

A version is the Data packet `<D>/32=log/<C>/seq=<n>` whose Content is a
`VersionRecord` (§16.2), signed by the key `<D>/KEY/<id>`. A reader MUST
refuse (and MUST NOT apply) a log entry whose signature does not verify
against its trust context, whose signing key is not a key of the `D` its
name starts with, or whose record's collection is not the `C` in its name.
Such a refusal is of that packet, not of the name: whoever answers an
Interest — a cache, an on-path node, a holder under `32=held` — can make a
packet of any name, signed by any key the trust context accepts for it, so
the reader drops it, keeps nothing against the name, and asks the next
source; the genuine copy is taken when it comes. A reader SHOULD check that
the key locator names a key of `D` before walking the certificate chain.
Only a decision on the genuine writer's own packet — refused by the members
record (§6, §8), unsealed in a sealed collection, or a sealed payload that
does not open (§9) — is kept against the name, and later versions of that
writer do not wait for a version so refused (§5.2).

### 4.1 Blocks — slice 4

A **block** is one version whose payload is a list of small entries
carried inline, in the version's own packet, under its one signature (model
change M6).

- **Format.** The `VersionRecord` of a block carries `Block` (§16.2) in
  place of `Fields` and `MergeOp`: one or more `BlockEntry`, each an
  `Offset` and that entry's `Fields`. A sealed block (§9) is sealed like any
  payload: the `Block` TLV is the plaintext `Sealed` carries. A block is
  always one packet: its `Block` encoding is at most 6,144 octets
  (`INLINE_MAX`), so it is never in pieces (§13.1). Blocks are for log and
  one-key collections; a merge collection carries one operation per version,
  and a reader refuses a block in one (`NotInline`).
- **Entry dates.** An entry's date is the version's `Dated` plus its
  `Offset`, in milliseconds. The first offset MUST be 0 — the version's
  `Dated` is its first entry's date — and offsets MUST NOT decrease along
  the block; a reader MUST refuse a block that breaks either. A writer dates
  the entries it puts into one collection under one key non-decreasing:
  each entry gets the later of its clock reading and the last date it gave
  in that collection. Dates stay display, indexing and retention: a reader
  refuses nothing for the order of dates across versions (§4).
- **Entry names.** Entry `i` (0-based) of block `V` is named
  `<V>/32=entry/seg=<i>`. Like a state name it is local and never fetched:
  `get` of it uses or fetches the block `V`, verifies it as any log entry
  (§4) and answers that one entry (§15). An entry exists only inside the
  signed packet, so no entry travels apart from the signature that covers
  it: an entry altered, or spliced in from another block, breaks the block's
  signature, and the block is refused — dropped and fetched elsewhere, as
  from a poisoned cache (§17). So each entry is verifiable on its own,
  through its block's signature.
- **Batching.** `put` with `batch = d` (§15) puts the entry into the
  device's open block for the collection, the entry's type and the
  collection's seal epoch, and returns once the block carrying it is signed,
  with that block's id. A block closes — is signed, applied and published
  (§12) — at the earliest `arrival + d` of its entries; before an entry that
  would make its `Block` encoding exceed `INLINE_MAX`; and before an entry
  whose type, keep kind or seal epoch differs; and when the record naming
  the seal epoch moves before the block is signed — every `put` waiting on
  a block that cannot then be signed answers that error. So no entry waits
  longer than the delay its producer accepted, and every block is one
  packet. A `put` without `batch`, and an entry whose own payload exceeds
  `INLINE_MAX`, first close the open block; the entry is then put alone,
  the large one in pieces (§13.1), so seqs follow the order of `put`s.
- **Keep of a block.** Entries kept `Until` a date make a block kept until
  the latest of their dates: no entry is dropped before its own keep, and
  none is kept more than the batch delay past it. Entries kept `Forever`,
  or for the last `n`, share a block only with entries of the same keep.
- `batch` on a merge collection answers `BadRequest` (next step
  `FixRequest`: a merge collection carries one operation per version; put
  without batch).
- `batch` is at most a day (`BATCH_MAX`): an entry waits unsigned no
  longer, and a one-key head states the delay as the `Freshness` every
  reader adds to an answer's age (§5.3). A longer one answers `BadRequest`
  (next step `FixRequest`: put with a batch of at most a day, or without
  batch), before anything is written.
- A single-entry version reads, wherever entries are listed (§5.4), as one
  entry: index 0, dated its `Dated`.

## 5. Collection and rule — slices 1, 2, 4 (one key), 6 (rules by name, groups)

A collection is a named, growing set of versions with a rule and a members
record. It exists when its first members record is signed (§6): `share`, or
a writer's first `put` into a collection of its own namespace (§3), which
signs the host's default record (merge with `/merge/yrs`, the namespace
writing and reading, sealed to it). A collection under a folder whose
members record is in force exists with that record (§6.1): `put` into it
writes under its effective record and signs no default record.

| Rule | Meaning |
|---|---|
| one key | One key writes; the newest is what its signed head names, with a freshness bound (§5.3). `get` returns that version; range reads read the stream by seq or by time (§5.4). |
| log | Each member key appends; the collection is the union of exactly its members' logs. `get` returns the newest version. |
| merge | Member logs plus a named merge function every reader runs alike. `get` returns the merged state at a frontier. |

The collection, not the application, decides what "newest" means. A
collection's rule is the newest members record's; changing it starts the
collection again (§6).

Under the **log rule** the collection is the union of exactly the versions
its newest members record admits (§6): every member's versions reach every
reader that follows it, and a version by any other key reaches none — a
reader refuses it, and it is never delivered to a watcher. Versions are
delivered in the order of §5.2. The newest of a log collection is, of the
versions applied that no other applied version names as a parent (the
concurrent heads), the greatest by `(writer key name, seq)` — an order
every reader computes alike, with no clock.

### 5.1 Merge functions

A merge function — a merge **rule** — turns a writer's edit into an
**operation** carried in the version (`MergeOp`) and folds operations into
a state. Every reader that applies the same versions MUST obtain the same
state. A reader that does not know a collection's function MUST NOT claim a
state for it and says so.

**Rules by name — slice 6.**

- A merge collection's members record names exactly one rule by its full
  name (`Rule`, §16.2). A reader MUST match it by exact equality of names:
  never by prefix, by a part of the name or by the nearest version. By
  convention the last component is a version (`v=<n>`, as in
  `/ndf/merge/element/v=1`), and a change of meaning is a new name: every
  program that runs a rule under one name MUST compute what every other
  does. `/merge/yrs` keeps its name.
- A device that does not know the rule holds every version of the
  collection as it holds any version — verifies, stores and serves it, and
  lists it to `watch` with nothing applied — and answers `get(C)`, `get` of
  a state name of `C` (§11), and `put`, `put_op` and `put_group` into `C`,
  with `RuleUnknown`, naming the collection and the rule (next step
  `UpdateProgram`: run a program that knows the rule). It MUST NOT compute a
  state of `C` under any other rule, `/merge/yrs` included.

**The rule interface — slice 6.** A rule makes, per merge collection, a
state for the local writer (ndn-data: `MergeRule::start`, `MergeState`).
The layer hands the state each operation as an `Op`: the version's id
`(w, s)` — its writer, one key, and its seq —, the implicit digest of its
packet (SHA-256 of the whole Data packet: the version's content address),
its parents, its **past** and the `MergeOp` octets. The past is exactly
`down(P(v))` (§5.2): the rule asks it whether a version id lies inside it,
and which version of `C` inside it, held here, has a given implicit digest.

- **Edit** (`put` with fields) makes the local writer's edit into an
  operation; the layer then checks and applies that operation as any other.
  A rule whose edit already changed its state MUST make that apply
  idempotent (`/merge/yrs`: applying an update already integrated changes
  nothing). A rule that takes only operations the application builds
  refuses edits, saying so, and `put` answers `BadRequest` (next step
  `FixRequest`: build the operation and use `put_op`).
- **Check** says whether the operation is one its writer may have made:
  nothing in it outside its writer's identity, and nothing it is made over
  outside its past. It answers the operation's kind — an **edit** or a
  **checkpoint** (§5.2) — or refuses it for good with a reason. Its answer
  MUST depend on the `Op` alone — never on versions concurrent to it, on
  the device or on a clock — so every reader decides alike.
- **Apply** folds a checked operation into the state and answers
  **counted** (it is in the value), **not counted** with a reason (it is
  held, applied to the frontier and shown, and not in the value, §5.2), or
  refuses it for good with a reason.
- **Now counted** lists the versions it answered not counted that count
  since it was last asked; the layer asks after every apply.
- **Value** is the merged value, typed by the rule: named fields (what
  `/merge/yrs` merges into), or the rule's own encoding, which the program
  defining the rule decodes.
- **Determinism.** The layer applies parents first (§5.2), and versions
  concurrent to each other arrive in different orders on different
  devices. A rule MUST answer the same value, the same versions not counted
  and the same refusals for one set of applied versions in every such
  order. A rule may promise more: any order at all.

`/merge/yrs` is a Yjs document. Its root map `fields` holds one entry per
field, each value a binary (`Uint8Array`). The operation of a version is the
Yjs update (lib0 v1 encoding) of its edit: set every field the version sets,
delete every field it sets to an empty value. Concurrent sets of one field
resolve as Yjs resolves them; different fields never conflict. A writer's
Yjs client id is the low 53 bits of SHA-256 over the TLV encoding of its key
name, and a reader MUST refuse an operation that inserts content under any
other client id: that is its check, and every operation is an edit, which
its apply counts. A Yjs peer may therefore apply the same updates (it sees
the fields as binaries). A reader ignores root-map entries of other Yjs
shapes; they stay in the document.

### 5.2 Applying versions

A reader applies an admitted version `v = (w, s)` of collection `C` only
when

1. every entry of `w` in `C` below `s` — as `w`'s summary (§7) lists them —
   is applied, unless it never applies: the record in force refuses it by
   its key (a cut that does not list it, §8), or the trust context does (a
   revocation whose cut neither accepts it nor re-admits it, §8.1, §8.2), or
   it was held and refused for
   what it carries (`Unsealed`, §9; an operation the rule refuses), or it
   is pruned (§14), expired here (§14.1), or — in a log or one-key
   collection, and not held here — shown by the newest node of `w` for `C`
   the reader verified to have expired (§7): at or below that node's `Head`
   and not listed by it, or listed in an `Expiry` run whose date this
   device's clock has reached, and
2. for every `(y, t)` in `v`'s parents, the reader has applied `y`'s entries
   in `C` up to `t`.

Until then `v` waits. The state's frontier `at` is, per writer, the highest
seq applied; by these rules every entry at or below it that applies at all
is applied, so `at` names exactly the versions the value is computed from.
A parent `(y, t)` that never applies is needed only up to the highest
version of `y` below it that does (for a cut, removal or revocation, the
highest it accepts or re-admits): a
version written on top of refused work is not held back by it (what of the
refused work its operation depended on, the merge function decides). This
holds for seqs the reader never learned as well: a seq of `y` at or below
the `Head` of `y`'s newest node it verified that the node does not list,
and that the reader does not hold, never applies, so a reader that started
after older versions expired is not held back by a parent naming them.
When the reader's clock reaches an `Expiry` date of that node, it reads
again what waits and applies what became ready.

**Checking and counting — slice 6.** In a merge collection a version that
is ready (above) is checked, then applied:

- `P(v)` is `v`'s parents joined with `(w, s − 1)`, and `down(P)` is every
  version of `C` at or below `P`, writer by writer, that applies at all.
  The rule checks `v` when it is ready to apply, never at admission, with
  the past `down(P(v))`: what `v` was made over, whatever arrived since. An
  operation whose basis lies outside that past is refused.
- A version the rule refuses — check or apply — is refused for good for
  what it carries: kept against its name with the reason (`Refused`,
  `Refusal::Rule`), never applied, and never waited for (1. above).
- A version the rule does not count is applied: it lies inside `at`, later
  versions do not wait for it, and it is held, served, delivered to
  watchers as a version and as not counted with the reason
  (`Change::NotCounted`), and listed in the state's `not_counted`; it is
  not in the value. When the rule later counts it, watchers are told
  (`Change::Counted`) and it leaves `not_counted`. A version not counted is
  never dropped. So in a merge collection `at` names exactly the versions
  applied; the value is computed from those of them the rule counts.

**Checkpoints — slice 6.** A checkpoint is an operation the rule's check
says is one; the layer gives it no other mark, and nothing on the wire
tells it from an edit. It **covers** exactly `down(P(CP))`, by frontier.

- Check depends on the `Op` alone, so a reader may check an admitted
  version as soon as it is held whole (§13.1) and every version of
  `down(P(v))` that applies at all is held as a signed record, whole or
  not. A checkpoint is ready then, in place of conditions 1 and 2 above: it
  waits neither for those versions' pieces nor for their application.
- Applying it, the layer applies it to the rule, then raises `at` to
  `P(CP)` writer by writer (`at[w] = max(at[w], P(CP)[w])`). Every waiting
  version now inside `at` is **covered**: held, stored, delivered as a
  version, and never applied to the rule nor checked. A version arriving
  later inside `at` is covered likewise.
- The rule MUST make applying `CP` yield the state of `down(P(CP))` with
  `CP`, plus the versions concurrent to it already applied, whichever
  subset of `down(P(CP))` it applied before.
- A reader MUST NOT fetch the pieces (§13.1) of a version covered by a
  checkpoint it holds whole and checked.

### 5.3 One key — slice 4

A one-key collection is written by exactly one key.

- **Members.** Its members record has the rule one key (`RuleKind` 0) and
  `Writers` of exactly one name, a key name `<D>/KEY/<id>`; admission (§6)
  then admits exactly that key. `share(C, {rule: one key, writers: [w]})`
  takes `w` as it is when it is a key name, and as this device's key when
  it is this device's name; any other name, or not exactly one, answers
  `BadRequest` (next step `FixRequest`: name the one key that writes,
  `<D>/KEY/<id>`, or this device). A one-key record whose `Writers` is not
  exactly one key name (signed elsewhere) admits by prefix as usual and
  has no head: `get(C)` answers by the log rule, and a range read answers
  `BadRequest` (`FixRequest`: the record names no single key).
- **Log-like.** Otherwise a one-key collection is a log collection whose
  one member is that key: sync, watch, summaries, custody, prune, pieces,
  seals, blocks and expiry apply to it as to a log collection. Its newest
  is the version of that key's highest seq in `C`.
- **Head.** The writer's head of `C` is the Data packet
  `<D>/32=summary/<C>/32=head/seq=<s>`, `D` the one key's device, signed by
  that key, Content `HeadRecord` (§16.2): `Name` `C`; `Seq` `s`, the `Head`
  of the writer's summary node of `C`; `Digest`, SHA-256 of that node's
  whole packet `<D>/32=summary/<C>/seq=<s>`; and `Freshness`, in
  milliseconds: the batch delay of the entries of the writer's newest
  version in `C`, 0 when it was put without one — the writer holds an
  entry unsigned that long anyway. The packet's FreshnessPeriod is
  `Freshness`. A reader discovers it with `<D>/32=summary/<C>/32=head`
  (CanBePrefix, MustBeFresh), which no node, page, root or other head
  extends. A writer SHOULD sign a head only when one is asked for and its
  node of `C` changed since its last head (as for the root, §7), keeps its
  last head with what it holds, so a restart serves the same packet, and
  MUST serve the node every head it signed names, as it serves the nodes
  its roots list (§7).
- **Reader checks.** A reader MUST verify a head as a log entry (§4) signed
  by the one key of the record in force — a head signed by any other key is
  refused, whatever device it names — whose subject is `C` and whose name's
  seq is its `Seq`. It MUST refuse a head whose `Seq` is lower than one of
  the same key it verified for `C`, or than the highest seq of that key it
  knows in `C` — held, listed by a node of that key it verified, or kept by
  a tombstone (§14.1) — (rollback, invariant 3); a head of the same `Seq`
  is taken again, and renews its receipt once its node checks out. The
  floor is the key's: each key's device numbers its own log, so once the
  owner names another one key
  (a replaced sensor), that key's heads are not compared with the previous
  key's seqs, and a range read without a head uses only what a head of the
  current key listed. The highest `Seq` verified per collection and key is
  durable, kept with what the reader holds, so a restarted reader refuses
  the same rollback. It then fetches the node by name and refuses it unless
  its digest is the head's `Digest`; the node is checked as §7 says.
- **`get(C)`.** A reader answers `get(C)` from the head: head, node, the
  version of the highest seq the node's `Entries` list, and that version —
  from its store, else by name, else from the holders of live leases it
  knows (`32=held`, §13.1). It answers `Got::Version` with
  `Age::Newest { unconfirmed_for }`, `unconfirmed_for` being the time on
  the reader's monotonic clock since it received that head, plus the head's
  `Freshness`. A head's receipt counts only once the node it names checked
  out; a head whose node is withheld or does not match proves only that the
  key's log reached its seq. When the newest version the node lists, or the
  head, or its node, is not to be had, the reader answers the newest version
  of the one key it holds (by seq), aged by how long ago that version was
  last known the newest: `unconfirmed_for` measured from the receipt of the
  last head, received since it started, that named that very version the
  newest and delivered it, plus that head's `Freshness`. It never gives an
  older version the receipt of a head that names a newer one. When no head
  since it started named that version the newest, but a head of the key it
  verified since it started has a higher seq — a newer version may exist,
  and nothing bounds how long ago the held one was the newest — it answers
  `Unavailable` (next step `RetryLater`) rather than an age it cannot bound
  (§14.2: older verified data is answered only with its own age). A receipt
  time does not survive a restart — a monotonic clock does not — so a
  reader that verified no head of `C` above the version it holds since it
  started answers with the age of a log collection (§15). Stale, never
  wrong (invariant 5).

**The freshness bound.** No clock is trusted and none is compared across
devices: the bound is a duration measured on the reader's monotonic clock
plus the duration the writer stated. What it promises, and no more:

- A head the reader received fresh was the writer's newest head — the node
  it names the writer's newest node of `C`, its newest version the
  collection's newest — at a moment no longer than `Freshness` before
  receipt, *if* the one cache that answered honoured FreshnessPeriod. The
  writer's own answer adds nothing; each further caching hop that honoured
  it may add up to `Freshness` more. So `unconfirmed_for` bounds how long
  ago the answer was last known to be the newest, under that proviso.
- It never promises that nothing newer exists now: a partition, a cache
  withholding newer heads and a writer that wrote nothing look alike to a
  reader. Nor does it cover entries the writer holds unsigned in an open
  block, which are at most the delay it accepted old (§4.1).
- A cache or replayer that ignores FreshnessPeriod can serve as fresh any
  old head it saw. The age then understates; the answer is still never
  wrong: the head is never forged (it is signed by the one key) and never
  older than one the reader verified (rollback is refused, also after a
  restart). A reader that must know the writer is alive needs an answer
  from the writer itself, which no name of this layer can force through a
  cache that lies about freshness.

### 5.4 Range reads — slice 4

- **Names.** `get(<C>/32=range/<R>)`, `R` one GenericNameComponent whose
  value is one TLV: `SeqRange` (low, high, inclusive) reads the versions of
  the one key in `C` with those seqs, so by name; `TimeRange` (from, to,
  `from < to`) reads the entries dated `from ≤ date < to` (§4.1). A range
  name is local and never fetched. Range reads read one key's stream: of a
  collection of another rule `get` answers `BadRequest` (next step
  `FixRequest`); a range name that is malformed answers `BadName`
  (`FixName`).
- **Mapping to Interests.** There is no index and no new packet: the reader
  reads the stream through the names it already has — the head (§5.3), the
  node it names, and the versions, `<D>/32=log/<C>/seq=<n>`. The node's
  `Entries` list every version of the stream still listed (§7), the
  seq → name mapping. By seq, the reader fetches exactly the listed seqs in
  the range. By time, it uses that each block states its own first and last
  entry dates (its `Dated`, and `Dated` plus its last `Offset`): it searches
  the listed seqs for the first version whose last date is at least `from`
  and the last whose first date is below `to` — probing the first and the
  last listed first, then, each round, interpolating on the dates of the
  versions probed so far and bisecting in turn — fetching each probed
  version, each immutable and cacheable anywhere, from its store first.
  Each round probes the seq it guessed; only when that probe is not
  answered does the round probe at once the nearest others of the interval
  not yet probed, up to the reader's fetch window, and go on from the
  nearest that answers; when none of them answers, the rest of the
  interval is not probed: it is taken into the range and its versions are
  reported `missing`. A version it knows expired is placed by the dates its
  tombstone keeps (§14.1); a version in pieces, by its `Dated`. It then
  fetches the versions between, a window at once, and keeps the entries in
  range. A range read answers within a bound the reader sets (eight first
  looks in this implementation): versions it has not reached by then
  are reported `missing`, so withheld or unreachable blocks cost it time,
  never more than the bound. The cost is the head, the node, `O(log n)`
  probes (two or three for a steady stream, where interpolation lands near
  the answer) when probes answer — a probe that is not answered adds at
  most one window of probes, run at once — and the versions in the range.
- **Why not a prefix or an index.** Selecting by a prefix of dated names
  would need range selectors NDN no longer has, and would put the writer's
  clock into names readers must guess. A range index as named data would be
  either signed by the producer — more signatures and state on the
  constrained device, and a second structure to keep consistent with the
  log — or built by a holder, which is untrusted: it could only omit or
  misdirect, and every block must be verified anyway. The node already
  lists every version; the blocks' own signed dates are the index.
- **Answer.** `Got::Entries(Entries)`: the collection, the writer (the one
  key), and
  - `entries`, in (seq, index) order, each with its entry name
    `<V>/32=entry/seg=<i>`, its version's id, its index, its date and its
    content, every one from a version verified as a log entry of the one
    key (§4); a single-entry version is one entry (§4.1);
  - `missing`: versions listed within the bounds that no path answered;
  - `expired`: versions within the bounds this device knows expired
    (§14.1);
  - `large`: versions in pieces within the bounds, read whole by name
    (§13.1).

  A pruned version within the bounds is in none of the lists (§14).

  The age is that of `get(C)` (§5.3). The answer is complete exactly when
  `missing` is empty, and complete relative to the head's node (invariant
  4): what the writer signed after that node, it does not cover.
- **Honest and date-disordered writers.** For a writer whose dates do not
  decrease (§4.1), a time range returns exactly the entries dated in it of
  the versions the node lists. A writer whose dates go back is held to its
  own order: the search may miss entries it dated out of order, and never
  returns an entry the writer did not sign or one dated outside the range.
  No date decides validity.

### 5.5 Groups of versions — slice 6

A **group** is a set of versions one writer signs to be counted all or
none: one transaction of one device across collections of one folder. A
reader counts a group's versions only once all of them are held and
readable, and none of them when any is refused, on every member alike and
in any arrival order.

- **Format.** A version of a group carries `Group` (§16.2): the group's
  `id`, the seq in its writer's log of the group's first version, and its
  `count`, `1 ≤ count ≤ 1,024` (`GROUP_MAX`). The group `(w, id)` is
  exactly `w`'s versions at seqs `id` to `id + count − 1`, consecutive, one
  per collection, all in collections of one folder — the same parent name,
  every component but the last — and all declaring one `Seal`.
- **Writing.** `put_group` (§15) signs its items under one lock at
  consecutive seqs of the device's log, each carrying the group; no other
  entry of that log comes between them. It refuses, and writes nothing — no
  version signed, no seq taken, nothing published — when there are no
  items or more than `GROUP_MAX`, a collection appears twice, the
  collections are not all of one folder, the records in force of the
  collections list different readers (one was narrowed, say: a reader of
  one could then never complete the group), `batch` is set, or the rule of
  an item's collection refuses its operation: `BadRequest`, saying which
  item and why (next step `FixRequest`). When a collection's rule is
  unknown here it answers `RuleUnknown` (§5.1), and when a collection is not
  writable by this device, that collection's own error, unchanged; again
  nothing is written.
- **Verdict.** A reader judges each group `(w, id)` from the group's own
  signed versions and their admission alone, so every reader with the same
  access judges it alike:
  - **Malformed** — refused for good: a member's seq outside `id` to
    `id + count − 1`, members disagreeing on `count`, members in
    collections of different parents, two members in one collection, or
    members whose declared `Seal`s differ as sets.
  - **Refused** — a member is refused for good: by the record in force of
    its collection (`NotMember`, `OutsideCut`, §6, §8), by a revocation cut
    or an untrusted chain (§8.1, §8.3), `Unsealed` (§9), by its rule (check
    or apply, §5.2), or because the group is malformed. Then no member ever
    applies: each is a version refused for what it carries (§5.2), so later
    versions do not wait for it, and each is reported not counted
    (`Change::NotCounted`, the group refused). A member applied before is
    withdrawn, in every collection of the group: watchers are told
    `Withdrawn` with the reason `Refusal::Group` — the refused member and
    why — and `get` of each other member answers `Refused` with that
    reason, while `get` of the member refused for its own sake answers its
    own refusal (`OutsideCut`, `NotMember`, …). Versions by
    other writers made over a withdrawn member stay counted: a parent that
    never applies holds nothing back (§5.2).
  - **Unreadable here** — a member is held sealed and this device cannot
    open it: no member is shown — none delivered as a version, none in a
    value — each is reported not counted ("group not readable here"), and
    versions that depend on a member wait (stale).
  - **Incomplete** — fewer than `count` members are present: held,
    admitted, whole and opened, or known pruned or expired (below). Each
    held member waits, reported not counted ("group incomplete: k of n"),
    and versions that depend on one wait.
  - **Complete** — all `count` members are present, and each held one is
    ready (§5.2), a dependency on another member of the group counting as
    met: all held members are applied together, across their collections,
    in seq order.
- **Pruned or expired members.** A member this reader knows pruned (§14)
  or expired here (§14.1) — held before or not — counts as present for its
  group's verdict: prune and expiry are its writer's own retention, never
  a refusal. The group counts once every other member is present, and
  nothing counted is uncounted by a prune or an expiry.
- A device holding a member of an incomplete group follows the member's
  folder (its parent name, §12), so that the others arrive.
- A rule's not counted on one member does not hold the others back: they
  count, and that member is shown not counted (§5.2). A rule that must keep
  a whole group out refuses its member (check or apply), which refuses the
  group.
- Groups work in merge, log and one-key collections alike: counted means
  applied, delivered, and a candidate for the newest.

## 6. Members — slices 1, 2, 6 (folder records)

The members record is signed by a device of the collection's owner
namespace (the owner rule, §3). It lists the rule, the key-name prefixes
that may write — of any namespace (`/bob` writes into
`/alice/32=data/docs/plan`) — the audience that may read, the cuts of
removed writers, the epoch the collection is sealed in with its key check,
and, once the rule changed, where the current rule starts.

- A members record is an entry of its signer's log, `<D>/32=log/<C>/seq=<n>`
  with Content `MembersRecord` (§16.2). Its `Revision` is one more than the
  revision of the record in force at its signer (1 for the first), and from
  revision 2 it names that record as its **parent**: its revision and the
  SHA-256 of its `MembersRecord` TLV — the Content of the packet carrying
  it or, when the record in force was a merge of concurrent records
  (below), the `MembersRecord` that merge stands for, encoded as §16.2
  lists (its parent the one its records share, none when they name
  different ones). The digest is of the Content, not of the whole Data
  packet: a merge is carried by no packet, and devices holding the same
  records compute the same merge, so the same digest, whoever signed what.
- A reader MUST ignore a members record that the owner rule (§3) does not
  give to `C`'s namespace. The **record in force** is the merge of the
  records it holds of the highest `Revision`, one per signer (its latest);
  a record of a lower revision changes it only as the parent the records
  of the highest revision name (below). A reader keeps, besides those,
  every record of the revision below that it took and every merge of them
  it computed: the parents they may name.
- **Concurrent records.** Two devices of the owner may each sign revision
  `n` from their own view (the laptop adds Carol while the phone, offline,
  removes Bob). Their records merge, whatever order they arrive in:
  - **Against their parent.** When every record merged names one parent
    `P` and the reader holds it, writers and readers are `P`'s, plus every
    one a record lists that `P` does not (an addition), minus every one of
    `P`'s that a record does not list (a removal). A removal beats an
    addition: a writer prefix one record adds is no writer when it covers,
    or lies under, a prefix another record removed. Rule and `Since` are
    `P`'s unless a record changed them, then that record's; when several
    did, those of the one with the highest signer key name.
  - **Without one.** When the records name different parents or none, or
    the reader does not hold the one they name, writers are the
    intersection (a key is a writer only if every record admits it),
    readers the intersection, rule and `Since` those of the record with
    the highest signer key name. An addition is then lost until a record
    resolving the merge (below) arrives from a device that held `P`.
  - Either way cuts are the union by prefix (where two records cut one
    prefix, the intersection of what they accept), and the epoch (with its
    key check) is that of the record listing the fewest readers the merge
    leaves out, then the fewest readers (ties: the highest signer key
    name). Removals win.
  - **Resolving.** A merge is **resolved** — a device of the owner
    namespace that holds it and is of its audience MUST sign revision
    `n + 1` with the merged writers, readers, cuts and rule, naming the
    merge as its parent — in a new epoch when the merged readers leave out
    a reader of the epoch kept or, merged against `P`, a reader of `P` or
    of any record merged (a reader one record removed is still of the
    epoch another kept); and in the epoch kept, with its key check, when
    they only list a reader no merged record naming that epoch lists (one
    record added a reader while another moved to a new epoch). Devices
    resolving at once sign records of one revision, one parent and one
    audience, whose merge needs no more.
- **Admission.** A reader MUST apply to `C` only versions the record in
  force admits (and, as for every entry, the trust schema admits under the
  writer's own name): a key under a writer prefix is admitted; else a key
  under the prefix of one of the record's cuts is admitted exactly when the
  cut lists that version, and refused otherwise, `OutsideCut`, whatever
  date or seq it claims; any other key is refused `NotMember`. Versions that
  arrive before any members record wait for one. Admission depends on the
  record in force only, so every change of it re-checks everything held of
  `C` (§8).
- **Removing a writer.** A record that drops a writer prefix `P` of the
  record in force MUST carry a cut of `P` that lists, per key under `P`,
  exactly the seqs of that key's versions in `C` the signer holds verified
  — never entries a summary only listed. Cuts carry over to later
  revisions; a revision whose writers cover a cut's prefix again drops that
  cut, and the prefix's keys are admitted again (all of their versions, the
  owner having written them back in).
- **Readers.** The audience is exactly the readers listed — people (a
  namespace), devices and groups — plus the device that signed the record
  starting the epoch (§9). A group is a collection: its members are the
  readers its own record in force lists. No device reads for being of the
  owner's namespace: the host default record lists
  `Person(<own namespace>)`, and a record listing `Device(/alice/laptop)`
  alone leaves Alice's phone out of its epoch and every later one. A
  record with readers seals the collection (§9) and names its epoch; a
  record that drops a reader starts a new epoch; one that only adds keeps
  it and copies its key check.
- **Groups.** A device that holds a record naming `Group(G)` follows `G`
  (§12), so that it holds `G`'s record and hears its changes. When a device
  of `C`'s namespace that is of `C`'s audience takes a record of `G` that
  drops a reader, it MUST sign a new record of `C` in a new epoch, whoever
  owns `G`. Several owner devices rotating at once sign concurrent records,
  which merge as above.
- **Changing the rule.** A record whose rule differs from the previous
  revision's — or that seals a collection the previous revision left
  unsealed — carries `Since`: the frontier its signer had applied, joined
  with the previous `Since`. Versions inside `Since` stay held, readable by
  name and listed by `watch`, and are applied as history only: they order
  later versions (§5.2) and never enter the new rule's state. A state of
  `C` after the change is named by a frontier covering `Since`.

### 6.1 Folder records — slice 6

A folder `F = <O>/32=data/<path>`, of one or more path components, may
have a members record of its own, which governs every collection strictly
under `F`: one record for a folder of any number of collections, with one
seal epoch, and so one grant per reader, for all of them.

- **Format.** A folder record is a members record carrying `Folder`
  (§16.2) right after its name, the entry `<D>/32=log/<F>/seq=<n>` of its
  signer's log. All of §6 holds for it as for a collection's record — the
  owner rule, revisions and parents, the merge of concurrent records and
  its resolution, cuts, epochs and `Since` — over the records of `F` that
  carry `Folder`. Records of one name with and without `Folder` are two
  separate lines: a revision, a parent and a merge count only records of
  their own kind, so a collection named `F` keeps its own record beside the
  folder's. A reader refuses a record carrying `Folder` whose name has no
  path component (`<O>/32=data`).
- **Effective record.** A collection `C` is judged by its **effective
  record**: its own record in force, if any, narrowed by the folder record
  in force of every proper prefix `F` of `C` that has one. Every reader
  computes it from the records it holds; it is never signed or carried.
  - *Writers:* a key writes into `C` exactly when every level admits it,
    the intersection of the levels' writer prefixes. An own record with no
    `Writers` inherits.
  - *Readers:* an own record with no `Readers` inherits the readers of the
    nearest folder that has a record, and its epoch, bound to that folder
    (§9). An own record with readers seals `C` in its own epoch, and its
    readers count only as far as every folder's readers admit them.
  - *Cuts:* every level's cuts apply. A key any level refuses is refused:
    `OutsideCut` when a level's cut refuses it, else `NotMember`.
  - *Rule and `Since`:* the own record's when `C` has one, else the
    nearest folder record's.

  Admission (§6), sealing and grants (§9) and the re-check (§8) read the
  effective record wherever they read the record in force, so a change of
  the record in force at any level re-checks every collection under it.
- **Narrowing only.** A record under a folder — a collection's own, or a
  nested folder's — that lists a writer or a reader the folder does not
  admit widens nothing: at every reader the folder's level refuses what it
  does not admit.
- **Sharing a folder.** `share_folder(F, …)` (§15), at a device of `F`'s
  owner namespace only (else `NotOwner`), of a folder of at least one path
  component (else `BadName`), signs the next revision of `F`'s folder
  record as `share` signs a collection's: its parent, its `Since`, a new
  folder epoch when it drops a reader, and, for every writer prefix it
  drops, a cut listing per key exactly the seqs of that key's versions in
  every collection under `F` the signer holds verified. A key's seqs are
  unique across its log, so one list serves every collection.
- **Widening refused.** `share(C, …)` of a collection under a folder whose
  record is in force answers `BadRequest`, saying what it would widen and
  to share the folder instead (next step `FixRequest`), when it lists a
  writer the folder's writers do not cover or a reader the folder's
  readers do not admit.
- **Re-keying own audiences.** When a folder record drops a reader that a
  collection under it, sealed in its own epoch, lists, a device of that
  collection's owner namespace that is of its audience MUST sign a new
  record of it in a new epoch, as for a group dropping a reader (§6): the
  removed reader holds the key of the epoch it is in.
- **Writing.** `put` into `C` under a folder in force writes under the
  effective record, sealing in the epoch it names, and signs no default
  record (§5).
- **Sync.** A reader following a collection `C` under `F` also takes the
  members records listed under `MembersEntries` (§7) at the summary nodes
  of every folder above `C`, and only those entries there. A device that
  signs a folder record publishes its notice as for a collection's (§12),
  into the groups of the namespaces of its writers and readers.
- A collection no folder record governs keeps its own records exactly as
  in slice 2.

### 6.2 Threat notes — slice 6

**A member writing a bogus checkpoint.** A checkpoint is its writer's
claim of the state of what it covers (§5.2), and nothing else checks it
beyond the rule's check against its past (a rule may admit checkpoints
from fewer writers than edits, and verify what it can by digest). Every
reader applies it alike, so it cannot make two readers disagree; covered
versions are never applied, and their pieces never fetched, so a reader
does not find the lie by itself. The remedy is the owner's: a removal cut
that does not list the checkpoint withdraws it (§8), and the versions it
covered then apply, their pieces fetched. A release never drops what
holders lease, and drops a device's own merge pieces only on a covering
checkpoint proved whole by audited holders (§13.3), so the covered
versions stay where the hold record says.

**A rule refusing or withholding.** A rule is code every reader runs under
one name (§5.1). A version it does not count is held, applied to the
frontier, served, shown with the reason to every watcher and listed in the
state: never dropped, never hidden. A version it refuses is kept against
its name with the reason, and nothing waits for it. A program whose rule
behaves otherwise than another's under the same name breaks determinism;
the defence is the versioned name — a change of meaning is a new name.

**Group griefing.** Only a group's own writer can make it incomplete, and
only its own versions: a member never sent keeps the others held and shown
as not counted, and what depends on them waits — stale, never wrong.
Another writer's version can depend on a member only if that writer held
the group complete, so the member then exists to be fetched from it. A
malformed group is refused by every reader alike, from its own signed
versions, and a group none of whose members are refused is counted whole
or not at all, never in part.

**Narrowing races.** An owner narrowing one collection's readers while a
writer signs a group across it does not split the verdict: a reader judges
a group by the `Seal`s its members declare, as they were signed, never by
the record in force it happens to hold, so every reader with the same
access judges it alike. A reader the narrowing leaves out finds the group
unreadable here, and counts none of it.

**Folder-level widening attempts.** `share` refuses to widen a
collection under a folder; a record that widens anyway — signed by older
software, another implementation or a device ignoring the refusal — has no
effect, as every reader intersects the levels. Only a device of the owner
namespace signs a folder record (§3).

**One folder key covering many collections.** A leaked key of a folder
epoch opens every version of every inheriting collection sealed in that
epoch: the blast radius is the folder, not one collection. Removing a
reader at folder level starts one new folder epoch, which re-keys every
inheriting collection at once; collections with their own readers move to
their own new epochs (§6.1). A collection that needs a smaller radius lists
its own readers. What a removed reader opened it keeps (invariant 9).

**Release of merge pieces and permanent blocking.** In a merge collection
every later version waits for an earlier one's pieces (§13.1), so pieces
lost for good would block the collection for every reader lacking them.
A device therefore drops its own merge pieces only when a checkpoint
covering them is proved whole by `copies` audited holders, under
quarantine (§13.3); a holder relaying audits cannot make it release, as in
slice 3. A holder that loses merge pieces no checkpoint covers leaves the
readers lacking them waiting — stale — until repair brings them back.

**Unknown-rule downgrade.** No one can make a reader compute a collection
under another rule than the one its record names: names match exactly,
never by prefix or by nearest version, and an unknown name answers
`RuleUnknown` with nothing computed (§5.1). The name is in the owner-signed
record; changing it is a new revision that starts the collection again
(`Since`, §6), and altering it in transit breaks the signature.

## 7. Summary — slice 1 (listing by keep: slice 4)

A writer's summary of a namespace `O` is its own log's index over `O`: a
tree of **nodes**, one per name under `O` the writer wrote into (and every
name on the way there). The tree runs from `O` through its marker: the
root is the node of `O`, its one child the folder `O/32=data`, and below
that one node per path component down to each collection
`O/32=data/<path>`. A reader descends from a root only into the child
`32=data`; any other child of a root names no data of `O`. Completeness is
per writer: with many writers each publishes its own, and a reader gathers
them from the devices it hears move (§12) — the members records it holds
say which writers a collection gathers, of whichever namespace. A device's
own log is complete to itself; a summary is for the others. Nothing signs a
combined summary of many writers.

A node of name `X` carries:

- `Head`: the writer's highest seq in the subtree of `X`;
- `Entries`: the seqs of the writer's versions directly in `X`, as ranges —
  the seq → name mapping, since an entry's name is `<D>/32=log/<X>/seq=<n>`;
  of a log or one-key collection, only those unexpired at the node's
  reference date (listing by keep, below); of a merge collection, all;
- `Expiry` (slice 4): of a log or one-key collection, bounds of the keeps of
  the listed versions kept `Until` a date, in at most 64 runs, each a list
  of seq ranges and a date no earlier than the keep of any version in it
  (listing by keep, below);
- `MembersEntries`: the seqs of its members records of `X`;
- its children: for each next name component under `X` with entries in its
  subtree, the child's component, `Head` and the implicit digest (SHA-256 of
  the whole Data packet) of the child's node. A node with more than 64
  children lists them on **pages** instead: 16 buckets by the first nibble
  of SHA-256 over the child component's TLV, each a page node listing its
  children, or (beyond 64 again) 16 sub-pages by the next nibble.

A node's content is fixed by the writer's log up to its head, so one node
name (`<D>/32=summary/<X>/seq=<head>`, a page
`<D>/32=summary/<X>/32=page/<buckets>/seq=<head>`) has one packet. Inner nodes
and pages are DigestSha256 packets; a reader MUST check each against the
digest its parent lists. The **root**, the node of `O` itself, is the only
signed one: `<D>/32=summary/<O>/32=root/seq=<head>`, signed by the device key,
FreshnessPeriod 0 so that discovery always reaches the writer. A writer
SHOULD sign a new root only when one is asked for and the tree changed. A
one-key collection's node is also named by the collection's signed head
(§5.3), one hop from the reader.

**Listing by keep (slice 4).** A writer's node of a log or one-key
collection `X` lists in `Entries` only its versions unexpired (§14.1) at
the node's **reference date** `E`: the `Dated` of the writer's newest
version in `X` up to the node's head. A version kept `Until(t)` is listed
when `t > E`; one kept for the last `n` while fewer than `n` of the writer's
later versions in `X` lie at or below the head; one kept `Forever`, always.
`E` and those counts are fixed by the log up to the head, so one node name
still has one packet, and a constant stream's node stays bounded by its
keep window: 30 days at one block a minute is 43,200 seqs, within the
65,536 a node may list. The writer's own clock moves only its own listing:
it decides the dates, hence `E`, and nothing else of any reader.

**Keep bounds (slice 4).** A writer that stops writing leaves `E` where it
was, so its newest node keeps listing versions kept `Until` a date that has
since passed by every holder's clock: the holders dropped them, and a reader
that never held them could fetch them from no one and could not tell from
the node that they expired. So the node also states, in `Expiry`, a bound
of each such version's keep. The writer takes the listed versions kept
`Until` a date in seq order; while the groups of consecutive ones with one
keep number at most 64, each group is a run stating that keep, exact;
beyond, they split in seq order into 64 runs of equal count (the last may
hold fewer), each stating the latest keep in it. A version kept `Forever`
or for the last `n` is in no run: the last-`n` listing already matches what
holders keep, since a stopped writer writes no newer versions to end them.
The runs are fixed by the log up to the head (the writer's tombstones keep
each dropped version's keep, §14.1), so one node name still has one packet.

A reader keeps, per collection and writer, the newest node it verified —
its `Head`, `Entries` and `Expiry` — and does not wait (§5.2) for a seq of
that writer at or below the `Head` that it does not hold and that either
the node does not list (whether or not the reader ever learned the seq) or
the node lists in a run whose date its own clock has reached. It does not
fetch such versions. It reads again what waits when its clock reaches the
earliest such date still ahead, with the expiry sweep of §14.1, and applies
what became ready. A run's date is an upper bound: the reader stops waiting
at most one run's span (its latest keep minus its earliest) after a
version's own keep, and never before it, so nothing it applied or skipped
depends on a date it was not given.

A writer MUST serve every node and page that any root or head it signed
lists, for as long as it holds the log entries that node lists — in slice 1
a writer never drops its own entries, so always, across its own restarts
too (prune, slice 3, and expiry, slice 4, drop entries, not nodes: the
writer's tombstones keep each node's content, §14, §14.1). Keeping them
costs no storage: a node's content is fixed by the log up to its head, so
a superseded node is rebuilt from the log when asked for; a writer MAY
keep recently superseded packets ready. A writer MUST answer an Interest
for a summary name that none of its roots or heads listed with a Nack.
Hence the time a reader's descent takes is bounded by the descent alone —
its own fetches being answered — and never by how fast or how long the
writer keeps putting.

A reader:

- discovers a writer's root with `<D>/32=summary/<O>/32=root` (CanBePrefix,
  MustBeFresh), verifies it as a log entry is verified (§4), and checks
  that its subject is `O`, its writer field its signing key and its name's
  seq its `Head`;
- MUST refuse a root whose `Head` is lower than one it verified from that
  writer for `O`, or than the highest seq it holds of that writer under `O`
  (invariant 3, "rollback"). The highest `Head` verified per writer and
  namespace is durable: the reader keeps it with what it holds (the
  reference keeps the root itself), so a restarted reader refuses the same
  rollback;
- descends only into what it follows (the collections and folders it has
  put into, read or watched, and the names on the way to them), and only
  into children and pages whose digest differs from the one it last
  processed in full: an unchanged branch costs nothing. Watching a folder
  of 10,000 notes of which 37 changed costs the root, the `O/32=data` node,
  the folder node, the changed pages, the 37 notes and their new entries;
- descends the root it verified to the end: it fetches the nodes and pages
  that root lists, not a newer root's, until every branch it follows is
  processed. A node that is not answered leaves the descent incomplete; the
  branches processed in full stay processed, so the next descent skips
  them. Only after a descent does the reader take the writer's newer root,
  if the writer moved meanwhile, and descend from what it has processed.
  One complete descent of a root gives the reader everything that root
  covers in what it follows, however fast the writer keeps putting;
- MUST refuse a node (or page) whose `Entries` or `MembersEntries` ranges
  are not ascending and disjoint, reach above its `Head`, or list more than
  65,536 seqs together: a node lists no entry its head does not cover, and
  one node never makes a reader expand an unbounded list;
- MUST refuse a node (or page) with more than 64 `Expiry` runs, a run with
  no seqs or not exactly one date, runs whose seqs are not ascending and
  disjoint across all of them, or a run naming a seq the node does not
  list in `Entries`: a bound covers only what the node lists;
- fetches the entries the visited nodes list that it does not hold, except
  those its newest node of their writer shows expired (keep bounds, above).

`watch` reports a `Summary` for each verified node of the watched name or
below it that it descends into: the collection, the signing writer,
frontier `{writer: Head}` and the node's inline children by digest (a paged
node lists none; its pages are not sub-collections).

## 8. Cut — slice 2 (removal), slice 5 (revocation)

A cut is a signed list of exactly which versions of a key or of a member's
keys stay valid: every version it lists stays valid; anything else by those
keys MUST be refused, whatever date or seq it claims. A removal cut is
carried by the members record that removes a writer (§6), signed with it by
the owner. A revocation cut is carried by the trust context that revokes a
key, signed with it by the namespace's root (§8.1).

- A cut lists exact versions, never a limit. A writer's log is shared by
  all its collections, so its seqs in one collection have gaps; under a
  limit, a removed writer could sign a new entry at a seq of such a gap
  below it — a new name, so no equivocation — and be admitted. Under a list
  that entry is outside. The list is what the cut's signer held verified:
  an entry a summary only listed is not in it; and, for a revocation cut,
  only what it first verified before the key was lost (§8.1).
- A cut replaces clock-based signing-time validity: no date in a version,
  and no certificate's validity period, decides whether it is inside
  (§8.5).
- **Re-check when a cut arrives.** When the record in force changes (a
  newer record, or one that merges with it, §6), a reader MUST read the
  collection again under it: admit or refuse every version it holds of the
  collection anew, and recompute the state from the versions admitted. A
  version it had applied that the new record refuses by a cut is
  **withdrawn**: it leaves the state, the reader MUST report it to every
  watcher of the collection as `Withdrawn` (the version and the cut),
  whatever the watcher's frontier, and `get` of it by name answers
  `Refused` (`OutsideCut`, next step: ask the owner). A version applied
  before and still admitted is not delivered again. The writer's own
  device does the same with its own versions. A newer trust context does the
  same for revocation cuts (§8.3).
- Withdrawing is forward-only (invariant 9): copies already read stay read.

A version passes both: the members record in force admits its key (§6) and
the trust context does not refuse it (§8.1). The two cuts are independent:
a removal cut is the owner's, per collection, and ends a writer there; a
revocation cut is the root's, per key, and ends the key everywhere.

### 8.1 Revocation cut — slice 5

When the owner revokes a device key `K` (`<D>/KEY/<k>`;
[personal-namespace.md](personal-namespace.md) F4), the root signs a new
trust-context version listing `K` as revoked
([trust-context.md](trust-context.md) §3.3.6) and, beside it, `K`'s
**revocation cut** (`RevocationCut`, trust-context.md §3.3.12). A
revocation without a cut refuses everything `K` signed, as revocations
always did.

- **What it lists.** One CutRange per collection `C` that `K` wrote into,
  with prefix `<D>/32=log/<C>` and the runs of the seqs of `K`'s log entries
  in `C` it keeps — versions, blocks, members records, hold, lease and
  prune records — and one with prefix `<D>/32=log` for `K`'s snapshots
  (§16.1). The prefix is per collection because a writer's seqs are one
  sequence across its collections: a cut by seqs alone would let a thief
  sign an accepted seq again under another collection, a new name.
- **What it refuses.** Every log entry of `K` outside the cut, whatever its
  date or seq, and every other packet `K` signed — summary roots, one-key
  heads, seal keys, grants, audit answers, an asker's proofs — since no cut
  ever lists those (§8.6 says what this costs a thief and an honest
  reader).
- **The cut is the listing.** `K`'s summary roots and heads are refused
  once the cut is held, so a reader following `C` learns `K`'s entries in
  `C` from the cut: when it adopts the context and when it starts following
  `C`, it fetches every entry of `C` the cut accepts that it neither holds
  nor has refused. When the cut has a manifest (trust-context.md §3.3.12),
  the reader first fetches the manifest packets by full name, then each
  entry by its full name, digest included, as the manifest lists it: only
  the honest bytes can answer, whoever serves them. A cut made before
  manifests lists names only; its entries are fetched by name, and the
  first answer that verifies is taken (§8.6). Holders and caches may
  answer either. Snapshots under `<D>/32=log` are fetched only when asked
  for by name. Nodes of `K`'s summary verified before the reader held the
  cut stay verified (they still say which seqs exist, §5.2), but none is
  taken after it. An entry of `K` in `C` that the cut neither accepts nor
  re-admits never applies, so `K`'s later entries and other writers'
  versions naming it as a parent do not wait for it (§5.2).
- **Produced from what the root saw before the loss.** A thief holding `K`
  writes as `K` from the theft until the revocation, and the producer's
  data layer verifies and stores those writes like any other until then. A
  cut that listed everything held would make them valid for good. So a cut
  lists exactly the log entries of `K` that the producing device — the root
  device, or the device recovering the namespace (§8.4) — holds verified,
  has not withdrawn or refused, and **first verified before the loss of
  the key**, as the owner states it; never entries a summary only listed.
  - *First verified.* Every device records, with each log entry it holds,
    the time by its own clock at which it first verified it (for its own
    entries, when it wrote them), never a date the entry carries, with the
    digest of the public key that verified it. The record is stored with
    the entry and survives a restart; an entry restored keeps its time. An
    entry stored before devices recorded this has no time; it counts as
    unknown.
  - *The bound.* `held_before` (a time) admits only entries first verified
    strictly before it; `upto` (a seq per collection) admits only entries
    of the collections it names whose seq is at most the one named (other
    collections and snapshots are left out). At least one MUST be
    given: a producer MUST refuse an unbounded cut, saying to state when
    the device was lost. The owner answers "when did you lose it?"; the
    default is the time the key was marked suspected (below).
  - *Left out.* Every entry of `K` the device holds verified that the bound
    leaves out — first verified at or after `held_before`, past `upto`, or
    of unknown time — is listed by its full name with its digest, so the
    owner can look at each and re-admit the honest ones one by one (§8.2).
  - *Key and bytes.* The producer gives the cut the digest of the public
    key whose certificate verified the entries it lists (refusing when
    they verify under two public keys of the one key name), and a manifest
    listing the seq and implicit digest of every entry its ranges list
    (trust-context.md §3.3.12).

  Entries of collections the producer does not follow, or did not hold
  yet, fall outside; the owner re-admits them (§8.2). ndn-data:
  `Device::revocation_cut(&self, key: &Name, bound: &CutBound) ->
  Result<CutProposal, DataError>`, with `CutBound { held_before:
  Option<Timestamp>, upto: BTreeMap<Name, u64> }` (collection to seq) and
  `CutProposal { cut: RevocationCut, manifest: Vec<Bytes>, left_out:
  Vec<Name> }`. The root takes the cut as a file
  ([personal-namespace.md](personal-namespace.md) F4): `ndn-fwd revoke
  <name> --cut <file>`, which refuses a cut whose key the version does not
  newly revoke (`cut-refused`, [mgmt-trust.md](mgmt-trust.md)), a cut made
  without a bound, and one bounded later than the loss time the owner
  answered, and prints the entries left out.
- **Suspected.** Between noticing the loss and signing the revocation, the
  owner marks `K` **suspected** on the producing device (ndn-data:
  `Device::suspect(&self, key: &Name, since: Timestamp) -> Result<(),
  DataError>`, `Device::unsuspect(&self, key: &Name) -> bool`,
  `Device::suspected(&self, key: &Name) -> Option<Timestamp>`). The mark is stored and survives
  a restart. It ends when the device adopts a version that revokes `K`, and
  is ignored while a held version revokes `K`: the cut then decides. While
  it holds, the device takes no new log entry of `K` — it does not fetch
  the log entries of `K`'s device, and does not apply or store one of `K`
  — and entries it already holds stay. An entry of `K` offered to it is
  refused `Suspected` (the key and since when; next step: finish the
  revocation, or lift the mark if the key was not lost). The default
  `held_before` of a cut of `K` is the mark's `since`.
  So what the root verifies of a thief's writes stops at once, and the
  owner's answer and the root's view describe the same moment.
- **Checking.** A reader verifies every entry under the trust context's
  durable rule (trust-context.md §6.3), never by date: an entry of a revoked
  key outside its cut is refused `OutsideCut`, the cut stated as the key, the
  runs of the collection's CutRange (as for that writer, accepted) and the
  context's anchor key that signed it, next step: ask the owner. Under a
  cut with a manifest, an entry at a name a range lists is accepted only
  with the bytes the manifest lists; while the manifest packet that lists
  it is not held, the entry is pending, neither applied nor refused, and
  the packet is fetched as a missing certificate is. Under a cut with a
  key digest, an entry is accepted only through a certificate of that
  public key. The refusal is decided by signed data, so it is kept: the
  entry is not fetched again from another source as an entry failing its
  signature is (§17, poisoned cache). A members record refused this way
  does not count for the record in force, which is computed from the
  others; a hold, lease or prune record refused this way stops counting.
  An in-cut entry still needs a certificate of `K` to verify: the
  namespace CA keeps serving the certificates of a key revoked with a cut,
  and forwarders and validators keep them and the cut's manifest, for that
  use only (trust-context.md §5.1, §6.3).

### 8.2 Re-admission — slice 5

A cut can drop honest work: a stolen device's offline edits nobody had
seen, or entries in collections the producer did not follow. The root
re-admits them one by one: a trust-context version that adds **CutExact**
entries to `K`'s cut, each the full name of one entry, ending in its
implicit digest (trust-context.md §3.3.12, §5.3). It never adds a range,
and nothing about it is in the members record.

- **Finding them.** The producer prints, with the cut, every entry of `K`
  it held that the bound left out (§8.1). A device that refused an entry by
  a cut reports it with its full name and digest (ndn-data:
  `Device::refused_by_revocation(&self, key: &Name) -> Vec<Name>`). The
  owner looks at each and hands the honest ones to the root (`ndn-fwd
  readmit <key> <full-name>…`). The root refuses a key its held version
  revokes without a cut (`readmit-no-cut`) and a name that does not end in
  a 32-octet digest or lies outside `K`'s device log `<D>/32=log`
  (`readmit-refused`).
- **Admitting.** When a device adopts a version, it admits every CutExact
  that names an entry it holds refused, or an entry of a collection it
  follows that it does not hold: it fetches it by its full name (digest
  included) when not held, verifies it, applies it and delivers it to
  watchers as a new version. A refused entry it holds with other bytes at
  that name is dropped for the one admitted.
- **Only those bytes.** A re-admission admits no neighbouring seq, no
  entry at the same seq in another collection, and no other bytes at the
  name it lists.

### 8.3 Late revocation and re-checking — slice 5

A reader that has not yet adopted the revoking version accepts what `K`
signs, as a reader not holding a removal cut does (§8). When a device
adopts a trust-context version that may refuse more than the one it held
(trust-context.md §5.1: it revokes a name, drops, shrinks or changes a cut,
drops an anchor, or lists a new role in DataRequiresCut; and the first
version of a namespace it adopts), it MUST judge again every entry it
holds with the whole durable walk a fresh fetch gets (trust-context.md
§6.3), run again on the stored packet: signature, chain, issuers, schema,
revocation, cut, manifest and key digest. Checking only whether the
entry's own signing key is revoked is not enough: a version can revoke an
issuer, such as the old CA a compromised-root recovery revokes, and every
key that issuer certified then loses its authority.

- An entry whose verdict is pending (a certificate or manifest packet not
  held) stays held as it was; the missing packet is fetched, and the entry
  judged again once it is resolved.
- An entry it had applied that the walk now refuses is **withdrawn**,
  exactly as for a removal cut: it leaves the state, every watcher of its
  collection is told `Withdrawn` whatever its frontier, with the version
  and why (ndn-data: `Change::Withdrawn { id: VersionId, why: Refusal }`),
  and `get` of it answers `Refused` with the same reason. The why
  is either the key's revocation cut (`OutsideCut`, next step: ask the
  owner, who can re-admit it by exact name, §8.2), or the chain above or
  beside the cut (`Untrusted`, with the reason: a revoked or unauthorized
  issuer, a lapsed key of a role listed in DataRequiresCut waiting for its
  cut). No re-admission applies to the second kind, since a cut never
  excuses an issuer; the device keeps the stored packet, judges it again
  on restore, on the next adoption that may refuse more, and whenever a
  packet of that key verifies again (after the key is certified by a new
  CA, say), and takes it back, delivered as a new version, once the walk
  accepts it.
- An entry applied before and still accepted is not delivered again.
- The writer's own device does the same with its own entries for its own
  key's cut (`OutsideCut`). Its own entries are not judged again by the
  whole walk: the device trusts what it signed itself.
- The clock withdraws nothing by itself: an entry of a key of a role listed
  in DataRequiresCut that a reader accepted before the key's certificate
  lapsed stays applied until the next re-check (an adoption that may
  refuse more, a restart, the key's packets verifying again); a re-check
  after the lapse withdraws it (`Untrusted`) until the key's cut arrives,
  which then decides.

**Restore.** A refusal and a withdrawal survive a restart: a device
restoring its store judges every stored entry again with the same walk,
against the contexts it holds, as on adoption; pending entries stay held.
Withdrawing is forward-only (invariant 9).

**A device's own log at restore.** An entry under the device's own name is
its own only if the device wrote it. A copy of the device key in other
hands — a thief's, before the revocation reaches the device — can write
under that name too, and the device takes such an entry live as it takes
any writer's. So:

- the device keeps a record of the entries it wrote itself (ndn-data: the
  implicit digest of each, stored locally beside the log); at restore, an
  entry under its name whose stored bytes the record does not list is
  restored as another writer's, never as its own;
- its log head moves only for entries it wrote, never for a refused or
  foreign entry;
- its next seq is the head plus one, computed without overflow: a write
  past the largest seq is refused, never wrapped;
- a live entry under its own name that it did not write, with a seq more
  than 64 above its head, is refused (`BeyondOwnLog`, stating the head);
  within that margin it is taken as another writer's.

A store written before devices kept this record is migrated once, at its
first restore, with the earlier rule (every entry under the device's name
counts as its own); entries a thief had placed in such a store before the
update are taken as the device's own by that migration (residual).

### 8.4 Renewal, rotation, expiry and recovery — slice 5

- **Renewal** re-certifies the same key (personal-namespace.md F10). Since
  Data is judged without validity periods (§8.5), the device keeps
  signing with its key and its log continues: entries signed under the old
  certificate and under the new one verify alike, also after the old one
  expired. Nothing else is needed.
- **Rotation** to a new key is a new enrollment: the new key is a new
  writer (§4), admitted where a members record's writer prefix covers it.
  When the CA enrolls a new key for a device identity that already has
  one, the old key is **replaced**, and the owner ends it with a
  revocation and a cut bounded at the replacement's enrollment
  (`held_before` = the first NotBefore of the new key's certificates).
  Until that is signed, the old key stays valid for Data; the root's
  tools list it as a key to end, with the cut to make.
- **Expiry of a guest.** A key of a role the trust context lists in
  DataRequiresCut — `guest`, by default — fails closed once its
  certificate lapsed by the reader's clock (§8.5), and is ended the same
  way, with a cut bounded at its certificate's NotAfter. Its entries the
  root verified before that stay valid; the rest the owner re-admits one
  by one (§8.2).
- **Ending them.** The root device makes each cut in its data layer with
  that bound (§8.1) and signs one version ending every such key that has
  one (`ndn-fwd end-keys`, after one confirmation, or unattended from a
  timer when the root store opens without a secret). A key to end is never
  revoked without a cut. Until then `ndn-fwd status`, the root's other
  commands and its admin TUI list it ([personal-namespace.md](personal-namespace.md)
  F9, F10).
- **Recovery** after losing the root device (recovery-kit.md §6) carries
  every cut into `N+1` and `N+2`, except orphan cuts (whose key no
  revocation covers) and cuts listing a name outside their key's device
  log, which it drops and reports: the old root, which signed them, may
  have been in a thief's hands. A recovery from a compromised root MAY add
  a cut for each key it newly revokes — the old root device's admin key,
  say — produced as §8.1 says by the recovering device from what it holds
  verified, bounded by when the root was lost. Such a recovery revokes the
  old CA key, an issuer, and a cut never excuses an issuer
  (trust-context.md §6.3); so the new CA certifies again every key the
  recovered context revokes with a cut, from a certificate of it the
  recovering device holds, and the in-cut versions keep a chain to the new
  root. It does so once `N+1` is taken, after showing the cuts to the
  operator and on their confirmation, and only for a certificate whose
  public key has the cut's key digest: a certificate carrying another
  public key under the key's name is never certified, and the key of a
  cut made before key digests is not certified again at all (reported).
  That certificate authorizes nothing outside the cut: the revocation of
  the key stands, excused only for the key's own in-cut packets. A cut key
  not certified again is reported with why, and its versions stay refused
  until the owner certifies it. Devices whose key was not revoked enroll
  again or renew with the new CA (personal-namespace.md F8); their
  versions withdrawn because the old CA was revoked come back once their
  key is certified by the new CA (§8.3).

### 8.5 Time — slice 5

No validity decision accepts because of a clock (invariant 1). For Data
this now holds of the certificate chain too: a version is judged without
the validity period of any certificate or anchor (trust-context.md §6.3),
with one exception that can only refuse (below).

**What "valid when it signed" became.** The study's first text asked that
a version be accepted if its key was valid when it signed it. That needs a
trusted time of signing, and none exists: the only dates are the one the
key writes — a stolen key writes any date — and the reader's clock, which
would refuse honest old data once its certificate lapsed and would let
whoever sets the reader's clock decide. Built instead, with signed data at
both ends of a key's authority and the key's own order in between: the
**certificate chain**, signed by the key's issuer, proves the key was
authorized; the **cut**, signed by the root, proves where that authority
ended, as names in the key's log rather than as a moment. This decides
what "valid when it signed" was meant to decide — was this version signed
while the key was trusted — and it is the plan's "the validator checks
cuts, not `now()`". The residual: a key without a revocation has no end
by itself. A leaked key of a role that renews, whose certificate expired
and that nobody revoked, still signs data that is accepted; ending it is
the owner's revocation with a cut.

**What the clock does now: DataRequiresCut.** Some keys are meant to end by
the calendar. A guest's certificate is short-lived to end the invitation,
and guests do not renew. For a role the trust context lists in
DataRequiresCut (trust-context.md §3.3.13; `guest` in every context
`ndn-fwd init` makes), a version signed by such a key is accepted only
while a certificate of that key is valid by the reader's clock, or once
the key is revoked with a cut, which then decides alone. In between it is
refused, fail-closed, as revoked without a cut: the key's certificate
lapsed and the owner's cut is awaited. The owner's root device makes that
cut bounded at the certificate's NotAfter and signs it (§8.4), and it
accepts what the guest wrote while invited, as far as the root saw it.
The clock can only refuse here: a fast
reader clock refuses a guest's versions early until the cut arrives; a
slow one accepts them a little longer, as a reader that has not adopted a
revocation does; neither makes a reader accept what a cut refuses. Roles
that renew (member, admin, node, relay) are not listed by default:
listing them would refuse a device's honest versions whenever its renewal
is late or a reader's clock runs fast.

**What the root's clock does: the bound of a cut.** The producer of a cut
reads its own clock twice: when it first verifies an entry, and when the
owner marks a key suspected or answers when it was lost (§8.1). Both are
the root's own observations, never a date the key wrote. A wrong root
clock moves which entries a cut lists; the producer prints what it leaves
out, and readers never read that clock.

**What still uses a clock, and why that is safe.**

- In this layer: a version's date (display, time ranges, §5.4), expiry
  (each device's own retention, §14.1, and the summary's keep bounds,
  §7), the one-key head's freshness and the age `get` reports (§5.3), the
  batch delay (§4.1) and the audit's clock skew (§13.3). None decides
  whether a version is valid; a wrong clock moves only its own device's
  retention, listing and waiting. The root's clock bounds the cuts it makes
  (above).
- The reader's clock refuses, never accepts, the versions of a lapsed key
  of a role listed in DataRequiresCut (above).
- Outside it, the live exchanges keep the clock: signed and command
  Interests (management authorization), adopting a trust context (its
  signing anchor valid now), enrollment, renewal and NDNCERT, link
  admission and peer authentication, certificate issuance and serving,
  and prefix announcements a forwarder learns routes from.
  Their freshness is the point, and a refusal is retried, never stored: a
  lying clock there denies service, loudly, and decides nothing about
  stored data.

### 8.6 Threat notes — slice 5

**A thief holding `K`.**

- *Can*, before a reader holds the revoking version: write as `K` and have
  it accepted there, until that reader adopts the version and withdraws it
  (§8.3). Keep for good the writes the root first verified before the loss
  time the owner stated: the cut lists them (§8.1), and nothing in them
  tells them from the owner's. So the owner should state the earliest
  moment the key may have been out of their hands, and mark it suspected
  as soon as they notice. Use `K` for live exchanges until its certificate
  expires or a node holds the revocation (links close on adoption).
- *Cannot*, at a reader holding the revoking version: have any new name
  accepted — a seq after the cut, a seq in a gap below it, an accepted seq
  under another collection, or a backdated version (dates decide nothing);
  have accepted what it wrote after the stated loss time, even if the root
  verified it; have a summary, head, seal key, grant or audit answer
  accepted; have other bytes accepted at a name a range of a cut with a
  manifest lists, by any reader, a late joiner included, or by a forwarder
  on its path; be re-admitted by a range (re-admission is by exact name
  and digest, so its other bytes at a re-admitted name stay out); make a
  reader withdraw an in-cut version (the cut is the root's); have a new
  certificate of `K`'s name for another public key excuse anything (the
  cut's key digest), or have one made in a recovery (§8.4).
- *Residual, old cuts only: equivocation at an accepted name.* A cut made
  before manifests binds names, not bytes. Under such a cut a reader
  holding the honest version keeps both and reports the equivocation
  (invariant 2); a reader holding neither may take whichever answers
  first. Every cut made now carries a manifest, which closes this.

**A thief holding a copy of a device's own key, before the device holds
the revocation.** It can write under that device's name, and the device
takes such an entry as another writer's. It cannot make the device take
it as its own at restore, raise the device's log head, or make the
device's next seq wrap around and sign over seqs it used (§8.3).

**A lying clock.**

- *The signer's* moves only the dates it writes: where a version sorts in
  a time range (§5.4) and, for keep dates, its retention (§14.1). It
  cannot make a version valid or invalid; a stolen key's backdated version
  is outside the cut.
- *The reader's* moves only its own retention, waiting and reported ages
  (§5.3, §14.1), its live exchanges (a context whose anchor it thinks
  expired is not adopted, loudly), and when it starts refusing a lapsed
  key of a role listed in DataRequiresCut (early when fast, late when
  slow, until the key's cut). It cannot refuse honest old Data of any
  other role, nor accept what a cut refuses.
- *The root's* moves which entries a cut it makes lists (§8.1); the
  producer prints the entries it leaves out. Nobody else reads it.

**A malicious holder** (a repository, cache or relay).

- *Cannot* forge or alter a version, make a reader accept one the cut
  refuses, or make it withdraw one the cut accepts: both are decided by the
  root-signed context. It cannot serve an older context in place of a newer
  one held (anti-rollback, trust-context.md §5.1), nor other bytes than
  the manifest lists.
- *Can* withhold: in-cut versions (the reader knows what is missing from
  the cut's runs and fetches them elsewhere), manifest packets (the
  versions they list stay pending, never accepted with other bytes), and
  newer trust contexts, which delays a revocation until the reader gets the
  version by another path (refresh, sync); what it accepted meanwhile is
  withdrawn then (§8.3). Under a cut made before manifests, it can serve a
  thief's other bytes at an accepted name to a reader holding neither (the
  residual above).

**A leaked, expired, unrevoked key.** For a role the context lists in
DataRequiresCut (guests, by default), its versions are refused once its
certificate lapsed, until the root's cut. A key replaced by a new
enrollment stays valid for Data until the owner ends it with a cut; the
root lists it until then (§8.4). For any other key — a
member's, admin's, node's or relay's, never replaced — Data ignores
validity periods, so its thief signs data that is accepted until the
owner revokes the key: the price of not trusting clocks for that Data;
the remedy is revocation with a cut. Nothing lists such a key: the root's
list of keys to end holds lapsed keys of listed roles and replaced keys.

## 9. Seal — slice 2 (folder epochs: slice 6)

A seal is a read policy over people, devices and groups (§6). An
application is never a seal audience: lenses hold no keys, and the host
opens only what the person pointed at. Holders without the key store and
forward ciphertext. Erasure is the destruction of the key.

- **Epochs.** A collection whose record in force lists readers is
  **sealed** in that record's epoch, `(D, n)`: the device that signed the
  record starting the epoch and that record's seq in its log. A record with
  no readers leaves the collection unsealed from then on.
- **Epoch keys.** The content key of an epoch is 32 random octets that `D`
  makes when it signs the record starting the epoch, and keeps with what it
  holds. Nothing derives it: no key of an epoch exists before its record is
  signed, and no device holds a secret that yields the keys of epochs to
  come. The record starting the epoch carries its **key check**
  (`KeyCheck`, §16.2): HKDF-SHA256 (RFC 5869) with the key as input keying
  material, no salt, and as info `ndn-data/seal/check/1`, the TLVs of `C`
  and of `D`, and `n` as 8 octets, big-endian; 32 octets. A record that
  keeps the epoch copies it. A device MUST take a key as epoch `E`'s of `C`
  — granted, or read back after a restart — only if it matches the check of
  a held owner-signed record of `C` naming `E` (the starting record's, when
  held); a key that does not is dropped.
- **Recipient keys.** Each device holds an X25519 **recipient key**, kept
  with its signing keys in its key store — never with the data it holds,
  which may be served or copied — and never sent; its public half is its
  **seal key**, the packet `<D>/32=seal/<public key>` signed by the device
  key. Epoch keys a device made or was granted stay with what it holds,
  wrapped to its seal key, under no name any device serves (the reference
  keeps grants as received and its own keys under
  `/localhost/ndn-data/epoch/<D>/…`).
- **Sealing.** A writer of a sealed collection encrypts each version's
  payload — its `Fields` and `MergeOp` TLVs — with ChaCha20-Poly1305 under
  the content key of the epoch its record in force names, a random 96-bit
  nonce, and the TLV of the version's own name as associated data; the
  record carries `Sealed` (the epoch and `nonce ‖ tag ‖ ciphertext`) in
  place of them. A reader opens it with that epoch's key; a payload that
  does not open under it is refused as a bad signature. A reader without
  the key holds the version verified and closed, applies nothing that waits
  on it, and asks for the key if it may hold it. A reader MUST refuse a
  version of a sealed collection that is not sealed, `Unsealed`, unless it
  lies inside the record's `Since`: its writer wrote it before hearing the
  record that sealed the collection, and relays have it in clear. A record
  that seals a collection its previous revision left unsealed sets `Since`
  (§6), so what was written before stays held, as history.
- **Grants.** A device asks for an epoch key with the Interest
  `<G>/32=grant/<GrantAsk>`, `GrantAsk` naming its own seal key, the
  collection `C` and the epoch `E`. The granter `G` MUST answer only when
  (1) an owner-signed record of `C` it holds names `E`, (2) the readers the
  held records naming `E` list, or `E`'s creator, admit the asker, (3) the
  record in force, when it seals `C`, admits the asker, and (4) `G` holds
  `E`'s key; anything else gets no answer, and `G` fetches nothing for it.
  It then fetches and verifies the asker's seal key (signed by the asker's
  device key) and answers, signed by its own key, with the key wrapped to
  it: a fresh X25519 key agrees a secret with the seal key, the wrapping
  key is HKDF-SHA256 of that secret (no salt; info
  `ndn-security/confidentiality/x25519-kek/1`, the ephemeral and the seal
  key), and the key is sealed under it (ChaCha20-Poly1305, the grant's name
  as associated data). Any device holding `E`'s key may grant it: the
  asker checks what it gets against the record. A granter keeps the grants
  it signed (the reference, its last 4,096), so asking again gets the same
  packet; past that it signs the name anew, a packet that opens to the same
  key. An asker asks only for an epoch a held record names and that it may
  hold by (2) and (3) as far as it can tell, the epoch's creator first,
  then every other device it knows to write into `C`'s namespace. Keys are
  per epoch for every reader: a device of the owner's own namespace is
  granted like any other (a second device of 10,000 collections, each in
  its own epoch, asks 10,000 grants once).
- **Forward only.** A removed reader is refused every grant from then on
  (condition 3), and the epoch that removal starts has a key that did not
  exist before, so nothing written after it reaches it; what it already
  opened it keeps, said plainly (invariant 9). A reader added by a record
  that only adds is of the epoch it keeps, and reads that epoch's history;
  an epoch that ended before a reader was listed stays closed to it.
- **Folder epochs — slice 6.** A folder record with readers (§6.1) starts
  a **folder epoch** `(D, n)` as a collection's record starts an epoch: a
  random key made by `D`, and a key check computed as above with the TLV of
  the folder `F` in place of `C`'s. Every collection under `F` whose
  effective record inherits its readers (§6.1) is sealed in that epoch:
  its versions' `Sealed` names it, and a key is taken as its key only if it
  matches the check of a held folder record of `F` naming it. A device asks
  for it with a `GrantAsk` naming `F` in place of a collection, and the
  granter reads conditions (1) to (3) against the folder records of `F`;
  for a collection sealed in its own epoch, condition (3) reads the
  effective record. So a reader asks one grant per folder epoch, however
  many collections inherit it. A folder record that drops a reader starts
  a new folder epoch for every inheriting collection at once.
- A device outside a sealed collection's audience answers `get` of it, of
  its states and of its versions with `Sealed` (next step: ask the owner).
- **What a relay sees.** Every relay, cache or repository carries the
  ciphertext and the grants (each wrapped to one device) and reads no
  payload and no key. It does see, in clear: every name (devices,
  collections and their paths, log seqs, summaries); members records —
  rule, writers, readers (people, devices, groups), cuts with the exact
  versions they keep, revision and `Since`, and whether a record is a
  folder's; each epoch and its key check; each version's record but its
  payload — collection, writer, seq, parents, type, the seal it declares,
  keep, the writer's date, its group (§5.5) — and the ciphertext's size;
  seal keys; and who asks whom for which epoch's key (the grant's name
  names the asker's seal key, the collection or folder and the epoch), and
  when.

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
writers' summaries list them; a version a checkpoint inside `F` covers, as
its signed record, §5.2) MUST NOT answer a partial value. Of a collection
whose rule the device does not know, it answers `RuleUnknown` (§5.1).

A **snapshot** is an entry of its signer's log, `<D>/32=log/seq=<n>` (no
collection), Content `SnapshotRecord`: the names it pins, each an exact log
entry name or a state name. Publishing it makes a set of versions and
merged states citable together: a link carries the snapshot's name. It
does not hold the versions it pins back — a reader may count them before
the snapshot arrives; versions counted all or none are a group (§5.5).

## 12. Sync notice — slices 1, 2

Each namespace `O` has a **sync group** `<O>/32=sync`: `O`'s whole name,
however many components it has, then the KeywordNameComponent `sync`
(`ndn_security::sync_group`, the one definition the data layer and the
forwarder's libraries share). It runs as State Vector Sync (ndn-svs v2
dialect). A device joins its own namespace's group — `O` the namespace of
the trust context governing it (§3), so the very group the forwarder's
libraries carry for that context — and the group of every other namespace
whose collections it puts into, reads or watches, `O` read off the
collection's name at its marker (`/home/bob/32=data/notes` →
`/home/bob/32=sync`). Each member's state-vector entry is named by its
device name `D`.

**Publishing.** After every entry a device signs about collection `C` of
`O`, it publishes into `O`'s group and into the group of every other
namespace that `C`'s newest members record names — the namespaces of its
writer prefixes and readers (a group reader by its collection's namespace),
each as the held context governing it says (§3) — joining those groups
first. So the notice reaches every member's devices through the group of
their own namespace, which every forwarder holding that namespace carries
to its devices; no group needs to reach outside its namespace.

**Hearing.** The group only says "`D` moved". It carries no data and
decides nothing: a reader that hears it in any group fetches `D`'s root for
the group's namespace and for every other namespace it follows that `D`
writes into — `D`'s own, and each one of whose collections a members
record it holds lists a writer of `D`'s namespace (§7). The devices a
reader looks at for a namespace `O` (its first look, a watch, a key) are
those it heard in `O`'s group and those it heard in any group that write
into `O` by the same rule. Sync Interests are unsigned; a stranger in a
group costs a reader a root fetch, never a wrong answer. A device's
counter in a group starts at its log head when it joins, so it stays above
anything an earlier run of the same key announced.

The group needs no configuration, and no forwarder treats its name
specially: a forwarder carries it with an ordinary strategy choice and
ordinary routes, which the libraries that already know the namespace's
membership install from data the forwarder holds.

- **Strategy (trust-context and link libraries).** A forwarder that holds
  `O`'s trust context runs `<O>/32=sync` with the multicast strategy from
  the moment it holds the context — held at start, or adopted later
  (`ndn_namespace::sync_group`). A newer version of the context leaves the
  choice as it is. A relay that serves `O`'s devices without holding `O`
  runs the group with multicast while `O` is in transit there, from the
  first served device of `O` linked until the last one leaves
  ([ndn-link.md](ndn-link.md) §15.7).
- **Routes (link library).** A link carries `O` when its peer was admitted
  in `O`: as a member of `O`, held here, or as a device the forwarder
  serves for `O` without holding it. Such a link gets a route for
  `<O>/32=sync` beside the routes it gets for the peer's device name or
  namespace (`ndn_link::group_routes`), with the same lifecycle: added when
  the link is up, taken when a revocation takes the link's last membership
  in `O`, and gone with the link's face when the link ends. An enrollment
  link carries no group.
- **Members.** A device registers `<O>/32=sync` for its own sync face when
  it joins and does nothing else for the group. Its registration sits
  beside the link routes in the same entry, so the multicast strategy sends
  each Sync Interest to the local member and over every link that carries
  `O`, never back toward the face it came from.

A forwarder that neither holds `O` nor serves its devices (a hub with
default routes) forwards the group like any other name. A forwarder learns
no route from the face a Sync Interest arrived on.

**Reaching other people.** A person's devices reach another person's when
their forwarders link — directly (each names the other's device in a peer
entry) or through a relay both use — and hold each other's trust contexts
(§3). A forwarder routes a namespace it follows (holds without a
certificate in it) over every relay it uses, as it routes its own: one its
person added, and one its namespace advertises in its trust context
([ndn-link.md](ndn-link.md) §10, §15.5). The other person's device names
and, by route inheritance, their group go to the relay. The relay needs no
context of the people it carries: it serves their devices against their
roots (`open`, or `listed`), routes each linked device's name, its issuers'
key names and its namespace's group to it, runs the group with multicast
while the namespace is in transit, and forwards their Data unvalidated; the
devices validate it end to end, fetching the chain from the device that
signed it. Two people who each advertise a community relay and adopt
each other's anchor link reach each other with no further step. Nothing is
routed by hand and no route is learnt from traffic: the routes come from
the links' admitted identities and the contexts held, the groups a device
publishes into from the members records it holds.

## 13. Custody — slice 3 (merge pieces: slice 6)

### 13.1 Large payloads

A version's payload `P` — `Fields` and `MergeOp` as §16.2 encodes them, or
its sealed ciphertext (§9) — of more than 6,144 octets (`INLINE_MAX`)
travels in pieces, in a collection of any rule: from slice 6 a merge
collection's operations and checkpoints too (slices 3 to 5 carried every
merge operation inline, answering `TooLarge` and `NotInline` for larger
ones). A block is never in pieces (§4.1), and a reader refuses a block in
a merge collection (`NotInline`).

A payload carries at most 64 MiB (`PAYLOAD_MAX`, 67,108,864 octets) — per
version, so per operation or checkpoint —, as a reader assembles it whole:
`put` of more answers `TooLarge`, and a reader refuses, when it decodes
the record, a `Chunks` whose `Size` is above it (or at most `INLINE_MAX`).

- Chunk `i` is `P[4096·i ..]`, at most 4,096 octets, the packet
  `<V>/seg=<i>` (`V` the version's name, `seg=` a SegmentNameComponent).
- The manifest tree lists the chunks with fan-out 128: depth `d` is the
  least `d ≥ 1` with `128^d` at least the number of chunks; nodes are
  numbered in heap order from the root (0; the children of node `k` are
  `128k+1 …`), the bottom level listing chunks, the others nodes. Node `k`
  is the packet `<V>/32=manifest/seg=<k>`, Content `Digest*` in order.
- Every piece is DigestSha256-signed; a Digest is SHA-256 of the child's
  whole Data packet (the implicit digest), as in summaries (§7). The signed
  VersionRecord carries `Chunks` (`Size`, `Digest` of the root node) in
  place of `Fields`/`MergeOp` — or, sealed, after a `Sealed` carrying only
  its `SealEpoch`. So each piece verifies on its own from wherever it came,
  and a sealed payload stays sealed in pieces: holders see the size.
- A reader lists such a version with `Payload::Large { size }` and reads it
  whole on `get` of its name (or of a log or one-key collection's newest):
  each piece from its store, else by name, else from each holder of a live
  lease it knows (§13.2) by the Interest `<H>/32=held/<Name TLV>`, which the
  holder answers (DigestSha256) with the packet inside; a piece that is not
  the one its parent lists is dropped and fetched elsewhere.
- **In a merge collection — slice 6.** A version in pieces is admitted,
  and its pieces fetched as above unless a checkpoint the reader holds
  whole and checked covers it (§5.2). Until it is whole it waits as a
  missing parent does: later versions of its writer and versions naming it
  wait. Whole, it is opened (when sealed), checked and applied (§5.2).

### 13.2 Hold records and leases

- A **hold record** is an entry of an owner device's log about collection
  `C` (Content `HoldRecord`: `C`, `Copies`, `KeepUntil` — until when — the
  `Frontier` `at` the asker had applied, and `Holders`: the holder devices
  the owner chose, by name, ascending). It is the custody policy, taken
  only when owner-signed (the owner rule, §3). `hold(C, {copies, until,
  holders})` signs one when the device's newest differs in any of them.
  Each copy is kept by a distinct device the record names: `hold` answers
  `BadRequest` (next step: `FixRequest`) when it names fewer holders than
  `copies`, or a name that is no device name (§16.1) or the asking device.
- A **lease** is an entry of the holder `H`'s log about `C` (Content
  `LeaseRecord`: `C`, the hold record's name, `KeepUntil`, and the
  `Frontier` `holds`). It promises every version of `C` inside `holds` that
  applies — admitted by the record in force, not pruned — with its pieces,
  each until the earlier of the lease's date and the version's keep. A
  reader keeps one lease per holder *device*: the newest by log seq,
  whichever of the device's keys signed it, so a device counts once however
  many keys it has. It counts a lease only when the hold record it answers
  is held and names that device a holder; the asking device never counts
  for itself (by device name, not key). Both records are listed in summary
  nodes under `MembersEntries`, which from slice 3 lists every entry of a
  collection that is not a version.
- **Keep caps hold.** A lease's date MUST NOT pass the hold record's, nor
  the latest `Keep::Until` date of the versions inside `holds` when every
  one of them is kept until a date. A holder signs no lease that would end
  by its clock, and a reader does not count a lease that breaks either
  bound (or whose hold record or versions it does not hold yet). Every
  device drops what has expired by its own clock (§14.1).
- **Asking.** The owner device `A` asks each holder `H` its record names
  with the Interest `<H>/32=hold/<HoldAsk>`: the hold record's name, a
  fresh 16-octet `Nonce`, and `Asker`, `A`'s proof of asking — a Data
  packet `<A>/32=ask/<binding>` signed by `A`'s device key, `binding` the
  SHA-256 of `H`'s Name TLV followed by the `HoldAsk` TLV without its
  `Asker`. The proof binds the holder and this one ask, so it serves no
  other. A device holds only for the namespaces its host lists, and
  answers a hold ask only when, in this order: `C` is of such a namespace;
  the proof's key locator names the device that signed the hold record —
  any other ask is dropped before a signature is checked; that asker has
  no other hold ask in progress here; the proof is named for this ask and
  verifies to a key of that device (at most 8 proofs are verified at once);
  the record, fetched and verified, is that device's newest hold record for
  `C` and names `H`; and its date is past now. `H` then follows `C`, takes
  every version inside `at` with every piece (fetching back what it lost —
  re-replication — from the writer or another holder), signs the lease
  over what its store holds whole, and answers with it (a DigestSha256 Data
  whose Content is the lease's packet). It keeps its last 1,024 answers by
  name, so an ask asked again gets the same packet at no cost. It signs a
  new lease when what it holds grows. Holders join the groups of the
  namespaces they hold for, to hear what they keep; an owner asks only the
  devices its record names, never one heard in a group (sync Interests are
  unsigned, §12). A holder serves every entry and piece of a collection it
  holds, whoever wrote it, by its own name and under `<H>/32=held/…`.
- **What a holder stores** is bounded by what the owner signed. Of records,
  only those it accepts: owner-signed members and hold records, leases of
  a holder the hold record they answer names (or its own), and prunes it
  does not ignore (§14). Of another device's versions, only those of a
  collection it holds — a merge collection's as a log one's (slice 6), with
  their pieces — admitted by the record in force and inside the `at` of the
  hold record it accepted; re-replication fetches back that set and no
  more. Leases, audits and repair treat merge versions and their pieces as
  log ones.

### 13.3 Audits

- Each `hold` audits every live lease: from the device's randomness it
  draws pieces (16 by default) uniformly from what the lease promises — the
  log entry of each version inside `holds` that applies and whose keep has
  not passed by the auditor's clock (§14.1), and each manifest node and
  chunk of it — and asks each with the Interest `<H>/32=audit/<AuditAsk>`
  (`Nonce`, 16 fresh random octets, the piece's name, and `Asker`, the
  auditor's proof binding `H` and the ask as in §13.2). A manifest node the
  auditor lacks, needed to list the chunks, it fetches from the writer or
  the holders, and at last asks of the audited holder itself through an
  audit ask, judged like any other.
- `H` answers only an ask about a collection it holds, from an owner device
  whose hold record held here names `H` (by the proof's key locator, before
  any signature is checked), with at most 64 audits of that asker in
  progress, its proof verified (§13.2). It answers under the ask's name,
  signed by its device key, FreshnessPeriod 0, `AuditAnswer`: `Piece`, the
  piece's whole packet; `PrunedBy`, the packet of the prune record that
  ended the piece's version (§14); `RefusedBy`, the packet of the members
  record of the revision in force there that refuses the version;
  `Expired`, empty: the piece's version expired by the holder's clock and it
  dropped it (§14.1); or `Missing`, it does not hold the piece and knows no
  record that ends it.
  The same answer cache as §13.2 applies.
- The auditor judges each answer:
  - `Piece` whose digest is the one the auditor holds (the version
    packet's, or the one its manifest lists): the piece is there.
  - `Missing`, or a `Piece` that is not the piece: signed evidence of a
    breach, as the auditor's own records say the piece should be there.
  - `PrunedBy`: the auditor verifies and takes the record (§14). It
    excuses the piece — which leaves the audit — when it covers the
    version; a verified prune that does not, or a record that is not a
    prune of the version's writer in `C`, is evidence. A record it cannot
    verify yet is no answer.
  - `RefusedBy`: verified and taken, it excuses the piece when the record
    in force at the auditor now refuses the version; when the auditor
    still admits it, the two views differ and it is no answer, never
    evidence.
  - `Expired`: the auditor checks it against the keep the version's writer
    signed. Kept `Forever`, or `Until(t)` with `t` later than the auditor's
    clock plus the clock skew it allows (a day by default): signed evidence
    of a breach, as no clock explains it — the holder dropped what it
    promised and claims expiry. Otherwise — `t` within the skew, or kept for
    the last `n`, as the holder may know newer versions the auditor does not
    — no answer, never evidence: the lease is unanswered for the piece and
    repair may ask again. So an auditor whose clock is behind the holder's
    cannot frame an honest holder that dropped at keep.
  - Nothing signed by `H`: no answer.
- Verdict: **broken** on any evidence; else **unanswered** when an ask got
  no answer, or no device produced a manifest node a promised version's
  chunks are listed in (the audit is unverified, never kept); else
  **kept**. Only evidence makes a lease broken: a timeout is never a
  verdict, so a slow network can only cause a copy more, never a wrong
  judgement.
- **Repair.** A lease not live, broken or unanswered, or one that holds
  less than the hold record's `at`, does not count. While fewer than
  `copies` count, `hold` asks every holder the record names whose lease
  does not count, all at once (a holder asked again fetches back what it
  lost), and audits each lease that comes back. It asks no other device.
  `Custody` lists the live leases with this device's audit of each, those
  found broken or unanswered before repair, and `unkept`: the versions
  inside `at` that this device does not keep whole and that no lease
  audited kept holds.
- **Release.** A host MAY drop its own chunks of a large version
  (`Device::release`, by version or by collection) only on fresh evidence,
  never on a stored verdict:
  1. It holds the version whole, and its own hold record for `C`. The
     candidates are the holders that record names whose live lease holds
     the version.
  2. While it asks them it serves none of the version's chunks and
     manifest nodes, to anyone (quarantine); its log entry stays served.
  3. It asks each candidate one audit ask marked `Whole`, naming the
     version's log entry, under a fresh nonce. The answer is `Proof`:
     SHA-256 over the nonce, then, for each piece of the version — its log
     entry, its manifest nodes in heap order, its chunks in order — the
     piece's length (8 octets, big-endian) and its whole packet. A holder
     lacking any piece answers `Missing` (or `PrunedBy`, `RefusedBy`). The
     releaser checks the proof against its own copy.
  4. It drops the chunks only when at least `copies` (at least one)
     distinct holder devices proved. Otherwise it keeps them, saying for
     each version which holder proved what (`Released::kept`), and when it
     released nothing it answers `NotHeld` with those reasons (next step:
     hold first).
  5. *Slice 6.* A version of a merge collection is released only on a
     checkpoint `CP` covering it (§5.2) that the device holds whole and
     checked: steps 2 to 4 are done for `CP` — the candidates are the
     holders the record names whose live lease holds `CP`, and `CP`'s
     pieces are quarantined while they prove it whole — and the version's
     chunks are dropped only when at least `copies` distinct holders prove
     `CP`. Otherwise they are kept, saying why ("no checkpoint covering it
     is proved held by N audited holders; write a checkpoint and hold it"),
     and when nothing is released the answer is `NotHeld`. A merge
     version's pieces hold back every later version of the collection
     (§13.1); a covering checkpoint proved held makes them unneeded by
     every reader that takes it.

### 13.4 What a holder can and cannot do

- It cannot forge, alter or substitute data: every piece verifies against
  the writer's signature through the manifest. It cannot pass an audit for
  a piece it cannot produce when asked: the nonce makes every ask a new
  name, so no cache and no earlier answer answers it, and the pieces are
  the auditor's choice. A holder keeping a fraction `f` of what it promised
  passes one audit with probability at most about `f^16`.
- It cannot make an owner release on a copy it cannot produce: a release
  asks a proof over every piece of the version, under a fresh nonce, from
  each of `copies` distinct holders, while the releaser serves none of
  those pieces.
- It cannot be counted unless the owner's hold record names it, nor be
  counted twice under two keys; a device the owner did not choose gets no
  hold ask and its lease counts for nothing.
- It cannot be made to work by a stranger: an ask from a device that is not
  the owner device its record names costs it a parse, no signature check
  and no fetch; an owner's asks are bounded (one hold ask and 64 audits in
  progress per asker, 8 proofs verified at once), and a replayed ask is
  answered from the cache.
- It cannot be framed by records its auditor has not heard yet: a prune or
  a members record it followed is its answer, and it is evidence against it
  only where the auditor's own records prove the piece should be there.
- It cannot read sealed data it holds without being of the audience: it
  stores and serves ciphertext (§9 lists the metadata it sees). A device of
  the namespace is an owner device (§3): it may sign the members record
  that defines the audience, so no audience rule binds it, and it reads
  and owns. A holder that must not read is therefore enrolled outside the
  namespace it holds for.
- It cannot keep its promise past keep and be counted, nor extend a lease
  past the owner's date. Serving past keep (a slow clock, or on purpose)
  makes no reader keep what it serves: each drops it by its own clock and
  stores nothing expired (§14.1).
- It can fetch an asked piece from elsewhere at audit time — a cache, or
  another holder — but not from the releaser during a release: an audit
  proves it can produce the data, not that it stored it. Two holders can
  collude that way, so `copies` holders owned by one party are one failure
  domain. It can stop answering: its lease becomes unanswered and repair
  starts, but nothing marks it broken without evidence. It sees which
  pieces are asked, and when.

## 14. Prune and expiry — slices 2 (scope), 3, 4 (expiry)

A prune is an entry of the pruner's log about collection `C` (Content
`PruneRecord`: the prefix — `C` or one of the pruner's version names in it
— and the `Frontier` `upto`). It spreads like data.

- A prune MUST cover only versions the pruner wrote. A device asked to
  prune a log entry of another device, or up to a frontier naming another
  key, MUST refuse with `NotOwnWrites`, whose next step is to edit instead:
  removing another writer's data in a shared collection is an edit (a merge
  edit that removes the field) every reader applies, and the author's own
  version stays theirs, readable by its name. A reader ignores a prune
  record that names another key.
- It covers the signer's versions of `C` (or the one version named) with
  seq at most `upto`'s for its key — versions only, never the signer's
  members, hold, lease or prune records or snapshots. `upto` MUST be below
  the prune record's own seq, or the prune would swallow versions written
  after it: `prune` answers `BadRequest` (next step: `FixRequest`) for an
  `upto` past the device's newest entry (the record takes the next seq),
  and a reader ignores a prune record whose `upto` reaches its own seq.
  Prune applies to log and one-key collections: a merge collection's state
  is computed from every version, so `prune` answers `NotPrunable` (next
  step: edit instead).
- A reader that knows a prune MUST report `Pruned` for what it covers, not
  the data, drop its copies (record and pieces), tell its watchers
  (`Change::Pruned`) and serve none of it — by the prune records it holds,
  whether or not it held the version, by its own name, under `32=held` and
  in audit answers, also after a restart, which drops pieces and records a
  prune covers that the store still keeps; a piece fetched for a pruned
  version is not stored. Later versions do not wait for it. A holder drops
  it too: its leases end for it, and audits never ask for it. The writer
  keeps a local tombstone so its summary still lists the entry (the log
  never changes).
- **What "erased" means.** A device destroys the key of epoch `E` of `C` —
  the key it holds, the key it made, the grants it kept or signed for
  others — once all of these hold: `E` is not the record in force's epoch;
  at least one version sealed in `E` is pruned; every version of `C` it
  knows of is pruned, held and of another epoch (or unsealed), or not held
  and never applies (refused); and every writer known to write into `C`
  has left `E`, as signed data shows — it is this device, the record in
  force admits no further version of it (cut, or not a writer), or it has
  a version in the record in force's epoch. Until then the erasure is
  pending, since a writer that has not moved on may still write into `E`;
  it is checked again whenever a version, a members record or a prune
  arrives. Erasing, the device stores an erased-epoch marker, which a
  restart loads before the keys, and from then on refuses that key if
  granted again — unless an admitted version sealed in `E` that no prune
  covers arrives (from a writer it had not heard of): then it takes the key
  again and removes the marker. From
  erasure on, every copy of that ciphertext anywhere, in any holder, cache
  or backup, is unreadable to whoever did not keep the key. Not erased:
  what a reader already opened (plaintext it kept, forward-only, invariant
  9); a key a device copied out of the layer; versions of an epoch that
  still has unpruned versions or a writer that has not left it — those are
  deleted by honest devices and holders only; and copies in caches, which
  expire by their own policy.
- **What a pruner can and cannot do.** It drops only its own versions; it
  cannot end another writer's data or another holder's promise for it, and
  it cannot recall copies already made.

### 14.1 Retention by expiry — slice 4

Keep is chosen at write (invariant 7) and, from slice 4, enforced: every
device drops what has expired, by its own clock. Expiry is local
housekeeping; it never decides whether anything verifies.

- **Scope.** Log and one-key collections. A merge collection's state needs
  every operation: it is edited instead, as `prune` answers `NotPrunable`,
  and its versions' keep is not enforced by expiry.
- **When.** A version **expires at a device** when it is kept `Until(t)`
  and `t` is at or before the device's own clock, or kept for the last `n`
  and the device knows `n` newer versions of the same writer in `C` — held,
  or listed by a summary node of that writer it verified. A version kept
  `Forever` never expires. Keep was set at write; nothing extends it, and
  custody neither (§13.2).
- **What every device does.** Every device — writer, holder or reader —
  MUST drop an expired version, record and pieces; MUST serve none of it,
  by its own name, under `32=held` or in audit answers; MUST NOT store one
  it fetches after it expired; keeps a durable tombstone (the version's
  id, writer and keep, and its first and last entry dates, so the writer's
  nodes stay rebuildable and a range read places it — of a sealed block
  dropped before it was opened, the last date is unknown and kept as such,
  and a range read takes the block as reaching any date from its first on,
  so lists it under `expired` wherever it may overlap); reports it to its
  watchers as `Change::Expired` (the version and its keep); and answers
  `get` of its name, or of an entry name in it,
  `Expired` (the name and the keep; next step `None`: nothing to do, and
  asking again does not help). A range read lists it under `expired`
  (§5.4). A device checks expiry on every access and sweeps at the earliest
  keep it holds, or keep bound its writers' newest nodes state (§7),
  reading its clock again when it wakes; a restart drops what the store
  still keeps that has expired. Later versions do not wait for an expired
  one (§5.2), and the writer's node stops listing it once the node's
  reference date passes its keep (§7).
- **A stopped writer.** When a writer stops writing into `X`, its newest
  node's reference date stops moving, so that node keeps listing versions
  whose keep has since passed by the holders' clocks; every honest holder
  dropped them, and a reader that never held them cannot fetch them. The
  node states a bound of each listed `Until` keep (`Expiry`, §7), so the
  reader sees by its own clock that they expired: it does not fetch them,
  and a watch of `X` stops waiting on them (§5.2) and applies what the
  writer wrote after them, without the writer writing again. Precision: a
  run's date is the latest keep in it, so the reader stops waiting at most
  one run's span after a version's own keep (none while the node's groups
  of one keep fit its 64 runs), never before it. When the writer does write
  again, a seq its new node no longer lists is not waited for either, even
  one the reader never learned. Versions kept for the last `n` need no
  bound: a stopped writer writes nothing newer that would end them, so
  holders keep them. Nothing wrong is delivered: the reader skips only
  what its own clock, against the bound in the writer's node (verified
  through its signed root or head), says expired.
- **Custody.** Leases are capped by keep (§13.2); audits never ask a piece
  whose keep has passed by the auditor's clock; a holder asked for a piece
  it dropped as expired by its own clock answers `Expired`, which is no
  answer and not evidence — unless the writer's signed keep proves it false
  beyond any clock skew the auditor allows (kept `Forever`, or until a date
  more than that skew past the auditor's clock), which is evidence of a
  broken lease (§13.3).
- **Clocks.** A slow — or lying — clock makes a device hold and serve
  longer; readers with right clocks still answer `Expired` and store
  nothing past keep. A fast clock makes a device drop early its own copy
  only: its lease stops counting for what it dropped — and a holder whose
  clock runs ahead of its auditor's by more than the skew the auditor
  allows is judged broken for it — and nothing of any other device
  changes. A writer's clock moves only its own dates and its own listing
  (§7). A reader's clock moves only what it waits for: a slow one waits
  longer on a stopped writer's expired versions, a fast one stops waiting
  earlier for versions it would itself drop as expired anyway.
- **Forward-only.** Expiry deletes at the devices that keep this
  specification; it recalls no copy (invariant 9). A cache, a device whose
  clock is slow, or a reader that copied the data out of the layer keeps
  what it has.

### 14.2 What a producer, holder or reader can and cannot do — slice 4

With blocks, heads and expiry:

- **A producer** — the one key, or a writer of a log collection:
  - can lie about its dates. That moves only its own order and indexing —
    where its entries fall in time ranges (§5.4) and its own listing by keep
    (§7) — never validity: a reader refuses nothing for a date;
  - can equivocate: two different blocks at one `(writer, seq)` are, like
    any two versions, evidence against its key, kept and reported
    (invariant 2), entries and all;
  - can set any keep, from a moment to forever, and change it only for
    later writes; nothing it signs later extends what it wrote, and only its
    own prune narrows it (§14);
  - can delay its entries up to the batch delay it states, and go silent:
    readers' age grows, and the bound promises no more (§5.3); a stream it
    stops keeps its last node listing what has since expired, with the keep
    bounds that let a watch stop waiting on it (§7, §14.1);
  - can state keep bounds other than its versions' keeps: too early, and
    readers that never held those versions skip them sooner; too late, and
    they wait longer. That moves only what readers wait for of its own
    stream, as choosing the keep itself does; nothing is delivered wrong;
  - cannot make an entry outside a block's signature, nor a head of a key
    the members record does not name.
- **A holder**, cache or relay:
  - can withhold blocks, nodes and heads: a range read lists what it lacks
    under `missing`; `get` answers older verified data with its own age —
    how long ago that version was last known the newest, never the age of
    a newer head whose node or version was withheld — or `Unavailable` when
    a newer head was verified and the held version was never confirmed the
    newest since the reader started (§5.3); and the reader fetches
    elsewhere;
  - can replay old heads it saw, as fresh: they are never forged and never
    older than one the reader verified (rollback, durable); the age then
    understates (§5.3);
  - can serve past keep: readers drop by their own clocks and store
    nothing expired (§14.1);
  - can answer `Expired` in an audit: no answer, not evidence, within the
    clock skew the auditor allows or for a version kept for the last `n`;
    for a version whose writer-signed keep proves it has not expired (kept
    `Forever`, or until beyond the skew) it is evidence, and the lease is
    broken. A holder that lost what it promised can so escape evidence only
    within that skew, never the count: an unanswered lease counts for
    nothing and repair starts (§13.3);
  - cannot forge an entry or splice one from another block: the block's
    signature covers every entry (§4.1). It cannot alter which versions a
    range read considers: the reader takes them from the node the signed
    head names by digest, so a holder can only omit them.
- **A reader** can cache and replay heads to others, as a cache can, and
  keep copies past keep: nothing recalls copies already made (invariant 9).
  It sees, of a sealed block, what §9 lists of any version — its date, keep
  and size, not its entries, their number or their offsets — and of a head
  its seq, digest and freshness, so the writer's batch delay.

## 15. Verbs — slices 1–4, 6, host surface slice 7

| Verb | Shape | Slice |
|---|---|---|
| `get` | `get(name) → version, state or entries + age` | 1 (entries, ranges: 4) |
| `put` | `put(collection, content, {type, keep, batch}) → (writer, seq)` | 1 (`batch`: 4) |
| `put_op` | `put_op(collection, operation, {type, keep}) → (writer, seq)` | 6 |
| `put_group` | `put_group([(collection, fields \| operation)…], {type, keep}) → [(writer, seq)…]` | 6 |
| `watch` | `watch(collection, since F) → summary, new versions…` | 1 |
| `snapshot` | `snapshot(names \| collections) → snapshot` | 1 |
| `hold` | `hold(prefix, {copies, until, holders}) → custody` | 3 |
| `prune` | `prune(prefix, upto)` | 2 (refusing others' writes), 3 |
| `share` | `share(collection, {rule, readers, writers})` | 1 (adding), 2 (removing, the rule), 4 (one key) |
| `share_folder` | `share_folder(folder, {rule, readers, writers})` | 6 |

`put_op` and `put_group` are forms of `put`, and `share_folder` of
`share`: the verbs stay seven. Code mostly uses `get`, `put` and `watch`.
`hold`, `prune` and `share` run on host policy, or on the person's
gesture. A function's answer is a `get` on its name (a later slice).
Exposure over forwarder management and the mobile FFI is slice 7. A device
answers a verb or option of a later slice with an error that names the
slice.

- **`get(C)`** of a merge collection answers its state now — `State` with a
  state name, `at`, the value (typed by the rule, §5.1) and `not_counted`:
  the versions held that are not in the value, sorted by id, each with why
  (the rule's not counted inside `at`, members of groups incomplete or
  unreadable here, §5.2, §5.5); of a log collection, its newest version
  (§5) — with `Age::Newest`: the time since the device last knew nothing
  newer was outstanding in `C`'s sync group (it heard the group with no
  refresh pending, or finished one), measured on its monotonic clock. Of a
  one-key collection it answers the newest version the writer's head names,
  aged by the head's receipt and freshness (§5.3). The
  first `get` of a collection the device does not follow looks at what the
  devices known to write into its namespace hold first (§12); a reader of a
  sealed collection holding versions it has no key for yet waits as long
  for the keys it asks for. Nothing held: `Unavailable`. Not of a sealed
  collection's audience: `Sealed`. A merge collection whose rule the device
  does not know: `RuleUnknown`, naming the collection and the rule (next
  step `UpdateProgram`), §5.1.
- **`get(state name)`** answers that exact state (`Age::Exact`), §11; under
  a rule the device does not know, `RuleUnknown`.
- **`get(log entry name)`** answers the version or snapshot (`Age::Exact`),
  fetching it when not held; a members record is not a version
  (`NotFound`); a refused entry answers `Refused` with the reason; a
  version sealed to an audience the device is not in, `Sealed`; an expired
  one, `Expired` (§14.1).
- **`get(entry name)`** answers `Entries` with that one entry of its block
  (`Age::Exact`), fetching the block when not held, as `get` of the block's
  name would (§4.1); an index past the block's last entry, `NotFound`.
- **`get(range name)`** of a one-key collection answers `Entries` (§5.4),
  aged as `get(C)`; of another rule, `BadRequest` (next step `FixRequest`).
- **`put(C, content, {type, keep, batch})`** signs the next entry of the
  device's log with parents = the state's `at` — in a merge collection, the
  operation its rule's edit makes (§5.1) —, applies it, and publishes it
  (§12).
  It requires a members record — under a folder, an effective record
  (§6.1) — that lists the device's key among the
  writers; for a collection of another namespace the device first looks for
  one, and answers `Unavailable` when no device writing into that namespace
  was heard, else `NotAllowed`. In a sealed collection it seals the payload
  (§9), asking for the epoch key first if it lacks it: `Sealed` when it is
  not of the audience, `Unavailable` when no device granted the key.
  With `batch = d` in a log or one-key collection it puts the entry into
  the open block and returns once that block is signed, at most `d` later,
  with the block's id (§4.1); in a merge collection, or with `d` longer
  than a day, `BadRequest` (next step `FixRequest`: put without batch, or
  with a batch of at most a day).
  In a merge collection whose rule the device does not know it answers
  `RuleUnknown` (§5.1); under a rule that takes only operations the
  application builds, `BadRequest` (next step `FixRequest`: use `put_op`).
- **`put_op(C, operation, {type, keep})`** is `put` with the operation the
  application built (`MergeOp`), in a merge collection whose rule the
  device knows: parents = the state's `at`, past = `down(at)`; the device
  signs the version and has the rule check and apply it (§5.1, §5.2), then
  stores and publishes it. An operation the rule refuses answers
  `BadRequest` with the rule's reason (next step `FixRequest`), and nothing
  is stored or published and the log head does not move. Of another rule,
  `BadRequest` (next step `FixRequest`: `put_op` is for merge collections);
  under a rule the device does not know, `RuleUnknown`; with `batch`, as
  `put` in a merge collection. It answers as `put` does otherwise.
- **`put_group(items, {type, keep})`** signs one version per item — fields
  (made into an operation by the rule's edit in a merge collection) or an
  operation — as one group (§5.5), and answers their ids in item order, or
  refuses as §5.5 says, writing nothing.
- **`watch(C, since F)`** reports every held version of `C` (or of the
  collections under folder `C`, which may be `<O>/32=data`) outside `F`,
  then every version applied later, the summaries of §7, each outside `F`,
  and every version withdrawn (§8), pruned (§14) or expired (§14.1); from
  slice 6 also every version held but not counted, with why
  (`Change::NotCounted`, §5.2, §5.5), and every such version once it
  counts (`Change::Counted`); it
  starts a refresh of every device known to write into the namespace. The
  stream ends when the device stops.
- **`snapshot(names)`** pins, for each name, the current state name of a
  merge collection or the exact name of a version, snapshot or entry, and
  signs the `SnapshotRecord`; a range name, which names no fixed set,
  answers `BadRequest` (next step `FixRequest`).
- **`share(C, {rule, writers, readers})`** signs the next members revision
  (`C` of the device's own namespace only, §3: else `NotOwner`), with the
  cuts, epoch and `Since` of §6. A collection sealed to a group moves to a
  new epoch when the group drops a reader, signed by a device of the
  collection's own namespace (§6), whoever owns the group. With the rule
  one key, `writers` names exactly the one key, or this device (§5.3): else
  `BadRequest` (next step `FixRequest`).
  Under a folder whose record is in force (§6.1), a `share` that lists a
  writer the folder's writers do not cover or a reader its readers do not
  admit answers `BadRequest`, saying what it would widen and to share the
  folder instead (next step `FixRequest`).
- **`share_folder(F, {rule, writers, readers})`** signs the next revision
  of folder `F`'s folder record (§6.1): at a device of `F`'s namespace
  only (else `NotOwner`), of a folder of at least one path component
  (else `BadName`), with the cuts across every collection under `F`, the
  folder epoch and `Since` of §6 and §9.
- **`hold(C, {copies, until, holders})`** (a device of `C`'s namespace,
  else `NotOwner`) names the holder devices, at least `copies` of them,
  none of them this device: else `BadRequest`, whose next step,
  `FixRequest`, is to correct the request itself (name more holders, or
  devices). It signs the hold record naming them, audits every live lease
  and repairs by asking the named holders only (§13), and answers
  `Custody`: the live leases with this device's audit of each, those found
  broken or unanswered before repair, and `unkept`, what nothing confirms
  is kept (§13.3). Releasing the device's own copy of what holders keep is
  host policy outside the verbs (`Device::release`, §13.3).
- **`prune(prefix, upto)`** of another device's entry, or up to a frontier
  naming another key, answers `NotOwnWrites`; of a merge collection,
  `NotPrunable`; up to a seq past the device's newest entry, `BadRequest`
  (next step `FixRequest`); else it signs the prune record and publishes
  it (§14).
- A verb given a name it cannot take answers `BadName` (§3).

## 16. Wire format — slices 1–4, 6 (slice 5 adds none)

### 16.1 Names

`D` is the device name, `C` a collection, `O` a namespace, `X` a name of a
summary tree: `O/32=data` or `O/32=data/<path>`, a folder or collection.
`32=` is a KeywordNameComponent, `seq=` a SequenceNumNameComponent (0x3A),
both from the NDN naming conventions.

| Name | Form |
|---|---|
| namespace `O` | one or more components; none a keyword, digest or `seq=` |
| device `D` | one or more components; none a keyword or digest |
| collection `C` | `<O>/32=data/<path>`, one or more path components; none a keyword or digest |
| folder | `<O>/32=data[/<path>]` (a watch target, a summary node) |

| Packet | Name | Signature |
|---|---|---|
| version, members record (a folder's too, `<D>/32=log/<F>/seq=<n>`, §6.1) | `<D>/32=log/<C>/seq=<n>` (a block too, §4.1) | device key |
| snapshot | `<D>/32=log/seq=<n>` | device key |
| summary root of `O` | `<D>/32=summary/<O>/32=root/seq=<head>`, FreshnessPeriod 0; discovered by `<D>/32=summary/<O>/32=root` (CanBePrefix, MustBeFresh), which no node, page or head name extends, so only a root answers it | device key |
| head of one-key collection `C` | `<D>/32=summary/<C>/32=head/seq=<s>`, Content `HeadRecord`, FreshnessPeriod = its `Freshness`; discovered by `<D>/32=summary/<C>/32=head` (CanBePrefix, MustBeFresh), which no node, page, root or other head extends (§5.3) | the one key |
| summary node of `X` | `<D>/32=summary/<X>/seq=<head>` | DigestSha256 |
| summary page of `X` | `<D>/32=summary/<X>/32=page/<buckets>/seq=<head>` | DigestSha256 |
| state (never fetched) | `<C>/32=state/<Frontier TLV>` | — |
| entry `i` of block `V` (never fetched) | `<V>/32=entry/seg=<i>` | — (the block's) |
| range of `C` (never fetched) | `<C>/32=range/<SeqRange or TimeRange TLV>` | — |
| sync group | `<O>/32=sync` (State Vector Sync Interests) | — |
| seal key | `<D>/32=seal/<public key>`, Content `SealKey` | device key |
| grant | `<G>/32=grant/<GrantAsk TLV>`, Content `Grant` | the granter's device key |
| hold, lease, prune record | `<D>/32=log/<C>/seq=<n>` | device key |
| chunk of version `V` | `<V>/seg=<i>` | DigestSha256 |
| manifest node of `V` | `<V>/32=manifest/seg=<k>`, Content `Digest*` | DigestSha256 |
| hold ask (answer: the lease's packet) | `<H>/32=hold/<HoldAsk TLV>` | DigestSha256 |
| held packet (answer: the packet) | `<H>/32=held/<Name TLV>` | DigestSha256 |
| audit ask and answer | `<H>/32=audit/<AuditAsk TLV>`, Content `AuditAnswer`, FreshnessPeriod 0 | the holder's device key |
| asker's proof (inside a hold or audit ask, never fetched) | `<A>/32=ask/<binding>`, empty Content, FreshnessPeriod 0 | the asker's device key |

`<buckets>` is a GenericNameComponent whose octets are the buckets taken
from the node, one octet (0–15) each. Log entries are named after the
writer's device, not the collection, because a writer of another namespace
can only sign under its own (`/bob/laptop/32=log/alice/32=data/docs/plan/seq=3`).
Data packets carry no MetaInfo besides the FreshnessPeriod the table
lists; ContentType is BLOB.

Every name parses one way, and a reader MUST refuse one that does not:

- **Collection.** The namespace is the components before the first
  `32=data`; the path, the ones after it. A name with no marker, nothing
  before it, nothing after it, or another keyword or digest component is
  no collection.
- **Log entry.** `D` is the components before the first `32=log` (`D` has
  no keyword); the last component is `seq=<n>`; what lies between is empty
  (a snapshot) or a collection name.
- **Summary.** `D` is the components before the first `32=summary`; a last
  `seq=` component is the head; a `32=page` then the next-to-last
  component is the page, and a `32=head` just before the last `seq=` makes
  the name a one-key collection's head packet (§5.3). What remains is the
  subject: a namespace (the root) or a folder or collection name (a head's
  subject is a collection). A root's subject is followed by `32=root`, and
  only the discovery names `<D>/32=summary/<O>/32=root` and
  `<D>/32=summary/<C>/32=head` lack the head — a namespace never ends in
  `seq=` — so a node or page name always carries it, and the subject's own
  last component is never read as the head. A subject without a marker is a
  namespace, never a node under one.
- **State.** `32=state` is the next-to-last component and the collection
  name precedes it.
- **Entry.** The last component is `seg=<i>` (a SegmentNameComponent), the
  next-to-last `32=entry`, and what precedes them is a log entry name with a
  collection: the block.
- **Range.** `32=range` is the next-to-last component and the collection
  name precedes it; the last is one GenericNameComponent whose value is one
  `SeqRange` (low ≤ high) or one `TimeRange` (from < to) TLV, nothing else.
- **Seal key.** `D` is the components before the first `32=seal`; one
  GenericNameComponent of 32 octets follows, the X25519 public key, equal
  to the `SealKey` the packet carries.
- **Grant.** `G` is the components before the first `32=grant`; one
  GenericNameComponent follows whose value is one `GrantAsk` TLV: a seal key
  name, a collection Name (or, for a folder epoch, the folder's, §9) and a
  `SealEpoch`.
- **Hold ask, audit ask.** `H` is the components before the first
  `32=hold` (`32=audit`), a device name; one GenericNameComponent follows
  whose value is one `HoldAsk` (`AuditAsk`) TLV. A hold ask's record is a
  log entry with a collection.
- **Asker's proof.** `A` is the components before the first `32=ask`, a
  device name; one GenericNameComponent of 32 octets follows, the binding:
  SHA-256 of the holder's Name TLV followed by the ask's TLV without its
  `Asker` (§13.2).

### 16.2 TLV-TYPE numbers

The data layer uses 0x0520–0x057F (registered in
[README.md](README.md#tlv-type-numbers)). Every number is even: a decoder
MUST skip an unknown even TLV inside these records and MUST refuse an
unknown odd one, so a later revision can add fields old readers pass over
(and fields they must not).

| Type | Name | Value |
|---|---|---|
| 0x0520 | VersionRecord | Name (collection), Frontier (parents), TypeId, Seal, Keep, Dated, [Group] (§5.5), then Fields, MergeOp — or Block (§4.1), or Chunks (§13.1; in a collection of any rule from slice 6) — or, sealed, Sealed |
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
| 0x0546 | MembersRecord | Name (collection, or with Folder the folder), [Folder] (§6.1), Revision, Rule, Writers, Readers, [Cuts], [SealEpoch, KeyCheck], [RuleSince], [Seq, Digest] (the parent, from revision 2: its revision, one below this record's, and the SHA-256 of its `MembersRecord`, §6) |
| 0x0548 | Rule | RuleKind [Name (merge rule: its full, versioned name, matched exactly, §5.1)] |
| 0x054A | RuleKind | NonNegativeInteger: 0 one key, 1 log, 2 merge |
| 0x054C | Writers | Name* (key-name prefixes) |
| 0x054E | Readers | Audience* |
| 0x0550 | SnapshotRecord | Name* (pins) |
| 0x0552 | SummaryNode | Name (subject), Writer, Seq (head), [PagePath], [Entries], [MembersEntries], [Expiry*], [Children \| Pages] |
| 0x0554 | Entries | SeqRange* |
| 0x0556 | MembersEntries | SeqRange* |
| 0x0558 | SeqRange | Seq (low), Seq (high), low ≤ high; a list of them is ascending and disjoint, and a summary node's lie at or below its Head and hold at most 65,536 seqs together (§7) |
| 0x055A | Children | Child*, by component |
| 0x055C | Child | Name (one component), Seq (head), Digest |
| 0x055E | Digest | 32 octets: SHA-256 of the child's whole Data packet; in a `MembersRecord`, of the parent's `MembersRecord` (§6) |
| 0x0560 | Pages | Page*, by bucket |
| 0x0562 | Page | Bucket, Seq (head), Digest |
| 0x0564 | Bucket | NonNegativeInteger 0–15 |
| 0x0566 | PagePath | octets, one bucket each (pages only) |
| 0x0568 | Writer | Name (the writer's key) |
| 0x056A | Cuts | Cut*, by prefix |
| 0x056C | Cut | Name (removed writer prefix), then per key it keeps versions of, by key: Writer, Entries (exactly those seqs, §8) |
| 0x056E | SealEpoch | Name (the device that signed the record starting it), Seq (that record's seq) |
| 0x0570 | RuleSince | Frontier: what the owner had applied when the rule changed, or when it sealed the collection |
| 0x0572 | Sealed | SealEpoch, Ciphertext |
| 0x0574 | Ciphertext | octets: nonce (12) ‖ tag (16) ‖ ciphertext, ChaCha20-Poly1305 |
| 0x0576 | SealKey | 32 octets: X25519 public key |
| 0x0578 | GrantAsk | Name (the asker's seal key), Name (collection; for a folder epoch, the folder, §9), SealEpoch |
| 0x057A | Grant | EphemeralKey, Ciphertext (the key, wrapped) |
| 0x057C | EphemeralKey | 32 octets: the granter's X25519 public key for this grant |
| 0x057E | KeyCheck | 32 octets: HKDF-SHA256 of the epoch's key (§9) |
| 0x0521 | Chunks | Size, Digest (the root manifest node's packet), in a VersionRecord in place of Fields and MergeOp, or after a Sealed without Ciphertext (§13.1) |
| 0x0523 | Size | NonNegativeInteger: the payload's octets, more than 6,144 and at most 67,108,864 (`PAYLOAD_MAX`, §13.1) |
| 0x0525 | HoldRecord | Name (collection), Copies, KeepUntil, Frontier (what the asker had applied), Holders |
| 0x0527 | Copies | NonNegativeInteger |
| 0x0529 | LeaseRecord | Name (collection), Name (the hold record), KeepUntil, Frontier (what it holds) |
| 0x052B | PruneRecord | Name (collection or version), Frontier (up to, below the record's own seq) |
| 0x052D | HoldAsk | Name (the hold record), Nonce, Asker |
| 0x052F | AuditAsk | Nonce, Name (the piece; with Whole, the version's log entry), [Whole], Asker |
| 0x0531 | Nonce | 16 octets, fresh random per ask |
| 0x0533 | AuditAnswer | one of Piece, Missing, Proof, PrunedBy, RefusedBy, Expired |
| 0x0535 | Piece | octets: the piece's whole Data packet |
| 0x0537 | Missing | empty: the holder does not hold the piece and knows no record that ends it |
| 0x0539 | Holders | Name* (the holder devices the owner chose), ascending; required in a HoldRecord |
| 0x053B | Asker | octets: the asker's proof, the Data packet `<A>/32=ask/<binding>` (§13.2) |
| 0x053D | Whole | empty: the audit asks one proof over every piece of the version (§13.3, release) |
| 0x053F | Proof | 32 octets: SHA-256 over the Nonce, then each piece's length (8 octets, big-endian) and whole packet: the log entry, the manifest nodes in heap order, the chunks in order |
| 0x0541 | PrunedBy | octets: the packet of the prune record that ended the piece's version |
| 0x0543 | RefusedBy | octets: the packet of the members record that refuses the piece's version |
| 0x0545 | Block | BlockEntry+, in a VersionRecord in place of Fields and MergeOp (sealed: the plaintext of Sealed), its encoding at most 6,144 octets (§4.1) |
| 0x0547 | BlockEntry | Offset, Fields |
| 0x0549 | Offset | NonNegativeInteger: ms after the version's Dated; the first 0, non-decreasing along the block |
| 0x054B | HeadRecord | Name (collection), Seq (the Head of the writer's node of it), Digest (SHA-256 of that node's whole packet), Freshness (§5.3) |
| 0x054D | Freshness | NonNegativeInteger: ms, the batch delay of the writer's newest version; the head's FreshnessPeriod |
| 0x054F | TimeRange | Dated (from), Dated (to), from < to; in range names only (§5.4) |
| 0x0551 | Expired | empty, an AuditAnswer: the piece's version expired by the holder's clock and it dropped it (§14.1) |
| 0x0553 | Expiry | SeqRange+ (seqs the node lists in Entries), KeepUntil (a date at or after each one's keep); in a SummaryNode, at most 64, their seqs ascending and disjoint across all of them (§7) |
| 0x0555 | Folder | empty; in a MembersRecord right after its Name: the record governs the folder Name and every collection strictly under it (§6.1) |
| 0x0557 | Group | Seq (the group's id: the seq of its first version), GroupCount; in a VersionRecord right after Dated (§5.5) |
| 0x0559 | GroupCount | NonNegativeInteger 1–1024 (`GROUP_MAX`): the number of versions in the group |

Slice 3's numbers are odd — critical — because the even ones of the block
are taken and because a reader that does not know them must not pass over
them: a version in pieces read as one without a payload, or a hold, lease
or prune record mistaken for nothing, would be wrong, not stale. So with
the custody fields: a reader passing over `Holders` would count any
device's lease, a holder passing over `Whole` would answer a release with
one piece, and an auditor passing over `PrunedBy` would judge an honest
holder broken. A hold record without `Holders` is refused.

Slice 4's numbers are odd for the same reasons. A reader passing over
`Block` would read a version with no payload, and one passing over
`Offset` would date every entry at its block's date; a reader passing over
a `HeadRecord` would take a head for nothing, and one passing over
`Freshness` would take a cached head as just confirmed — an age that says
fresher than it is. A range name with an unknown `TimeRange` read as some
other range would answer the wrong entries. An auditor passing over
`Expired` would read an empty answer as no `AuditAnswer` it knows, and
must instead judge it against the piece's keep (§13.3). A reader passing
over `Expiry` would wait without end on a stopped writer's expired versions
and could not say why; refusing the node says that its format is newer
than the reader.

Slice 6's numbers are odd for the same reasons. A reader passing over
`Folder` would take a folder's record as the record of a collection named
like the folder, and judge every collection under it without it: a writer
the folder removed would be admitted there — wrong, not stale. One passing
over `Group` would count the members of an incomplete or refused group in
part, which is the one thing a group forbids; one passing over
`GroupCount` could not tell a complete group from an incomplete one.
Refusing them, an older reader drops such a record as one it cannot decode
and waits (§4): stale, until it is updated. The one residual is a
collection whose own record such a reader holds: it applies that record
alone, without the folder's narrowing, until it is updated (§17).
Checkpoints, versions not counted and effective records are not on the
wire.

Names are the Name TLV (0x07). Inside a record, fields appear in the order
the table lists them; lists are sorted as stated, so equal content encodes
to equal bytes and equal nodes have equal digests.

Slice 5 adds no data-layer TLV. A revocation cut is not a data-layer record:
it is the trust context's `RevocationCut` (`0x0428`, with `CutRange`
`0x042A`, `CutRun` `0x042C` and `CutExact` `0x042E`,
[trust-context.md](trust-context.md) §3.3.12), signed by the root with the
revocation it belongs to, so it reaches every node the revocation reaches.
The layer's own names are what its ranges list (§8.1, §16.1). The
slice-2 `Cut` (0x056C) stays the members record's removal cut.

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
- **Seals reuse** `ndn-security`'s confidentiality content key
  (ChaCha20-Poly1305) and its key wrap `wrap_ck`, which seals a key under
  a key-encryption key. `wrap_ck` needs a key-encryption key both ends
  already share, and two people's devices share none: their only keys are
  signing keys (Ed25519 or P-256, possibly in a TPM or a YubiKey that signs
  and cannot agree keys). The one addition, `wrap_ck_to`, is the agreement
  that makes that key: an ephemeral X25519 key against the reader's
  published X25519 seal key, HKDF-SHA256 into the key-encryption key, then
  `wrap_ck`. Epoch keys, not the in-tree `ndn_security::abe` (rabe,
  opt-in): an audience here is a short list of people, devices and groups
  the owner's devices check against the owner-signed record they hold, so
  ABE's attribute authority is not needed — and would not remove the
  agreement, since an authority must deliver each reader's attribute keys
  confidentially too (`ndn-nacabe` does it with an X25519 sealed box);
  rabe's curve gives about 100-bit security and pairing crypto is heavy
  for phones and the browser build. ndn-ext's `ndn-sealed-box` does the
  same agreement but cannot be used from ndn-rs, and takes only ephemeral
  recipient keys.
- **Random epoch keys and a key check**, not keys derived from a secret
  per device: a derived key exists before its epoch does, so a reader
  could collect the keys of epochs to come, and every holder of the secret
  could never be left out of an audience. One random key per epoch costs a
  grant per epoch per reading device; the check (HKDF, the one key
  derivation of the layer) lets a reader verify any granted key against the
  owner-signed record, so any holder of the key may grant it.
- **Exact cuts** reuse `Writer` and `Entries`, the summary node's own
  fields for "this key's seqs", rather than a frontier: a frontier is a
  limit, and a cut must not be one (§8).
- **Pieces reuse** RDR's shape (segments under the object's name, one
  manifest the only signed root, DigestSha256 segments) and the summary's
  digest-of-packet links; RDR's flat manifest (`ndn-app`, TLV 0xF504) caps at
  256 segments and lists payload hashes, so the tree here is FLIC-like
  instead: nested, any size, digests of whole packets, the root in the
  signed record. A holder is asked for another producer's packet under its
  own name (`32=held`), which routes like any of its names; a forwarding
  hint would need every forwarder on the way to route the hint, which the
  link layer does not promise.
- **Leases and holds are log entries**, so they spread through summaries
  like everything else and carry the writer's own monotonic order; the
  audit answer is the one per-ask signature, under a nonce name no cache can
  hold.
- **Holders named in the hold record**, not learned from sync: sync
  Interests are unsigned (§12), so a device heard in a group is no evidence
  of anything; the owner's signed choice is the one policy every reader
  checks a lease against.
- **The asker's proof is a signed Data packet** (`<A>/32=ask/<binding>`)
  rather than a signed Interest, so the existing validator and trust
  schema check it like any packet of `A`, and its key locator names the
  claimed asker before any signature is checked, which is what lets a
  holder drop a stranger's ask for the cost of a parse.
- **Release by quarantine and a whole proof**, not a holder-specific
  encoding of the pieces: any encoding a holder can compute from its
  storage it can also compute from the plain pieces fetched from the
  releaser at the time of the ask. Only the releaser refusing to serve them
  removes that relay; the proof over every piece then makes the holder
  hold all of them at once.
- **A members record's parent** reuses `Seq` and `Digest`, the pair a
  summary's child and page name their packet by, in a position of its own
  rather than a new number: both are even, so a reader of the previous
  revision of this format passes over them and merges concurrent records
  by intersection, as it did. The digest is of the parent's Content
  because the record in force may be a merge no packet carries (§6).
- **Blocks carry their entries inline** — a deviation from the model's
  first text, "a block with a digest per entry". Per-entry packets named
  by digest in the signed block cost one Interest and about 160 octets of
  packet (name, signature info, digest) per reading, for every reader, about
  five times the bytes; inline entries cost about 35 octets per reading
  and one Interest per block (1/60 of one per reading at a block a minute),
  and leave nothing apart from the signature to splice or substitute. The
  one signature per block is what model change M6 asked for; each entry
  stays verifiable on its own through its block's signature, so the digest
  per entry is not needed for it. `Block` reuses `Fields` for each entry, so
  an entry reads like any version's payload, and `Offset` rather than a
  `Dated` per entry keeps an entry's date to an octet or two.
- **A head separate from the root.** The root has FreshnessPeriod 0 so
  that discovery always reaches the writer (§7); a battery producer cannot
  answer every reader. The head's FreshnessPeriod is the writer's batch
  delay, so caches absorb readers for as long as the writer would have held
  an entry unsigned anyway, and the head names the collection's node by
  digest — one hop, where the root reaches it through every node from `O`
  down. A `HeadRecord` rather than a second signed node keeps the node
  DigestSha256 and fixed by the log, so heads and roots name the same
  packets.
- **Range reads use the log's own names** (§5.4): the head, the node's
  `Entries` and the blocks' dates, with no index a producer would sign or a
  holder could falsify. `SeqRange` is reused for ranges by seq; `TimeRange`
  reuses `Dated`.
- **Keep bounds in runs** (§7), not a keep per listed version: a node
  stays bounded however many versions it lists — at most 64 dates, and no
  more seq ranges than seqs it lists — and needs no new number for seqs or
  dates (the runs reuse `SeqRange` and `KeepUntil`). Versions sharing a
  keep, as a stream kept to one date does, take one exact run. Past 64
  groups — a stream whose every block is kept a fixed time after its date
  — equal-count runs in seq order keep each run's span (its latest keep
  minus its earliest) to about a 64th of the listed keeps' spread: 30 days
  of keep, about 11 hours, the most later than a version's own keep that a
  reader may stop waiting for it, and only once the writer has stopped. A
  bound rather than the keep itself is enough: a reader needs only to know
  that a version expired, never before it did.
- **`Expired` is an empty answer**, not a record: a holder's clock is
  evidence of nothing, so the answer says only that it dropped the piece at
  keep by its clock; the auditor judges it only against the writer's signed
  keep and its own clock with the skew it allows (§13.3, §14.1).
- **Rules by exact, versioned name** (§5.1), not a rule kind with
  parameters or a name matched by prefix: the name in the owner-signed
  record is the whole policy, a device either runs exactly it or computes
  nothing, and a change of meaning gets a new name, so no two programs
  compute different states under one name and no reader falls back to
  another rule. `/merge/yrs` keeps its name, so slice-2 records still mean
  what they meant.
- **A group's id is its first seq**, and its versions are its writer's
  consecutive seqs (§5.5): a key's seqs are unique across its log, so
  `(writer, id)` names the group with no new identifier; a reader knows
  exactly which seqs make it up, so it can tell what is missing and fetch
  it by name from the summaries, and no other version can claim to belong
  (a seq outside the range is malformed). `put_group` signs under one lock,
  so nothing else of the device's log comes between. `GroupCount` makes
  completeness a fact of each member's own signed record.
- **A folder record is the existing members record with a flag** (§6.1),
  not a new record: the owner rule, revisions, parents, the merge of
  concurrent records, cuts, epochs, key checks and `Since` all carry over
  unchanged, and the folder's summary node already lists its members
  entries. The flag is odd so that a reader that does not know it refuses
  the record rather than read it as a collection's (§16.2). The effective
  record is not on the wire: it is a function of signed records every
  reader holds, and a second, carried copy could only disagree with them.
- **Checkpoints are rule-defined and cover by frontier** (§5.2): only the
  rule knows which operation summarizes a state, so the rule's check says
  so, and no wire mark could be trusted beyond what that check says. What a
  checkpoint covers is `down(P(CP))`, read from the frontier its writer
  signed: every reader computes it alike, it needs no new field, and a
  checkpoint cannot claim to cover a version its writer had not applied.
- **Pieces in the version, not references to log versions** (§13.1), as
  agreed with ndf-rs (`handoff-ndf-rs/REPLY-3.md`): a reference to a
  version of another collection would leave open whether its readers and
  epoch match the merge collection's, who may write there, and what happens
  when the referenced version is pruned while the operation still needs
  it. Pieces in the version itself raise none of these: they verify through
  the version's own signature and stay sealed in its epoch. The one rule
  they bring is the release rule for merge pieces (§13.3), as a lost piece
  of a merge version would hold back every later one.

## 17. Failure model

| Failure | Required behaviour | Rests on |
|---|---|---|
| Partition / offline | Reads and writes continue locally under each device's key; collections reconcile from summaries when a path returns. | §4, §7 |
| Lost device | Its leases lapse; repair asks the other holders the hold record names; the owner marks its key suspected on the root device, says when it was lost, and revokes it with a cut of what the root first verified before then; the entries left out are printed, and any honest one is re-admitted by exact name and digest. | §8.1, §8.2, §13 |
| Compromised key | The revocation cut keeps exactly the versions it lists, with the bytes its manifest lists, and refuses the rest, whatever dates they claim; the key's summaries, heads, seal keys and grants are refused; sealed data re-keys forward. | §8.1, §9 |
| Bad or lying clock | Never makes a version accepted: Data is judged without certificate validity periods, and the cut, not a date, ends a key; for a role listed in DataRequiresCut (guest) a reader's clock only decides when a lapsed key's versions start being refused until its cut. Under expiry it moves only that device's own retention: a slow clock holds and serves longer, a fast one drops its own copy early; a writer's clock moves only its own dates and listing; the root's clock moves only which entries the cuts it makes list, and it prints those left out. A wrong clock refuses live exchanges, loudly. | invariant 1, §8.1, §8.5, §14.1 |
| Thief writes between the theft and the revocation | Writes the root first verified before the loss time the owner states stay accepted (residual); later ones are left out of the cut and refused everywhere; once the key is marked suspected, the root takes none. | §8.1, §8.6 |
| Thief backdates or fills a gap with a revoked key | Refused wherever the revoking version is held: the cut lists names, and no date or seq outside it counts. | §8.1 |
| Thief reuses an accepted seq in another collection | Refused: the cut's ranges are per collection prefix. | §8.1 |
| Thief signs other bytes at an accepted name | Refused by every reader and forwarder under a cut with a manifest: only the bytes it lists are accepted, and in-cut versions are fetched by full name. Under a cut made before manifests, a reader holding the honest version keeps both and reports the equivocation; one holding neither may take whichever answers first (residual of old cuts). | invariant 2, §8.1, §8.6 |
| Manifest packets withheld | The versions they list stay pending, never accepted with other bytes; they are fetched from another holder. | §8.1 |
| Revocation arrives after a thief's version was accepted | On adopting the revoking context the reader withdraws it and tells every watcher; in-cut versions stay. | §8.3 |
| Issuer revoked after its keys' versions were held | On adopting the revoking context, and on restore, every held version is judged again with the whole walk; those whose chain passes the revoked issuer are withdrawn, saying an issuer refuses them (no re-admission). | §8.3 |
| Honest work outside the cut | Refused and reported with its full name and digest; the root re-admits it by exact name and digest, and every device holding or following it then applies it; no neighbour seq and no other bytes come with it. | §8.2 |
| Certificate renewed, or expired | The key's versions verify alike under the old and the new certificate, before and after either expires; the log continues. A role listed in DataRequiresCut (guest) is the exception: lapsed, its versions are refused until its cut. | §8.4, §8.5 |
| Guest's certificate lapses | Its versions are refused, fail-closed, until the root's revocation with a cut bounded at the NotAfter, which keeps what it wrote while invited. | §8.4, §8.5 |
| Device key replaced by a new enrollment | Its versions stay accepted until the owner ends it: the root's tools list it with the cut to make (bounded at the replacement's enrollment), and `ndn-fwd end-keys` revokes it with that cut. | §8.4 |
| Leaked key, certificate expired, never revoked | For a role not listed in DataRequiresCut, never replaced, its thief's versions are accepted (residual), and nothing lists it: revocation with a cut ends it. | §8.5, §8.6 |
| Copy of the device's own key writes under its name | The device takes such an entry as another writer's, never as its own at restore; its log head moves only for what it wrote, its seqs never wrap, and an entry far above its head is refused. | §8.3 |
| Root compromised | The recovery's versions carry every cut but orphans and cuts naming entries outside their key's log, may cut the keys they revoke, and, on the operator's confirmation, the new CA certifies a cut key again only for the public key its cut's digest names, so its in-cut versions keep a chain and nothing else gains one. | §8.4 |
| Node that predates cuts | Refuses every version of a revoked key, the in-cut ones too: safe, and fixed by updating. A node that knows cuts but predates manifests, key digests and DataRequiresCut keeps those residuals until updated. | trust-context.md §3.3.12 |
| Member removed mid-edit | Edits inside the removal cut merge; later ones are refused, and a reader that applied one before the cut arrived withdraws it and says so. | §6, §8 |
| Holder withholds | The summary shows what is missing; fetch from another holder. | invariant 4 |
| Holder withholds a range's blocks | A time search probes a window at once and stops a round none of whose probes answers; the read answers within its bound, listing what it did not reach `missing`. | invariant 4, §5.4 |
| Holder rolls back | A summary older than one already seen is refused, also by a reader that restarted since. | invariant 3, §7 |
| Writer never pauses | Each descent finishes against the root it started from, whose nodes the writer keeps serving; the reader then continues from there and keeps up. | §7 |
| Writer equivocates | Both versions are kept and reported. | invariant 2 |
| Old software writes | Unknown fields survive its edit. | invariant 8, §10 |
| Poisoned cache | Verification fails, or the packet is signed by another device's key or does not decode: that packet is dropped, nothing is kept against its name, and it is fetched elsewhere; the genuine copy is taken. | invariant 1, §4 |
| Stranger in a sync group | Costs a root fetch; its entries are refused `NotMember`. | §6, §12 |
| Removed reader | Refused every grant; the key of the epoch its removal starts did not exist before it, so the new epoch's versions stay closed to it; what it opened before it keeps. | §9 |
| Owner's devices edit members at once | Records of one revision merge against the parent they name, keeping every addition and removal, removals winning (by intersection when the parent is not held); a merge that leaves a removed reader in the epoch is resolved by a new record in a new epoch. | §6 |
| Group member removed | Every collection sealed to the group, of any owner, moves to a new epoch signed by a device of its own namespace. | §6 |
| Own device left out | An audience that does not list it leaves it out of the epoch and every later one; no device holds a secret that yields future keys. | §6, §9 |
| Removed writer fills a gap | A new entry at a seq below what its cut kept is refused: the cut lists exactly the versions kept. | §8 |
| Wrong key granted | Refused against the epoch's key check; the right key from any device is taken. | §9 |
| Writer behind on a seal | Its unsealed version is refused `Unsealed`; its later sealed versions do not wait for it. | §5.2, §9 |
| Relay or repository of another person | Carries ciphertext and grants wrapped to one device each; reads no payload and no key, and sees the metadata §9 lists. | §9 |
| Member offline | Its newest verified summary is what the reader is complete against; it catches up when the member returns. | §7 |
| Holder relays audits | Passes spot audits (they prove it can produce, not that it stores), but cannot make the owner release: a release asks a proof over every piece while the owner serves none of them. | §13.3, §13.4 |
| Stranger asks a holder | Dropped for the cost of a parse: only an owner device whose hold record names the holder may ask, and its asks are bounded. | §13.2, §13.3 |
| Holder hears a prune first | Its audit answer names the prune; the auditor verifies and takes it, and the piece is excused. | §13.3, §14 |
| Writer offline when an epoch is pruned | Erasure stays pending until it has left the epoch; a version it sealed in an erased epoch, arriving later, brings the key back. | §14 |
| Replayed head | A cache or holder serving an old head as fresh: never forged; refused when older than one of the same key verified or than what the reader knows of that key, also after a restart; otherwise the reader answers the verified version that head names, with an age that understates — stale, never wrong data. | invariant 3, §5.3 |
| Head served, node or newest version withheld | The head raises its key's rollback floor, but its receipt does not count; `get` answers the held version aged from the last head that named it the newest, or `Unavailable` (`RetryLater`) when a newer head was verified and none named it the newest since the reader started. | invariant 5, §5.3 |
| Forged or spliced entry | The block's signature fails; the block is dropped and fetched elsewhere; the entry is never returned. | invariant 1, §4.1 |
| Holder serves past keep | Readers drop by their own clocks, answer `Expired` and store nothing expired. | §14.1 |
| Holder claims `Expired` | Within the auditor's clock skew, or for a version kept for the last `n`: no answer, not evidence — the lease does not count for the piece and repair may ask again. For a version its writer kept `Forever`, or until beyond that skew: evidence, the lease is broken (`Breach::Expired`). | §13.3, §14.1 |
| Writer's dates go back | Its entries dated out of order may be missed by a time range; nothing it did not sign is returned. | §5.4 |
| Battery producer, many readers | Caches answer its head for its batch delay; readers' age includes it. | §5.3 |
| Writer stops, keep passes | Its newest node keeps listing what has since expired, with a bound of each `Until` keep (`Expiry`); a reader that never held such a version does not fetch it, and once its own clock passes the bound its watch stops waiting on it and applies what the writer wrote after it, without the writer writing again — at most one run's span after the keep. A seq the writer's newer node no longer lists is not waited for even if the reader never learned it. Nothing wrong is delivered. | §5.2, §7, §14.1 |
| Device lacks a collection's merge rule | It holds, verifies, serves and lists every version, applies none, and answers `RuleUnknown` (`UpdateProgram`); it never computes a state under another rule. | §5.1 |
| Operation made over a basis outside its past | Refused for good by the rule's check against `down(P(v))`, the same at every reader; later versions do not wait for it. | §5.1, §5.2 |
| Rule does not count a version | It is applied to the frontier, held, served and shown with why (`NotCounted`, `not_counted`), never dropped; when the rule counts it, watchers are told (`Counted`). | §5.2 |
| Merge version's pieces missing | It waits as a missing parent, with what depends on it, while its pieces are fetched from the writer and the holders; covered by a checkpoint held whole and checked, its pieces are never fetched. | §5.2, §13.1 |
| Member writes a bogus checkpoint | Applied alike everywhere as its writer's claim; the owner's removal cut withdraws it, and the versions it covered then apply. | §5.2, §6.2, §8 |
| Group member never arrives | The group stays incomplete: its members held and shown not counted, what depends on them waiting — stale, never wrong. | §5.5 |
| Group member refused, or group malformed | No member counts, on every reader alike; members applied before are withdrawn in every collection (`Refusal::Group`); others' versions made over them stay counted. | §5.5 |
| Narrowing concurrent with a group | Judged by the members' declared seals, alike everywhere; a reader left out finds it unreadable here and counts none of it. | §5.5, §6.2 |
| `put_group` that cannot complete | Refused before anything is signed, saying which item and why. | §5.5 |
| Group member pruned or expired | It counts as present for its group's verdict: the group counts once every other member is present, and nothing counted is uncounted by the prune or expiry. | §5.5, §14, §14.1 |
| Reader removed at folder level | One new folder epoch for every inheriting collection; collections in their own epoch listing the reader move to new epochs of their own. | §6.1, §9 |
| Collection record wider than its folder | `share` refuses it; one signed anyway widens nothing: every reader intersects the levels. | §6.1 |
| Release of merge pieces without a covering checkpoint proved held | Refused: the pieces are kept, saying why, and `NotHeld` when nothing is released. | §13.3 |
| Reader that predates slice 6 | Refuses folder records and group members (odd TLVs) and waits for them — stale; it applies a collection's own record alone, without a folder's narrowing, until updated. | §16.2 |

## 18. Conformance

`ndn-data-conformance` (ndn-sim) runs the study's use cases against an
implementation. Each case names the features it needs; a provider that
lacks one is reported "not implemented", naming it. The slice-1 cases are
c1 (offline notes on two devices, in the two-component namespace
`/home/bob`), c7 (an older lens keeps a newer field),
c8 (a laptop back after four months: 10,000 notes, 37 changed), c11
(citing a merged state) and o4 (a reader keeps up with a writer that never
pauses: it holds everything written before it looked, then every later
moment's versions, while the writer keeps putting and a second reader
makes it sign a new root many times a second). The slice-2 cases are c2
(Bob removed while offline: his later edit is refused whatever its date),
c4 (a note sealed to Alice opens for her host, and a device outside the
audience cannot read it), c9 (a family chat under the log rule: members'
messages reach every member, a non-member's post reaches no one), c10
(prune of another's comment refused, the removal done as an edit), o1 (a
cut that arrives after a version was accepted withdraws it), o3
(completeness with many writers, measured: a full check of every member's
summary and the catch-up of one new version, with 8 and with 32 writers),
and the slice-2 security review: r1 (two of the owner's devices remove
readers at once; neither removed reader opens what is written after), r2
(a member leaves a group another person's collection is sealed to; that
collection moves to a new epoch), r3 (the owner lists one of her devices
alone; her other device opens nothing written after) and r4 (one of the
owner's devices adds Carol while another, offline, removes Bob, both from
one record; Carol then writes and reads everywhere, Bob's later edits are
refused and he opens nothing written after).

The slice-3 cases are c5 (a photo the repo leased is pruned: no lease
outlives keep, readers report it pruned), h1 (a photo of hundreds of pieces
read whole and verified), h2 (a holder that silently lost what it leased is
caught by audit and repaired, and released data stays readable from it), h3
(a holder keeping three quarters of what it promised fails its audit), h4
(no lease outlives keep, before or after the keep passes), h5 (prune ends
leases: the holder drops what it covers, audits never ask for it), h6
(sealed data held by a device outside its audience stays unreadable to it
and readable from it), h7 (with one copy, the only holder's loss leaves the
photo kept nowhere, and `hold` reports it unkept, claiming no repair), and
from the slice-3 security review h8 (a holder that keeps nothing and
relays audits from the owner cannot make it release: the owner keeps its
copy, saying why) and h9 (a prune the holder heard before its auditor does
not frame it: its answer names the prune, and the audit passes).

The slice-4 cases are c6 (a soil sensor puts a reading a second, batched
by a minute, into a one-key collection whose one writer is the sensor's
key: signatures grow with blocks, not readings, no reading waits longer
than the delay accepted, every reading reaches the repo; signatures,
Interests, bytes and energy per reading are recorded, batched and
unbatched), s1 (a range read by time and by seq returns exactly the entries
in the range, with far fewer Interests than the stream has blocks), s2 (an
entry forged inside a block at the holder is never returned: the sensor
offline, the reader reads from the holder, and the genuine entry arrives
later), s3 (an entry spliced in from another block, likewise), s4 (after
keep passes, the holder and the reader drop the data, `get` answers
`Expired`, watch reports it, a range read lists it expired; a holder whose
slow clock still serves it does not make a right-clock reader keep it),
s5 (a replayed old head, the sensor offline, does not make `get(C)` answer
a version older than one already verified) and s6 (a stopped stream: the
sensor writes readings kept until a date, then one kept forever, and never
writes again; after the keep passes and the sensor, the repo and the
caches dropped the expired blocks, a phone that never held the stream
starts watching it and reports the reading kept forever within a bounded
time, reporting and storing none of the expired blocks).

The slice-5 cases are c3 (a stolen phone's key: the revocation cut keeps
the phone's versions from before the theft and refuses the thief's, dated
last week or not), o2 (the owner re-admits one exact version by a
root-signed trust-context version adding its name and digest), k1 (an
expired, unrevoked member key's old data still verifies at a reader whose
clock is a year ahead), k2 (a revoked key's backdated version is refused
everywhere, by a reader that joins after the revocation too, while the
versions before the cut stay readable), k3 (a re-admission by exact name
and digest admits neither a neighbouring seq nor a thief's version at the
same seq in another collection), k4 (a late revocation withdraws a thief's
version a reader accepted before the cut reached it, and keeps the in-cut
ones), k5 (a renewed certificate continues the log: old versions stay
valid after the old certificate expired) and k6 (a recovery after the
root's compromise carries the cut); c3, k2–k6 and o2 revoke with a stated
loss time (a bounded cut). The slice-5 security review adds k7, cut
bounded by the loss (the owner marks the stolen key suspected and states
the loss time; the thief's writes between the theft and the report, which
the root held before revoking, stay out of the cut, are refused at every
honest device and withdrawn where held, and the honest entries the root
first saw after the loss time are listed and re-admitted one by one); k8,
lapsed guest key (data its key signs after its certificate lapsed is
refused by readers whose clock says it lapsed; after the root's
revocation with a cut, its data from before expiry is accepted even at a
reader a year ahead, and its data after expiry stays out); k9, other
bytes at a name in the cut (a late joiner gets the honest bytes at an
in-cut name through the manifest, and the thief's other bytes at the same
name are refused, also when a forwarder on the path saw the thief's copy
first); and k10, issuer revoked later (entries of a key the old CA
certified before a compromised-root recovery, held by readers, are
withdrawn on adoption and after a restart, and an honest device's entry
from before the recovery comes back once its key is certified by the new
CA). Their features are `BoundedCut`, `GuestExpiry`, `CutManifest` and
`IssuerRecheck`.

The slice-6 cases are b1 (a custom rule on two devices: both compute the
same rule-typed value; a third device without the rule holds every version
and reports the collection unreadable, `RuleUnknown`, computing nothing),
b2 (an operation whose basis lies outside its causal past is refused at
every reader, and later versions do not wait for it), b3 (a version the
rule does not count is kept, shown with why, and later reported counted),
b4 (a 20 KiB operation and a 100 KiB checkpoint in one merge collection,
in pieces, read and applied at another device; versions the checkpoint
covers are not fetched), b5 (releasing merge pieces without a covering
checkpoint proved held by audited holders is refused, saying why), g1 (a
group counted all or none on arrival, and withdrawn whole when one member
is refused), g2 (`put_group` refuses a group that could not complete,
writing nothing), g3 (a group judged the same at every reader despite a
concurrent narrowing of one of its collections), f1 (a folder of 1,000
collections: a reader asks one grant per folder epoch, not one per
collection) and f2 (narrowing a collection under a folder works; widening
it is refused, and a widening record signed anyway has no effect). Their
features are `RuleByName`, `AppOps`, `MergePieces`, `Groups` and
`FolderMembers`.
