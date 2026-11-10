# Data layer: named, signed, versioned data

- **Status:** Slices 1–6 normative, with the durability barrier (§4.2:
  nothing published before it is on disk) (slice 6, the substrate for ndf-rs, B
  and C: merge rules by exact versioned name and the rule interface,
  operations the application builds, versions held but not counted,
  checkpoints covering by frontier, pieces in merge collections and the
  release of merge pieces only on an audited covering checkpoint, groups
  of versions counted all or none, folder members records narrowing every
  collection under a folder with one seal epoch per folder epoch, and
  joining a folder by a code (introductions, §19), §5.1,
  §5.2, §5.5, §6.1, §6.2, §9, §13, §15, §16, §19); slice 5: a revoked key's versions kept
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
   back, a power loss included: a device publishes only what is durable
   (§4.2). A reader MUST refuse a summary or members record older than one
   it has seen from the same signer, also after the reader restarts.
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
  hierarchical trust schema, so it is the person data belongs to. A
  person's **self-certifying namespace** `/user/<h>` (`<h>` a component of
  type `0xA1`, 32 octets: SHA-256 of the Ed25519 key that signed its
  context's version 1, trust-context.md §4.5) is a namespace like any
  other here: its collections are `/user/<h>/32=data/<path>`, its devices
  `/user/<h>/<role>/<device>`, and members records, folders, seals and
  introductions name it as they name `/alice`. A device adopts it by its
  name alone (trust-context.md §4.5.3).
- A **collection name** is `<O>/32=data/<path>`: the namespace, the
  KeywordNameComponent `data` (the **marker**, which says where `O` ends),
  and a path of one or more components. No component of it besides the
  marker is a KeywordNameComponent or a digest component: keyword
  components mark the layer's own names (§16.1). A **folder** is
  `<O>/32=data/<path>` with a path that other collections extend, and
  `<O>/32=data` is the folder of every collection of `O`. The **owner** of
  collection `C` is its namespace, the components before its marker.
- `put`, `get`, `share` and `snapshot` take collection names; `watch` takes
  a collection or folder name (`<O>/32=data[/<path>]`): a folder's watch is
  one stream for every collection under it, those created after it began
  included, each change tagged with its collection (§15). A verb given a name
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
  is its longest prefix; a name no held context governs has none. A name
  under `/user/<h>` is governed only by `/user/<h>`'s own context, never by
  a held `/user` or `/` (trust-context.md §6.1): without `/user/<h>` held it
  has none. A
  device that writes into or reads another person's collections holds that
  person's trust context — it verifies their entries with it — so the
  person's namespace is held wherever their data is used. Holding it is
  the person's gesture of pointing at someone (adopting their anchor
  link); nothing else names people, with one exception: a self-certifying
  writer an owner-signed members record lists is adopted by name for that
  record's subject alone (§6.3) — the owner's gesture, judging the
  writer's data there and nowhere else, and making it the namespace of no
  name here.
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
- Two different entries of one key at one seq — in one collection or in
  two, of one kind or of two — are **equivocation** (invariant 2). A reader
  holding both keeps both and reports `Change::Equivocation` to the
  watchers of each collection when both are versions — to each
  collection's watchers its own version whole and the other collection's
  by name and id only (`Equivocal::Elsewhere`), never its content or
  anything opened of it, so a watch of one folder learns nothing of
  another folder's content — and lists it to every watch begun later
  while both are held, across restarts too: two packets at one name keep
  the second in the store beside the first (ndn-data: under
  `/localhost/ndn-data/equivocal/<log entry name>`, one per name), stored
  before it is reported; a group of the key
  over that seq is malformed (§5.5). A cut accepts a seq only in the
  collection it lists it under (§6.1, §8, §8.1), so a removed or revoked
  key gains nothing by signing an accepted seq again elsewhere. An entry
  the trust context refuses (§8.1) is no evidence against its key: a copy
  of a revoked key wrote it.
- Parents are the frontier (writer → highest seq) of the collection's state
  the writer had applied when it wrote (§5.2), each **tip** `(y, t)` bound
  to the implicit digest of `y`'s packet at `t` (`Digest` in its
  `FrontierEntry`, §16.2). A seq alone names a packet that may not exist
  yet; a digest only a writer that held the packet can name. In a merge
  collection every parent carries one; under the log and one-key rules a
  writer names it when it holds the tip (an expired tip goes without).
- A merge version names the rule its operation was made for (`Rule`,
  §16.2); a reader applies it only under that rule (§5.1).
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

### 4.2 Durability before publication — durability barrier

A device publishes only what is on disk. Otherwise a power loss takes an
entry its peers already hold, the device signs again at that seq after it
restarts, and an honest writer has equivocated (invariant 2).

- **The store's barrier.** A device keeps its log in a store with a
  durability barrier (`DataStore::sync`): it returns once every write that
  returned before it survives a power loss, or with the error saying why it
  may not. Each store instance keeps, on its own: a write that returned
  survives the process being killed; a write before a returned barrier
  survives a power loss; after a power loss the store opens at a whole
  state at or after its last returned barrier — never part of a write —
  and a torn tail rolls back without error and without refusing to open.
  A process may open several stores (a device's, and a program's own local
  one); nothing ties one to another.
- **The durable head.** A device's durable head is the highest seq `h` such
  that every entry of its own log up to `h` was stored before a barrier
  that returned. A device MUST NOT publish what names or lists anything of
  its own log above its durable head. It MUST NOT:
  - serve an own log entry, or a piece of an own version, above it;
  - serve a summary root, node or page, or a one-key head, listing
    anything above it: what it serves of its summary and heads is what the
    log up to its durable head fixes (§5.3, §7);
  - announce in a sync group (§12) before the entries the announcement
    covers are durable; the counter it announces is itself stored before,
    and durable when it goes out;
  - grant the key of an epoch it started before the record starting the
    epoch is durable (§9);
  - ask a holder to hold under a hold record that is not durable, answer a
    hold ask with a lease before the lease is durable, or answer an audit
    ask before what it answers from is durable (§13.2, §13.3).
- **Local application is immediate.** `put`, `put_op` and `put_group` return
  once the entry is signed, stored and applied; the device reads its own
  writes at once and refuses nothing for the disk. Only publication waits.
- **Group commit, bounded delay.** A device flushes its store once per
  round for everything written since the last round began, so many puts
  share one flush; an entry is published at most two flushes after its
  `put` returned. A flush that fails publishes nothing: the device says why,
  keeps reading and writing locally, and asks again later, until the flush
  succeeds or the device stops.
- **At start.** What the store holds may be only in the operating system's
  buffers (a run killed before its flush). The device makes it durable
  before publishing any of it; a store that cannot refuses the start
  (`Local`, `FixLocal`), saying why.
- **Positions after a restart.** The log head after a restart is the
  highest own entry the store holds (§8.3), at or above the durable head of
  the run before, so a restarted device never signs again at a seq it
  published. A one-key head states the batch delay of the newest version it
  lists, stored with that version, so one head name is one packet across a
  restart (§5.3); a summary's content is fixed by the log up to its head
  (§7); a group counter is durable before it is announced (§12).

Why this suffices: each engine recovers to a prefix of its writes (fjall
replays its journal to its last whole batch; each redb write is its own
transaction, committed with fsync), so after a power loss the store is as
it was at some moment at or after its last returned barrier, and a device
restarted on it is that device stopped at that moment — which restore
already handles (§8.3). Everything it published was at or below the
durable head, so behind the barrier, so held.

**Threat notes.**

- A disk or filesystem that acknowledges a flush it did not make (a write
  cache without power-loss protection, a virtual disk with unsafe caching,
  some removable media) defeats the barrier: a power loss can then still
  make an honest device equivocate. Readers treat that as any equivocation
  (invariant 2, `Change::Equivocation`); it is a residual of such hardware.
- A store that keeps nothing across a restart (an in-memory store) reports
  every write durable at once, and keeps nothing: a device on one starts
  again with an empty log and signs from seq 1 under the same key. It is
  for tests and identities that never restart.
- A process killed without a power loss loses nothing that returned; the
  restarted device flushes it before publishing it.
- A program's own unsigned state (an editor's transaction log) belongs in a
  store of its own, not the device's: the device serves from its store
  only, so nothing in another store reaches the network by a naming slip.

## 5. Collection and rule — slices 1, 2, 4 (one key), 6 (rules by name, groups)

A collection is a named, growing set of versions with a rule and a members
record. It exists when its first members record is signed (§6): `share`, or
a writer's first `put` (`put_op`, `put_group`) into a collection of its own
namespace (§3), which signs the host's default record (merge with
`/merge/yrs`, the namespace writing and reading, sealed to it). A collection
under a folder whose members record is in force exists with that record
(§6.1): `put` into it writes under its effective record and signs no
default record.

- **The default record comes with the first version.** The first version
  is signed and judged by the rule on the state the default record starts
  before the record is signed; the record and the version are kept
  together, at consecutive seqs, or neither is. A first write the rule
  refuses, or too large, leaves no record behind.
- **Only once nothing held elsewhere governs it.** A default record narrows
  the collection for good (its writers and readers are the namespace's
  only, its rule `/merge/yrs`), even under a folder whose record this
  device does not hold yet. So a device signs it only once it has walked
  the summary of every other device of its namespace it knows of — heard
  in its group, or whose summary it verified before, in this run or an
  earlier one: walked in full since it last followed something new there,
  or walked in full up to the newest root it knows of that device, in this
  run or an earlier one, while following a name in the collection's
  folder or a folder above it. A walk takes the folder records above what
  it goes toward only (§6.1, Sync), so one that went toward other folders
  says nothing of this one; the head of each root walked in full is kept
  with the names it went toward, so a device merely offline since such a
  walk does not hold anything back. Nor does a device ended here — a key
  of it marked suspected, or revoked by the trust context governing it
  (§8.1): what it holds is not taken anyway —, nor one nothing signed held
  here vouches for (§13.5: no root of it verified, in this run or an
  earlier one, no version of it applied, no lease, hold or members record
  naming it) once its walks spent their tries with no root of it verified
  — `REFRESH_TRIES` (16) walks of one refresh loop (§17.1) whose root's
  rounds all missed, or no trust context held judges its roots and no
  record held lists its person (§6.3) —: a name a Sync Interest carried,
  or a device never reached, gives no reason to wait, and holds this back
  for those tries at most (a few minutes), however many notices of it come;
  a real device a faulty path kept from a walk or a few is still waited
  for (round 3; before, one unsigned Sync Interest naming a device that
  does not exist held `put`, `get` and folder erasure here until restart).
  Each one not
  walked is refreshed once more, for at most the first-look time. Until
  then `put` answers `NotReady` (next step `RetryLater`), naming each
  device it waits for and what to do — bring it online, or, if it is
  lost, mark its key suspected or revoke it — and signs nothing. So it
  does, saying so, when the
  collection holds versions that wait for a record: they were written
  under one this device does not hold. A device that knows no other device
  of its namespace signs it at once.

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
state for the local writer (ndn-data: `MergeRule::start(collection,
local)`, `MergeState`); the layer passes the collection's name, so the
state knows whose collection it is. The layer hands the state each
operation as an `Op`: the version's id
`(w, s)` — its writer, one key, and its seq —, the implicit digest of its
packet (SHA-256 of the whole Data packet: the version's content address),
its parents, its **past**, the `MergeOp` octets and — round 3 — its
**signed date** (`Dated`, §4.1: its writer's clock when it signed). The past
is exactly `down(P(v))` (§5.2): the rule asks it whether a version id lies
inside it, and which version of `C` inside it, held here, has a given
implicit digest. The date is the very value the version's signature
covers, so every reader sees the same one: a rule that orders by time
(ndf's "latest wins") reads it rather than a time its operation carries
beside it. It is a writer's claim, as everywhere in the layer (display
only, §4.1): a rule MAY order by it only where its order is bounded by the
past (a version never loses to one made over it), never let it decide a
check, and MUST treat it as any other field of the operation — the same
on every reader.

- **Owners** (ndn-data: `merge::owns(collection, writer)`). A writer `w`
  (key `<D>/KEY/<k>`) is an **owner device** of `C` exactly when `D` lies
  under `C`'s namespace, the components before its marker (§3). It depends
  on the two names alone, so every member answers alike in any order; the
  layer's owner rule (§3) asks this same test, together with the trust
  context governing the record. A device of a longer held namespace (§3:
  a `/home/bob` device for `/home/32=data/x`) is not distinguishable from
  names alone: `owns` answers the name half — what a reader holding `C`'s
  namespace and none longer under it concludes. A revoked owner device,
  or one outside a cut, needs no handling by a rule: its versions refused
  by their key never reach apply (§5.2, §8).
- **Edit** (`put` with fields) makes the local writer's edit into an
  operation; the layer then checks and applies that operation as any other.
  A rule whose edit already changed its state MUST make that apply
  idempotent (`/merge/yrs`: applying an update already integrated changes
  nothing). A write refused after the edit — too large (`TooLarge`),
  refused by the check, or failing to apply to the writer's own state —
  leaves no trace: nothing is signed, and
  the layer reads the collection again from its versions (§8), so the edit
  is not in the writer's state either. A rule that takes only operations
  the application builds refuses edits, saying so, and `put` answers
  `BadRequest` (next step `FixRequest`: build the operation and use
  `put_op`).
- **Check** says whether the operation is one its writer may have made:
  nothing in it outside its writer's identity, and nothing it is made over
  outside its past. It answers the operation's kind — an **edit** or a
  **checkpoint** (§5.2) — or refuses it for good with a reason. Its answer
  MUST depend on the `Op` alone — never on versions concurrent to it, on
  the device or on a clock — so every reader decides alike.
- **Apply** folds a checked operation into the state and answers
  **counted** (it is in the value) or **not counted** with a reason (it is
  held, applied to the frontier and shown, and not in the value, §5.2).
  Every reason in the operation itself is the check's; apply meets the
  state, which other writers' versions make, so an exclusion that depends
  on it is not counted — never a refusal, which would let one writer
  withdraw another's version and its group. An apply that fails MUST leave
  the state as it was before it; the layer keeps the version applied and
  not counted, with the reason (an own operation that fails is not
  written).
- **Basis** (ndn-data: `MergeState::basis`, round 3) hands the state a
  version a checkpoint applied here covers, which a version not covered
  was made over (§5.2, covered versions as a basis): it is what that
  version is merged against, never applied, counted, told or shown. A rule
  that keeps no history of its own needs none, and ignores it.
- **Made for one rule.** A merge version names the rule its operation was
  made for. A reader refuses one that names another rule than the one in
  force, or none — unless it lies inside the record's `since` (history) —
  for good (`Refusal::OtherRule`, next step `None`: its writer, once it has
  the record naming the new rule, writes the change again under it). A
  stale writer's operation is never read under a rule it was not made for.
- **Counting is a function of the applied set.** Whether a version
  counts MUST be a pure function of the set of versions of `C` that passed
  check and were applied (each with its past), never of their arrival
  order: two devices holding the same applied set count the same versions,
  with the same reasons. As the set grows a version's counting may start
  or stop (a lock arriving after a write made apart from it). **Counting
  changed** (ndn-data: `counting_changed`) lists, since it was last asked,
  every applied version other than the one just applied whose counting
  changed, with how it counts now; the layer asks after every apply and
  tells each change (`Change::Counted`, `Change::NotCounted` with the
  rule's reason unchanged), and the state's `not_counted` follows.
- **Value** is the merged value, typed by the rule: named fields (what
  `/merge/yrs` merges into), or the rule's own encoding, which the program
  defining the rule decodes. The layer passes the applied versions it holds
  back (members of a group waiting on another member, §5.5, and versions
  covered only by checkpoints the rule does not count, §5.2); the value
  leaves them out, while the rule's counting of every version still sees
  them (the layer's holding back never feeds back into the rule).
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
name, and a reader MUST refuse an operation that carries content (items or
garbage-collected ranges) under any other client id, or that places an
item against (left or right origin, parent item) or deletes an id of
another client at or past the clock that client's writer had reached in
the operation's past (its parents, and its writer's previous version):
that is its check — an update reaches only content its writer held — and
every operation is an edit, which its apply counts. A Yjs peer may
therefore apply the same updates (it sees
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
- A version the rule's check refuses is refused for good for what it
  carries: kept against its name with the reason (`Refused`,
  `Refusal::Rule`), never applied, and never waited for (1. above). Only
  the check refuses: an apply that fails leaves the state unchanged, and
  the version is applied and not counted, with the reason (§5.1) — what
  the state makes impossible is no refusal.
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
- **Parents bound to packets.** Before a merge version applies — an edit
  ready, or a checkpoint whose past is held — each parent `(y, t)` that
  applies at all is checked against the packet held at `(y, t)`: it waits
  while none is held, and is refused for good (`Refusal::Parent`, next step
  `None`) when the parent carries no digest or the packet held there has
  another digest. A mismatch means the version was not made over what this
  reader holds: its writer named a packet that does not exist, or `y`
  signed two packets at `t` (an equivocation; readers holding different
  packets at `(y, t)` differ there already). Every reader holding the same
  packets decides alike, in any arrival order and with no clock. A
  checkpoint whose parent never applies here (a cut, a revocation, a
  refusal for what it carries) is refused likewise: it cannot stand for
  what lies below a version that does not apply.
- Applying it, the layer applies it to the rule, then raises `at` to
  `P(CP)` writer by writer (`at[w] = max(at[w], P(CP)[w])`) — each parent
  held as the packet it names, so a checkpoint covers only what its writer
  applied. Every waiting version now inside `at` is **covered**: held,
  stored, delivered as a version, and never applied to the rule nor
  checked (it reaches the rule only as a basis, below). A version arriving
  later inside `at` is covered likewise. A
  checkpoint planted in a log a removal cut later accepts gains nothing:
  the same check applies to it.
- The rule MUST make applying `CP` yield the state of `down(P(CP))` with
  `CP`, plus the versions concurrent to it already applied, whichever
  subset of `down(P(CP))` it applied before.
- **A checkpoint stands alone for what it covers — round 3.** A rule's
  state after applying a checkpoint MUST NOT depend on whether the versions
  it covers were applied before it: its value, which versions it counts
  and why, and whatever it keeps (locks, alternatives, heads) are the same
  on a device that applied `V1..Vn` before `CP` and on one that applied
  `CP` first and never fetched them, for `CP` and for every version
  applied after it, given the same bases (below). Applying `CP`, the rule
  drops every version `CP` covers from its applied set: a covered version
  counts for nothing on its own — it writes nothing into the value, takes
  and lifts no lock, is no head and no alternative of a conflict — and no
  version is judged against it, except as what a version written apart
  from the checkpoint was made over (below). A version written apart from
  `CP` over some of `V1..Vn` is then counted alike, for the same reason,
  on both devices (conformance `b8`).
- **Covered versions as a basis — round 3.** A version `W` that no
  checkpoint applied here covers may be made over versions one covers:
  its writer worked apart from the checkpoint. A rule merges `W` exactly
  only against what it was made over, so before `W` applies the reader
  hands the rule `W`'s **basis** (`MergeState::basis`, §5.1): every
  version inside the cover of a checkpoint applied here that lies in
  `down(P(W))` and in no `down(P(K))` of a checkpoint `K` applied here
  inside `down(P(W))` — and, of each of those, its own basis by the same
  rule — that the rule does not hold yet. A version the rule applied before
  a checkpoint covered it serves as a basis as it is; nothing is handed
  twice. Each is taken from what the reader holds:
  - held whole — its operation inline in its record, which a reader holds
    before it applies the checkpoint (above), or its pieces held — it is
    opened, checked (one the check refuses is not handed: the check
    answers from the `Op` alone, alike on every reader) and handed as an
    `Op` with its own past;
  - in pieces not held, its pieces are fetched from any holder (§13.1:
    its writer, each holder of a live lease, each device whose version
    held here is made over it — `W`'s writer among them, which applied it
    whole before it wrote `W` — and any device holding it), and `W` waits
    for them as for a parent's pieces — but for its whole basis set at
    most one budget of missed asks: once 16 asks for the bases `W` waits
    for missed, counted over all of them together (each with the
    missed-fetch backoff of §17.1), `W` applies without the ones still
    missing — one lost packet is no evidence they are gone — and they are
    still fetched, and handed whenever they arrive; a basis whose last 16
    asks in a row missed already is not waited for (round 3, review L5:
    counted per basis, a `W` over a wide covered past waited 16 asks for
    each batch of 16 bases, the next fetched only as one ended);
  - held sealed in an epoch whose key the reader does not hold, it is
    handed once the key arrives, and `W` does not wait for it.

  The rule takes a basis only as what the versions made over it were made
  over: it MUST NOT count it, list it in `counting_changed` or show it,
  and handing it changes nothing else. Its state is a function of the
  versions applied that no checkpoint covers (each with its past) and of
  the basis held for them: a basis handed after the versions made over it
  MUST give the state handing it before gives — what was made over it
  merges again, and the counting that moves is told (`counting_changed`).
  When a basis handed after the versions made over it changes the value
  (`MergeState::value`), the collection's watchers are told
  `Change::Remerged` with the collection and the bases handed (§15),
  whatever their frontier: no version arrives with the change, so without
  it a host showing the value would not know to read it again. A basis
  that leaves the value as it was is not told.
  So `W` merges exactly on every device that holds its basis or can fetch
  it: the reference rule replaces with `W`'s edit what the checkpoint
  restated of what `W` was made over, and keeps what the checkpoint
  changed beside (conformance `b9`).
- **When a basis is gone.** Given no basis for a version `W` was made
  over, a rule merges `W` against the checkpoint's state alone: its
  conflict handling (the reference rule keeps `W`'s edit as an alternative
  beside the checkpoint's statement; ndf's turns an edit that no longer
  fits into a conflict carrying its words). This happens only after a
  release. A merge collection is never pruned nor expired (§14, §14.1),
  and a version's record — an inline operation with it — is never
  released; only a large version's chunks leave a device, by release
  (§13.3), which drops a device's own copy only once a covering checkpoint
  is proved held, and never drops the basis of a version held there (§13.3,
  step 6). `W`'s writer applied `W`'s basis whole and serves it, as does
  every device that merged `W` exactly (§13.1). A basis is therefore gone
  everywhere only once every device that held it whole released it, and a
  reader knows it as it knows a missing piece: every holder it asks
  answers without it, ask after ask (16 in a row, above). Every reader
  then merges `W` without it alike; one
  that finds it again (a holder returning) hands it, and its state moves
  to the exact merge, with every other reader's as they find it too; its
  watchers are told `Change::Remerged` when the value moved.
- **Bound — round 3.** `W`'s writer chooses `P(W)`, so it chooses what
  readers fetch as a basis: at most the versions inside the cover in
  `down(P(W))` — signed versions of `C` that exist, each bound to its
  packet by the parents' digests above and carrying at most `PAYLOAD_MAX`
  (§13.1) — each fetched once per device and held after; at most 16 basis
  versions of one collection are fetched at once (ndn-data:
  `BASIS_FETCHES`), the next as one ends; and only for a version admitted
  (signed by a key the record in force names a writer, §8). However many
  bases `W` names, it waits for them at most 16 missed asks in all
  (above): what it names delays its own exact merge, never its applying.

  **Threat note.** A member who writes over a frontier deep in the
  history a checkpoint covers makes every reader that applied the
  checkpoint first fetch and hold that history again — what a reader that
  joined before the checkpoint fetched anyway, and no more: nothing outside
  `C`, nothing its writer did not sign, nothing a reader does not verify
  through the manifest. It cannot make a reader count a covered version,
  nor change how any version counts beyond what an exact merge against its
  own past gives. A holder withholding a basis delays the exact merge on
  readers that can ask only it, as a withheld piece delays any version; it
  cannot make readers differ once the basis reaches them.
- **Newest first; what it covers counts as it counts.** In each pass a
  reader first applies, if one is pending and its past is held, the newest
  checkpoint (by its writer's seq), then what became ready; so a
  collection read anew from its versions applies its newest checkpoint and
  what came after it, whatever order they were held in. A version inside
  the cover of a checkpoint applied here (its `P(CP)`) counts exactly when
  a checkpoint covering it counts: one no other checkpoint applied covers
  counts as its rule counts it, one covered by others as this same test
  says (a covered checkpoint is never applied by a collection read anew
  from its newest checkpoint, so only uncovered ones decide). Covered by a
  checkpoint that counts, a version leaves `not_counted`
  (`Change::Counted` if it was told not counted); covered only by
  checkpoints the rule does not count, it is not counted — listed in
  `not_counted` with the reason ("covered by the checkpoint `<key>` seq
  `<s>`, which its rule does not count: `<the rule's reason>`"), told
  `Change::NotCounted`, and left out of the value (the layer passes it
  back to the rule's value as held back, §5.1), whether the rule applied it
  before or never. It follows its checkpoints' counting as
  `counting_changed` moves it, told each time it changes; what the rule
  says of the covered version itself is not told. The state, value and
  `not_counted` are then the same whether a covered version was applied
  before its checkpoint or never, and after a restart. A rule that would
  not count a checkpoint should rather refuse it in its check: a
  checkpoint not counted takes everything it covers out of the value.
- A reader MUST NOT fetch the pieces (§13.1) of a version covered by a
  checkpoint it holds whole and checked, unless it is the basis of a
  version that no checkpoint applied here covers (above). Release (§13.3)
  counts only a checkpoint applied here.
- **The past every reader sees.** `down(P)` holds the versions at or
  below `P` not refused by their key (a cut that does not list them, a key
  no writer, a revocation, an issuer no longer trusted): `Past::contains`
  and `Past::by_digest` answer from those held — admitted, held sealed, or
  held and refused for what they carry or for their group, which every
  reader holds before it judges a version over them. A version refused by
  its key is in no past, held here or not (a late reader never fetches
  it): a rule finds no basis there and judges the operation as one whose
  basis is outside its past (it refuses it, or counts it without that
  basis, as it defines).

**Merge state across restarts: built lazily — slice 6.** A merge
collection's state is a function of the signed versions held (above), so
a device need not build it at start; it builds it on first need, and the
state it builds is the one it had before the restart.

- **What start restores.** What the device needs to publish and judge:
  its log and summaries, heads, records (members, holds, leases, prunes,
  cuts, introductions), groups, refusals, equivocation evidence, and per
  merge collection the index of the versions its store holds (ndn-data:
  `Coll::dormant`, each writer's seqs and the writers their parents name).
  No merge state is built then.
- **What builds a state.** A `get` of the collection, of a state name,
  version or entry of it; a `watch` of it; a `watch` of a folder over it,
  only when the collection holds a version past the watch's `since` (one
  to list — a collection wholly inside `since` stays unbuilt, and what
  arrives later builds it); `put`, `put_op` or `put_group` into it; `hold`
  or `release` of it; a version arriving for it; a group with a member in
  it being judged; a new members record over it; a revocation of a key
  that wrote in it.
- **The build.** It loads the collection's versions from the store and
  applies them by the rules above — its newest checkpoint first, then the
  versions after it — so its state, frontier, value, `not_counted` and
  every verdict are those it had before the restart: each a function of
  the signed versions held, never of timing.
- **Nothing more persisted.** The store holds, of other writers, only
  versions applied here (stored as they apply), and of this device every
  version it wrote; a check's verdict is a function of the operation
  alone, so refused versions, not stored, are fetched and refused again
  alike.
- **Until built,** the collection serves what its store holds of it as
  applied (§13.1). A collection nobody touches costs its index entries
  only.

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
  Each round probes the seq it guessed. A probe not answered — every ask
  of it missed, lost on the way or refused as not verifying (§17.1) — is
  asked again in place, after the pause of §17.1, up to `SEARCH_TRIES`
  probes of the seq, before the round looks anywhere else: loss costs a
  search time, never other versions. Only a guess none of those probes
  reached widens the round: it probes at once the nearest two others of
  the interval not yet probed (`SEARCH_WIDEN`), each asked again in place
  alike, then twice as many each time none of them answers, up to the
  reader's fetch window, and goes on from the nearest that answers; when a
  window of them answers none, the rest of the interval is not probed: it
  is taken into the range and its versions are reported `missing`. A
  search's cost is counted in distinct versions probed, not Interests:
  asking a version again adds Interests and time, never a version. A
  version it knows expired is placed by the dates its tombstone keeps
  (§14.1); a version in pieces, by its `Dated`. It then fetches the
  versions between, a window at once, each one not answered asked again
  in place after the pause of §17.1 until the bound below, and keeps the
  entries in range. A range read probes its versions within a bound the
  reader sets,
  counted from when it holds the node listing them — the records and the
  head have bounds of their own (§15, §17.1), so a slow path to them does
  not eat the probes' time. In this implementation the bound is eight
  looks (`RANGE_LOOKS`), each the first-look time or four of the device's
  retransmission timeouts (`RANGE_RTOS` · `RTO`, §17.1, once a round trip
  was measured; the first-look time alone before), whichever is
  longer: a search probes one version a round, so the bound covers as many
  rounds on a path whose round trips near the lifetime as on a fast one.
  As `RTO` never exceeds the lifetime, the bound is at most
  `RANGE_LOOKS` · max(first look, `RANGE_RTOS` · lifetime) — 64 s with the
  defaults — however slow or hostile the path:
  versions it has not reached by then
  are reported `missing`, so withheld or unreachable blocks cost it time,
  never more than the bound. The cost is the head, the node, `O(log n)`
  probes (two or three for a steady stream, where interpolation lands near
  the answer) when probes answer — a lost probe is asked again at no cost
  in versions; a guess no ask reaches adds probes in steps of two, four, …
  up to a window, each step run at once — and the versions in the range.
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
  `count`, `1 ≤ count ≤ 65,536` (`GROUP_MAX`, as many seqs as a summary
  node lists, §7; a chosen bound, not a limit of the design). The group `(w, id)` is
  exactly `w`'s versions at seqs `id` to `id + count − 1`, consecutive, one
  per collection and one per seq, all in collections of one folder — the
  same parent name, every component but the last — all declaring one
  `Seal`, and all kept `Forever` (until pruned): a member that expired
  would leave a reader that never held it unable to tell the group
  complete (§14.1).
- **A reader's memory.** While a group waits — incomplete, or for a key, an
  audience or a keep — a reader keeps each member it holds whole and
  opened in its store, not in memory (ndn-data: under
  `/localhost/ndn-data/parked/<log entry name>`), and in memory only what
  judging the group reads of it: its id, name, keep, declared seal and
  epoch. The member is listed not counted with why as before. Once the
  group is complete or refused its members are loaded and applied, or
  refused, together. A stalled group so costs a reader that index per
  member, not the members. A parked member is not applied, yet it was
  verified as it was parked, so it is kept across a restart: read back from
  its parked copy at start as any held entry, it parks again while its
  group waits, and a stalled group is never fetched again for it. Its seq
  is noted again as it is read back, so an equivocation it is part of is
  kept and reported after the restart too (§4). A
  member in pieces not held whole stays in memory while its pieces are
  fetched, so does a member held sealed that this device cannot open (no
  key of its epoch held, §9), and so does a member of a collection held
  for its owner (§13.2): a holder keeps, audits and leases exactly what it
  holds.
- **Writing.** `put_group` (§15) signs its items under one lock at
  consecutive seqs of the device's log, each carrying the group; no other
  entry of that log comes between them. It refuses, and writes nothing — no
  version signed, no seq taken, nothing published — when there are no
  items or more than `GROUP_MAX`, a collection appears twice, the
  collections are not all of one folder, the records in force of the
  collections list different readers (one was narrowed, say: a reader of
  one could then never complete the group), `batch` is set, `keep` is not
  `Forever`, or the rule of an item's collection refuses its operation:
  `BadRequest`, saying which item and why (next step `FixRequest`). When a
  collection's rule is unknown here it answers `RuleUnknown` (§5.1), and
  when a collection is not writable by this device, that collection's own
  error, unchanged; again nothing is written.
- **Verdict.** A reader judges each group `(w, id)` from what every reader
  of the group's folder holds alike: the group's own signed versions and
  their admission, the entries and listings `w` signed in the folder's
  collections, and the audiences of the epochs its members are sealed in:
  - **Malformed** — refused for good: a member's seq outside `id` to
    `id + count − 1`, members disagreeing on `count`, members in
    collections of different parents, two members in one collection,
    members whose declared `Seal`s differ as sets, sealed and unsealed
    members together, or two entries of `w` at one seq of the group in
    collections of its folder (equivocation, §4). An entry of `w` at a seq
    counts here when it is held kept `Forever`, or known (held, or listed
    by a node of `w` the reader verified, ever) and covered by `w`'s prune
    record, or known in a merge collection (whose nodes list every entry):
    what every reader following the folder learns from `w`'s signed nodes
    and fetches. Evidence once taken is kept: a node that later stops
    listing an entry — its writer's store lost it, say — takes nothing
    back. An entry outside the folder, or kept for its last `n` or until a
    date — which leaves `w`'s listing, so a reader starting later never
    learns of it — is not evidence against the group; cuts accept a seq
    only in its collection (§6.1, §8), so such an entry gains its writer
    nothing. An absent listing is never evidence: what an honest writer's
    node stops listing may be listed, and fetched, again (§7).
  - **Refused** — a member is refused for good: by the record in force of
    its collection (`NotMember`, `OutsideCut`, §6, §8), by a revocation cut
    or an untrusted chain (§8.1, §8.3), `Unsealed` (§9), by its rule's
    check (§5.2; an apply that fails only leaves its member not counted),
    or because the group is malformed. Then no member ever
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
  - **Not covered** — the members' epochs do not all admit the same
    readers: some epoch's audience, as the records held here name it
    (every reader a record naming the epoch lists, and the device that
    started it, §9), does not admit a reader listed by another member's
    epoch (epoch creators aside). A reader could then open some members
    and never others. No member counts, at any reader: each is reported
    not counted ("group waits: … sealed in the epoch …, whose readers do
    not include …; it counts once the owner adds them to that epoch"), and
    versions that depend on a member wait. A record that only adds
    readers keeps its epoch (§6), so audiences only grow: the group
    counts, at every reader alike, once records admitting them are held
    and the keys granted. The requirement comes from the epochs used,
    never from the seal the writer declares.
  - **Never counted** — a member is kept otherwise than `Forever`: no
    member counts and none is refused, at any reader; each waits, reported
    not counted ("group never counts: … kept …"), and versions that depend
    on a member — its writer's later versions in those collections among
    them — wait. A reader that never learns of that member (it left its
    writer's listing) finds the group incomplete and waits alike, so no
    reader applies what follows it and no honest writer builds on it: only
    the misbehaving writer's own later versions are held back.
  - **Unreadable here** — a member is held sealed and this device cannot
    open it: no member is shown — none delivered as a version, none in a
    value — each is reported not counted ("group not readable here"), and
    versions that depend on a member wait (stale).
  - **Incomplete** — fewer than `count` members are present: held,
    admitted and whole (one in pieces: every piece held, below), or known
    pruned (below). Each
    held member waits, reported not counted ("group incomplete: k of n"),
    and versions that depend on one wait.
  - **Complete** — all `count` members are present, and each held one is
    ready (§5.2), a dependency on another member of the group counting as
    met: all held members are applied together, across their collections,
    in seq order.
- **Pruned members.** A member this reader knows pruned (§14) — held
  before or not — counts as present for its group's verdict: prune is its
  writer's own retention, never a refusal, and every reader knows it alike
  from the signed prune record and the writer's summary, which keeps
  listing what it pruned. The group counts once every other member is
  present, and nothing counted is uncounted by a prune. Expiry has no such
  evidence for a reader that never held the member — the writer's node
  stops listing it — which is why a group with a member that may expire
  never counts.
- **Members in pieces.** A member whose payload travels in pieces (§13.1)
  is present once its record is admitted and every piece is held here —
  whether or not it is opened yet. It is opened (and, sealed, unsealed) as
  it applies, which only the group's verdict lets it do: a reader that
  required it opened before counting it present would wait for its group
  while the group waits for it, and the group would never count (ndf's
  report: a 37,847-octet operation in a group of three). A member whose
  pieces turn out not to open is refused (`BadSignature`, its writer
  signed what does not decode), and its group with it. The same holds for
  the writer's own device: what it applied in pieces is let go from memory
  (§13.1), so when it reads a collection again — a new members record, a
  re-admission, a revocation — its own members are pending and unopened,
  present by their pieces held, and its group counts again whole.
- A device holding a member of an incomplete group follows the member's
  folder (its parent name, §12), so that the others arrive.
- **A group counts only while every member counts.** While a member
  applied here is not counted — its rule's answer, or an apply that failed
  — every other applied member is not counted either: applied (later
  versions do not wait for it), held, shown, left out of its collection's
  value and newest, and reported not counted with the reason "group
  waiting on `<member>`: `<that member's reason>`", naming the first such
  member by seq. A member its rule does not count keeps its own reason.
  When every member counts, every member is reported counted. The rule
  computes counting over the whole applied set, waiting groups included,
  and the layer's holding back never feeds back into it, so the judgement
  is one pass and the same at every reader in any order. Refusal for good
  still withdraws the group (above).
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
  it or, when the record in force was a merge of concurrent records or a
  record taken onto the revision below (below), the `MembersRecord` it
  stands for, encoded as §16.2 lists (a merge's parent the one its records
  share, none when they name different ones; a record taken, what the
  revision below stands for). The digest is of the Content, not of the
  whole Data packet: a merge is carried by no packet, and devices holding
  the same records compute the same merge, so the same digest, whoever
  signed what.
- A reader MUST ignore a members record that the owner rule (§3) does not
  give to `C`'s namespace. It keeps every record it takes, one per signer
  and revision (its latest). Each revision held **stands for** one record:
  the merge (below) of its records, each signed from another view first
  taken onto what the revision below stands for (below, across
  revisions). The **record in force** is what the highest revision held
  stands for. It is a function of the records held alone: readers holding
  the same records hold the same record in force, whatever order the
  records arrived in.
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
- **Across revisions.** A record of revision `n + 1` signed from a view
  without a record of revision `n` the reader holds names another parent
  than `B`, what revision `n` stands for at the reader (the laptop's
  revision 2 removes Carol, with a cut, while the phone, offline, signs
  revision 2 admitting Dave, then revision 3 for Eve on top of its own
  revision 2, still listing Carol and carrying no cut). The reader MUST
  first take it onto `B`: when it holds the record's parent `P`, the
  record and `B` merge three ways against `P` as concurrent records do
  (above) — so a removal, and its cut, that `B` carries and `P` does not
  still applies, a removal beating an addition, and what the record itself
  changed stands; else they merge without one (the intersection, above).
  The record taken keeps its revision and signer and names `B` as parent;
  the records of revision `n + 1` then merge against `B`. The reader holds
  `P` when it is `B`, a record of revision `n` it holds, or what a device
  holding only some of those records took revision `n` to stand for: the
  records of a proper subset of them settled as above (each taken onto
  what revision `n − 1` stands for, then merged). It looks for `P` among
  those subsets when revision `n` holds records of at most 8 signers (at
  most 254 merges, made once per change of what it holds); with more, a
  record whose parent is not `B` nor a record held merges without one,
  losing its additions as such a merge does (above). A record of a
  revision below the highest (arriving late, or from a device long
  offline) settles its revision and every revision above it held in a row
  again, with the merges of subsets made from what is held then.
  What taking a record leaves to resolve is resolved as a merge is
  (above), by a record naming what its revision stands for. So Carol
  stays removed and her later versions refused `OutsideCut`, and Dave and
  Eve are admitted, at every reader holding the four records, whatever
  order they arrived in.
- **Admission.** A reader MUST apply to `C` only versions the record in
  force admits (and, as for every entry, the trust schema admits under the
  writer's own name): a key under a writer prefix is admitted; else a key
  under the prefix of one of the record's cuts is admitted exactly when the
  cut lists that version, with the bytes it binds there (§8), and refused
  otherwise, `OutsideCut`, whatever date or seq it claims; any other key is
  refused `NotMember`. Versions that
  arrive before any members record wait for one. Admission depends on the
  record in force only, so every change of it re-checks everything held of
  `C` (§8).
- **Removing a writer.** A record that drops a writer prefix `P` of the
  record in force (under a folder, the effective record, §6.1) MUST carry
  a cut of `P` that lists, per key under `P`, exactly the seqs of that
  key's versions in `C` the signer holds verified — never entries a
  summary only listed. Only the summaries of `P`'s devices list those
  versions (§7), so before signing it the signer looks at `C` (§12) and
  walks the summary of every device under `P` it knows of that it has not
  walked — heard in a group, or whose summary it verified before, in this
  run or an earlier one — as far as each is reachable within the
  first-look time. The cut then covers what the signer holds after that
  walk; versions that only a device it could not reach holds fall outside
  it. The record is never held off for a device that stays away: a removed
  writer cannot delay its own removal (it would stay a writer meanwhile).
  The signer also binds every version the cut keeps to its bytes: it
  builds the record's cut manifest, listing the implicit digest of each,
  and the cut names it (`CutBytes`, §8); a kept version whose bytes it
  does not know is left out, as one a summary only listed.
  Cuts carry over to later revisions, bound again by each new record's own
  manifest from the digests the manifests carried over list (§8); a
  revision whose writers cover a cut's prefix again
  drops that cut, and the prefix's keys are admitted again (all of their
  versions, the owner having written them back in).
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
- **Changing the rule.** A record whose rule differs from the record in
  force's — or that seals a collection the record in force left unsealed —
  carries `Since`: the frontier its signer had applied, joined with the
  `Since` in force; else it carries the `Since` in force. Versions inside
  `Since` stay held, readable by name and listed by `watch`, and are
  applied as history only: they order later versions (§5.2) and never
  enter the new rule's state. A state of `C` after the change is named by
  a frontier covering `Since`.

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
    `OutsideCut` when a level's cut refuses it, else `NotMember`. A folder
    cut accepts, for `C`, exactly what it lists under `C` (below), with the
    bytes it binds; where cuts of several levels keep one version, every
    level's manifests bind it, and all must list the same bytes (§8).
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
  drops, a cut listing, per collection under `F` and per key, exactly the
  seqs of that key's versions in that collection the signer holds
  verified (`CutIn`, §16.2). A key's log is one sequence across its
  collections (§4), so a seq is accepted only in the collection it is
  listed under: a removed writer that signs an accepted seq again in
  another collection — a new name, so no same-name equivocation — is
  outside the cut there, at every reader. Before signing it looks at `F`,
  so every collection under `F` is followed whole, and walks the removed
  writers' devices as §6 says; the cut covers what it holds then, and its
  manifest binds what it keeps in every collection to its bytes (§8).
- **Changing a folder's members.** `share_folder(F, change)` (§15) adds
  and removes writer prefixes and readers of `F`'s own record in force,
  and signs the result as the next revision exactly as a whole record
  listing it: the same cuts for the writers it drops, the same new epoch
  for a reader it drops, the same offers closed (§19.7). The change MUST
  be applied to the record in force at the moment the device signs, under
  the same lock it signs under, never to a copy read earlier: a member
  added in between — by this device's admission of an introduction
  (§19.4), or by a record of another owner device taken meanwhile — stays,
  and a let-go names only whom it lets go. A writer to add that a listed
  prefix covers, a reader to add that the record admits (or any reader of
  a folder not sealed, which every reader reads), a writer or reader to
  remove that is neither listed nor covered: each changes nothing. A
  change that changes nothing signs nothing. The rule stays the record's.
  It is refused, nothing signed (`BadRequest`, saying why and to share the
  record whole instead), when it removes a writer or reader not listed but
  covered by one listed (removing it would remove nothing at readers),
  leaves no writer (a record listing none takes the writers of the
  folders above, another meaning), leaves a sealed folder no reader (it
  would unseal it), or changes the one writer of a one-key record. With no
  record of `F` held it answers `NotReady`: share it whole first. An
  introduction's admission is such a change (§19.4).
- **Reading the record in force.** `members(F)` answers the rule, writers
  and readers of `F`'s record in force: its own narrowed by the folders
  above (the effective record's levels, above), whoever signed it.
  `members(C)` of a collection answers its effective record's, which for
  a collection with no record of its own is its nearest folder's; a name
  with a folder record held answers the folder's. A watch is told
  `Change::Members` when it changes (§15). Both read only records held
  and verified here, so two devices holding the same records answer alike.
  A collection under a followed folder that a walk listed before any of
  its versions was taken is read under that record all the same: `get`
  answers its state at what it applied (none yet), not `Unavailable`
  while the versions listed are on their way (or withheld).
- **A collection's first own record.** `share(C, …)` of a collection that
  so far had none — it was written and read under the folder's — starts
  from the effective record, as any record starts from the record in
  force: revision 1, no parent, and against the effective record a rule
  change or a seal of a collection the folder left unsealed sets `Since`
  (else the folder's `Since` carries over), a writer prefix the folder
  admitted that the record drops gets its cut, and the folder's cuts carry
  over, bound by the record's own manifest to the bytes the folder's
  manifests list (§8). A first record listing readers starts an epoch of
  its own (its key check is bound to `C`, §9). So a collection taking its
  own record keeps its history readable and its writers' past admitted, as
  a revision would.
- **Widening refused.** `share(C, …)` of a collection under a folder whose
  record is in force answers `BadRequest`, saying what it would widen and
  to share the folder instead (next step `FixRequest`), when it lists a
  writer the folder's writers do not cover or a reader the folder's
  readers do not admit.
- **Re-keying own audiences.** An epoch has **outgrown** its audience when
  a held record naming it lists a reader the record in force over the
  subject no longer admits — a folder above dropped a reader that a
  collection (or nested folder) under it, sealed in its own epoch, lists;
  or a merge left one out. That reader holds the epoch's key. A device of
  the subject's owner namespace that is of its audience MUST then sign a
  new record of it in a new epoch, without the reader, as for a group
  dropping a reader (§6). Until that record is held, no writer seals in
  the outgrown epoch: `put` answers `NotReady` (next step `RetryLater`)
  and signs nothing (§9). The condition reads only the records held, so
  every writer decides alike, whatever order the records arrived in.
- **Writing.** `put` into `C` under a folder in force writes under the
  effective record, sealing in the epoch it names, and signs no default
  record (§5). An owner device that holds no folder record over `C` signs
  a default record only once it has walked its namespace's devices (§5).
- **Sync.** A reader following a collection `C` under `F` also takes the
  members records listed under `MembersEntries` (§7) at the summary nodes
  of every folder above `C`, and only those entries there. A device that
  signs a folder record publishes its notice as for a collection's (§12),
  into the groups of the namespaces of its writers and readers.
- A collection no folder record governs keeps its own records exactly as
  in slice 2.

### 6.2 Threat notes — slice 6

**A member writing a bogus checkpoint.** A checkpoint is its writer's
claim of the state of what it covers (§5.2), and nothing else checks its
content beyond the rule's check against its past (a rule may admit
checkpoints from fewer writers than edits, and verify what it can by
digest). What it covers it cannot overstate: each parent carries the
digest of the packet it names (§4), so a writer can name only tips it
held. A checkpoint naming another writer's seq that does not exist yet —
to cover, once it does, edits it never saw — matches no packet there and
is refused (`Refusal::Parent`) on every reader, the other writer's own
device included; one naming a parent that never applies (outside a cut,
refused) is refused likewise, as it would stand for what lies below. Every
reader applies a checkpoint alike, so it cannot make two readers disagree;
covered versions are never applied, and their pieces never fetched, so a
reader does not find a lie about content by itself. The remedy is the
owner's: a removal cut that does not list the checkpoint withdraws it
(§8), and the versions it covered then apply, their pieces fetched. A cut
that does list a checkpoint planted before the removal grants it nothing
the digest check would not. A release never drops what holders lease, and
drops a device's own merge pieces only on a covering checkpoint applied
here and proved whole by audited holders (§13.3), so the covered versions
stay where the hold record says.

**A rule refusing or withholding.** A rule is code every reader runs under
one name (§5.1). A version it does not count is held, applied to the
frontier, served, shown with the reason to every watcher and listed in the
state: never dropped, never hidden. Only its check refuses, from the
operation and its past alone; what its apply answers, meeting the state
other writers made, never refuses a version nor withdraws its group (it is
not counted, with the reason), so no writer can arrange a state that gets
another writer's group withdrawn. A version it refuses is kept against its
name with the reason, and nothing waits for it. A program whose rule
behaves otherwise than another's under the same name breaks determinism;
the defence is the versioned name — a change of meaning is a new name.

**A stale writer and a rule change.** An operation made for one rule could
mean something else under the next. A merge version names the rule it was
made for (§4), and a reader refuses one naming another rule than the one
in force (`Refusal::OtherRule`), except history inside `Since`: a writer
that had not heard of the change loses that operation, and writes it again
under the new rule; it is never read under a rule it was not made for.

**A basis held by some readers only.** Which refused records a device
holds depends on when it started: a late reader never fetches an entry a
revocation or a cut refuses. Such a version is in no operation's past
(§5.2), held here or not, so a rule's check finds no basis there on any
reader; versions refused for what they carry or for their group stay in
the past, as every reader holds them before judging what was made over
them. An honest writer whose basis is later cut out loses the operations
that need it, alike everywhere.

**A let-go signed from a stale list.** A host that kept its own copy of a
folder's members and signed a whole record from it would drop every
member added since — an introduction's admission signs internally — and
the cut would refuse that member's later writes. The layer answers the
record in force (`members`), tells every change of it (`Change::Members`),
and takes a change applied under the signing lock to the record held
then (§6.1), so a let-go removes exactly whom it names. Records of one
revision signed concurrently by two owner devices still merge with
removals winning (§6): a change does not make an addition outlast a
removal another device signed, nor does a later revision signed by a
device that had not seen that removal (§6, across revisions).

**A Yjs update reaching outside its past.** Yjs ids are predictable, and
yrs keeps an update whose references it lacks pending until they arrive,
so an update could delete, or place items against, another writer's
concurrent or future content. `/merge/yrs` refuses any update whose
origins or deletes reach, for any other writer, past the clock that
writer had reached in the update's past (§5.1).

**Pieces served to some devices only.** A writer could serve a version's
pieces to one device, which builds on it, and to no one else, so everyone
else's copy of what that device writes would stall. A device serves the
pieces of every merge version it applied, and readers ask the devices
whose versions are made over it (§13.1), so the version is available
wherever something built on it is. This lets a holder under audit relay a
version's pieces from such a device rather than keep them: the release
proof (§13.3) then shows the pieces were held, at the audit, by the holder
or by a device that applied the version — no longer the holder alone. That
is acceptable because what release protects is that the pieces stay
obtainable after the writer drops its copy, and they are, from whoever
answered; it is bounded because every proof is fresh — a whole proof over
a new nonce, within the audit's deadline, costing the relaying holder the
whole version each time — so once no applier answers, the holder's next
audit fails and its lease is a breach the owner repairs, as with a holder
losing pieces (§13.3, §13.4). A device wanting the stronger guarantee keeps
its own copy, or holds with more copies.

**Group griefing.** Only a group's own writer can make it incomplete, and
only its own versions: a member never sent keeps the others held and shown
as not counted, and what depends on them waits — stale, never wrong.
Another writer's version can depend on a member only if that writer held
the group complete, so the member then exists to be fetched from it. A
malformed group is refused by every reader alike, from its own signed
versions, and a group none of whose members are refused is counted whole
or not at all, never in part.

**Seq reuse across collections.** A writer's log is one sequence, and a
collection holds a subset of it, so a writer can sign a second entry at a
seq it used, in another collection: a new name, unseen by a reader that
follows only the first collection. Nothing that matters trusts such a
seq: a cut, removal or revocation, accepts a seq only in the collection it
lists it under (§6.1, §8, §8.1), so a removed writer cannot inject an entry
at a seq its cut kept elsewhere; and a group whose writer signed two
entries at one of its seqs, in collections of its folder, is malformed
(§5.5). The verdict reads only what every reader of the folder holds
alike — the writer's entries kept `Forever` and its signed listings there,
pruned entries included — never an entry outside the folder, which only
some readers fetch, nor one kept to expire, which a reader starting later
never learns of. A reader that has fetched one of two entries counts the
group until it holds the other, which the writer's node under the folder
lists, as a reader that has not yet heard of a removal cut keeps a version
until the cut arrives. Readers report any equivocation they hold
(`Change::Equivocation`), inside the folder or not.

**Narrowing races and seals declared falsely.** An owner narrowing one
collection's readers while a writer signs a group across it does not split
the verdict: a reader judges a group by the epochs its members are sealed
in and their audiences, never by the record in force it happens to hold,
so every reader with the same access judges it alike. A reader the
narrowing leaves out finds the group unreadable here, and counts none of
it. A writer that seals one member in an epoch leaving out a reader
another member's epoch admits — whatever seal it declares, larger,
smaller or none, and whether or not it leaves a member unsealed (then the
group is malformed) — so that one reader could count the group and
another never could, gains nothing: no reader counts a group while its
members' epochs do not all admit the same readers (§5.5), and it counts
everywhere once the owner admits them to every epoch.

**Expiring members.** A member kept for the last `n` versions or until a
date would vanish from its writer's listing once expired, and a reader
starting later could never learn it had existed, while readers that held
it counted the group and built on it. Group members are therefore kept
until pruned: `put_group` refuses another keep. A writer that signs one
anyway gains no split: a reader holding it never counts the group and
refuses none of it, and a reader that never learns of it finds the group
incomplete — both wait, so no reader applies the writer's later versions
there and no honest writer builds on them; only the misbehaving writer
is held back. Nothing is refused for a listing that is absent: an honest
writer's node may stop listing an entry its store lost and list it again
once found, and the group then counts everywhere. A prune leaves signed
evidence every reader fetches — the prune record, and the writer's
summary still listing the entry — so a pruned member counts as present
alike everywhere.

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
their own new epochs (§6.1), and between the folder record and theirs no
writer seals in their outgrown epochs, whose key the removed reader holds:
the writer decides from the records it holds, so the folder record arriving
first stops it. A collection that needs a smaller radius lists its own
readers. What a removed reader opened it keeps (invariant 9). A folder
epoch's key is erased only at a device that follows the folder whole and
has walked every device it knows (§14); a device that follows only some
collections under it keeps the key, as it cannot tell what the others
still hold.

**Narrowing by accident.** A collection's first own record under a folder
starts from the folder's effective record, so taking one never silently
drops history (no `Since` where the rule changed), seals out what was
written unsealed, or withdraws a narrowed writer's past (§6.1). An owner
device that does not hold the folder's record yet does not sign a default
record that would narrow the collection for good: it signs one only once
it walked its namespace's known devices (§5). A brand-new device that knows
no other device of its namespace cannot tell, and signs it.

**A removed writer staying away.** A removal cut lists what the signer
holds, and only a writer's own summaries list its versions, so `share`
first walks every known device of each writer it removes, as far as it is
reachable (§6), then signs. A removed writer that keeps its devices
unreachable cannot delay its own removal — a folder's owner could not
revoke another namespace's key — and what only its unreachable devices
hold falls outside the cut, refused `OutsideCut` everywhere: the price of
staying away while being removed.

**Other bytes at a kept seq.** A removed writer — or a copy of its device,
key and storage — can sign other bytes at a name its cut keeps: the same
name as the version the owner held, so no reader can tell them apart by
name, and an equivocation only a device holding both sees. Were a cut to
list seqs only, a reader that never held the honest version would take
whichever bytes reached it first as inside the cut, for good, while the
owner reads the honest ones: the removed writer would choose what late
readers read. A removal cut therefore binds every version it keeps to the
implicit digest of the packet the owner held (§8). Other bytes at that
name are refused `OutsideCut` at every reader, whenever they arrive, and
let go, so that the honest bytes — fetched by full name, the only ones that
answer it, whoever serves them — are taken once any device holding them
answers; a reader that applied other bytes before it held the cut
withdraws them on the re-check (§8). The manifest is self-certifying: the
signed record names its root by digest, each node its children, so any
holder or cache may serve it and no other packet answers for it. A
withheld manifest — the owner's devices, and every device that took it,
unreachable — makes the versions the cut keeps wait at a reader that does
not hold it: stale, never accepted unbound. A cut signed before cuts bound
bytes keeps nothing at an updated reader until the owner's next record
binds it again, from the bytes the owner holds: a seq alone is never
trusted.

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

**A malicious owner listing a victim's namespace.** An owner may list any
person's `/user/<h>` as a writer of its folder (§6.3). Readers then adopt
that namespace from its own genesis, so the only versions the folder
accepts under it are versions that person's keys signed, and only in the
owner's own folder, where the owner already decides who writes. Nothing
of the victim's is vouched for elsewhere: not its own folders, not another
owner's, not at any forwarder. What the owner can cost the readers is the
adoption itself — a version 1, a pointer and a walk per record, bounded
as every walk (trust-context.md §4.5.6 note 5) and at most
`SCOPE_ASKS` (4) in flight per device — and a reader's forwarder carrying
that namespace in transit meanwhile.

**Scope leaks.** A namespace adopted for a folder judges only its own
packets about that folder (§6.3), through a view of the device's validator
that nothing else uses: the node's keyring never holds it, so the
forwarder's validation, the node's other apps and the device's judgement
of every other subject keep refusing it as a person's namespace not held
(trust-context.md §4.5.6 note 4, §4.5.7). It makes the person no owner of
anything at the reader — the owner rule (§3) reads held contexts only — so
no members record of theirs is taken, nor a collection of theirs read. The
one exposure is the transit that carries the namespace's Data to the
device through a forwarder that cannot validate it: that forwarder
vouches for none of it and caches none of it, as for any namespace in
transit, so a local app that relies on its forwarder's validation instead
of validating gets that namespace's Data with no verdict while it is
carried. Apps that read a person's names validate them, as the data layer
does.

**Record churn.** An owner signing record after record makes every reader
refresh each namespace the records list, once per `REFRESH_PAUSE_MAX`
(4 s) at most, however many records arrive (§6.3). A refresh is a walk
from the version held (bounded as every walk), at most one in flight per
namespace and `SCOPE_ASKS` (4) per device; records arriving meanwhile
coalesce into the next. A record that drops and adds a writer again does
not unsettle what is held: versions the cut keeps stay applied, the others
wait for the record that admits them again (§6).

**Many writers.** An owner can list any number of persons' namespaces,
real or made up. A reader lists at most `SCOPE_PER_SUBJECT` (64) for one
subject and `SCOPE_NAMESPACES` (256) in all (§6.3), so that is all it ever
adopts, refreshes, carries in transit or joins the groups of; a person's
namespace it has not adopted is no group at all (§12). The rest are told
to the subject's watchers (`Change::NotAdopted`) and their versions wait:
the owner's records are the owner's to fix.

**Stale walks.** A namespace adopted for a folder is as new as its last
walk: a revocation or a recovery in a later version reaches the reader
with the next record listing the namespace, or the next refresh (a
restart refreshes it). Until then the reader judges that namespace's
versions in the folder by the version it holds, as any holder of a
context that has not yet refreshed (§8.3), and the owner can bring the
refresh forward by signing a record. The version held is kept in the
store, signed (§6.3): after a restart the reader judges by it again and
walks on from it by continuity, as a holder of the namespace would, never
from the genesis again — so neither a path serving only older versions nor
a thief's branch that does not descend from it, whatever its numbers, is
taken, and a key a newer version revoked does not write again. Only a
namespace first adopted from its genesis is open to a fresh adopter's
limit (trust-context.md §4.5.6 note 1). A namespace the node holds is never
taken from a walk of this kind.

### 6.3 Members' namespaces, adopted for the folder — round 3

Members of one folder read each other: a device reads, in a folder, what
every writer the folder's records list writes there, when that writer's
namespace is self-certifying (`/user/<h>`, trust-context.md §4.5), with no
gesture beyond the owner's records.

- **Adoption.** For each subject `S` — a folder, or a collection, each by
  its name and kind: a folder and a collection of one name have a record
  each, and each lists its own — whose own record in force (owner-signed,
  taken as every record, §6, §6.1) lists a writer prefix, or the prefix of
  a cut, under a person's self-certifying namespace `P` that the device's
  node does not hold, the device MUST adopt `P` by name for `S`, within
  the caps below: version 1 fetched and checked as the genesis `P` hashes,
  the newest reached from it by the continuity rule, with the bounds of
  every walk (trust-context.md §4.5.3, §4.5.6 note 5). The adoption is the
  host's (`Introducer::adopt_scoped`): over the node's network, its
  forwarder told to expect the versions, and into no keyring the node
  judges by (trust-context.md §4.5.7). A namespace the node holds — an
  introduction or an anchor link adopted it — is not adopted again: its
  held context judges, as it does everywhere.
- **Caps.** A device lists for adoption at most `SCOPE_PER_SUBJECT` (64)
  persons' namespaces for one subject — the first its record lists,
  writer prefixes before cuts — and at most `SCOPE_NAMESPACES` (256) for
  all subjects together, subjects taken in name order (a collection before
  a folder of the same name), so the caps fall the same way whatever order
  the records came in; namespaces the node holds count too. A namespace
  past a cap is not adopted for that subject, and its versions there are
  refused while it is not. The device logs it and tells the subject's
  watchers `Change::NotAdopted` (§15) with the namespaces left out, why and
  what to do — the owner lists too many writers: list fewer, or adopt
  those namespaces on the node — each time the namespaces left out change.
  A person's namespace not adopted is no sync group either (§12): a record
  listing many writers costs a reader at most the caps' adoptions, groups
  and transit marks.
- **No going back.** The device keeps the newest version of `P` it
  adopted in its store (`/localhost/ndn-data/scoped/<P>`): its number, the
  SHA-256 of its content, and — as the host gives them
  (`ScopedContext::data`) — the genesis's and that version's signed Data.
  At start, before anything asks for `P`, it opens them again (signatures
  checked; no clock decides) and holds `P` at that version for the subjects
  listing it: judging at once, and refreshed from it by continuity (`held`
  given to `Introducer::adopt_scoped`), so a branch that does not descend
  from it is refused whatever its numbers. An adoption that reaches an
  older version, or that number with other content, is refused — its
  transit released when it was a fresh adoption — and asked again as any
  refusal. A refresh that fails keeps the version held judging and is
  asked again after a pause doubling from 8 s to 64 s. A record that keeps
  the number and digest only (a host that gave no signed Data) still
  refuses older versions (trust-context.md §4.5.7).
- **Scope.** The adopted context judges exactly `P`'s packets about `S`:
  log entries of `S` and of every collection under it, with their pieces
  and block entries; one-key heads of those collections; the signal run
  headers of `P`'s devices about `S` or a collection under it (§20); and
  the summary roots, nodes and pages of `P`'s devices whose subject lies
  under `S` or on the way to it (a prefix of `S`: the root of `S`'s
  namespace, the folders above `S`). Every other packet of `P` — about
  another folder, about a collection of `P`'s own, about the device's own
  collections — is judged by the device's validator, which refuses it
  while `P` is not held (trust-context.md §4.5.6 note 4). `P` is no
  namespace of a name here (§3): a device of `P` owns nothing at the
  reader, so no members record `P` signs is taken.
- **Never replaces, never seen.** A context of `P` the node holds is used
  as is: while it is held, adopted before the folder's or after, it judges
  `P`'s names everywhere, and the folder's is released. The folder's is
  never in the node's keyring: the forwarder, the node's other apps and the
  device's every other judgement keep refusing `P` as a person's namespace
  not held. Through a forwarder that cannot validate `P`, the host carries
  `P`'s Data to the device in transit while `P` is adopted for a folder
  (ndn-link.md §15.7): forwarded unvalidated to the Interests pending for
  it, cached by no one; the device validates every packet itself. The
  host's carrying is idempotent: every successful `adopt_scoped` of `P` —
  fresh, or a refresh from a version held, one restored after a restart
  included — has the host carry `P` if it does not already, until
  `release_scoped(P)`; a failed one leaves the carrying as it was; a
  release of what it does not carry does nothing. A host beside a
  forwarder daemon asks it to (`security/transit`, mgmt-trust.md
  "Transit": one mark for each namespace it carries, taken back when it is
  released or the adoption that took it failed), before the adoption's
  first fetch, over a management connection it keeps for its run: the
  marks are that connection's, released by the daemon when it closes, so a
  host that crashes leaves none. It runs with the transit capability
  (`[security] transit_groups`), not as a trust admin.
- **Records move.** As each subject's own record in force moves, the
  namespaces it lists are read again: one a record newly lists is adopted;
  one already adopted is refreshed by continuity from the version held
  (never checked again from its genesis key) — at most once per
  `REFRESH_PAUSE_MAX` (4 s), a burst of records coalescing into one
  refresh after the pause — so a recovery or a revocation reaches the
  reader with the record; one that no record in force lists any more —
  neither as a writer nor by a cut — is released. A
  record that drops a writer keeps it listed by the removal cut it must
  carry (§6): the versions the cut keeps, bound to their bytes, stay
  judged and applied; every other version of that writer in `S` is refused
  `OutsideCut` by admission, whatever context still judges its signature.
  So the device stops trusting a dropped writer for new versions in the
  folder, and the cut governs the old ones.
- **Cost and refusals.** A device has at most `SCOPE_ASKS` (4) adoptions
  in flight; the rest wait their turn. One the host could not make is asked
  again after 2 s, doubling to 64 s, and its refusal is reported with the
  namespace, why and what to do (adopt the namespace on the node by an
  anchor link naming it, or configure a host that adopts for a folder:
  without `Config::introducer`, or with a host that adopts for the node
  only, none is made). Meanwhile that writer's versions in `S` wait —
  stale, never wrong — and are fetched once it is adopted (what it refused
  is judged again, and the summaries of `S`'s namespace refreshed).
- A writer namespace that is not self-certifying is unchanged: a reader
  adopts it (an introduction, an anchor link) before it reads its
  versions, and no record vouches for it.

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
  seq its `Head`. A writer that does not answer is answered for by the
  devices that hold its newest root (§13.5): taken only at or above the
  head verified, under each device's own name, never by the root's
  discovery name;
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
  the folder node, the changed pages, the 37 notes and their new entries.
  Everything under a followed folder is followed, so a collection created
  under it later — by any writer — is a new child of the folder node (or
  of one of its pages): that node's digest changes and the next descent
  goes into the new child alone, at the cost of the root, the nodes on the
  way, the folder node or its changed page, and the new collection's node
  and entries — never the folder's other collections, and no new call.
  Reading, writing or watching a collection held under a followed folder
  is so nothing new: the descents toward the folder took it, and the
  reader neither walks again nor waits a first look for it (a
  collection the reader does not hold yet there — new, or one a writer
  outside the namespace was refused making it follow, §15 — is followed
  anew by its name);
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
  A node, page or entry its writer does not answer is asked of the devices
  that hold it (§13.5), and checked as from the writer.

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
  that entry is outside. A list names each version in its collection: a
  removal cut of a collection's record lists that collection's versions,
  one of a folder's record lists them per collection under the folder
  (§6.1), a revocation cut per collection prefix (§8.1); so an accepted
  seq signed again in another collection — a new name — is outside too.
  The list is what the cut's signer held verified: an entry a summary only
  listed is not in it; and, for a revocation cut, only what it first
  verified before the key was lost (§8.1).
- **A removal cut binds its bytes.** A seq names a version, but a removed
  writer can sign other bytes at the same name (§6.2). So a removal cut
  that keeps versions carries `CutBytes` (§16.2): the full name, ending in
  its implicit digest, of the root of a **cut manifest** listing, under
  each kept version's log prefix `<D>/32=log/<C>`, its seq and the
  implicit digest of its packet. The manifest has the form of a revocation
  cut's (trust-context.md §3.3.12: self-certifying DigestSha256 packets,
  each node naming its children by full name), its packets named
  `<R>/32=cut/seg=<i>`, `R` the members record's log entry name, the root
  `seg=0` (§16.1). A cut that keeps nothing carries no `CutBytes`.
  - *Signing.* A record's cuts share one manifest, which its signer builds
    as it signs: the digest of each kept version is the one a manifest
    binding it already lists (a cut carried over or merged), else that of
    the packet the signer holds verified; a kept version whose bytes it
    knows neither way is left out of the cut, as an entry a summary only
    listed is. While a manifest packet of a cut it carries over is not held
    here, signing answers `NotReady` (next step `RetryLater`) and signs
    nothing; `share` first fetches those packets, by full name. The
    manifest's packets are stored with the record and served as its log
    entries are, once durable (§4.2). A record's cuts keep at most 262,144
    versions; beyond, `share` answers `BadRequest` (next step
    `FixRequest`: write the removed writers back in, or share the
    collections apart).
  - *Reading.* A version at a seq a removal cut keeps is inside it only
    with the bytes every manifest binding its key in its collection lists
    at its name — one per record whose cut keeps it, where concurrent
    records merge (§6) or a folder's levels meet (§6.1). Other bytes, or a
    manifest listing none there, put it outside, `OutsideCut`, when it
    arrives and on every re-check. Such a version is not kept refused
    against its name: it is let go (withdrawn when it was applied), and the
    listed bytes are fetched by full name, digest included, from any
    device, asked again later until they come; `get` of the version
    fetches it so, and answers `Refused` (`OutsideCut`) while only other
    bytes have come. While a manifest packet on the path to its entry is
    not held, the version waits, neither applied nor refused, and the
    packet is fetched by full name; a packet of other bytes under that name
    is never taken for it. A reader fetches the manifest packets of an
    owner-signed members record's cuts before it takes the record — asked
    again after the pause of §17.1, up to `FETCH_TRIES` (3) rounds — so its
    cuts judge every version from the moment it is in force, and a version
    a cut keeps that the reader applied under the record before stays
    applied across the switch rather than waiting for a packet the new
    record names; a record whose packets are still not to be had then is
    taken without them, and what its cuts keep waits as above.
  - *Unbound cuts.* A removal cut keeping versions without `CutBytes` — one
    signed by a build from before cuts bound bytes — binds them to no
    bytes, and a reader refuses every version it keeps, `OutsideCut`
    (its reason names this case and asks the owner to share again from a
    current build): nothing is accepted unbound. A version it keeps that
    the reader holds is **kept**, packet and all — never let go, across
    restarts, a state built lazily (§5.2) and every new record — so the
    owner's next record binds it again from the bytes the owner holds
    (*Signing* above takes them from a version held, refused or not), and
    every reader holding it takes it back on that record's re-check. Only
    a manifest listing other bytes at its name lets it go (*Reading*). A
    packet arriving at a seq an unbound cut keeps that the reader does not
    hold is refused as a packet, unheld: bytes taken now need not be the
    ones the owner held; once a record binds the seq, the listed bytes are
    fetched by full name as above.
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
a removal cut is the owner's, per collection or per folder, and ends a
writer there; a revocation cut is the root's, per key, and ends the key
everywhere.

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
  nor has refused; one not to be had then (its writer away, every reply
  lost) is asked for again on the schedule of re-admitted entries (§17.1),
  as nothing else would ask. When the cut has a manifest (trust-context.md
  §3.3.12), the reader first fetches the manifest packets by full name, then each
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
  place of them. A writer MUST NOT seal in an epoch that has outgrown its
  audience (§6.1: a held record naming it lists a reader the record in
  force no longer admits, who holds its key); `put` answers `NotReady`
  (next step `RetryLater`) until a record moving the collection to a new
  epoch is held. A reader opens it with that epoch's key; a payload that
  does not open under it is refused as a bad signature. A reader without
  the key holds the version verified and closed, applies nothing that waits
  on it, and asks for the key if it may hold it. A reader MUST refuse a
  version of a sealed collection that is not sealed, `Unsealed`, unless it
  lies inside the record's `Since`: its writer wrote it before hearing the
  record that sealed the collection, and relays have it in clear. A record
  that seals a collection the record in force left unsealed sets `Since`
  (§6), so what was written before stays held, as history.
- **Grants.** A device asks for an epoch key with the Interest
  `<G>/32=grant/<GrantAsk>`, `GrantAsk` naming its own seal key, the
  collection `C` and the epoch `E`. The granter `G` MUST answer only when
  (1) an owner-signed record of `C` it holds names `E`, (2) the readers the
  held records naming `E` list, or `E`'s creator, admit the asker, (3) the
  record in force, when it seals `C`, admits the asker, and (4) `G` holds
  `E`'s key; anything else gets no answer, and `G` fetches nothing for it.
  It then fetches and verifies the asker's seal key (signed by the asker's
  device key) — one ask in place, within the asker's wait; when it misses,
  up to `FETCH_TRIES` asks more in the background, one run per seal key, the
  key kept once verified, so the asker's next round is answered at once
  (round 3, faulty cases f2 and r7: a lossy path to the asker made every
  round's one ask miss) — and answers, signed by its own key, with the key wrapped to
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
  then the devices answering for others (§13.5: those it knows to write
  into `C`'s namespace that signed data it holds vouches for, at most
  `RELAYS_ASKED`), round after round with a capped backoff until the key
  is held or no longer owed (§17.1), never one try per granter; a name a
  Sync Interest carried is never asked, so a round never waits behind
  strangers. Keys are
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
  a new folder epoch for every inheriting collection at once; a collection
  under it sealed in its own epoch moves to a new one by its own record
  (§6.1), and nothing is sealed in its outgrown epoch meanwhile. A folder
  epoch's key is erased as a collection's is, across every collection under
  the folder (§14).
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
each as the held context governing it says (§3), or, for a person's
self-certifying name no held context covers, that person's namespace
`/user/<h>` once it is adopted here for the folder (§6.3) — joining those
groups first. A person's namespace neither held nor adopted is no group:
never by the name's shape alone, so an owner listing many made-up writers
makes no device join their groups (§6.2). When a writer's namespace is
adopted, a device that publishes about a subject listing it — one of its
own namespace's, or one it wrote into — joins that group then and
announces into it. So the notice reaches every member's devices through
the group of their own namespace, which every forwarder holding that
namespace carries to its devices; no group needs to reach outside its
namespace. Without the self-certifying rule two members who hold only the
owner's namespace, each adopting the other for the folder, would hear each
other only if the owner's group reached both, which nothing routes; the
group of a writer adopted for a folder carries no trust (a notice decides
nothing).

**Hearing.** The group only says "`D` moved". It carries no data and
decides nothing: a reader that hears it in any group fetches `D`'s root for
the group's namespace and for every other namespace it follows that `D`
writes into — `D`'s own, and each one of whose collections a members
record it holds lists a writer of `D`'s namespace (§7), `D`'s namespace and
each writer's taken by the same rule as for publishing. The devices a
reader looks at for a namespace `O` (its first look, a watch, a key) are
those it heard in `O`'s group and those it heard in any group that write
into `O` by the same rule. Sync Interests are unsigned: anyone who can
send one names any devices it likes. So a reader keeps at most
`HEARD_MAX` (64) devices heard per group; past it, it drops the device
heard longest ago that no signed data it holds vouches for (§13.5,
asking for a writer who does not answer), and only when every other one
is vouched for, the device heard longest ago — a name a Sync Interest
carried never displaces a device vouched for. A name dropped is walked no
more, and what was noted of it without anything of it verified is
forgotten. The state vector it keeps for the group — which every Sync
Interest it sends carries whole — holds the same devices by the same rule
(ndn-sync `SvsConfig::max_producers` and `vouch`): at most `HEARD_MAX`
besides itself, a device vouched for never displaced by a name a Sync
Interest carried, an entry at counter 0 never kept (it brings nothing to
fetch), and what the group was heard to carry (§17.1, a change
announced) noted for those only. So names a stranger sends grow neither
its memory nor its Sync Interests (round 3; before, the vector took up
to 16,384 names, each Sync Interest carrying them all — past the packet
size, so the device's group went silent — and the noted carriage grew
without bound). A stranger in a group costs a reader a root fetch, never
a wrong answer, and is never asked to answer for another device. A device's
counter in a group starts, when it joins, above its durable log head and
above every counter it announced there before, which it keeps; a counter
is kept, and durable, before it is announced, and an announcement goes
out only once the entries it announces are durable (§4.2). So it stays
above anything an earlier run of the same key announced, a power loss
included.

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
- **Fetching pieces — round 3.** A read walks a version's pieces a window
  at once: the manifest a level at a time, the nodes of one level at once,
  then the chunks, at most `Config::window` (32 by default) pieces of one
  walk in flight, each an owed fetch (§17.1: at most `FETCH_TRIES` asks
  per source, each source tried in turn). The first chunk is asked alone,
  to find which source answers; every other chunk is asked first of that
  one. A piece not to be had neither ends the walk nor holds back the
  pieces behind it: every other piece the walk can name (its parent node
  came) is fetched, checked against its parent's digest and stored, so
  reading again asks only for what is still missing. The payload is
  assembled only when every piece is held, each chunk in its place by
  index, never by when it came; a walk holds nothing beyond the window's
  fetches in flight and, when it reads the payload, the chunks it
  assembles (at most `PAYLOAD_MAX`). A holder's repair (§13.3) and a merge
  version's pieces walk the same way.
- **In a merge collection — slice 6.** A version in pieces is admitted,
  and its pieces fetched as above unless a checkpoint the reader holds
  whole and checked covers it (§5.2) and no version that checkpoint does
  not cover is made over it (a basis, §5.2: fetched then, at most 16 of a
  collection at once). Until it is whole it waits as a
  missing parent does: later versions of its writer and versions naming it
  wait. Whole, it is opened (when sealed), checked and applied (§5.2).
  A later version in pieces — maybe a checkpoint covering it, which only
  its opened payload tells — holds back the fetch of the pieces in its
  past (its parents and its writer's earlier entries) until it is found
  whole or `REFRESH_TRIES` of its fetches missed (§17.1): one lost packet
  is no evidence that it is not to be had.
- Besides its writer and the holders, a reader asks for those pieces the
  devices whose versions held here are made over the version (their
  parents include it), each under its own name `<D>/32=held/<Name TLV>`:
  a device serves the entry and pieces of every version it holds (§13.5).
  A writer that serves its pieces to some devices only does not stall what
  others build over them.
- A reader does not keep an applied operation in pieces in memory: it is
  opened again from the pieces when the state is computed anew. A version
  found not whole is not looked for again until its pieces arrive.

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
  SHA-256 of the hold label (§16.1) followed by `H`'s Name TLV and the
  `HoldAsk` TLV without its `Asker`. The proof binds the protocol, the
  holder and this one ask, so it serves no
  other. A device holds only for the namespaces its host lists, and
  answers a hold ask only when, in this order: `C` is of such a namespace;
  the proof's key locator names the device that signed the hold record —
  any other ask is dropped before a signature is checked; that asker has
  no other ask in progress here (one more ask of that asker — the same
  ask duplicated on the way, or the owner asking again, §13.3 — waits for
  the one in progress to end, at most a hold ask's lifetime: three first
  looks and one Interest lifetime, 14 s by default; any further one is
  dropped); the proof is named for this ask and
  verifies to a key of that device (at most `Config::asks_verifying`
  proofs, 8 by default, are verified at once);
  the record, fetched and verified, is that device's newest hold record for
  `C` and names `H`; and its date is past now. `H` then follows `C`, takes
  every version inside `at` with every piece (fetching back what it lost —
  re-replication — from the writer or another holder), signs the lease
  over what its store holds whole, and answers with it (a DigestSha256 Data
  whose Content is the lease's packet). The take runs in a task of its
  own, one per collection at a time, which outlives any one ask: over a
  lossy path a large collection takes longer than an ask lives. It goes in
  rounds — while a version inside `at` is not held, it refreshes every
  device writing into the namespace, then asks by its name every entry
  inside `at` it still does not hold, refuse or skip: each writer's newest
  inside `at`, and every earlier one a summary listed (a walk that listed
  an entry but did not take it under loss leaves it to the take, which
  must not wait on summaries for it); then it asks each
  piece it lacks once of each source — asked again after the pause of
  §17.1, at most 16 rounds (`REPAIR_ROUNDS`), stopping after 3 rounds in a
  row that brought no version heard of and no piece (`REPAIR_IDLE`). An
  ask that finds every version inside `at` kept whole (seen, not merely
  not yet known) is answered at once; else it waits for the take for a
  hold ask's lifetime less one Interest lifetime and is answered when the
  take is done (whole, or out of rounds: the lease holds what is kept),
  or, the take still under way, when it brought nothing since `H` last
  answered this record with less than `at` — before any such answer,
  nothing during the wait — no record inside `at` and no piece of what it
  lacks came, as nothing in reach has it — with the lease of what is
  kept, so the owner learns `H` keeps less than asked instead of asking
  again a take that gets nowhere. While the take brings more since that
  answer — even if nothing came during this wait — the ask is not
  answered: the owner asks again. A take that brought a record or a piece
  between two asks has not shown that it keeps all it can, and answering
  the same lease twice would end the owner's asks (below). The members
  record in force over `C` counts as one record the take lacks until `H`
  holds it — before it, no version is judged and the pieces a version
  lacks are not counted, so its arrival is never mistaken for nothing
  brought — and the last answer is the one given when this ask is
  answered, by any ask of the owner waiting beside it.
  It keeps its last 1,024 answers by
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
  auditor's proof binding `H` and the ask as in §13.2, under the audit
  label, §16.1). An ask to which no answer signed by `H` comes back —
  lost, late, refused on the way as a packet (§4) or Nacked — is asked
  again after the pause of §17.1, each time as a new ask: a fresh nonce,
  so a new name and a new proof. At most `AUDIT_TRIES` (8) asks are sent
  for one piece in one audit; only when none got an answer signed by `H`
  is the piece unanswered. Once at least `AUDIT_TRIES` of the audit's asks,
  all pieces counted, went unanswered and `H` answered none, a piece is
  asked no more after `SILENT_ROUNDS` (3) asks: `H` is **silent** in this
  audit, which is unanswered. A lossy
  path (a fifth of the packets lost each way) leaves every one of eight
  asks unanswered under one time in three thousand, and an audit of 16
  pieces asks 48 before calling `H` silent; a path down costs the audit
  three Interest lifetimes and two pauses, not eight and seven. An answer
  counts only as the answer to the ask
  whose name it carries, judged under that ask's nonce, so a holder never
  passes with an answer to an earlier ask, and a retry is never evidence.
  A manifest node the
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
  - Nothing signed by `H` to any of the `AUDIT_TRIES` asks: no answer.
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
  lost), and audits each lease that comes back — except a holder silent to
  this call's audit of its live lease (above): it is listed unanswered
  among the leases found before repair, not asked to hold in this call,
  and asked again by the next. It asks no other device.
  A holder whose lease still does not count — no lease came back, as the
  ask or its answer was lost or the holder's take is still under way
  (§13.2), or the lease that came is not live, not audited kept, or holds
  less than `at` (the holder's own fetches met loss) — is asked again
  after the pause of §17.1, each time under a fresh nonce and proof, while
  fewer than `copies` count: at most `HOLD_TRIES` (16) hold asks per
  holder in one `hold` call — some four minutes of 14 s asks, for a holder
  taking a large collection over a lossy path — each lease that comes back
  audited afresh. It stops asking a holder that answers the same lease
  twice, audited kept: that holder keeps all it could take of what was
  asked (`H` answers with the same lease again only if its take brought
  nothing since its last such answer, §13.2), and the next `hold` asks
  again.
  Each such audit draws its pieces anew; it passes only with every piece
  answered, so a holder keeping a fraction `f` passes one `hold` call with
  probability at most about `HOLD_TRIES · f^16`, and staying silent on the
  pieces it lacks gains it nothing.
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
     version's log entry, under a fresh nonce (asked again, each time
     under a new nonce, while no signed answer comes back, up to
     `AUDIT_TRIES` asks; the proof is checked under the nonce of the ask
     it answers). The answer is `Proof`:
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
  6. *Round 3.* A merge version that a version held here is made over
     apart from every checkpoint applied here covering it — the basis of
     a version written apart from the checkpoint (§5.2) — is not released:
     its chunks are kept, saying why ("the version `<key>` seq `<s>`,
     written apart from the checkpoint covering it, is made over it: its
     rule merges that version exactly only with it"). A device holding
     such a version is never the one that lets its basis go, so a basis is
     gone only once no device holding a version made over it held it
     (§5.2, when a basis is gone).

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
  and no fetch; an owner's asks are bounded (one hold ask in progress and
  one waiting, and 64 audits in progress, per asker; `Config::asks_verifying`
  proofs verified at once), and a replayed ask is answered from the cache.
  An owner asking again under loss sends at most `HOLD_TRIES` hold asks
  per holder per `hold` call and `AUDIT_TRIES` audit asks per piece per
  audit (§13.3).
- It cannot be framed by records its auditor has not heard yet: a prune or
  a members record it followed is its answer, and it is evidence against it
  only where the auditor's own records prove the piece should be there.
  Nor by a lossy path: a lost ask or answer is asked again, and an ask
  still unanswered after the bound leaves the lease unanswered, never
  broken; a holder silent to an audit is unanswered, never broken, and is
  asked again by the next `hold`.
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

### 13.5 What a device serves — slice 6 (round 3)

Any holder of a signed packet may answer for it: a packet is trusted for
its signature and the digests that name it, never for who sent it (§1).
So a device serves every entry it holds verified, of every writer — its
own, other devices of its namespace, other namespaces — not only its own
log. Before, a device served only its own log, a holder's collections and
the merge versions it applied: a person whose phone writes and goes away
had their work reach others only while the phone, or a custody holder,
was online (ndf's REPLY-12 §1; case h10).

**What it serves.** By name and, asked under its own name, by
`<D>/32=held/<Name TLV>` (answered DigestSha256, the packet inside, §13.1):

- every log entry of another device it holds verified: a version, opened
  or held sealed — a sealed one as the ciphertext its writer signed —, and
  every record (members, folder, hold, lease, prune, snapshot); stored, or
  waiting in memory (pending, parked while its group waits, locked);
- every piece (chunk and manifest node) of such a version that it holds;
- every node and page of another device's summary it verified in its
  newest descent of that device: the reader keeps, per writer, node and
  page, the newest packet it checked against the digest its parent listed
  (ndn-data: under `/localhost/ndn-data/relayed/<node name without its
  head>`, so a newer one of the node replaces it), and answers the node's
  name with it when the head matches;
- under its own name only, asked by the discovery prefix
  `<W>/32=summary/<O>/32=root`, the newest summary root of writer `W` for
  `O` it verified (kept for the rollback floor, §7). By name a root's
  discovery still reaches the writer alone (FreshnessPeriod 0, §7): a
  holder answering it would race the writer with an older root.

It always serves exactly the packet it holds, never one it signs or
re-wraps (the `32=held` answer carries the packet unchanged).

**What it never serves.** What a known prune covers — by the prune
records it holds, whether or not it held the version (§14) — and what
expired by its own clock (§14.1): retention and erasure are the writer's,
and a holder answering for pruned bytes would undo them. Erasure destroys
an epoch's key only once every version sealed in it is pruned (§14), so a
version of an erased epoch is never served either. Nothing refused or
withdrawn here: by the record in force (`NotMember`, `OutsideCut`), a
revocation cut or an untrusted chain (§8), its group (§5.5) or its rule's
check (§5.2) — another reader would refuse it too, and serving it would
only cost that reader a verification. This holds for a collection the
device holds for its owner (§13.2) as for any other: a holder keeps
outsiders' versions and packets withdrawn after it stored them, and
serves none of them (round 3, review L3). Nothing it holds unverified: a
packet that did not verify is never kept (§4). An own entry above the
durable head, and an own piece a release is auditing holders for, stay
unserved as before (§4.2, §13.3). An ask for an entry the device does not
hold costs it one lookup by name, whatever it holds of the collection
(ndn-data: `St::held` indexes every entry held, waiting or refused
included), so asks for made-up seqs cost no scan under its lock.

**Asking for a writer who does not answer.** A reader asks the writer
first, by name, as before. When the writer does not answer, it asks, in
order, the holders of a live lease on the collection (§13.2), then, for
pieces, the devices whose versions are made over the version (§13.1),
then the other devices it hears for the namespace (§12: heard in its
group, or writing into it by the records held) that signed data it
holds vouches for as members or holders of the namespace — a summary
root of theirs for it verified (in this run or kept from an earlier one),
a version of theirs applied in a collection of it, a lease or hold record
of such a collection naming them, or a members record in force of a
collection or folder of it listing their device or one of their keys (a
writer prefix naming a whole namespace or person vouches for no device
under it: a Sync Interest may carry any name there) — not ended here (a
key suspected or revoked), those whose root it verified first, at most
`RELAYS_ASKED` (8) of them, all at once, each under its own name. A name
only a Sync Interest carried is never asked to answer for another
device; it is walked toward itself, as any device a notice names (§12).

- for the writer's root of `O` (§7), every such device of `O`; of their
  replies whose head is at least the highest it verified of that writer —
  an older one is a holder that is behind, not the writer rolling back,
  and is not taken — it checks each, from the highest head down, against
  the writer's signature and its name, and takes the first that checks:
  a reply that does not check is passed over, never taken in place of the
  others of its round. It is asked MustBeFresh, so no cache answers with
  an earlier answer;
- for a node or page the root lists, the same devices; the packet must be
  the one whose digest its parent lists, as from the writer;
- for an entry and for a piece, the devices of the collection's namespace;
  of the answers as they come, it takes the first that checks: an entry
  verified against its writer's key as from the writer (or the very bytes
  a digest names, when it asks by one), a piece against its manifest. The
  holders of a live lease, asked in turn before, are checked the same way.

A device that holds nothing of it answers with a Nack, at once. The writer
asked first, a reader that reaches it never waits on a holder. Outside a
walk, a reader that does not reach the writer asks the devices once the
writer's asks missed (§17.1), all at once, so one that is away too costs no
more than one of them, and only for what the writer did not answer. (Asked
one after another, devices away each cost a lifetime: a holder taking a
hold, which refreshes every writer it knows, outlived its asker's
patience; case g1.) A piece of a version being read is asked as a walk's
packets are: once the writer's first ask missed, beside its later asks,
the holders and the devices whose versions are made over it in turn, then
the other devices at once; the first answer that checks is taken. So a
device that holds nothing — its Nack lost or held back on the way — costs
the read no time beside the writer's own asks (round 3, faulty case h9:
asked after them, such a device cost every piece the writer's lost asks
missed `FETCH_TRIES` lifetimes more).

**Rounds of a walk (normative).** A walk (§7) asks for its root, and for
each node, page and entry it lists, in rounds (§17.1). The first round asks
the writer alone: its root by one ask, what the root lists by up to
`FETCH_TRIES` asks. Each later round asks the writer again and, at the
same time, the devices above, up to `FETCH_TRIES` rounds with the pause
between. A root the writer gives in a round is taken over any a device
gives in it, which may be behind the writer's — as it comes, when newer
than the floor: the devices' answers are not waited for, so a device
that is silent costs it no lifetime; a node, page or entry is
taken from whichever answers first with the packet that checks. So a
writer that answers never waits behind a device. One that does not
answer costs one Interest lifetime more for its root — its first ask —
and one round for a packet the root lists, before a device answers for
it; a device away or holding nothing costs no time beside the writer, who
is still asked; and one packet of the writer's lost does not make the walk
take a device's older root, the writes since left to a later walk. A walk
begun beside others of its refresh loop's pass (§17.1, walks of newer
roots) takes a device's root only if its head is above every root a walk
of that pass took; otherwise it asks the writer again in the next round.

**Threat notes.**

- *What serving others' packets exposes.* Nothing a reader of the
  collection could not fetch from the writer: the same signed packets,
  sealed payloads as ciphertext, under the same names. What is new is
  that the holder's own name now answers for them, so anyone who can
  reach the holder learns, by asking, which entries, pieces and summary
  nodes it holds — which collections it follows and how far its copy
  goes — and can fetch metadata (§9 lists it: names, sizes, parents,
  groups, dates, the writer) longer than the writer stays online. Sealed
  content stays sealed: the holder never unseals for anyone. A person who
  wants a device to serve nothing of others does not let it follow their
  collections; prune and expiry bound how long anything is served.
- *Cache poisoning.* A holder answering with another packet than the one
  asked for gains nothing: an entry is verified against its writer's key
  (a packet signed by another key, or that does not decode, is dropped and
  nothing is kept against its name, §4), a node or piece against the
  digest its parent lists, a root by its writer's signature and the
  rollback floor. Each answer is checked as it is chosen, so a hostile
  device answering first, or claiming a higher head, cancels no other
  device's answer in that round: its forgery is passed over and the next
  answer checked (round 3, review M3; before, the highest head won
  unchecked and its refusal threw the round away, so one hostile device
  heard kept a writer that is away from being read through anyone). The
  `32=held` wrapper is DigestSha256 under the holder's name: a cache
  holding it answers only that holder's name, with the same bytes; a root,
  asked fresh, is never answered from a cache.
- *Amplification.* A holder answers one Interest with one packet it holds,
  no larger than that packet and its wrapper; it never fetches on an
  asker's behalf, signs nothing, and verifies nothing to answer (a lookup
  in its store and its index). A reader asks at most `RELAYS_ASKED`
  devices once per packet the writer did not answer, each vouched for by
  signed data it holds, so its cost is bounded by that and what it was
  going to fetch anyway, whatever names Sync Interests carry. Before
  (round 3, review M2), every device heard was asked, and one unsigned Sync
  Interest naming `N` devices made every walk of each ask all `N` — about
  `N`² · `FETCH_TRIES` asks, reflected onto any device it named; now such
  names are at most `HEARD_MAX` per group (§12), each walked toward itself
  only, and asked for no one else.
- *A holder that withholds or is behind.* It can answer nothing, or serve
  an older root: the reader then gets less, never wrong data, and never
  goes below the head it verified; the writer, once reachable, is asked
  first again. Withholding by every holder is the writer's being offline,
  as before.
- *Equivocation.* A holder answers for a name with the packet it holds. A
  writer that signed two packets at one name (a copy of its key, §4)
  may have one held at one device and the other elsewhere; a reader
  takes the first that verifies, and the second, met later from any
  source, is the equivocation §4 reports and §5.5 refuses a group for. A
  holder cannot make one: it cannot sign for the writer. A removal cut
  bound to bytes (§8) decides which packet stays, whoever serves it.
- *Erasure.* Prune and expiry are checked as a packet is asked for, by the
  prune records held and the device's clock; a device restarted with
  orphan pieces of a pruned version serves none of them (the prune
  records are restored, not only the versions held).

## 14. Prune and expiry — slices 2 (scope), 3, 4 (expiry), 6 (folder epochs)

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
- **Folder epochs — slice 6.** A folder epoch (§9) is one key for every
  collection under the folder that inherits its readers, so it is erased
  by the same rule taken across all of them: a device destroys the key of
  epoch `E` of folder `F`'s records — held, made, granted — once `E` is
  not the epoch of `F`'s record in force; a version sealed in `E` is
  pruned in some collection under `F`; in every collection under `F` it
  knows of, every version it knows of is pruned, held and of another
  epoch (or unsealed), or not held and never applying; and every writer
  known to write under `F` has left `E` — it is this device, `F`'s record
  in force admits no further version of it, or it has a version in `F`'s
  epoch in force in a collection that reads in it. It must also know
  every collection under `F`: the erasure stays pending unless it follows
  `F` whole (every collection under it is inside what it follows, §12)
  and has walked in full the summary of every device it knows to write
  into `F`'s namespace since it last followed something new there. A
  device that follows only some collections under `F` keeps the key.
  The erased-folder-epoch marker is stored apart from collections' (a name
  may be both), loaded at restart before the keys, and lifted only as
  above: an admitted version sealed in `E` under `F` that no prune covers.
- **A prune asks for erasure.** A folder's epoch in force is never erased,
  and outlives most prunes: when a device of `F`'s owner namespace takes a
  prune record — its own or any writer's — that drops a version sealed in
  `F`'s epoch in force, in a collection under `F` reading in it, it owes
  `F` a new epoch (a new record of `F`, same writers and readers, §6.1),
  signed by a device of that namespace that is of `F`'s audience, so the
  pruned epoch can be erased once every writer has moved on. What is owed
  is computed again from the records and prunes held at every restart, and
  a record owed that could not be signed stays owed. A collection's own
  epoch in force is not rotated by a prune.
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
  reading its clock again when it wakes; a version that waited for its
  collection's members record counts from the moment the record admits it
  — the sweep reads every collection's earliest keep again whenever a
  members record is taken — so a holder that took versions before their
  record (over a lossy path) drops them on time, unasked. A restart drops
  what the store
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
| `share_folder` | `share_folder(folder, {rule, readers, writers} \| change)` | 6 |
| `members` | `members(folder \| collection) → {rule, writers, readers}` | 6 |

`put_op` and `put_group` are forms of `put`, `share_folder` of `share`,
and `members` reads what they signed, as a `get` reads a version: the
verbs stay seven. Code mostly uses `get`, `put` and `watch`.
`hold`, `prune` and `share` run on host policy, or on the person's
gesture. A function's answer is a `get` on its name (a later slice).
Exposure over forwarder management and the mobile FFI is slice 7. A device
answers a verb or option of a later slice with an error that names the
slice. Beside the verbs, a `Device` makes and takes introductions (§19):
`offer(folder, {role, until, tries}) → code` and `close_offer(offer)` on
an owner device, and `join(code) → {folder, role, inviter}` on the
joiner's; the joiner then uses the folder with the verbs as any member.

- **`get(C)`** of a merge collection answers its state now — `State` with a
  state name, `at`, the value (typed by the rule, §5.1) and `not_counted`:
  the versions held that are not in the value, sorted by id, each with why
  as a `NotCounted` (`Excluded`: the rule's not counted inside `at`;
  `Waits`: members of groups incomplete or unreadable here, §5.2, §5.5; see
  the `NotCounted` bullet below); of a log collection, its newest version
  (§5) — with `Age::Newest`: the time since the device last knew nothing
  newer was outstanding in `C`'s sync group, measured on its monotonic
  clock: it finished a refresh that reached the writer's state with no
  other pending, or heard one of the group's Sync Interests
  (`<O>/32=sync/v=N`, admitted as the group's driver admits it) with none
  pending whose state vector carried no device's counter above what
  notices brought here and no refresh of that device ended short of (round
  4 review; before, any Interest under `<O>/32=sync` confirmed, signals of
  §20 included, so a stream of them kept the age near zero whatever was
  outstanding). Signals and every other Interest under the group's prefix
  confirm nothing. Of a
  one-key collection it answers the newest version the writer's head names,
  aged by the head's receipt and freshness (§5.3); the head and the node it
  names are asked in place as a walk's packets are (§17.1). The
  first `get` of a collection the device does not follow looks at what the
  devices known to write into its namespace hold first (§12); a reader of a
  sealed collection holding versions it has no key for yet waits as long
  for the keys it asks for. Nothing held: `Unavailable` (next step
  `RetryLater`: the first look's walks go on past the answer, §17.1, so
  asking again reads what they bring). Not of a sealed collection's
  audience: `Sealed`, judged by records held, never by how long the device
  waited (§18.1), as `put` judges a writer: while no record held admits the
  device to the audience — none is held, or the one in force seals without
  it — and a device of the collection's namespace heard here has not been
  walked toward the collection's folder, `NotReady` (next step
  `RetryLater`, naming the devices), since the record a share or an
  introduction signed admitting it may still be on its way; once every one
  was walked, `Sealed`. Every `get` below that answers `Sealed` judges so.
  A merge collection whose rule the device
  does not know: `RuleUnknown`, naming the collection and the rule (next
  step `UpdateProgram`), §5.1.
- **`get(state name)`** answers that exact state (`Age::Exact`), §11; under
  a rule the device does not know, `RuleUnknown`.
- **`get(log entry name)`** answers the version or snapshot (`Age::Exact`),
  fetching it when not held; a members record is not a version
  (`NotFound`); a refused entry answers `Refused` with the reason; a
  version sealed to an audience the device is not in, `Sealed`; an expired
  one, `Expired` (§14.1).
- **Every `Version` a host receives** — answered by `get`, delivered or
  listed by `watch`, carried whole in an equivocation — MUST carry
  `digest`, the implicit digest of its packet (SHA-256 of the whole Data
  wire: the name a merge operation's basis and a parent's `Digest` use,
  §4, §5.1), and `op`: the `MergeOp` octets of a merge version, exactly
  as its rule's check and apply received them, or nothing under the log
  and one-key rules. A merge version's `op` is absent too while its
  operation is not open here — sealed in an epoch whose key the device
  does not hold, or carried in pieces and not read whole (`Payload::Large`,
  listed by its size); a `get` of its name reads it whole and carries it.
  A host keeping versions for history so names them as operations do,
  and reads their edits, with no index of its own.
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
  one admitting its key. With none held and no device writing into that
  namespace heard, it answers `Unavailable`. While none held admits the
  key — none is held, or the one in force does not list the key as a
  writer or, sealed, does not admit the device to its audience — and a
  device of that namespace heard here has not been walked toward the
  collection's folder (as for the default record, §5), it answers
  `NotReady` (next step `RetryLater`, naming the devices): the record a
  share or an introduction signed admitting the key may still be on its
  way, and a refusal is judged by records held, never by how long the
  device waited (§18.1). Once every one was walked, the records held
  decide: `NotAllowed` with none held or a record not listing the key,
  `Sealed` with one not admitting the device. For a collection of its own
  namespace with
  no record in force it signs the host's default record with the first
  version, once that version is judged, and only once nothing a device of
  its namespace holds can govern the collection (§5): else `NotReady`
  (next step `RetryLater`, saying what it waits for), nothing signed. In a
  sealed collection it seals the payload
  (§9), asking for the epoch key first if it lacks it: `Sealed` when it is
  not of the audience, `Unavailable` (next step `RetryLater`) when no
  device granted the key in the rounds it asks in place (§17.1), and
  `NotReady` when the epoch outgrew its audience (§6.1). Refused for any
  reason after the edit,
  it leaves no trace: nothing signed or stored, the log head unmoved, and
  the collection read again from its versions, so the refused edit is not
  in the state (§5.1).
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
  is stored or published and the log head does not move — nor, for a new
  collection, is its default record signed (§5). Of another rule,
  `BadRequest` (next step `FixRequest`: `put_op` is for merge collections);
  under a rule the device does not know, `RuleUnknown`; with `batch`, as
  `put` in a merge collection. It answers as `put` does otherwise.
- **`put_group(items, {type, keep})`** signs one version per item — fields
  (made into an operation by the rule's edit in a merge collection) or an
  operation — as one group (§5.5), and answers their ids in item order, or
  refuses as §5.5 says, writing nothing: the default records of new
  collections among them are signed only once every item passed, and as
  `put` signs them (§5).
- **`NotCounted`** is the type of every reason a held version is not in
  the value (`State::not_counted`, `Change::NotCounted::why`), two kinds
  that differ in whether they end by waiting, so a program shows a spinner
  for one and a mark for the other: **`Waits(why)`** is the layer's own
  wait — the group of the version is incomplete (`group incomplete: 1 of
  2`), not readable here, waits for the epoch its readers are in, or a
  basis or pieces of it are still arriving; it ends when what it waits for
  arrives, and the version then counts (`Change::Counted`). **`Excluded(why)`**
  is a rule's own exclusion (the rule's `Counting::NotCounted`, an apply
  that failed, a group refused, a group member held back by a member its
  rule excludes): it does not end by waiting for what the layer waits for
  (a later version the rule counts differently may still end it, as §5.2
  says, and `Change::Counted` follows then too). `Display` is the bare
  reason. A version whose reason moves from `Waits` to `Excluded`, or
  back, is told again with `Change::NotCounted`; the same reason of the
  same kind is told once. The rule's own `Counting::NotCounted(String)` is
  unchanged: the layer wraps it as `Excluded`.
- **`watch(C, since F)`** reports every held version of `C` (or of the
  collections under folder `C`, which may be `<O>/32=data`) outside `F`,
  then every version applied later, the summaries of §7, each outside `F`,
  every equivocation (§4), and every version withdrawn (§8), pruned (§14)
  or expired (§14.1); from slice 6 also every version held but not
  counted, with why (`Change::NotCounted`, §5.2, §5.5), and every such
  version once it counts (`Change::Counted`); it starts a refresh of every
  device known to write into the namespace. The stream ends when the
  device stops. A folder's watch is one stream for every collection under
  it, including each collection created after the watch began — by this
  device, or by any writer whose versions reach it (§7: the folder is
  followed, so the new collection's branch is descended into on the next
  notice) — with no further call. Every change MUST name the collection
  it is about (`Change::collection`): a version, withdrawal, prune,
  expiry, not-counted or counted report its version's collection; a
  summary the node it summarises (the watched name or one below it); an
  equivocation the collection it is told for — when the two entries at one
  seq are in two collections it is told once for each, tagged with each,
  carrying its own version whole and the other by name and id only (§4),
  so a watcher of both gets it twice, once per collection. The listing
  also reports the equivocation evidence held about what is watched,
  whatever `F`. The listing
  reports what is applied, and, right after a version, `NotCounted` with
  why when the rule does not count it, and a group member waiting for its
  group as `NotCounted` alone (its version comes once the group counts); a
  version held but not applied yet (it waits for an earlier one, its
  group, its key or its pieces) is not listed and comes once it applies,
  so the stream delivers no version twice (a version withdrawn and taken
  back comes again, after its `Withdrawn`). `F` filters every collection
  alike, by writer and seq, as a watch of that collection with `F` would;
  within one collection a writer's versions come in seq order (a group's
  members once their group counts), across collections in no common
  order — one may wait for its key while another applies — so a frontier
  joined from a folder's deliveries may cover a version of another
  collection still to come: a host resuming a whole folder passes the
  empty frontier (its listing is local), or resumes collections one by one
  from their own frontiers.

  A watch of a merge collection is told `Change::Remerged` (the
  collection and the bases handed) when bases that versions applied here
  were made over arrive after those versions applied without them and
  change the value (§5.2, covered versions as a basis): no version comes
  with that change, so a host showing the value reads it again. It is told
  to every watcher of the collection, whatever its frontier, and never for
  a basis that leaves the value as it was.

  A watch is told the members record in force (`Change::Members`, with
  the rule, writers and readers `members` answers): of a folder,
  whenever its record in force changes — whoever signed the record that
  changed it: this device (`share_folder`, an introduction's admission,
  §19.4), another device of the owner, a merge of concurrent records —
  tagged with the folder; of a collection, whenever its effective record
  changes, tagged with the collection. A watch of a name is told that
  name's; a watch of a folder is also told each folder under it, and each
  collection under it that has a record of its own (a collection that
  only inherits is told on its own watch, its folder's change included).
  Only a change of what `members` answers is told, never a cut or epoch
  alone. The listing starts with the record in force over each such name
  held here, so a host that watches and then reads misses no change.

  A watch is never queued for without bound. Past what its listing
  queued, a watcher may leave `Config::watch_queue` changes unread (4096
  by default); the change after them is not queued: the queue's last slot
  takes `Change::Lagged` (tagged with the watched name), and every change
  after it is dropped until the watcher has read the queue empty, when
  delivery goes on. The gap is so never silent: `Lagged` comes after every
  change delivered before it, and tells the watcher to read again — watch
  anew from the frontier it holds (the listing reports what it missed), or
  `get` what it shows.

  What a folder's watch follows is bounded by policy too. A writer outside
  a namespace may make a device follow at most `Config::writer_collections`
  collections of that namespace (1024 by default) by writing into a folder
  the device follows: each new collection is counted to the writer whose
  version or summary node first made the device follow it. The
  namespace's own devices are not counted, nor is a collection followed by
  its own name, held for its owner (§13.2) or with a members record of its
  own. Past it, the writer's new collection is not followed — none of its
  versions is fetched or taken from that writer — and the folder's
  watchers are told `Change::Untracked` with the collection, the writer
  and why, naming the writer and what to do: follow the collection by its
  name to read it, or have the namespace remove the writer from the
  folder's writers. The count is of what is held: read back at start, the
  versions held count again (never refused), so a restart gives no writer
  a fresh allowance. Likewise a subject whose record lists persons'
  namespaces past the caps of §6.3 has its watchers told
  `Change::NotAdopted` with the subject, the namespaces not adopted and
  why — the owner lists too many writers: list fewer, or adopt those
  namespaces on the node — each time the namespaces left out change.
- **`snapshot(names)`** pins, for each name, the current state name of a
  merge collection or the exact name of a version, snapshot or entry, and
  signs the `SnapshotRecord`; a range name, which names no fixed set,
  answers `BadRequest` (next step `FixRequest`).
- **`share(C, {rule, writers, readers})`** signs the next members revision
  (`C` of the device's own namespace only, §3: else `NotOwner`), with the
  cuts, epoch and `Since` of §6 — of a collection's first own record under
  a folder, against the effective record (§6.1). A record removing a
  writer first walks that writer's known devices, as far as they are
  reachable, and cuts over what is held then (§6).
  A collection sealed to a group moves to a
  new epoch when the group drops a reader, signed by a device of the
  collection's own namespace (§6), whoever owns the group. With the rule
  one key, `writers` names exactly the one key, or this device (§5.3): else
  `BadRequest` (next step `FixRequest`).
  Under a folder whose record is in force (§6.1), a `share` that lists a
  writer the folder's writers do not cover or a reader its readers do not
  admit answers `BadRequest`, saying what it would widen and to share the
  folder instead (next step `FixRequest`).
- **`share_folder(F, {rule, writers, readers} | change)`** signs the next
  revision of folder `F`'s folder record (§6.1): at a device of `F`'s
  namespace only (else `NotOwner`), of a folder of at least one path
  component (else `BadName`), with the cuts across every collection under
  `F`, the folder epoch and `Since` of §6 and §9. It looks at `F` first,
  and a record removing a writer walks that writer's devices as `share`
  does. Given a change (`ShareChange`: writers and readers to add and to
  remove), it applies it to `F`'s own record in force when it signs, under
  the signing lock, and signs the result as the whole record; a change
  that changes nothing signs nothing; refusals and `NotReady` as §6.1
  says.
- **`members(F | C)`** answers the record in force (§6.1): of a folder
  whose record is held, its own narrowed by the folders above; else of
  collection `C`, its effective record. With no record over the name held
  here it answers `NotReady` (next step `RetryLater`), saying so and what
  to do: a device of its namespace shares it first; any other device
  follows or watches it so the owner's record is fetched. A name that is
  no data-layer name answers `BadName`.
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
  it (§14); a prune in a folder's epoch in force, by this device or any
  writer, makes the folder move to a new epoch (§14).
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
| cut manifest node of members record `R` (§8) | `<R>/32=cut/seg=<i>`, the root `seg=0`, Content `CutManifestNode` (trust-context.md §3.3.12), FreshnessPeriod 1 h | DigestSha256 |
| hold ask (answer: the lease's packet) | `<H>/32=hold/<HoldAsk TLV>` | DigestSha256 |
| held packet (answer: the packet) | `<H>/32=held/<Name TLV>` (also a joiner's fetch of an offer from its device, §19.3) | DigestSha256 |
| audit ask and answer | `<H>/32=audit/<AuditAsk TLV>`, Content `AuditAnswer`, FreshnessPeriod 0 | the holder's device key |
| asker's proof (inside a hold, audit or introduction ask or answer, never fetched) | `<A>/32=ask/<binding>`, empty Content, FreshnessPeriod 0 | the asker's device key |
| offer, use mark (§19.1) | `<D>/32=log/<F>/seq=<n>` | device key |
| introduction ask and answer (§19) | Interest `<D>/32=intro/<ParametersSha256Digest>`, ApplicationParameters `IntroAsk`; answer named the same, Content `IntroAnswer` | DigestSha256 (the answer carries the offering device's proof inside) |
| signal run header (§20; never stored, served or fetched) | `<D>/32=signal/<S>/32=run/<run id>`, `S` a folder or collection, the run id one GenericNameComponent of 16 octets, no FreshnessPeriod | device key |

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
- **Signal run header.** `D` is the components before the first
  `32=signal` (`D` has no keyword); the last component is a
  GenericNameComponent of 16 octets, the next-to-last `32=run`; what lies
  between is a folder or collection name, the scope (§20).
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
- **Cut manifest.** The last component is `seg=<i>`, the next-to-last
  `32=cut`, and what precedes them is a log entry name with a collection:
  the members record whose cuts the manifest binds. A reader fetches its
  packets only by full name, as `CutBytes` names the root and each node
  its children (§8).
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
  SHA-256 of the protocol's label, then the holder's Name TLV followed by
  the ask's TLV without its `Asker` (§13.2, §13.3); in an introduction,
  the offering device's Name TLV followed by the ask's fields before its
  `Asker`, or the answer's fields before its `Asker` (§19.3). The labels,
  ASCII each ending in a zero octet so none is a prefix of another, are
  `ndn-data hold ask\0`, `ndn-data audit ask\0`, `ndn-data intro ask\0`
  and `ndn-data intro answer\0`. A receiver computes the binding with the
  label of the protocol it expects, so a proof made for one protocol
  never verifies as another's, whatever its fields.
- **Introduction ask.** `D` is the components before the first
  `32=intro`, a device name; exactly one ParametersSha256DigestComponent
  follows, the SHA-256 of the Interest's ApplicationParameters TLV, whose
  value is one `IntroAsk` TLV: one `EphemeralKey` and two `Ciphertext`, the
  wrapped content key, then the sealed `AskBody`. The ask travels in the
  parameters, not the name: its credentials take a few KB, and a link reads
  an Interest's name from its first fragment. An ask whose digest is not
  its parameters' is no ask.

### 16.2 TLV-TYPE numbers

The data layer uses 0x0520–0x057F (registered in
[README.md](README.md#tlv-type-numbers)). Every number is even: a decoder
MUST skip an unknown even TLV inside these records and MUST refuse an
unknown odd one, so a later revision can add fields old readers pass over
(and fields they must not).

| Type | Name | Value |
|---|---|---|
| 0x0520 | VersionRecord | Name (collection), Frontier (parents, each entry with its tip's Digest), TypeId, Seal, Keep, Dated, [Group] (§5.5), [Rule] (merge: the rule the operation was made for, §5.1), then Fields, MergeOp — or Block (§4.1), or Chunks (§13.1; in a collection of any rule from slice 6) — or, sealed, Sealed |
| 0x0522 | Frontier | FrontierEntry*, by writer (in a version's parents, one per writer) |
| 0x0524 | FrontierEntry | Name (writer key), Seq; in a version's parents, then Digest (the implicit digest of that writer's packet at that seq) |
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
| 0x0548 | Rule | RuleKind [Name (merge rule: its full, versioned name, matched exactly, §5.1)]; in a merge `VersionRecord`, kind 2 and the rule its operation was made for (§4) |
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
| 0x055E | Digest | 32 octets: SHA-256 of the child's whole Data packet; in a `MembersRecord`, of the parent's `MembersRecord` (§6); in a version's parents' `FrontierEntry`, the implicit digest of the tip's packet (§4) |
| 0x0560 | Pages | Page*, by bucket |
| 0x0562 | Page | Bucket, Seq (head), Digest |
| 0x0564 | Bucket | NonNegativeInteger 0–15 |
| 0x0566 | PagePath | octets, one bucket each (pages only) |
| 0x0568 | Writer | Name (the writer's key) |
| 0x056A | Cuts | Cut*, by prefix |
| 0x056C | Cut | Name (removed writer prefix), CutBytes* (§8), then — in a collection's record — per key it keeps versions of in the collection, by key: Writer, Entries (exactly those seqs, §8); or — in a folder's record — CutIn*, by collection (§6.1); a signer gives a cut that keeps versions its CutBytes, one that keeps none none (a cut keeping versions without them binds them to no bytes, §8) |
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
| 0x0559 | GroupCount | NonNegativeInteger 1–65,536 (`GROUP_MAX`): the number of versions in the group |
| 0x055B | CutBytes | Name: the full name, ending in its ImplicitSha256DigestComponent, of the root of a cut manifest (`<R>/32=cut/seg=0`, §16.1; trust-context.md §3.3.12) listing, under `<D>/32=log/<C>`, the seq and implicit digest of every version the cut keeps; in a Cut right after its Name, ascending, once each; never in a cut that keeps nothing (§8) |
| 0x055F | CutIn | Name (a collection strictly under the folder), then per key it keeps versions of in that collection, by key: Writer, Entries (exactly those seqs); in a folder record's Cut only, once per collection (§6.1, §8) |
| 0x0561 | IntroOffer | Name (the folder), Role, KeepUntil (its expiry), Tries, Digest (the commitment to its secret), SealKey (the offering device's); a log record (§19.1) |
| 0x0563 | IntroUsed | Name (the offer), then Writer and Digest (the asker key it was used by and its public key's digest) when used, neither when closed; a log record (§19.1) |
| 0x0565 | IntroAsk | EphemeralKey, Ciphertext (a content key wrapped to the offer's SealKey), Ciphertext (the AskBody — Name (offer), Nonce, Proof, Credentials, Asker — sealed under it); an ask Interest's ApplicationParameters (§19.3) |
| 0x0567 | IntroAnswer | Name (offer), Writer (the asker key), Digest (its public key's digest), then Name (folder), Role, Credentials, Asker (the offering device's proof), Proof — or IntroRefused, with no Proof; an answer's Content (§19.3, §19.4) |
| 0x0569 | Role | NonNegativeInteger: 0 reader, 1 writer |
| 0x056B | Tries | NonNegativeInteger: in an offer, the wrong tries that close it (≥ 1); in a refusal, those left |
| 0x056D | IntroRefused | NonNegativeInteger: 1 unknown, 2 used, 3 expired, 4 closed, 5 wrong proof (then Tries, left), 6 conflict |
| 0x056F | Credentials | octets: whole Data packets, a signed trust context then the certificates of its signer key's chain to that context's anchor, at most 8 |

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
`GroupCount` could not tell a complete group from an incomplete one. One
passing over `CutIn` would read a folder cut as accepting nothing, and
withdraw every version it kept — wrong, not stale; one reading its seqs
as valid in every collection would admit a removed writer's re-signed
seqs.

`CutBytes` is odd for the same reason. A reader passing over it would take
a cut's kept seqs as accepting whatever bytes arrive at them: a removed
writer's other bytes at a kept name, taken for good by a reader that never
held the honest ones (§6.2) — wrong, not stale. Refusing it, an older
reader drops every record whose cut keeps versions, and holds the record
before it in force (§17).

The introduction's numbers (§19) are odd for the same reasons: a reader
passing over `IntroOffer` or `IntroUsed` would take a record of the log
for nothing and could not say whether an offer is used; one passing over
`Role` would admit a reader as a writer, or `Tries` close an offer at the
wrong count; one passing over `IntroRefused` would read a refusal as an
admission without its fields; `IntroAsk`, `IntroAnswer` and `Credentials`
are read only by a device that implements §19. In them `Proof` (0x053F)
is an HMAC-SHA256 and `Asker` (0x053B) the signer's proof packet; `Nonce`,
`Ciphertext`, `EphemeralKey`, `SealKey`, `KeepUntil`, `Writer` and
`Digest` are reused as elsewhere.

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
slice-2 `Cut` (0x056C) stays the members record's removal cut; the
manifest its `CutBytes` names reuses the revocation cut's manifest form
(trust-context.md §3.3.12), named under the record (§16.1).

Round 3 adds no data-layer TLV either. A device serving what it holds
(§13.5) answers with the packets as signed, under their own names and the
existing `32=held` wrapper; a members change (§6.1) signs an ordinary
`MembersRecord`; a basis (§5.2) is a version already on the wire; a
writer's namespace adopted for one folder (§6.3) is fetched by the trust
context's own names; asking again (§17.1) and the faulty mode (§18.1) put
nothing on the wire. The odd numbers 0x0571–0x057F stay free.

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
  holder drop a stranger's ask for the cost of a parse. Its binding opens
  with a protocol label because every protocol's proofs share one name
  shape and one key: without it, only the first TLV type of each
  protocol's fields tells them apart, and a later protocol whose fields
  happen to start alike would let one protocol's proof stand for
  another's.
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
  checkpoint cannot claim to cover a version its writer had not applied:
  each parent carries the digest of the packet it names, which a writer
  can know only of a packet it held (§4).
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
| Power loss | The device loses only what it had not published: its store opens at a whole state at or after its last flush, a torn tail rolled back without error; its log head is at or above every seq it served, listed or announced, so it never signs a different entry at a seq a peer holds; local writes since the flush are gone, nobody saw them. | invariant 2, §4.2 |
| Process killed (no power loss) | Every write that returned is kept; the restarted device flushes the store before it publishes any of it. | §4.2 |
| Disk flush fails | Nothing written since the last flush is published; local reads and writes go on; the device says why and asks again later; a device whose store cannot flush does not start. | §4.2 |
| Disk acknowledges a flush it did not make | Residual: a power loss can then make an honest device equivocate, and readers report it as any equivocation. | §4.2 |
| Root compromised | The recovery's versions carry every cut but orphans and cuts naming entries outside their key's log, may cut the keys they revoke, and, on the operator's confirmation, the new CA certifies a cut key again only for the public key its cut's digest names, so its in-cut versions keep a chain and nothing else gains one. | §8.4 |
| Node that predates cuts | Refuses every version of a revoked key, the in-cut ones too: safe, and fixed by updating. A node that knows cuts but predates manifests, key digests and DataRequiresCut keeps those residuals until updated. | trust-context.md §3.3.12 |
| Node that predates cut bytes | Cannot decode a members record whose cut keeps versions (`CutBytes` is critical), so it holds the record before it in force: a writer removed since stays a writer there until the node is updated. | §8, §16.2 |
| Owner device that predates cut bytes signs a members record | It cannot read a record carrying `CutBytes`, so it never names one as parent: its record carries cuts bound to no bytes — or, from a view before the removal, no cut, the removed writer listed again. At a revision no higher than the bound record's it merges with it (§6: cuts by prefix, every manifest kept), and the binding stands. At a higher revision it is taken onto what the revision below stands for (§6, across revisions): a removal of the bound record that its parent does not carry stays, with the bound cut, so a writer it lists only because its view predates the removal stays removed; one it adds over its parent is a writer; updated readers refuse what its unbound cuts keep and keep it (§8). Updated devices do not refuse it as a downgrade: such a record names nothing that tells, and refusing would make the record in force depend on which records reached a device rather than on the signed records alone. Update every owner device before removing writers. Afterwards a current owner device's next record binds what an unbound cut it carries keeps, from the bytes it holds. | §6, §8 |
| Member removed mid-edit | Edits inside the removal cut merge; later ones are refused, and a reader that applied one before the cut arrived withdraws it and says so. | §6, §8 |
| Holder withholds | The summary shows what is missing; fetch from another holder. | invariant 4 |
| Holder withholds a range's blocks | A time search probes a window at once and stops a round none of whose probes answers; the read answers within its bound, listing what it did not reach `missing`. | invariant 4, §5.4 |
| Holder rolls back | A summary older than one already seen is refused, also by a reader that restarted since. | invariant 3, §7 |
| Writer never pauses | Each descent finishes against the root it started from, whose nodes the writer keeps serving; the reader then continues from there and keeps up. | §7 |
| Writer equivocates | Both entries are kept and reported (`Change::Equivocation`), at one name or at one seq in two collections or of two kinds; a group over that seq is refused. | invariant 2, §4, §5.5 |
| A writer names a parent seq that does not exist yet (a checkpoint over another's future) | Its parent's digest matches no packet at that seq: refused `Refusal::Parent` once the genuine one is held; it covers nothing, and the other writer's versions apply. A checkpoint over a parent that never applies is refused too. | §4, §5.2 |
| A stale writer's operation made for an earlier rule | Refused `Refusal::OtherRule`; never read under the rule in force. | §5.1 |
| A rule's apply fails on the state others made | Applied, not counted, with the reason; no version or group is refused for it. | §5.1 |
| A basis refused by its key | In no past on any reader, held or not: judged alike everywhere. | §5.2 |
| A Yjs update deleting or placing against content outside its past | Refused by `/merge/yrs`'s check. | §5.1 |
| Pieces served to one device only | Readers ask the devices whose versions are made over the version. | §13.1 |
| Writer offline, another device holds its work | Readers ask the other devices they hear for the namespace, under their own names, for the writer's newest root, summary nodes, entries and pieces; each answers with the writer's own packets (sealed as ciphertext), verified as from the writer. Nothing pruned, expired, refused or unverified is served. | §13.5 |
| Holder behind, or withholding | Its older root is not taken below the head verified; the reader gets less, never wrong data, and asks the writer first again once reachable. | §7, §13.5 |
| Group member in pieces, not opened yet | Present once every piece is held; opened as it applies; the group counts whole, on readers and on the writer after it reads a collection again. | §5.5 |
| Old software writes | Unknown fields survive its edit. | invariant 8, §10 |
| Poisoned cache | Verification fails, or the packet is signed by another device's key or does not decode: that packet is dropped, nothing is kept against its name, and it is fetched elsewhere; the genuine copy is taken. | invariant 1, §4 |
| Stranger in a sync group | Costs a root fetch per name it carries, at most `HEARD_MAX` names per group kept heard; never asked to answer for another device or to grant; its entries are refused `NotMember`. | §6, §12, §13.5 |
| Removed reader | Refused every grant; the key of the epoch its removal starts did not exist before it, so the new epoch's versions stay closed to it; what it opened before it keeps. | §9 |
| Owner's devices edit members at once | Records of one revision merge against the parent they name, keeping every addition and removal, removals winning (by intersection when the parent is not held); a record of the next revision signed without one of them is taken onto their merge, so a removal its signer never saw still wins; a merge that leaves a removed reader in the epoch is resolved by a new record in a new epoch. The record in force depends on the records held alone, not on their order. | §6 |
| Group member removed | Every collection sealed to the group, of any owner, moves to a new epoch signed by a device of its own namespace. | §6 |
| Own device left out | An audience that does not list it leaves it out of the epoch and every later one; no device holds a secret that yields future keys. | §6, §9 |
| Removed writer fills a gap | A new entry at a seq below what its cut kept is refused: the cut lists exactly the versions kept. | §8 |
| Removed writer re-signs a kept seq in another collection | Refused at every reader: a cut accepts each seq only in the collection it lists it under, a folder's cut per collection under the folder. | §6.1, §8 |
| Removed writer signs other bytes at a kept seq | Refused `OutsideCut` at every reader, whenever they arrive: the cut binds each version it keeps to the digest of the packet the owner held. A reader that never held the honest version lets the other bytes go and takes the honest ones, fetched by full name, once a device holding them answers; one that applied the other bytes first withdraws them. | §6.2, §8 |
| Removal cut's manifest withheld | The versions the cut keeps wait at a reader not holding a manifest packet, neither applied nor refused, the packet asked for by full name from any device; never accepted unbound. An owner device signing a record that carries the cut over answers `NotReady` until it holds the packets. | §6.2, §8 |
| Removal cut signed before cuts bound bytes | An updated reader refuses every version it keeps, `OutsideCut`, saying why, and keeps those it holds — bytes and all, across upgrades, restarts, lazy builds and new records — until the owner's next record binds them again from the bytes it holds; then every reader holding them takes them back. Nothing it keeps is deleted unless a manifest lists other bytes at its name. | §8 |
| Wrong key granted | Refused against the epoch's key check; the right key from any device is taken. | §9 |
| Writer behind on a seal | Its unsealed version is refused `Unsealed`; its later sealed versions do not wait for it. | §5.2, §9 |
| Relay or repository of another person | Carries ciphertext and grants wrapped to one device each; reads no payload and no key, and sees the metadata §9 lists. | §9 |
| Member offline | Its newest verified summary is what the reader is complete against; it catches up when the member returns. | §7 |
| Lossy link (packets dropped, delayed past the lifetime) | Every fetch that missed is asked again while the device's durable state still owes what it was for — a walk of a summary and what it lists, an epoch key, a merge version's pieces, a removal cut's manifest packet — with a pause doubling from 250 ms to 4 s, never waiting for a new sync notice and never one try per granter; within one ask, an Interest nothing answered is expressed again under a fresh nonce after a retransmission timeout from the round trips the device measured (at least 250 ms, doubling, at most 3 times within the lifetime), so a lost packet costs about that timeout rather than the lifetime; at 20 % loss a sealed folder's first version reaches a reader's watch in seconds. Bounded: at most `FETCH_TRIES` asks of at most 1 + `REEXPRESS_MAX` Interests each per owed packet and source per lifetime plus pause. | §17.1 |
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
| Checkpoint the rule does not count | What only such checkpoints cover is not counted, saying which checkpoint and why, and is out of the value, alike whether it was applied before the checkpoint or never and after a restart; a member's write the rule never counts stays not counted under her own checkpoint. It counts, and watchers are told, once a checkpoint covering it counts. | §5.2 |
| Group member never arrives | The group stays incomplete: its members held and shown not counted, what depends on them waiting — stale, never wrong. | §5.5 |
| Group member refused, or group malformed | No member counts, on every reader alike; members applied before are withdrawn in every collection (`Refusal::Group`); others' versions made over them stay counted. | §5.5 |
| Two members, or a member and another entry, at one seq of a group, in collections of its folder | The group is malformed at every reader of the folder once it holds both (an entry kept `Forever`, or listed and pruned, or listed in a merge collection), whatever their order; one outside the folder, or kept to expire, changes nothing; the equivocation is reported. | §4, §5.5 |
| Narrowing concurrent with a group | Judged by the epochs its members are sealed in and their audiences, alike everywhere; a reader left out finds it unreadable here and counts none of it. | §5.5, §6.2 |
| Group whose members' epochs admit different readers, whatever seal it declares | No reader counts it until every member's epoch admits every reader another member's epoch lists; sealed and unsealed members together make it malformed. | §5.5, §6.2 |
| `put_group` that cannot complete | Refused before anything is signed, saying which item and why — also for a keep other than `Forever`. | §5.5 |
| Group member pruned | It counts as present for its group's verdict, alike at every reader (the prune record and the writer's summary say so): the group counts once every other member is present, and nothing counted is uncounted by the prune. | §5.5, §14 |
| Group member that may expire | The group never counts and nothing of it is refused, at every reader: one holding the member and one that never learns of it both wait, so no reader applies the writer's later versions there and no honest writer builds on them. | §5.5, §6.2, §14.1 |
| Group member its writer's node stops listing (store loss) | Nothing is refused: the group waits, and counts everywhere — with versions made over the member — once the node lists it again and it is fetched. | §5.5, §7 |
| A stored version gone or no longer decoding when a merge state is first built after a restart | It is no longer held: the state is built from the versions that read, and the lost one is fetched again where a summary lists it; versions after it wait for it — stale, never wrong: every verdict is the one the signed versions held give, as before the restart. | §5.2, §7 |
| Device stops or loses power while a merge state is being built | Nothing is lost or changed: the build computes from the versions its store holds, each verdict a function of them; the next start indexes the collection again and its next need builds the same state. | §4.2, §5.2 |
| A large group stalls (a member never arrives, or never opens here) | Its members held whole and opened wait in the store, each costing memory only its index (id, name, keep, seal, epoch); members in pieces, members sealed in an epoch whose key is not held here, and members of a collection held for its owner stay in memory. Each is listed not counted with why; what depends on them waits — stale, never wrong. | §5.5 |
| Device restarts with group members parked | They are read back from their parked copies at start, verified when parked, and parked again while the group waits: nothing of a stalled group is fetched again, a member whose writer is gone still completes its group, and an equivocation a parked member is part of is noted again and still reported. A parked copy whose member applied, was refused or was let go is dropped. | §4, §5.5, §7 |
| Reader removed at folder level | One new folder epoch for every inheriting collection; collections in their own epoch listing the reader move to new epochs of their own, and until such a record is held no writer seals in the outgrown epoch (`NotReady`, `RetryLater`). | §6.1, §9 |
| Collection takes its first own record under a folder | Starts from the effective record: a rule change or a first seal sets `Since`, a writer the folder admitted gets a cut, the folder's cuts carry over; its history stays readable and its writers' past admitted. | §6, §6.1 |
| Owner device puts into a new collection before it synced the folder above | No default record is signed while a known device of its namespace was never walked toward the collection's folder, or is known at a newer root than the one walked (the head and the names walked toward are kept across restarts): `NotReady` (`RetryLater`), naming the devices; the folder's record, once held, governs the collection. A device merely offline since a walk toward that folder holds nothing back, nor does one nothing signed held vouches for once its walks spent their `REFRESH_TRIES` tries unreached; one a faulty path kept from a few walks is still waited for. | §5, §6.1, §13.5 |
| Reader holds sealed data before the record admitting it (lost on the way, or not walked to yet) | `get` answers `NotReady` (`RetryLater`), naming the devices, while a known device of the collection's namespace was not walked toward its folder; `Sealed` only once every one was walked and no record held admits the reader. Nothing is read meanwhile: reading takes a record admitting the device and the epoch key it grants. A name a stranger announced in the group delays the refusal by its walks' tries at most (nothing signed vouches for it), never turns it into a read; a device marked suspected or revoked is not waited for. | §5, §9, §15 |
| Write refused after the edit (too large, rule refuses) | Nothing signed or stored, no default record, the log head unmoved; the collection is read again, so the refused edit is not in the state. | §5, §5.1, §15 |
| Removed writer keeps its devices unreachable | The owner walks the writer's known devices as far as they are reachable and signs the cut over what it holds then; the removal is never held off, and versions only the unreachable devices hold fall outside the cut. | §6, §6.2 |
| Folder epoch pruned | Erased once every writer under the folder left it and every collection under it known here is done with it; pending while the device does not follow the folder whole or has not walked every known device toward it (one nothing signed vouches for, once its walks spent their tries unreached, is not waited for, §5); a prune by any writer in the folder's epoch in force makes an owner device of its audience move the folder to a new epoch first, owed again after a restart until signed. The erasure survives a restart. | §9, §14 |
| Collection record wider than its folder | `share` refuses it; one signed anyway widens nothing: every reader intersects the levels. | §6.1 |
| Release of merge pieces without a covering checkpoint proved held | Refused: the pieces are kept, saying why, and `NotHeld` when nothing is released. | §13.3 |
| Collection created under a watched folder, by this device or another writer | Reported on the folder's one watch with no further call, every change tagged with its collection; finding it costs the new branch only (the root, the nodes on the way, the folder node or its changed page, the new collection's node and entries), never a walk of the folder. | §7, §15 |
| Version listed by a watch while it waits (for an earlier version, its group, its key, its pieces) | Not listed: it comes once it applies, so no watch is handed a version twice; a group member waiting is listed `NotCounted` with why. | §15 |
| Folder watch resumed from a frontier joined across its collections | May skip a version of another collection still to come: a writer's versions come in seq order within a collection only. A host resumes a whole folder from the empty frontier (the listing is local) or each collection from its own frontier. | §15 |
| Watcher reads slower than changes come | Its queue holds what its listing queued and `Config::watch_queue` changes more; then `Change::Lagged`, and every change after it is dropped until the watcher read the queue empty — memory bounded, the gap told in order, never silent. The watcher reads again from its frontier. | §15 |
| Folder writer creates collection after collection | It makes a follower follow at most `Config::writer_collections` collections of a namespace outside its own; past it, its new collection is neither fetched nor taken, and the folder's watchers are told `Change::Untracked` naming the writer and what to do (follow the collection by name, or have the writer removed). Counted from what is held, so a restart grants no new allowance. | §15 |
| Owner lists thousands of persons' namespaces | A reader adopts, refreshes, carries in transit and joins the groups of at most `SCOPE_PER_SUBJECT` (64) for one subject and `SCOPE_NAMESPACES` (256) in all; no group of a namespace not adopted is joined; the rest are logged and told `Change::NotAdopted` with what to do, their versions waiting. | §6.3, §12 |
| After a restart, a path serves only an older version of a member's context, or a thief's branch numbered past the one held | The newest version adopted is kept in the store, signed, held again at start and refreshed from by continuity: an older version, that number with other content, or a branch not descending from it is refused and asked again later, so a key a newer version revoked never writes again. | §6.3 |
| Equivocation across two folders | Each collection's watchers are told with their own version whole and the other by name and id only: no watcher learns content of a collection it does not watch. | §4, §15 |
| Reader that predates slice 6 | Refuses folder records and group members (odd TLVs) and waits for them — stale; it applies a collection's own record alone, without a folder's narrowing, until updated. | §16.2 |
| Code stolen or forwarded | Admits whoever presents it first within its expiry, with its role; then one key only: every other is refused `Used` and gains nothing; the owner sees and removes the joiner as any member. | §19.4, §19.7 |
| Ask replayed | Answered from the answer kept for it, bound to the asker's key: admits nobody new. | §19.4, §19.7 |
| Ask without the secret, or guessing | Refused `WrongProof`, counted durably; at the offer's tries it closes for good, even to the right secret, across restarts. | §19.4 |
| Two keys present one code at once | Asks are judged one at a time: exactly one is admitted, the other refused `Used`. | §19.4 |
| Inviter offline or unreachable | `NotReady` (`RetryLater`); nothing is used or counted; the offer waits until its expiry. | §19.3 |
| Inviter's device loses power while answering | The use mark, a counted try and a closing mark are durable before any answer says so; a retry by the same key is answered again. | §4.2, §19.4 |
| Party answering for the inviter | Fails the secret's proof or the anchor the code names: `Forged`, nothing adopted; a forged refusal only denies. | §19.3, §19.7 |
| Asker claims a namespace the inviter knows under another anchor, or overlapping the inviter's | Refused `Conflict`; nothing adopted. | §19.4 |
| Offer asked of another device of the inviter | `Unknown`: only the offering device holds its proof key; its use mark is seen by every device of the inviter. | §19.7 |
| Lying relay hint | Fails to reach; nothing it says is trusted. | §19.7 |

### 17.1 Asking again under loss

A fetch **misses** when nothing answers within the Interest lifetime
(`Config::lifetime`, 2 s by default), the forwarder refuses the packet for
now (a certificate on its chain not to be had yet), a Nack comes, or what
comes is refused as a packet (§4: it does not verify, or is not its name's
packet) — by the device, or by its forwarder, whose `bad-signature`
refusal (forged or altered on the way) is final for that packet, never for
the name: asking again may bring the genuine one, so it is a miss like a
lost packet, asked again in place. A miss decides nothing (invariant 1):
it is the network's, and the device MUST ask again for what the fetch was
for, for as long as what it holds still owes it, whether or not a new sync
notice arrives (§12: the group counter does not move again for what was
announced). What is owed, and until when:

- **A walk of a summary** (§7) — the writer's root, the nodes and pages on
  the way, and the members records and versions they list that the device
  follows or peeks at, with the cut manifest packets on the way to an
  entry (§8). Asked again of the writer's device, from its newest root,
  skipping every branch processed in full.

  *What is owed after a walk ends (normative).* A walk of a device's
  summary of a namespace is owed, by what the device holds and follows
  alone, while something is followed or peeked at in the namespace and
  either (a) the head of the newest root verified of that device is above
  the head it walked in full (both kept across restarts, §7), or (b) a
  name followed there lies under none that a walk in full of that device's
  root went toward while the name was followed — a name only peeked at had
  its records taken, not its versions; this is kept for the run, so after
  a restart a name followed is walked toward anew. Every version a
  verified root lists that the device follows and does not hold — not
  pruned (§14) or released (§13), not shown expired by its writer's newest node
  (§14.1), not cut or otherwise refused — then lies in a branch no walk
  took in full, so the walk stays owed until one takes it or the version
  is no longer wanted, **whatever ended the walk before**: an ask inside it
  that missed every try, a refusal for now, a grant round or a reader that
  stopped waiting, a restart. A walk that ends owing is asked again after
  the pause, also when it was taken in full for less than is followed now
  (a name followed meanwhile, or a newer root verified meanwhile). A walk
  is taken in full only for what was followed and peeked at when it began:
  when that changes — a name followed or peeked at anew, a version let go
  for the bytes a cut keeps (§8) — the device forgets which branches on the
  way to that name and under it were processed, and a walk begun before
  records none of its branches, nor its root, as processed. A root that
  only a relay answered with (§13.5), no newer than the head walked in
  full, says nothing of what the writer did since: the writer counts as
  not reached; so does one answering a sync notice of the writer, whatever
  its head ("A notice answered", below). A walk a reader starts itself —
  the first look of `get`, `watch`, `put` or a hold (§15) — runs on its
  own: the reader stops waiting after the first-look time, the walk goes
  on; one not taken in
  full is walked again in place after the pause, up to `FETCH_TRIES` (3)
  walks, then handed to the one loop of that device and namespace, which
  asks again while the walk is owed. A device whose root does not come, of
  which nothing verified says it owes more than was walked (only a notice
  said it moved: it is offline, or a stranger named it), is asked at most
  `REFRESH_TRIES` (16) times in a row per trigger — a sync notice naming
  it, a watch of its namespace, a first look (its walks in place counted
  among them) — then left until the next one.

  *A root no trust context judges (normative).* A device's roots that lie
  in a person's self-certifying namespace (trust-context.md §4.5) that no
  trust context held here judges — neither the node's keyring nor a view
  adopted for a folder's scope (§6.3) — are refused whoever serves them,
  so they are not asked for: the walk ends at once, spends none of the
  tries above and asks nothing of the network. This is decided from the
  contexts held alone, before asking, never from a refusal received. Once
  a context held judges them — the namespace adopted by the node or for a
  scope, or a record in force listing it for the subject — the walk is
  owed until a root of that device verifies, and asked again from then on
  as any owed walk, however many refusals or notices came before; a notice
  is not needed.
- **The root of a walk** (§7) — asked of the writer's device by one ask;
  while the writer does not answer, the writer again and, at the same
  time, the devices answering for it (§13.5), up to `FETCH_TRIES` (3)
  rounds with the pause below between them. A root the writer gives in a
  round is taken over any a device gives, which may be behind it; a
  device's root is taken only if its head is at least the highest verified
  of that writer. So one lost packet costs neither the writer's newest
  root — a holder's older root walked instead, the writes since left to a
  later walk — nor a pass of the refresh loop, and a writer away costs one
  Interest lifetime more than one that answers.
- **A notice answered (normative).** A sync notice of a device says it
  moved (§12): the walks of its summary that begin after the notice answer
  it, and the loop of that device and namespace asks again until one does.
  Only a root the device itself gave answers a notice. A root a device
  answering for it gave (§13.5) may be behind what it announced: the walk
  of it goes on, and what it lists is taken, but the writer counts as not
  reached, and the loop asks again, at most `REFRESH_TRIES` (16) times in a
  row as for a root that does not come. In a walk answering a notice the
  root's rounds above take a device's root only above every root of the
  writer verified before, and the writer's own root no newer than those is
  asked for again in the next round, taken only once every round brought
  nothing newer: a path may deliver an old copy of the root late — a
  duplicate it delayed answers a later ask — and the notice may announce
  no new root (a device announcing itself as it joins), which costs
  `FETCH_TRIES` − 1 root asks more. A pass of the loop a notice asks for
  begins at once after a pass that took a root of the device newer than
  the one verified as it began, or that did not reach the device's state
  (a loss, a relay behind it: its own rounds pace its asks); after one
  that reached it and took nothing newer, it begins after the pause
  below, `k` being such passes in a row (64 s from `REFRESH_TRIES` on),
  the count starting afresh once a pass takes a newer root. So notices
  that bring nothing new — repeated by a stranger — cost root asks at the
  pace of misses, never one walk per notice back to back, while a writer
  that never pauses, its asks lost now and then, is followed as before;
  a notice whose root moved is answered as before, after at most the
  pause it falls in. A
  pass something held here asks for — a name followed, a namespace
  adopted — begins at once, whatever notices came.
  Which root answered decides nothing (invariant 1): what is held and owed
  follows from the roots and entries verified, as above.
- **A group heard from no one (normative).** A first look (§15, a peek
  of §5.3 among them) that finds no device heard that writes into the
  namespace — none heard in its group, none heard in another group that
  writes into it by the records held (§12) — has nothing to walk: the
  join announcement, or every answer to it, may have been lost, and a
  group's period is half a minute. The device announces its state vector
  in the group again after the pause below, `k` being the announcements
  made so far, up to `REFRESH_TRIES` (16) times, until a device writing
  into the namespace is heard; the notice that brings it begins its walk
  as any notice does. One such run per group at a time: a first look that
  finds one under way starts none. So a lost announcement costs a reader
  seconds at 10–20 % loss, not periods. Hearing a device decides nothing
  (invariant 1): it lets the walks begin, and what they take is judged as
  always.
- **A change announced (normative).** An announcement of a device's own
  change (§12, made once the change is durable, §4.2) may be lost, or
  every answer to it, and the members heard in the group would then learn
  of the change only at the group's next period, half a minute on — and
  at 20 % loss a period's exchange is lost as well about one time in
  three. In a group in which it heard some member, the device announces
  its state vector again after the pause below, `k` being the
  announcements made so far since its newest change was announced, up to
  `REFRESH_TRIES` (16) times in one run, until a member is heard to have
  taken the change: a Sync Interest of the group heard here carries the
  device's counter at that announcement, or the device answered an ask for
  its own newest root of any namespace since (a member walking it takes
  the change; members walk it in every namespace they follow that it
  writes into, whatever group they heard the announcement in, so a group
  of readers of another namespace counts as well). A newer change
  announced during the run is announced again in the same run, which
  keeps its count and pace. One such run per group at a time. A run that
  sent all its announcements while no ask for any root of the device was
  answered leaves the group unheard: its members' Sync Interests carry a
  change only on their period, which each announcement covering them
  defers, so nothing would ever end a run there, and no run starts in that
  group again until an ask for a root of the device is answered. Being
  heard to have taken it decides nothing (invariant 1): it only ends the
  announcing; what a member takes is judged as always.
- **Inside a walk (normative)**, a node, page, members record or version
  the walk lists that missed for want of an answer (or a refusal for now)
  is asked again in place, in rounds: the first round asks its writer's
  device, up to `FETCH_TRIES` (3) asks; each later round asks the writer
  again, up to `FETCH_TRIES` asks, and, at the same time, the devices
  answering for it (§13.5), the first answer that checks taken — the node
  or page whose digest its parent lists, an entry that verifies. At most
  `FETCH_TRIES` rounds, with the pause below between them. So one lost
  packet costs the walk about one retransmission timeout (below), a packet
  the writer missed a whole round of costs one round more rather than the
  walk, and a device answering for the writer that does not answer costs no
  time beside it. A refusal decided against the name, or a device whose
  key is suspected (§8), ends the rounds. Only when every round missed is
  the walk asked again from the root, after the walk ended. Two walks of
  one device's summary under way at once (below) that list the same packet
  — the same node or page by name and digest, both walking toward what was
  followed when they began (no reset between, above), or the same entry —
  ask for it once: the later waits for the earlier's outcome.
- **Walks of newer roots (normative).** A walk takes its root's branches
  side by side and ends once the last of them did, its slowest asks
  included. A writer that never pauses would otherwise have each version
  wait for the walk under way when it was written, long tail and all, and
  then for the next. So one pass of the refresh loop of a device and a
  namespace walks, beside the walk it began with, the newer roots sync
  notices tell of: once the walk begun last is past the way to its
  versions — it took a version its root lists, or a round of asks (above)
  for a node or page on the way missed — or ended with a root of the
  device newer than the one verified as it began, or without reaching the
  device's state, a notice of that
  device that arrived since that walk began begins a walk of the device's
  newest root, while fewer than `WALKS_AT_ONCE` (3) walks of the pass are
  under way; a walk ending makes room for one. A notice arriving after a
  walk that reached the device's state with nothing newer is left to the
  loop's next pass, after the pause ("A notice answered"). A walk begun
  beside others takes
  a root a device answering for the writer gives only if its head is above
  every root a walk of the pass took — an older or equal one says nothing
  of what the writer did since — and otherwise asks the writer again in
  the root's next round. The pass ends once all its walks ended, and
  counts as taken in full, and as reaching the writer, when the walk begun
  last did. Which walks run, and when, decides nothing (invariant 1): what
  is held, owed and walked in full follows from the roots and entries
  verified, as above.
- **An epoch key** (§9) — asked, round after round, of the epoch's creator,
  then of the devices answering for others that signed data held here
  vouches for (§13.5, at most `RELAYS_ASKED`), one
  Interest each a round, while the key is not held, a held owner-signed
  record of the subject names the epoch, the device may hold the key by
  conditions (2) and (3) of §9 as far as it can tell, and a version held
  here is sealed in it and waits for it, or it is the epoch of the record
  in force (for reading what comes next, and writing): that key is asked
  for as soon as the record is held, so a reader holds it before the first
  version sealed in it arrives. A device never stops after one try per
  granter. A watch of the namespace asks again for every key a held
  version waits for, after a restart too. The first `FETCH_TRIES` rounds
  of an ask are asked in place, with the pauses below between them, so a
  `put` that needs the key (§15) waits for them and is answered by them
  rather than by one lost packet — `Unavailable` (`RetryLater`) only once
  all of them missed; the rounds after go on in the background, at the
  same pace. A verb finding the ask already under way waits for it at most
  the first-look time.
- **A one-key read** (§5.3, §5.4) — the head of the one key and the node
  it names, within the `get` that reads them, never past it: each asked
  in place as a walk's packets are, a miss or a packet refused as not the
  head or not its node (one that does not verify or match, a forgery on
  the way) asked again after the pause below, up to `FETCH_TRIES` asks of
  each; a head refused as a rollback is a decision, not asked again. A
  version or entry a `get` fetches by name is asked as a walk's versions
  are, up to `FETCH_TRIES` asks of its writer's device; so is each probe
  of a block a range read makes, and a probe none of those asks answered
  (a miss, or a reply refused as not verifying) is probed again in place
  after the pause below (§5.4): a search's guess up to `SEARCH_TRIES`
  probes before its search widens, a block in the range until the range
  read's bound. A refusal kept against the name is not asked again.
- **A merge version's pieces** (§5.2, §13.1) — while the version waits for
  them: not covered by a checkpoint held whole, not pruned, cut or let go.
- **Inside a walk of a version's pieces** (§13.1) — a read, a holder's
  repair, a merge version's pieces — each piece is an owed fetch, asked in
  place up to `FETCH_TRIES` asks per source, at most `Config::window` of
  one walk's pieces at once; a piece that missed at every source leaves
  the others to be fetched and kept, and the walk ends without the
  payload. A read asks again as its caller does; the loops above ask
  again for merge pieces and a holder's take.
- **A removal cut's manifest packet** a version waits for (§8) — by its full
  name, from any device, while a version waits for it: asked when the
  version comes to wait, on whatever path admits it (an entry taken, a key
  obtained opening it, a descent ended, pieces arrived, a start), then
  after the pause above. Re-admitted entries, the entries a revocation
  cut accepts (§8) and the bytes a cut keeps (§8.2) keep their own
  schedule (`READMIT_TRIES` asks, the pause doubling from 500 ms), and are
  asked again at every group refresh.
- **Custody asks** (§13.3) — within one `hold` call or release, never
  past it: an audit ask no answer signed by the holder came back to, as a
  new ask under a fresh nonce, up to `AUDIT_TRIES` (8) asks per piece per
  audit — but, once at least `AUDIT_TRIES` of the audit's asks went
  unanswered and the holder answered none, at most `SILENT_ROUNDS` (3)
  per piece (the holder is silent in that audit); a hold ask to
  a named holder whose lease does not count, under a fresh nonce and
  proof, up to `HOLD_TRIES` (16) asks per holder per call, while fewer
  than `copies` count — none to a holder silent to the call's audit of
  its live lease. A piece still unanswered after its bound leaves the
  audit unanswered, never broken; a holder still without a lease that
  counts, or silent, is left to the next `hold`.
- **A holder's take** of what an accepted hold record asks (§13.2) — in
  rounds, while a version inside `at` is not held or a piece of one
  is missing: at most `REPAIR_ROUNDS` (16) rounds per take, ended by 3
  rounds in a row (`REPAIR_IDLE`) that brought nothing; the owner's next
  hold ask starts the next take. Each round asks each entry inside `at`
  it can name and does not hold as an owed fetch (`FETCH_TRIES` asks). A
  hold ask waiting for the take is answered, with the lease of what is
  kept, once the take brought nothing since the last such answer (before
  one, during its wait), so an owner's asks of a holder whose take gets
  nowhere end at the same lease twice, and those of a holder whose take
  still brings pieces do not.
- **A members record's cut manifests** (§8), before the record is taken —
  up to `FETCH_TRIES` (3) rounds over the record's manifest trees, after
  the pause above; then the record is taken whether or not they came, so
  a withheld manifest delays a removal by at most those rounds.
- **A trust context fetched by name** (§6.3, §19; trust-context.md §8.1)
  — an adoption by name, a scoped adoption and a refresh: each fetch is
  an ask of one Interest lifetime, expressed again every second inside
  it; at most 3 asks nothing answered and 8 asks in all (an answer refused
  as forged is asked again at once). A namespace nothing answers for is
  reported unreachable within three lifetimes, so a recovery that asks
  the person before vouching for the version held (`from_held`) asks
  within some 15 s.

**Re-expression within an ask (normative).** An ask is one fetch of one
name within one Interest lifetime. An Interest of it that nothing answered
within the device's retransmission timeout `RTO` MUST be expressed again —
the same name and selectors, a fresh nonce, the lifetime left as its
InterestLifetime — and again after 2·`RTO`, 4·`RTO`, … since the previous
one, at most `REEXPRESS_MAX` (3) times per ask, and only while at least
`RTO_MIN` (250 ms) of the lifetime is left after the wait. One ask so sends
at most 1 + `REEXPRESS_MAX` Interests and ends with its lifetime (and the
500 ms the consumer waits past it for a reply sent just before the end);
every Interest of it stays pending until then, and a reply to any of them
answers the ask. `RTO` comes from the round trips the device measured
(RFC 6298), one estimate per device. Only an ask answered by its first
Interest gives a sample R — one answered after a re-expression does not,
since which Interest was answered is not known (Karn). The first sample
sets SRTT = R and RTTVAR = R/2; each later one sets RTTVAR ← ¾·RTTVAR +
¼·|SRTT − R|, then SRTT ← ⅞·SRTT + ⅛·R. `RTO` = SRTT + 4·RTTVAR, doubled
once for every ask since the last sample that needed a re-expression or
that nothing answered, and kept within [`RTO_MIN`, `Config::lifetime`].
Before the first sample `RTO` is the lifetime: nothing is re-expressed on
a path the device has not measured. `RTO_MIN` is the longest a forwarder's
retransmission suppression holds back a fresh-nonce Interest from the same
downstream face (NFD `RetxSuppressionExponential` caps its window at
250 ms; the ndn-rs engine follows it), so every re-expression goes on
upstream rather than being aggregated, and the forwarder needs nothing
beyond its generic Interest pipeline. A packet lost on a measured path then
costs the ask about one `RTO` — a quarter second where round trips are
short — instead of the lifetime; where the round trip nears the lifetime,
`RTO` reaches it and an ask is one Interest, as without re-expression. A
custody ask (§13.3) is expressed once: its call asks again, as a new ask
under a fresh nonce. A granter that sees two Interests of one grant ask
answers both with the one packet it keeps for that name (§9). Re-expression
is liveness only: it decides nothing (invariant 1), and what is held or
counted never depends on its timing.

**Pause.** After `k` misses in a row of one such loop (`k` = 0, 1, …) the
device waits min(250 ms · 2^`k`, 4 s) before asking again
(`REFRESH_PAUSE`, `REFRESH_PAUSE_MAX`), and 64 s (`REFRESH_IDLE`) once 16
asks in a row missed. So at a loss `p` per packet, where an exchange
succeeds with (1 − `p`)², a lost packet costs about one `RTO` within an
ask; a whole ask misses only when all its Interests or their answers are
lost — (1 − (1 − `p`)²)⁴, about 1.7 % at 20 % loss, when all four fit in
the lifetime — and then costs one lifetime and a fraction of a second; and
a walk, a key and its grant complete in seconds at 10–20 % loss rather
than in minutes. What is no longer owed is not asked for again: held,
pruned, cut, expired past its keep, released, its collection or folder no
longer followed, its epoch no longer named or no longer admitting this
device.

**Bound (normative).** At most one loop asks for one owed thing at a time:
one per (device, namespace) for a walk — a notice for a device already
being walked marks it to walk again, and begins a walk of its newer root
within the loop's pass only as "Walks of newer roots" above says, at most
`WALKS_AT_ONCE` (3) walks of one pass under way at once, what two of them
both list asked once, and a pass a notice asks for after one that took
nothing newer waits the pause ("A notice answered"); a burst of members
records refreshes each person's namespace adopted for a folder that they
list (§6.3) at most once per `REFRESH_PAUSE_MAX`, not once per record;
the devices answering for a writer are at most `RELAYS_ASKED` (8) per
ask, a granter round at most the creator and `RELAYS_ASKED` more, and
the devices heard at most `HEARD_MAX` (64) per group (§12, §13.5); a
reader's first look walks beside the loop once,
at most `FETCH_TRIES` passes, and hands it what it did not take, starting
no second loop — one per (subject, epoch) for a key, one per version for
pieces, one per name for a manifest packet. Each pass of a loop makes at
most `FETCH_TRIES` asks per packet it misses (one per granter for a key),
or, for a root or a packet a walk lists, at most `FETCH_TRIES` rounds of
at most `FETCH_TRIES` asks per source (one ask of each for a root); each
ask is of at most 1 + `REEXPRESS_MAX` Interests within one lifetime, and
every fetch holds one of the device's `Config::in_flight` slots (256 by
default). So one owed packet costs at most `FETCH_TRIES` asks —
`FETCH_TRIES` · (1 + `REEXPRESS_MAX`) = 12 Interests — per source per
(lifetime + pause), and a walk at most `FETCH_TRIES` such rounds per packet
it lists, the walks of one pass sharing them: after the first misses,
about one ask per source every 6 s; after 16 misses in a row, one a
minute, until it is no longer owed. A name nothing verified
owes costs at most `REFRESH_TRIES` root asks per trigger, at most 4
Interests each. One walk has at most `Config::window` (32) asks in flight
— the nodes or entries one summary node lists, the pieces of one version,
one round of probes — and the whole device at most `Config::in_flight`:
its memory for fetching is bounded by that many pending Interests and
replies, and on a path whose round trip is `R` it asks at most
`in_flight` / `R` packets a second, so a writer that publishes faster than
that is followed with a lag that grows (§18.1). A version of `n` pieces
costs one walk at most `n` · `FETCH_TRIES` asks per source, the bound
above per piece, never more for being fetched at once. A first look in a
group heard from no one costs at most `REFRESH_TRIES` Sync Interests more
in that group, spread over about a minute, one run per group at a time;
so does a change announced that no member is heard to have taken: at most
`REFRESH_TRIES` per run whatever the rate of changes, and in a group whose
members never walk the device's roots one run in all, until one does.
A verb's own asks are bounded per call: a one-key read makes at most
`FETCH_TRIES` asks for the head and as many for the node it names; a verb
waiting for an epoch key waits for at most `FETCH_TRIES` rounds of its
ask, one ask per granter each; a range read probes for at most
`RANGE_LOOKS` · max(first look, `RANGE_RTOS` · `RTO`) (§5.4), never more
than `RANGE_LOOKS` · max(first look, `RANGE_RTOS` · lifetime), each probe
an owed fetch as above, probed again in place up to `SEARCH_TRIES` times
in a search and until that bound in the range; a search probes at most a
window more versions for a guess no probe reached, never more for loss.
Custody asks are bounded per call: one `hold` sends a holder at most
`HOLD_TRIES` hold asks (each with a lifetime of three first looks and one
Interest lifetime) and, per audit, `AUDIT_TRIES` asks for each of its
`Config::audit_pieces` pieces — and a holder silent to the audit, as when
its path is down, at most `SILENT_ROUNDS` asks per piece (three Interest
lifetimes and two pauses in all, the pieces asked at once) and no hold
ask; a holder whose take brings nothing answers each hold ask within
its wait, so it costs a call two asks; a release asks each candidate at
most `AUDIT_TRIES` `Whole` asks. A holder runs one take per collection at
a time, of at most `REPAIR_ROUNDS` rounds, each asking every missing
piece once per source; hold asks arriving meanwhile start nothing beside
it.

**Threat note: retry cost.** Who can make a device ask again? (1) A sync
notice is unsigned (§12): a stranger naming a device that never answers
costs the reader at most 16 root asks (64 Interests at most) per notice,
spread over about a minute, and none more while that name is being walked
— the "stranger in a sync group" row above, bounded in time as well. One
Sync Interest may name many devices: at most `HEARD_MAX` of them per group
are kept heard and walked (a name dropped begins no further pass, and
never displaces a device signed data held vouches for), and none is asked
to answer for another device or to grant (§13.5), so its cost is linear in
`HEARD_MAX`, never in the square of the names; the state vector, and so
every Sync Interest the reader sends into the group, stays at most
`HEARD_MAX` + 1 entries, and such a name holds back a default record, a
refusal or a folder erasure until its walks spent their tries (§5):
`REFRESH_TRIES` walks of one refresh loop whose root's rounds all missed,
paced as any loop's (a few minutes), its notices counting no try afresh
— so a real device a faulty path kept from a walk or a few, at a loss
that misses a whole root ask about one time in sixty, is still waited
for (round 3: counting one walk let a lost owner device stop holding
back a `put`, which then answered `NotAllowed`). A
stranger's notices of a device being walked begin walks of its newest
root only as the pass allows (at most `WALKS_AT_ONCE` under way, each
once the one before is past its way or ended with a newer root), each a
root ask and what that root newly lists, what two walks share asked once;
a root walked in full before ends its walk at once, once the root's
rounds brought nothing newer: a notice of a device whose root did not
move costs `FETCH_TRIES` root asks of it, and `FETCH_TRIES` − 1 of each
device answering for it, at most `RELAYS_ASKED` ("A notice answered") —
and notices repeated back to back cost that once per pause, `k` passes in
a row that reached the device and brought nothing newer waiting the pause
of `k` misses, one a minute from `REFRESH_TRIES` on (a pass that did not
reach it is itself bounded by its rounds' lifetimes and pauses: at most
`FETCH_TRIES` root asks per `FETCH_TRIES` lifetimes). They can so delay,
by at most that pause, the walk a genuine notice of the device asks for,
never what is held.
(2)
What is owed for
longer is named only by data the device verified: a root its writer
signed, a record its owner signed, a version a writer signed. A member
that lists what it never serves costs each reader the bounded rate above
for as long as it stays a member; its owner ends it by removing it. (3) A
cache or a forger answering with packets that do not verify makes a fetch
miss, never a hold: the same bound, and the genuine copy is still taken
when it comes (§4). One on the path that forges every reply, so that the
forwarder refuses each `bad-signature`, costs the asker exactly a lost
path's asks — `FETCH_TRIES` per packet per source — and decides nothing;
asking another source (a holder, §13.1) goes around it. (4) A granter is
asked only for an epoch a record held here names and that admits this
device; it answers only an asker the
records it holds admit (§9), and fetches that asker's seal key with one
ask per grant it makes and, when that misses, `FETCH_TRIES` asks more in
the background, one run per seal key at a time — only for an asker the
records admit, never for a stranger.
(5) A holder is asked again only by its owner, within the call that asked
it, up to the bounds above; it waits for at most one repeated hold ask of
an asker beside the one in progress (§13.2), and answers a repeated audit
ask, under its new nonce, as any other, never from an earlier answer.
(6) Re-expression is timed by what the device measured itself and bounded
per ask: nothing another party sends makes one ask carry more than 1 +
`REEXPRESS_MAX` Interests. A party that delays replies — or a slow
producer — raises `RTO`, or, by answering only after re-expressions, keeps
it doubled; either lowers how often the device re-expresses. A forger that
answers one of the Interests ends the ask with a packet refused as in (3).
(7) Nothing another party sends ends a walk that is owed: owing is judged
from the roots, records and versions the device verified and what it
follows, never from whether an ask was answered. A relay answering with an
older root its writer signed (§13.5) cannot stand in for the writer's
state — no newer than the head walked, or answering a notice of the
writer, the writer counts as not reached — nor can an old copy of the
writer's own root that a party on the path delays or replays: in a walk
answering a notice it is asked past, at most `FETCH_TRIES` root asks. A
reader that stops waiting cuts no walk short; each costs at most the
bounds above, never a version left unasked.
(8) Nothing another party sends makes a device stop asking for a walk: a
root is left unasked only while no trust context held here judges its
namespace, decided from the contexts held, never from a refusal or a
forged root (a forged root that names an anchor nobody holds is refused,
as in (3), and asked again); and the adoption that ends it owes the walk
without waiting for a notice, so a namespace adopted after its writer
fell quiet is still read.
(9) Only a first look of the device's own announces again in a group
heard from no one ("A group heard from no one"): nothing another party
sends starts a run, and each run is at most `REFRESH_TRIES` unsigned Sync
Interests carrying what the device announces anyway, each costing the
members that hear it at most one answer between them (the group's
suppression, §12). A stranger heard in the group ends the run as any
device does: the reader walks the stranger's root, which costs it the
bounded asks of (1) and never a wrong answer, and hears the writers at
the group's period, as it would without the run — a stranger can take
back the time the run saves, never what is held.

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
makes it sign a new root many times a second) and o5 (a sealed folder
converges under loss: with one packet in five dropped on its way into each
device, the first version Alice seals reaches Bob's folder watch, opened,
within 10 s of virtual time, §17.1). The slice-2 cases are c2
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
refused and he opens nothing written after). r5, added with removal cuts
binding their bytes (§8, §6.2), is a copy of Bob's phone, key and storage,
signing other bytes at the name of the plan Bob wrote into Alice's trip
folder, which Alice holds; Alice removes Bob, her folder cut keeping the
plan's seq. Carol, a reader away all along who never held the plan, comes
back while Bob and Alice are away and only the copy answers for Bob's
phone, so she meets the copy's bytes before the folder's record; once
Alice is back with the record, Carol shows no other bytes at the plan's
name and `get` of it answers `Refused` (`OutsideCut`), and once Bob is
back she reads his honest plan, fetched by full name, as Alice does,
neither listing the copy's bytes. Its features
are `Merge`, `WritersAcrossPrefixes`, `RemovalCut`, `FolderMembers` and
`CutManifest`. `ndn-data`'s unit tests check that `CutBytes` round-trips,
that one out of place, repeated, not a full name or in a cut keeping
nothing is refused, and that a kept version is inside a cut only with the
bytes every manifest binding it lists, outside under an unbound cut, and
waiting while a manifest packet is not held. r6, added with the round-2
review (§8, unbound cuts), is Alice's trip folder where Bob wrote two
versions of the plan that Alice and Carol hold; Alice removes Bob from a
build that predates cut bytes (the provider's `sign_unbound` rewrites her
record as that build signed it: the same seqs, no `CutBytes`), upgrades
and restarts, and opens the plan; Carol takes that record and restarts
too, and Bob stays away throughout. Both refuse Bob's versions
`OutsideCut` meanwhile; once Alice shares the folder again, both count and
serve them, from the bytes they kept. Its features add `UnboundCut`.
`ndn-data`'s unit test `a_version_a_checkpoint_covers_counts_as_that_checkpoint_counts`
checks that what only a checkpoint the rule does not count covers is not
counted and out of the value, the same after a restart's lazy build, and
counts once the rule counts the checkpoint (§5.2).

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
every reader, and later versions do not wait for it), b3 (a non-owner's
edit of a setting the owner locked, made with the lock in view, is kept
and shown with why and never counts, even once unlocked), b6 (two owner
devices: a lock set from one holds for the other, whose own later write
counts; a non-owner's edit made with the lock in view is not counted on
every member; one made apart from the lock waits and counts once an owner
writes over it), b7 (a write and a lock concurrent to it, received in
either order, give the same counting on every member: counting stops when
the lock arrives after the write, and starts on unlock),
b4 (a 20 KiB operation and a 100 KiB checkpoint in one merge collection,
in pieces, read and applied at another device; versions the checkpoint
covers are not fetched), b5 (releasing merge pieces without a covering
checkpoint proved held by audited holders is refused, saying why), b8 (a
device that applied a checkpoint first, never fetching what it covers, and
one that applied the covered versions before it count a version written
apart from the checkpoint alike, for the same reason, and show the same
value, also after an owner writes over it), b9 (a checkpoint written while
another member works offline: back before any release, the member's edit
merges exactly on every device, the device that applied the checkpoint
first fetching the covered version it was made over, with no conflict), g1 (a
group counted all or none on arrival, and withdrawn whole when one member
is refused), g6 (a group with one member under a lock waits whole, each
other member not counted with a reason naming that member and its
reason, then counts whole once unlocked), g7 (a group of three whose
37,847-octet member travels in pieces counts whole at a reader once every
piece is held, and at the writer after a new members record makes it read
the folder again), g2 (`put_group` refuses a group that could not complete,
writing nothing), g3 (a group judged the same at every reader despite a
concurrent narrowing of one of its collections), g4 (a copy of a
writer's device signs seqs it already used in other collections: entries
at seqs a folder cut kept are refused `OutsideCut` in the collection the
cut did not list them under, at every reader, and a group one of whose
seqs carries a second entry is refused for its group at every reader),
h10 (a device serves the versions it holds that another device wrote:
Alice's phone locks a paragraph of a sealed folder and goes away for good,
no cache keeping what it served; her laptop answers for the phone's root,
summary nodes and sealed entry, exactly as the phone signed them, and Bob
counts the lock),
f1 (a folder of 1,000
collections: a reader asks one grant per folder epoch, not one per
collection), f2 (narrowing a collection under a folder works; widening
it is refused, and a widening record signed anyway has no effect), f3
(a collection taking its first own record under a folder: a writer it
drops keeps its earlier versions, cut at what the owner held, and a seal
keeps what was written unsealed before readable, at every reader) and f4
(Carol and Bob join a note by codes; the owner's `members` and folder
watch show both with no gesture of hers; she lets Carol go with a change
naming Carol alone, and Bob stays a member, writing and reading, his
device holding the same record, while Carol no longer reads what follows).
Their features are `RuleByName`, `AppOps`, `MergePieces`, `Groups`,
`FolderMembers` and, for f4, `Introduction`.

The large-group case is g5 (one folder of 2,000 element collections; a
writer puts one edit into each as a single group, above the former bound
of 1,024; another member holds no member counted until all 2,000 are
held, then counts all of them, and a reader holding only some keeps them
in its store, not in memory, listed not counted with "group incomplete").
The lazy-state case is l1 (a note collection with edits, a checkpoint and
edits after it, beside collections nobody touches after a restart; the
device stops and starts again from its store: no merge state is built at
start, the first `get` builds the note's state from its newest checkpoint
— the checkpoint and the versions after it applied, none before — and its
frontier, value and `not_counted` equal those before the restart; the
untouched collections stay unbuilt, costing index entries only). ndn-data
carries l1 as a unit test, its rule counting starts and applies
(`device/lazy_tests.rs`), with a folder watch that builds only the
collections holding versions past its `since`, the parking of an
incomplete group's members, and parked members read back after a restart
(the group completes with nothing fetched, and an equivocation a parked
member is part of is still listed).

The folder-watch case is w1 (a note of 1,000 paragraphs, one element
collection each, under one folder shared by `share_folder` with a second
person as writer and reader; both watch the folder once. The other person
adds a paragraph — a collection created after the watch began — and the
watcher's stream reports its version tagged with the new collection; the
same the other way round, and for the watcher's own add; a version the
rule does not count, in another paragraph, is reported `NotCounted` and
then `Counted` on the same stream, tagged with that paragraph; no watch is
handed one version twice. The Interests the watching device sent from
each add to its delivery, and the time, are measured, not asserted). Its
feature is `FolderWatch`. Focused tests in `ndn-data`'s
`device/watch_tests.rs` hand a device crafted entries: a collection
created under a watched folder delivers its version, a group member's
`NotCounted` and `Counted`, and a cross-collection equivocation once per
collection, each tagged; an equivocation across two folders shows a
watcher nothing of the other folder's content; a watch lists a group
member waiting as `NotCounted`, and a version waiting for an earlier one
when the watch begins is delivered once, when it applies; a watcher that
falls behind is told `Lagged`, its queue bounded, and delivery goes on
once it read the queue empty; and an outside writer past
`writer_collections` is refused its next collection, told `Untracked`,
which following the collection by name lifts.

The storage durability cases (§4.2) run as cargo tests against both
on-disk engines, fjall and redb, killing processes for real, not in the
conformance runner: d1 (a write that returned survives `kill -9`, for two
store instances in one process) and d2 (after a simulated power loss —
every write not fsynced dropped, torn and zero-filled tails — the store
opens without error at a whole commit at or after its last flush) are in
`ndn-sync`'s `tests/durability.rs`; d3 (a device killed between a put and
its flush, after a power loss that takes everything not durable, never
serves a different entry or root at a name a peer was served) is in
`ndn-data`'s `device/durability_tests.rs`, with the in-process checks that
nothing is served, listed or announced before its flush returns and that
each store instance has its own barrier.

The introduction cases (§19) are run among strangers — each device's
forwarder holds its own person's trust context and certificates only,
until an introduction adopts another's: i1 (Alice offers her notebook
folder as a writer; Bob, given only the code's link, joins, and each then
reads what the other writes, with no further gesture; Carol joins a second
offer by its words as a reader, reads, and her own write is refused
`NotAllowed`; the time from code to member is measured), i2 (a used code:
another key presenting it, as a link or as words, is refused `Used`
(`AskOwner`) and reads nothing; the key that used it, asking again, is
answered again), i3 (a code past its expiry by the offering device's
clock is refused `Expired`; a new code admits), i4 (an offer closing at
two wrong tries: the first is refused `WrongProof` with one left
(`FixRequest`); the offering device restarts; the second is refused
`Closed`, and so is the right code afterwards from the same key — the
count survived the restart), i5 (two keys presenting one code at once:
exactly one is admitted, the other refused `Used`, also when it asks
again, and only the admitted one reads), i6 (an ask with a guessed secret
is refused `WrongProof`, counted, and grants nothing; the real code,
within its tries, still admits), i7 (the offering device offline: the
join is refused `NotReady` (`RetryLater`) and spends nothing; once it is
back the same code admits, and each reads what the other writes), i8 (a
joiner whose namespace lies under one the inviter trusts — `/carol/m`
once Carol joined — or is the shared `/user` is refused `Conflict`
(`FixLocal`), reads nothing, and the offer still admits its holder), i9 (a
code from `/carol/m` to a joiner trusting `/carol`, as a link or as words,
is refused `InviterConflict` (`AskOwner`) and the joiner adopts and reads
nothing of it), i10 (a member who joined by a code and was removed asks
again with the code, before and after the inviter restarts: refused
`Closed` — the removal closed the offer — and never reads what the owner
writes afterwards), i11 (a stranger spending its own wrong tries is
refused `Closed` while the code's holder still joins; on a used offer a
stranger's guesses are refused `Used`, counted nowhere, and the user
asking again is answered) and i12 (not among strangers, so the owner's
other device reads the member's writes: a member removed by that device,
which closes nothing, asks the offering device again: answered, never
admitted again). Their feature is `Introduction`.
`ndn-data`'s `intro.rs` unit tests check the records, asks and answers
round-trip, that malformed ones are refused, that each proof binds every
field it covers (another offer, key, digest, nonce or secret fails it),
and the default `IntroPolicy`; its device tests (`device/intro_tests.rs`)
check that only the certificates of the verified chain are cached, that a
joiner whose key is its own anchor is answered, that an offer is not spent
when the host does not adopt the asker, that a closed offer refuses its
user too, and that asks past `asks_queued` get no answer at once.

### 18.1 Faulty mode

A conforming implementation passes every case it implements on a faulty
network as on a clean one. `ndn-data-conformance --faulty` runs the whole
suite on ndf's faulty profile; `--faults SPEC` runs another profile and
`--fault-seed N` another seed. The integrator's runs use `--faulty` with
the default seed and two more, each with `--check-determinism`.

- **Profile.** `drop=0.2,dup=0.1,forge=0.05,delay=400,reorder=0.1,blocks=1500`,
  the profile of ndf's element-link fault layer, with its semantics
  exactly (`ndn_sim::Faults`). Each packet, with draws in this order: is
  dropped with probability 0.2; otherwise is held a uniform 0..=400 ms;
  with probability 0.1 is held a further max(400, 50) ms, so later packets
  overtake it; if it is a Data — a frame carrying a whole Data packet,
  bare or as an NDNLPv2 fragment; a fragment of a larger Data is not
  one — is held a further uniform 0..=1500 ms; with probability 0.1 is
  delivered twice, both copies after the same hold; and, if a Data, with
  probability 0.05 has one byte of its SignatureValue XORed with 0x5A. A
  SPEC is comma-separated `key=value` pairs of the keys `drop`, `dup`,
  `forge`, `delay`, `reorder`, `blocks` (milliseconds) and `seed`; a key
  left out is no fault, an unknown key or value is refused, saying which.
- **Where it applies.** To every packet arriving at a device from its
  link, below the device's forwarder. What arrives at the hub is not
  faulted, so every packet from one device to another meets the profile
  exactly once — as on a direct connection under ndf's per-arrival layer,
  where each end faults what it receives. The faulty links are the face
  ndf's layer sits on, an ndn-link QUIC stream face: whole packets meet
  the faults (no NDNLPv2 fragments, so a large Data is dropped, held or
  forged once), and no NDNLPv2 reliability resends what is dropped: every
  loss reaches the forwarder and the device. The faults ride on the
  link's own latency, and taking a device offline still cuts its link
  outright. A case that declares its own profile (o5) keeps it;
  `--fault-seed` replaces its seed too.
- **Seeding.** Each link direction draws from its own xorshift64 stream,
  seeded from the fault seed and the two node ids only (the default seed
  is 0). Nothing else — the order of cases, the process, the fabric's
  world seed, another link's traffic — enters a draw, and the kernel is
  virtual, so a faulty run is as deterministic as a clean one: a case run
  alone in a fresh process with the same flags must give the same status,
  faults, cost and measures as in the suite (`--check-determinism` checks
  this under `--faulty`; each child run gets the runner's fault flags).
  The implementation keeps its share of this: whatever it does for
  several groups or collections at one moment — announcements, their
  re-announcements, fetches, asks — it starts in name order, never in a
  hash table's per-process order, and the random bytes it draws (keys,
  nonces) change what it sends, never its order or timing.
  The JSON report records the network (`network`: `mode` — `clean`,
  `faulty` or `faults` — the profile as run and its seed) and, for each
  case, the profile it ran under (`faults`).
- **What passing means.** Every assertion a case makes holds, unchanged:
  what each device reads, what it refuses and why, what it keeps and
  serves, the signatures made and the person's gestures. Time to converge
  stays within the case's own limits and its budget of virtual time; the
  faults are never loosened to make a case pass, and a case is never made
  to tolerate a wrong answer. A failure under faults is a defect in the
  implementation (or the case) at its cause, fixed there.
- **A host does what a refusal says.** A case's host asks a verb again
  while it answers next step `RetryLater` — `Unavailable`, `NotReady`: a
  `put` racing the record or the epoch key that admits it, a `get` or a
  join whose first look races the network — every 500 ms for at most
  120 s of virtual time (the harness's `AGAIN_PAUSE`, `AGAIN_FOR`); a
  `release` answered next step `HoldFirst` (§13.3: no holder proved it
  keeps the cover, perhaps only because its answers were lost) holds again
  and releases again within the case's own limit; it does neither on any
  other answer. Asking again is liveness only: a `RetryLater` or
  `HoldFirst` refusal decides nothing, and what the verb answers when it
  succeeds is judged as on a first try.
- **A sustained-write case offers the load the path carries.** The one
  workload parameter that follows the path is the pace of a writer that
  never pauses (o4): every version is a packet a reader fetches by name,
  and a reader with `Config::in_flight` asks in flight (§17.1) fetches at
  most that many per mean packet time, so a writer saving every 2 ms over
  a path whose round trip is above a second outruns any bounded reader.
  Under faults the case derives its writer's pace from the profile and
  the reader's asks in flight: the packet time is the profile's mean round
  trip (each arrival held half `delay`, a Data a further half `blocks`, a
  reordered packet a further `max(delay, 50)` ms) plus, for each ask that
  misses (`1 / ((1 − drop)² (1 − forge)) − 1` per packet), a lifetime and
  its 500 ms slack; the writer takes a quarter of the packets that time
  carries, two per version (the version and the node that lists it) —
  about 89 ms a version on the faulty profile, against 2 ms clean. A later
  catch-up's time bound follows the path by the same rule: a version just
  saved reaches the reader through 7 exchanges in a row (the root, five
  summary levels, the version), so the bound is 3 such chains of that
  packet time, never less than its clean 10 s — about 60 s on the faulty
  profile. Every assertion is unchanged, and both paces and both bounds
  are recorded as measures.

**Threat notes — faulty mode.** A forged packet — any Data whose
signature fails — is refused by the device's verifier and is never
applied, stored, served or cached as good: not by the data layer, and not
by the device's forwarder, whose content store must not answer a later
Interest with it. Nothing is kept against its name: a forged copy never
makes a device refuse the genuine packet at that name, never counts as
evidence (an equivocation, a breach, a refused version), and never stops
the device asking again, from any holder, until the genuine one arrives.
The same holds for the certificates that verify a packet: a copy of a
signer's certificate whose own signature fails (forged on its way in,
e.g. fetched through a forwarder that carries the writer's namespace in
transit, §6.3) is evicted from the validator's certificate cache when a
walk refuses it, and the certificate is fetched again; it never makes the
device refuse the genuine packets that key signed (trust-context.md
§6.5). Before this rule, n2 failed on the faulty profile: one forged copy
of Bob's phone certificate, cached by Carol's tablet, refused every root
Bob's phone signed. And for the trust-context versions an adoption by
name fetches (§6.3): a copy whose signature fails is refused as forged
(`bad-signature`) and asked for again, never taken as a version that does
not follow (trust-context.md §8.1); n1 failed so before.
A duplicated packet is idempotent: a version, group member, grant,
members record, summary, head, ask or answer delivered twice is taken
once, reported to watchers once, and counted once — a duplicated ask with
a wrong proof spends one try, a duplicated join spends the code once. A
delayed or reordered packet is judged by what it signs, never by when it
arrives (§17): a version arriving before what it depends on waits for it.

## 19. Introductions — slice 6

A stranger who holds only a code joins a folder: no second gesture by the
owner, no prior trust either way. The owner's device makes a one-use
**offer** and shows its **code**; the joiner's device sends an **ask**
sealed to the offering device, proving the code's secret bound to its own
key; the offering device **answers**, admitting the asker into the
folder's members record, and each side's host adopts the other's anchor.
Records are log entries (§4); the ask and the answer are packets named
under the offering device (§16.1).

### 19.1 Records

An **offer** (`IntroOffer`) is an entry in the offering device's log about
the folder `F` it offers, `<D>/32=log/<F>/seq=<n>` — the offer's name. It
carries `F`; the `Role` it grants (0 reader, 1 writer); its expiry
(`KeepUntil`, judged by the offering device's clock); `Tries`, the number
of wrong tries of one asker key that close it to that key (at least 1);
the commitment to its secret (`Digest`, §19.6); and the offering device's
`SealKey` (§9), to which asks are sealed. `F` MUST be a folder of the
offering device's namespace (the device signs its members records, §6).
Nothing secret is in it: the secret is in the code only.

A **use mark** (`IntroUsed`) is an entry in the offering device's log
about the same folder naming the offer and either the key the offer was
used by and its public key's digest (`Writer`, `Digest`) — the offer is
used — or neither — a **closing mark**: the offer is closed for good, to
everyone, its user too (all askers' wrong tries at the device's cap,
§19.4; `close_offer`, §19.2; or a record it signs removing the member the
offer brought, §19.7). The
first mark naming a key stands and a device signs no second one; a closing
mark closes the offer whenever it comes, used or not, and a device signs
one at most. Only the offering device marks its offer: a reader takes an
offer or a mark only when a device of the folder's own namespace signed
it, and a mark only when the device that signed it is the offer's.

The offering device keeps in its store, each under a local name no device
serves: the offer's proof key (§19.6), wrapped to its own recipient key
(§9); the wrong tries of each asker key, by its public key's digest; the
wrong tries counted toward the overall cap and when the last was counted;
while a use is under way, the key it is for (§19.4); and once used, the
acceptance it answered. It keeps no secret.

### 19.2 Offering

`offer(F, {role, until, tries})` on a device of `F`'s namespace whose
members record of `F` is held:

1. MUST refuse `F` of another namespace (`NotOwner`), `tries` = 0 or an
   expiry already past by its clock (`BadRequest`), a folder without a
   held members record (`BadRequest`: share it first), and a host without
   an introducer (`Local`, naming the setting).
2. Draws a fresh 16-octet secret from the device's entropy, wraps the
   proof key into its store, signs the offer into its log.
3. Returns the code only once the offer and the wrapped proof key are
   durable (§4.2): before, a power loss could take the record and give its
   seq to another.

The **code** is a trust-envelope `intro` link
([trust-envelope.md](trust-envelope.md)): the inviter's namespace, its
anchor fingerprint (SHA-256 of its root anchor's public key), the offer's
name, the secret, and as many relay hints — the relays the inviter's trust
context advertises, by device name — as keep the link within one QR code;
the secret, the offer and the fingerprint are never dropped. The same code
as **words**: the offer's name, then 24 BIP39 English words encoding the
secret followed by the fingerprint's first 16 octets (its checksum catches
a mistyped word).

`close_offer(offer)` on the device that made the offer signs its closing
mark and returns once it is durable: every ask of the offer is then
refused `Closed`, its user's too; what the offer granted stays until a
members record removes it. Another device's offer, or a name that is no
offer held, is `BadRequest`; closing a closed offer does nothing more.

### 19.3 Joining

`join(code)`, the link (or its https mirror) or the words. A namespace the
code names is judged first, as in step 4, before anything is fetched or
asked:

1. Fetches the offer as `<D>/32=held/<offer>` (§16.1; DigestSha256, so the
   joiner's forwarder needs no trust of the inviter), `D` the offer name's
   device. No answer after its retries: `NotReady` (`RetryLater`): the
   inviter is offline or unreachable, and the offer waits until its
   expiry. A held packet that is not the offer's record: `Unknown`.
2. Sends the ask, the Interest `<D>/32=intro/<ParametersSha256Digest>`
   whose ApplicationParameters are one `IntroAsk`: `AskBody` — the offer, a fresh
   nonce, the ask proof (§19.6) bound to its own key and its digest, its
   credentials (its namespace's signed trust context, as its host gives
   it, then its key's certificates up to that context's anchor) and its
   proof packet `<J>/32=ask/<binding>` signed by its key, the binding
   SHA-256 of the intro-ask label (§16.1), `D`'s Name TLV and the body's
   fields before it — sealed:
   a fresh content key wrapped to the offer's `SealKey` and the body sealed
   under it, both binding `<D>/32=intro` (its Name TLV) as associated data
   (§9's primitives). Before sending, the joiner checks that its own
   credentials verify its proof packet (else `Local`: its enrollment is
   broken). It sends the same Interest again on no answer, then answers
   `NotReady` as in 1.
3. Takes the answer, a DigestSha256 Data of the ask's name whose Content is
   an `IntroAnswer`. A refusal is reported as it is (§19.5). An acceptance
   MUST pass every check, else the join answers `Forged` (`RetryLater`) and
   adopts nothing: it names the offer, this device's key and its digest;
   its `Proof` verifies under the proof key the code's secret yields; its
   credentials open (§19.4, step 2) to a context whose anchor fingerprint
   is the code's (whole, or its first half for words), whose namespace is
   the code's (when it names one) and a prefix of `D`; the inviter's proof
   packet `<D>/32=ask/<binding>`, the binding SHA-256 of the intro-answer
   label (§16.1) and the answer's fields before it, and the offer record
   are both signed by a key of `D`
   that chains to that anchor through those certificates; the offer's
   commitment is the code's secret's; the folder and role are the offer's.
4. **The inviter's namespace is no other's**, judged by this device (the
   words name none, so it is judged here for them too): not the root, not
   one the policy refuses (`Config::intro`, §19.4 step 10), not this
   device's own namespace nor under or over it, not under or over any
   namespace this device trusts, and not one it trusts under another
   anchor (the same namespace under the same anchor is a party it knows:
   joining a second folder of theirs). Else `InviterConflict { inviter,
   why }` (`AskOwner`: do not use the code), and nothing is adopted: a
   stranger's code can never make this device trust a name it trusts
   already, nor names under or over it.
5. Has its host adopt the inviter's anchor (an inline anchor link of the
   context the answer carried, `Introducer::adopt`); a refusal is `Local`
   (fix the host and join again with the same code: the same key asking
   again is answered again). A self-certifying inviter namespace
   `/user/<h>` not held is adopted from its genesis by name, never from the
   credentials (trust-context.md §4.5.3: the host fetches version 1 and the
   newest; a version 1 the credentials carry only checks against the
   fetched one, a different one refused as a fork; with no network to
   fetch over, the host refuses, saying to join again once the inviter's
   devices are reachable), so the credentials only count if
   they are that namespace's: every anchor they carry MUST then be an anchor
   of the context the host holds for it (by public key), else
   `InviterConflict` (`why`: its credentials carry anchors its namespace,
   adopted from its genesis, does not hold). For any other namespace the
   host adopted these very credentials, or holds the namespace already.
   Then, for every namespace, the inviter's proof packet and its offer
   entry are checked again by this device's validator — by the context it
   now holds (its anchors, schema and revocations), through the
   credentials' certificates — and MUST still be signed by the key that
   signed them under the credentials, a device of the inviter, else
   `InviterConflict` (`why`: it answered with a key its namespace, as
   this device holds it, does not certify). Takes into its
   validator the certificates on
   the chain from the key that signed the inviter's proof packet to its
   anchor, named under the inviter's namespace — no other certificate the
   answer carries — follows `F` (§15, `watch`'s first look), and goes on
   with 6.
6. **Returns only once the joiner may write** (round 4). A device an
   acceptance admitted as a writer notes durably, in its store, that it was
   admitted to the folder (the note is local, never served), before step
   5's look; the note lasts until a members record held admits the device
   (a write went through, or `join` returned), so a put in that window is
   `NotReady`, never `AskOwner` (§18.1). It then waits, for at most
   `Config::first_look * 3 + Config::lifetime` (the bound of every wait of a
   join), for the two things a write needs: the members record over `F`
   that admits it — for a writer role, one that lists its key as a writer;
   for a sealed folder, one whose audience admits its device — and, sealed,
   the key of the epoch it seals in (the grant, §9). While the record is
   missing it walks the summaries of the devices known to write into the
   inviter's namespace and the inviter's own, in the background; while the
   key is missing it asks for the grant (§9); neither wait ends the other's
   asks. `Ok(Joined)` therefore means: the offer answered **and** both
   are held, so a put in `F` is refused for want of neither. When the bound
   passes: `NotReady { name: F, why }` with next step `RetryLater`, `why`
   naming which is missing ("the members record of `F` is not held here
   yet", "… held here does not admit this device yet", "the epoch key of
   the folder (its grant) is not held here yet") and what to do: join again
   with the same code, or put again; both are safe. **`join` is idempotent
   for the same code**: a second call by the key an offer admitted asks
   the offer again, which answers it as it answered the first (§19.4: the
   same key asking again is answered again, and a closed offer still
   answers the writer it admitted until it expires, §19.2), and then waits
   for the same two things; it never
   answers "already used" to the device it admitted. A reader waits for the
   record over `F` and, sealed, the key, the same.

Absent a dial that succeeded, the joiner's Interests carry a
ForwardingHint: the relays the code names, else those its own namespace's
trust context advertises; none, routed by name. Hints only reach (§19.7).

### 19.4 Answering

The offering device answers an ask of its own name in its own task, one
ask at a time (so a use, a counted try and a closing mark each see the one
before), keeping each answer by the ask's name: the same ask asked again
gets the same answer while it is kept, and a refusal or an answer is never
computed twice for one ask. A crowd of asks is bounded: the device holds at
most `Config::intro.asks_queued` asks at once (32 by default), verifying or
waiting for their turn — one more gets no answer at once (a Nack), says so
in its log, and its asker retries — and opens and verifies at most
`Config::asks_verifying` at once (8 by default, the bound hold and audit
asks' proofs share, §13), before any unwrapping. It
checks, in this order:

1. **It opens**: the name's digest is its parameters', the content key
   unwraps with its recipient key and the body decodes, under
   `<D>/32=intro`. Else no answer (a Nack): nothing to address a refusal to.
2. **Its credentials parse**: a trust-context Data whose signature
   verifies under one of the context's own anchors, valid now
   (`SignedTrustContext::open_received`), then certificates (at most 8);
   the claimed key — the proof packet's KeyLocator — is an anchor of the
   context (a key that is its own anchor) or has a valid certificate among
   them. Else no answer.
3. **The offer is its own and known**: named under this device, an offer
   record it holds, its proof key in its store. Else `Unknown`.
4. **Not closed**: no closing mark, and fewer wrong tries counted toward
   the overall cap than `Config::intro.wrong_tries_max`. Else `Closed`.
5. **The asker's key chains to the anchor it sent**: the proof packet,
   named `<J>/32=ask/<binding>` for this ask, verifies by a validator that
   holds the presented context alone and the presented certificates (the
   hierarchical schema and certificate validity checked), signed by a key
   of `J`. Else no answer: a forgery, or a broken enrollment the joiner's
   own check (§19.3, step 2) reports.
6. **Not used by another key**: a use mark — or a use under way that a
   stop interrupted — naming another key or digest is `Used`; nothing is
   counted. Used by this key, it answers the acceptance it kept for the
   use, and does nothing else: no step below runs again, no anchor is
   adopted and no members record is signed — a namespace a later members
   record removed is never added back by its code.
7. **Not expired**: its expiry is after this device's clock now. Else
   `Expired`.
8. **The asker's tries are not spent**: fewer wrong tries of this key
   counted than the offer's `Tries`. Else `Closed`.
9. **The proof is right** (§19.6), for that key and its public key's
   digest. Else the wrong try is counted against the key, and toward the
   overall cap once the pause after the last one counted there has passed
   (`Config::intro.backoff`, 1 s by default, doubled by each counted, by
   this device's clock); both made durable before the answer. At the
   overall cap the device signs the closing mark, durable before the
   answer, and answers `Closed`; at the key's `Tries`, `Closed`; below,
   `WrongProof { left }`, the key's wrong tries left.
10. **The asker's namespace is no other's**: a prefix of `J`; not the
    root; not one the policy refuses — fewer components than
    `Config::intro.min_components` (1 by default: `/alice` is a person's
    namespace, the root never), equal to, under or over a name of
    `Config::intro.reserved` (by default `/localhost`, `/localhop`: scopes,
    never a person's), or equal to or over a name of
    `Config::intro.shared` (by default `/user`: its `/user/<hash>` names
    are people's, so `/user/<hash>` is fine and `/user` is not); not the
    inviter's own nor under or over it; not under or over any namespace
    this device trusts; and not one it trusts under another anchor. The
    same namespace under the same anchor is a party it knows already, and
    is not refused. Else `Conflict` (`FixLocal`).

Then the use. The device notes durably in its store the key the use is
for; has its host adopt the asker's anchor (an inline anchor link of the
presented context; a self-certifying asker namespace is adopted from its
genesis, as in §19.3 step 5, and then every anchor of the presented
context MUST be an anchor of the context the host holds for it, by public
key, else `Conflict`); checks the asker's proof packet again by this
device's validator — by the context it now holds for the asker's
namespace, through the presented certificates — which MUST find the same
key, else `Conflict` (a key the held version revokes, shown with an older
version, does not ask); takes into its validator the certificates on the
verified chain from the asker's key to its anchor, named under the asker's
namespace, and no other presented certificate; and signs the folder's next
members record adding the asker's namespace as a writer (a writer's role)
and as a reader (when the folder is sealed), unless the record in force
already admits it so — a change of the record in force, applied when it
signs (`share_folder`, §6.1), so a let-go signed meanwhile stays and the
host is told the new record (`Change::Members`, §15). If the adoption or the record
fails, or the anchors are refused, it drops the note durably — the offer
is not spent — and gives no answer to a failure, `Conflict` to refused
anchors; the joiner's retry is judged again. Else it keeps the acceptance
in its store and signs the use mark naming the key and digest, and answers
only once both are durable. A stop after the note and before the mark
leaves the offer to that key: its retry runs the use again (step 6 lets no
other key in). The acceptance names the offer, the asker's key and digest,
the folder, the role, the inviter's credentials and the inviter's proof
packet, and carries the answer proof.

### 19.5 Refusals

`DataError::Introduction { offer, why }`:

| `why` | When | Next | Retry |
|---|---|---|---|
| `Unknown` | the offering device holds no such offer | `AskOwner` (a new code) | no |
| `Used` | another key joined with this offer | `AskOwner` | no |
| `Expired` | past its expiry by the offering device's clock | `AskOwner` | no |
| `Closed` | closed for good, even to the right secret: this key's wrong tries spent, all askers' at the device's cap, `close_offer`, or the member it brought removed by a record the offering device signed | `AskOwner` | no |
| `WrongProof { left }` | the proof of the secret is wrong; counted against this key, `left` more allowed it | `FixRequest` (check the code) | no |
| `Conflict` | the asker's namespace overlaps the inviter's or one the inviter trusts, is one it trusts under another anchor, or one the policy refuses (§19.4 step 10); or, for a self-certifying asker namespace adopted from its genesis, the presented credentials carry an anchor the held context does not; or the asker's proof does not verify under the context the inviter's device holds (a key it revokes, shown with an older version) (§19.4, the use) | `FixLocal` (renew the device's certificate when it is the last) | no |
| `InviterConflict { inviter, why }` | the joiner refuses the inviter's namespace (§19.3 step 4; never on the wire): `why` says what it overlaps; or, for a self-certifying inviter namespace adopted from its genesis, the answer's credentials carry an anchor the held context does not; or the inviter's proof or offer entry does not verify under the context the joiner holds (§19.3 step 5) | `AskOwner` (do not use the code) | no |
| `Forged` | an acceptance fails a check of §19.3, step 3 (never on the wire) | `RetryLater` | yes |

The inviter unreachable is `NotReady { name: <offer> }` (`RetryLater`): the
offer waits. A code that does not parse is `BadRequest`; a host without an
introducer, or one that refuses an adoption, is `Local`.

### 19.6 Cryptography

Audited RustCrypto primitives only. The secret is 16 octets from the
device's entropy (the operating system's by default). The commitment is
SHA-256(`ndn-data/intro/commit/1` ‖ secret). The proof key is
HKDF-SHA256 with the secret as input keying material, no salt, and as
info `ndn-data/intro/proof/1` ‖ the offer's Name TLV: an offer's key opens
no other offer. The ask proof is HMAC-SHA256 under it over
`ndn-data/intro/ask/1` ‖ the offer's Name TLV ‖ the asker key's Name TLV ‖
its public key digest ‖ the nonce; the answer proof, over
`ndn-data/intro/answer/1` ‖ every field of the acceptance before `Proof`.
Proofs are compared in constant time. Asks are sealed with §9's
X25519-to-ChaCha20-Poly1305 wrap.

### 19.7 Threat notes

- **Code theft.** The code is a bearer secret until used: whoever presents
  it first, within its expiry, joins with its role. One use binds it to one
  key (step 6); the owner sees who joined in the folder's members record
  and removes them as any member (§6). The removal lasts: a used offer's
  user asking again — a fresh ask, before or after a restart — is answered
  the acceptance kept for its use and never admitted again (step 6), and
  no other key can use it, whichever owner device removed the member. A
  folder record the offering device signs removing a namespace also closes
  every offer of that device a key under it used (or was using), so even
  its acceptance is no longer answered; a record another device signed
  closes nothing (only the offering device marks its offers).
  `close_offer` closes an offer at any time. Keep expiries short.
- **Replay.** An ask replayed by anyone gets the answer kept for it: bound
  to the asker's key and digest, it admits only the asker's namespace,
  which the record already admits; it shows the replayer the folder's name,
  the role and the inviter's public credentials (the answer is not sealed).
  A replay after the inviter's device dropped the kept answer is judged
  again: a used offer answers its user's kept acceptance (admitting
  nothing) and anyone else `Used`, counting nothing; an unused one counts a
  wrong try again against the replayed key (when it was one).
- **Forged asks.** An ask without the secret fails step 9 and is counted;
  it cannot be turned into another key's membership: the proof binds the
  offer, the key, its digest and the nonce. One without valid credentials
  costs one signature check and gets no answer.
- **Offline guessing.** The offer and its commitment are public; the
  secret has 128 bits, so neither the commitment nor an observed proof can
  be searched for it.
- **Offer names are public.** An offer is an entry of the offering
  device's log: served to anyone who asks for it by name, and listed in its
  summaries. Anyone can thus ask with it.
- **Tries brute force.** Wrong tries are counted durably, across restarts,
  per asker key: past the offer's `Tries` it is closed to that key for good,
  even to the right secret. A stranger spends only its own tries — it
  cannot close an offer meant for someone else — and a used offer counts no
  tries at all. Anyone can make new keys, so all askers' wrong tries are
  bounded too (`Config::intro.wrong_tries_max`), counted with a backoff
  that doubles after each (`Config::intro.backoff`): at the cap the offer
  closes for everyone, a denial, never an admission, and reaching it takes
  strangers about `backoff` · 2^`wrong_tries_max` (some 18 hours by
  default), past any short expiry. Online guessing gains nothing: each
  guess is one in 2^128.
- **A crowd of asks.** Each ask costs an unwrap, an AEAD open and a
  signature check before it is judged; at most `Config::asks_verifying`
  are opened at once, and past
  `Config::intro.asks_queued` held an ask gets no answer at once, so a
  crowd costs bounded work and memory and delays honest asks only until it
  ebbs.
- **Inviter impersonation.** An acceptance must prove the secret and be
  signed by the offering device under the anchor whose fingerprint the code
  carries (128 bits of it in the words form); a party that served a
  substituted offer and opened the ask learns the joiner's public
  credentials, cannot answer as the inviter, and can at most relay the ask
  to the real inviter — whose answer admits exactly the joiner. A refusal
  is not authenticated: a forged one denies, never admits, and an on-path
  party can deny anyway.
- **Joiner impersonation.** The asker's key must chain to the anchor it
  presents, and a namespace already trusted under another anchor, one
  under or over any namespace the inviter trusts or its own, the root, or
  one the policy refuses is refused (`Conflict`): a joiner cannot speak for
  a namespace the inviter knows, take over a name under one (a device name
  of a person the inviter trusts, whose validation would then pick the
  joiner's longer context), become the trust root over the shared `/user`
  or a scope, nor shadow names of the inviter's own. A joiner can claim any
  namespace that overlaps none the inviter trusts — that is what a
  stranger is; the owner sees which one joined. A broad one (`/com`) is
  the joiner's root over every name under it the inviter does not trust
  yet, and a later introduction under it is refused `Conflict` while this
  device trusts it: a deployment whose people's namespaces sit under such
  a prefix lists it in `Config::intro.shared`.
- **Inviter impersonation of a namespace the joiner trusts.** A code is
  made by anyone. The joiner judges the inviter's namespace as the inviter
  judges the joiner's (§19.3 step 4) before it adopts anything, so a
  stranger's code cannot replace the anchor of a namespace the joiner
  trusts, nor claim one under or over it (`InviterConflict`).
- **Reuse across the inviter's devices.** An offer is answered only by the
  device that made it, which alone holds its proof key; another device of
  the inviter answers `Unknown`. The use mark is in that device's log, so
  every device of the inviter sees the offer used.
- **Clock.** Expiry, and the overall cap's backoff, are judged by the
  offering device's clock alone: a slow one keeps an offer open longer and
  counts toward the cap more slowly, a fast one closes it early and counts
  sooner; no other
  decision reads a clock, and certificate validity in the credentials is
  checked as a live exchange (§8.5).
- **Unauthenticated hints.** Relay hints in the code, or the joiner's own
  namespace's relays, are reachability only: a lying hint fails to reach,
  and nothing a relay carries is trusted — the offer, the ask and the
  answer are judged by the checks above.

## 20. Signals: the gate — round 4

A **signal** is ephemeral live data — presence, cursors, a drag, live
unsigned edits — pushed to the members of a folder or collection. It is
never a version. Its transport (run keys, packets, sealing, the push into
sync groups, the local ring, replay and expiry) is
[signals.md](signals.md); this section is what the data layer decides for
it, and the six questions the transport asks a device
(`Device::signal_scope`, `signal_header`, `signal_sender`, `signal_admit`,
`signal_member`, `signal_revocations`). Nothing else of the layer is
reachable from a signal.

- **The record in force over a scope.** A scope `S` is a folder or
  collection name (§16.1). The record in force over `S` is what `members`
  answers for it (§15): the folder `S`'s record in force when one is held;
  else collection `S`'s, its own narrowed by the folders above it, or the
  nearest folder's when it has none (§6.1). Nothing about signals over `S`
  is decided while none is held.
- **Members.** A key `K` of device `D` (`D` is `K` without `KEY/<id>`) is
  a **member** of `S` exactly when, by the record in force over `S` at
  the moment of the question, a writer prefix it lists covers `K`, or its
  audience admits `D` (§9: a reader names `D`'s person — the namespace of
  the trust context governing `D` here — or `D`, or a group whose record
  names either; or `D` started the record's epoch); and the trust context
  governing `K` — as the device judges `K`'s packets about `S`, so the
  context adopted for the folder for a person's namespace adopted there
  (§6.3) — does not revoke `K` (trust-context.md §3.3.6, §6.3). A key
  kept only by a removal cut (§8) is no member: a cut keeps versions, not
  a voice.
  In a scope with no readers listed only the writers are members. A
  device MUST answer membership from the records and contexts it holds at
  the question, with no network exchange, so the transport asks it for
  every packet: a member removed, or a key revoked, is refused from the
  first packet after the device holds the record or context that ends it.
- **The gate.** `signal_scope(S)` answers, for this device: the record in
  force over `S` (as a `Share`); the signal keys when `S` is sealed; the
  sync groups to push into; and this device's own namespace's group
  `sync_group(<own namespace>)`, where others push for it. It refuses with
  `NotReady` (retry) when no record over `S` is held; `NotAllowed` (ask
  the owner) when this device's key is no member of `S`, its key revoked
  included; `Sealed` when this device is a member only as a writer outside
  a sealed scope's audience, which may never hold its key; and `NotReady`
  when `S` is sealed and the key of its epoch in force is not held yet —
  its ask is then started as a sealed read's is (§9, §17.1: the epoch's
  creator, then the devices that write into it) and the same call
  succeeds once the key is granted. `signal_header` refuses as
  `signal_scope` does, except that a sealed scope's key need not be held
  to sign a header.
- **The groups.** The groups of `S` are `<O>/32=sync` for exactly the
  namespaces a version about `S` is published into (§12): `S`'s own, and
  that of every writer and reader the record in force over `S` names — a
  self-certifying namespace only once adopted here for the folder (§6.3),
  a group reader by the namespace of its collection.
- **Signal keys.** In a sealed scope, the signal key of epoch `E` (its
  creator `D`, its seq `s`) whose content key `CK` this device holds
  (§9) is HKDF-SHA256 with `CK` as input keying material, no salt, and as
  info `ndn-data/signal/1` ‖ the Name TLV of `S` ‖ the Name TLV of `D` ‖
  `s` as 8 octets big-endian; 32 octets. Its **id** is the first 8 octets
  of HKDF-SHA256 with the signal key as input keying material, no salt,
  and info `ndn-data/signal/id/1`. Every member holding `CK` derives the
  same key and id; the key binds `S`, so it opens nothing of another scope
  sealed in the same epoch, and nothing of the layer's own payloads (their
  key is `CK`, never derived from a signal key). `signal_scope` lists the
  key of the epoch in force first — the one to seal with — then those of
  the other epochs of `S`'s record line whose content keys are held, by
  their record's seq, highest first, to open what members still seal in
  them across a move to a new epoch; the transport opens with an earlier
  epoch's key only for a grace after it first sees that epoch superseded
  (signals.md §4.2), so a removed member's old key soon opens nothing. The
  content key never leaves the device; the signal key is handed to the
  transport, which zeroes it when dropped.
- **Run headers.** A run header is Data named
  `<D>/32=signal/<S>/32=run/<run id>` (§16.1), `D` the device whose key
  signs it, the run id 16 octets, its Content the transport's run header
  body (signals.md), signed by `D`'s device key, with no FreshnessPeriod.
  It is named under its signer's device, as every signed packet of the
  layer is, so the trust context governing its name is the signer's.
- **The sender.** `signal_sender(S, header)` answers a run header's signer
  before anything is verified — its key name, its device and its
  namespace (the one whose group the device notices in, §12, else the
  device itself), which the transport bounds admissions and runs by —
  exactly when: its name parses as a run header (§16.1) whose scope is `S`
  and whose device is the device of the key its KeyLocator names
  (`Malformed` otherwise); a record over `S` is held (`NotReady`
  otherwise); and its key is a member of `S` by the record in force
  (`NotMember` otherwise; `BadSignature` for a key the context governing
  it revokes). It is synchronous and offline, so a stranger's header costs
  a receiver nothing more.
- **Admission.** `signal_admit(S, header)` admits a run header, answering
  its sender, exactly when `signal_sender` does; it verifies by the
  device's validator — the view adopted for the folder for a
  self-certifying member's (§6.3) — by the **live** rule
  (trust-context.md §6.3: certificates valid by the device's clock, a
  revoked key or issuer refused; a header is never kept, so nothing needs
  a durable verdict) (`BadSignature` otherwise); and its key is still a
  member once it verified (`NotMember` otherwise). The chain is walked from
  the certificates held first. A certificate not held is fetched only
  while fewer than 2 headers of the signer's namespace wait for
  certificates here, and not for 30 s for a device whose last fetch for a
  header brought none, whatever key id its next header names
  (`Unverified` otherwise, or when no current certificate could be had:
  ask again when the header rides again). Each refusal's text says why and
  what to do.
- **Revocations.** `signal_revocations()` is a count that moves whenever
  a trust context revoking keys is adopted here: the device's own
  (its keyring's revocation epoch), or a view adopted for a person's
  namespace replaced by a version that refuses more (§6.3). A transport
  that admitted headers under one count and reads another walks their
  chains again, so a revoked issuer ends the runs of the keys it
  certified (signals.md §7).
- **Nothing kept.** A device MUST NOT store, serve, count or list anything
  of a signal: no run header is kept in the store or a summary, given a
  seq, counted as a version, a write or a holder's evidence, or answered
  to an Interest, and no signal packet reaches the layer at all. A signal
  never becomes a version; a commit of live work is an ordinary `put`.
