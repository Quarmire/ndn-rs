# Data layer: named, signed, versioned data

- **Status:** Slices 1–3, 5 and 6 normative, with the durability barrier (§4.2:
  nothing published before it is on disk) (slice 6, the substrate for ndf-rs, B
  and C: the built-in newest register as the one merge rule, named by its
  exact versioned name and written by `put_op`, folder
  members records narrowing every
  collection under a folder with one seal epoch per folder epoch, and
  joining a folder by a code (introductions, §19), §5,
  §6.1, §6.2, §9, §13, §15, §16, §19); slice 5: a revoked key's versions kept
  exactly where the root's revocation cut in the trust context accepts
  them, the cut bounded by when the owner says the key was lost and bound
  to the key and to each version's bytes, Data judged without clocks or
  validity periods except that a lapsed guest fails closed until its cut,
  re-admission of exact versions, late revocation withdrawn, issuers
  re-checked, renewal, rotation and recovery, §8.1–§8.6); slice 3: large payloads in
  pieces, §13);
  slices 1 and 2: versions, collections with
  owner-signed members records whose writers and readers are of any
  namespace, the merge rule (the register `/ndf/merge/newest/v=1`), the log rule,
  removal cuts and the re-check when a cut arrives, seals (epoch keys and
  grants), types, signed nested summaries, the sync notice and
  its reach across namespaces, the verbs `get`, `put`, `watch`
  and `share` (adding, removing, changing the rule), and
  their wire format (§16). Sections marked with a later slice are not yet
  normative beyond what they state; a section marked *open* has no
  normative content beyond its text.
- **Scope:** the data model shared by files, databases and network
  exchanges — versions, collections, members, summaries, cuts,
  seals and types — and the four verbs over it. The Rust
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
7. **Retention is chosen at write.** The keep is `Forever`: no device drops
   a version for its age.
8. **Nothing is lost by not understanding it.** A writer MUST keep every
   field it does not know.
9. **Forward-only, said plainly.** Revocation and deletion stop future
   reads; an implementation MUST NOT claim to recall copies already made.

No validity decision may accept anything because of a wall clock, nor
compare a certificate's validity period with one, with one exception that
can only refuse: a key of a role the trust context lists in DataRequiresCut
(every role, by default) whose certificate lapsed is refused until its
revocation cut is held (§8.5). Dates are display only. The root device's
own clock also bounds which entries it puts in a cut it makes (§8.1); a
reader never reads it.

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
- `put`, `get` and `share` take collection names; `watch` takes
  a collection or folder name (`<O>/32=data[/<path>]`): a folder's watch is
  one stream for every collection under it, those created after it began
  included, each change tagged with its collection (§15). A verb given a name
  that is none of these — no marker, nothing before it, nothing after it
  where a collection is asked for, or another keyword or digest component —
  answers `BadName`, saying which and how the name must be formed
  (`NextStep::FixName`). `get` also takes log entry names.
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

## 4. Version and log — slices 1, 2

A version is an immutable record signed by one key. It carries
`(writer, seq)`, parents, type, seal, keep, a date and a payload.

- A writer is one key, never a person. Each key keeps **one log**: every
  entry it signs about any collection — versions and members records (§6) —
  takes the next sequence number of that log. `seq` MUST
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
  before it is reported. A cut accepts a seq only in the
  collection it lists it under (§6.1, §8, §8.1), so a removed or revoked
  key gains nothing by signing an accepted seq again elsewhere. An entry
  the trust context refuses (§8.1) is no evidence against its key: a copy
  of a revoked key wrote it.
- **What two entries are.** Two packets are different entries of a key when
  the digest of their signed region — the Name through the `SignatureInfo`,
  not the signature value — differs (ndn-data: `wire::signed_digest`). A copy
  that differs only in its signature value is the same signed object and is
  never equivocation: no second packet is stored and no `Change::Equivocation`
  is told. ECDSA signatures are malleable in the
  signature value (`S` and `n - S` verify under one key and content;
  signers that randomize give another value for each signing; OpenSSL,
  ndn-cxx and python-ndn do not normalise `S`, and neither does ndn-data's
  own P-256 signer, which keeps whichever `S` its RFC 6979 computation
  gives, so about half of its signatures are high-S), so a verifier that
  refused high-S would refuse valid packets of other implementations and
  this one does not: **acceptance is malleable in the signature value for
  ECDSA, and nothing may depend on it.** An object named by an implicit
  digest names exact wire bytes: a high-S sibling is another implicit digest
  of the same signed object and is never evidence against the key. The
  implicit digest is the identity of a packet's bytes (a tip's `Digest`, the
  bytes a removal cut lists, §8), not of what a key signed: nothing that
  decides whether a key signed two things reads it. A relay, or a
  re-signing device, cannot make a key equivocate by changing the signature
  value.
- Parents are the frontier (writer → highest seq) of the collection's state
  the writer had applied when it wrote (§5), each **tip** `(y, t)` bound
  to the implicit digest of `y`'s packet at `t` (`Digest` in its
  `FrontierEntry`, §16.2). A seq alone names a packet that may not exist
  yet; a digest only a writer that held the packet can name. In a merge
  collection every parent carries one; under the log rule a
  writer names it when it holds the tip.
- A merge version names the rule its operation was made for (`Rule`,
  §16.2); a reader applies it only under that rule (§5).
- The date is the writer's clock reading in milliseconds since the Unix
  epoch. A reader MUST NOT use it to accept or refuse anything.
- The payload of a version is the fields the writer set (§10) under the
  log rule, or the register's bytes (`MergeOp`, §5) in a merge collection.
- The seal a version carries is the collection's readers at the time of
  writing, as the writer declares it. In a sealed collection (§9) the
  payload travels encrypted (`Sealed`, §16.2) under the key of the epoch
  the writer's newest members record names; everything else in the record
  stays readable. The keep a version carries is `Forever` (§16.2).

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
writer do not wait for a version so refused (§5).

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
  - serve a summary root, node or page listing
    anything above it: what it serves of its summary is what the
    log up to its durable head fixes (§7);
  - announce in a sync group (§12) before the entries the announcement
    covers are durable; the counter it announces is itself stored before,
    and durable when it goes out;
  - grant the key of an epoch it started before the record starting the
    epoch is durable (§9).
- **Local application is immediate.** `put` and `put_op` return
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
  published. A summary's content is fixed by the log up to its head
  (§7); a group counter is durable before it is announced (§12).

Why this suffices: each engine recovers to a prefix of its writes (fjall
replays its journal to its last whole batch; each redb write is its own
transaction, committed with fsync), so after a power loss the store is as
it was at some moment at or after its last returned barrier, and a device
restarted on it is that device stopped at that moment — which restore
already handles (§8.3). Everything it published was at or below the
durable head, so behind the barrier, so held. A batch is applied whole on an
atomic store, so the same holds of every put; on one that is not,
the order of the batch leaves only prefixes restore accepts.

**One batch per put (store write batching).** The writes of one put go to
the store as one `DataStore::apply`, not one call each: the markers (the
written marker, saying this device signed the entry, and the verified
marker), the pieces of an entry larger than a packet, then the entry
itself; a commit round's
announcement counters likewise. A device MUST hand a batch to the store
before the `put` that made it returns, and MUST NOT defer it to a
background writer: the guarantees above (a write that returned survives
`kill -9`) hold for the batch as for a single write. A device MUST write
a batch in the order markers, pieces, entry, and records before the
versions that need them, and the key of an epoch that a members record
starts (made by this device) before the record that names it; and MUST
apply the batches of puts in the order
the puts numbered their seqs, so publication, which follows the log head
read under the same lock, follows put order. A batch changes nothing
about publication: what a batch holds is published only after a barrier
that began after the batch was handed over has returned. A store MAY
apply a batch atomically (all of it survives a kill and a power loss, or
none of it; `BackendStore` over fjall, redb and the memory and flash
backends does), and one that cannot MAY apply it one write at a time in
order (the default); the order above is what makes that safe. A read by
prefix that a device makes while a batch is open MUST answer as the store would
with the batch applied (what the batch stores appears, what it removes
does not, in the store's order) and
MUST NOT hand a part of the batch to the store: a batch is one `apply`
whatever it reads. A device
never needs one write of a put durable before another: the barrier makes
all of the put durable at once. The announcement counter is the one write
that does have to precede a barrier: it is applied by the commit round
before the barrier it announces, and the announcement is sent after the
barrier returned, as before. No further coalescing of barriers is
specified: a burst of puts already shares a flush per round.

Measured, not guaranteed (ext4 on NVMe, release build, medians; one put at
a time, before and after batching): redb `put` 1.74 ms and 0.71 ms; fjall
`put` 146 µs and 155–168 µs (59.7 and 55–60 µs back to back), unchanged
within noise, a put on a store that costs nothing being 49 µs: on fjall the
writes were never most of a put. Batching is there for atomicity, and for
engines that pay per write.

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
- A batch cut short (a kill, a failing disk) on a store whose `apply` is
  atomic leaves none of it: the restarted device finds the log as before
  the put, and signs that seq afresh; nobody saw the cut put (it was not
  durable, so not published). On a store that applies a batch one write at
  a time, a prefix of it is what is left, and the order of the batch
  (markers, pieces, entry last, and the key of an epoch before the record
  that starts it) makes every prefix a state restore accepts:
  a marker or a piece with no entry is ignored or dropped, never an entry
  taken for another writer's. A store that returns from `apply` having kept
  only some of the batch, or that reports a batch durable before it is,
  defeats the barrier as a disk that lies about a flush does (first note).
  A key stored without its record is no authority: restore takes a stored
  made key only if a held members record names its epoch and its key check
  matches, and ignores it otherwise; it is one small entry per cut put on
  such a store (none on an atomic one), overwritten if that seq is signed
  again. The reverse state, a record this device made without the key it
  made for its epoch, which left the creator unable to write into the
  collection (`NotReady`, no other device having the key), is never left.

## 5. Collection and rule — slices 1, 2, 6 (the register)

A collection is a named, growing set of versions with a rule and a members
record. It exists when its first members record is signed (§6): `share`, or
a writer's first `put` (or `put_op`) into a collection of its own
namespace (§3), which signs the host's default record (merge with
`/ndf/merge/newest/v=1`, the namespace writing and reading, sealed to it). A collection
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
  only, its rule the register), even under a folder whose record this
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
  earlier one, no version of it applied, no members record
  naming it) once its walks spent their tries with no root of it verified
  — `REFRESH_TRIES` (16) walks of one refresh loop (§17.1) whose root's
  rounds all missed, or no trust context held judges its roots and no
  record held lists its person (§6.3) —: a name a Sync Interest carried,
  or a device never reached, gives no reason to wait, and holds this back
  for those tries at most (a few minutes), however many notices of it come;
  a real device a faulty path kept from a walk or a few is still waited
  for (round 3; before, one unsigned Sync Interest naming a device that
  does not exist held `put` and `get` here until restart).
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
| log | Each member key appends; the collection is the union of exactly its members' logs. `get` returns the newest version. |
| merge | Member logs plus the one built-in merge function, the newest register `/ndf/merge/newest/v=1`, which every reader runs alike. `get` returns the register's value at a frontier. |

The collection, not the application, decides what "newest" means. A
collection's rule is the newest members record's; changing it starts the
collection again (§6).

Under the **log rule** the collection is the union of exactly the versions
its newest members record admits (§6): every member's versions reach every
reader that follows it, and a version by any other key reaches none — a
reader refuses it, and it is never delivered to a watcher. Versions are
delivered in the order of Applying versions, below. The newest of a
log collection is, of the versions applied that no other applied version
names as a parent (the concurrent heads), the greatest by `(writer key
name, seq)` — an order every reader computes alike, with no clock.

**The register — slice 6.** A merge collection is a register: it holds one
value, the bytes of its newest version, and the layer has one merge
function, built in and named `/ndf/merge/newest/v=1` (ndn-data: `NEWEST`).
There is no registry and no way to install another function; a program that
keeps many values keeps one collection for each. Every reader that applies
the same versions MUST obtain the same state.

- **Rules by name.** A members record names a collection's rule by its full
  name (`Rule`, §16.2), and a reader MUST match it by exact equality of
  names: never by prefix, by a part of the name or by the nearest version.
  By convention the last component is a version (`v=<n>`), and a change of
  meaning is a new name: every program that runs a rule under one name MUST
  compute what every other does.
- **A rule the device does not know.** A record naming any function but the
  register's (the Yjs rule of the slice-2 records included) is
  held, not computed: the device holds every version of the collection as
  it holds any version — verifies, stores and serves it, and lists it to
  `watch` with nothing applied — and answers `get(C)`, and `put` and
  `put_op` into `C`, with `RuleUnknown`, naming the collection and the rule
  (next step `UpdateProgram`: run a program that knows the rule). It MUST
  NOT compute a state of `C` under another rule.
- **Made for one rule.** A merge version names the rule its operation was
  made for. A reader refuses one that names another rule than the one in
  force, or none — unless it lies inside the record's `since` (history) —
  for good (`Refusal::OtherRule`, next step `None`: its writer, once it has
  the record naming the new rule, writes the change again under it). A
  stale writer's operation is never read under a rule it was not made for.
- **Versions supersede.** A version `v` supersedes every version in its
  **past** (below): those its writer had applied when it signed it. The
  **heads** of a collection are the applied versions in no other applied
  version's past. The register keeps the heads only, so its memory is the
  concurrent writes, never the history.
- **The value is the head with the highest digest.** The digest is the
  implicit digest of the version's packet (SHA-256 of the whole Data
  packet, §4); heads compare as 32 octets, the first most significant. Two
  devices holding the same versions read the same winner whatever order
  they arrived in, and a version made over every head settles the value
  whatever its digest: a version never loses to one in its own past. No
  clock is read — the date a version carries is display only (§4).
- **`by ‖ bytes`.** The value is `by` followed by the winner's `bytes`, the
  octets of its `MergeOp` (what `put_op` wrote, §15). `by` is 32 octets: the
  hash of the self-certifying namespace `/user/<0xA1: hash>`
  (trust-context.md §4.5) the writer's key lies under — the second
  component of the key's name, of type 0xA1 — and 32 zero octets when the
  key lies under no such namespace. A collection with no applied version
  has no value at all, no octets.
- **Removal.** A version with empty `bytes` is a removal: the value is `by`
  alone, 32 octets with nothing after them. It is the newest like any
  version — a later `put_op` over it, or a concurrent head with a higher
  digest, takes over — so a removal stands until someone puts again.
- **Check and apply.** The register reads none of `bytes` and refuses no
  operation for them; its one refusal is a version whose bytes travel in
  pieces, which a register version never does (§13.1, `Refusal::Rule`,
  next step `None`). Applying a version already applied changes nothing.
  The state is a function of the applied versions, each with its past, and
  of nothing else — never of arrival order — so a device that starts again
  reads the winner it read before.
- **Owners** (ndn-data: `wire::owns(collection, writer)`). A writer `w`
  (key `<D>/KEY/<k>`) is an **owner device** of `C` exactly when `D` lies
  under `C`'s namespace, the components before its marker (§3). It depends
  on the two names alone, so every member answers alike in any order; the
  layer's owner rule (§3) asks this same test, together with the trust
  context governing the record. A device of a longer held namespace (§3:
  a `/home/bob` device for `/home/32=data/x`) is not distinguishable from
  names alone: `owns` answers the name half — what a reader holding `C`'s
  namespace and none longer under it concludes.

**Applying versions.** A reader applies an admitted version `v = (w, s)` of
collection `C` only when

1. every entry of `w` in `C` below `s` — as `w`'s summary (§7) lists them —
   is applied, unless it never applies: the record in force refuses it by
   its key (a cut that does not list it, §8), or the trust context does (a
   revocation whose cut neither accepts nor re-admits it, §8.1, §8.2), or
   it was held and refused for what it carries (`Unsealed`, §9), and
2. for every `(y, t)` in `v`'s parents, the reader has applied `y`'s entries
   in `C` up to `t`.

Until then `v` waits. The state's frontier `at` is, per writer, the highest
seq applied; by these rules every entry at or below it that applies at all
is applied, so `at` names exactly the versions the value is computed from.
A parent `(y, t)` that never applies is needed only up to the highest
version of `y` below it that does (for a cut, removal or revocation, the
highest it accepts or re-admits): a version written on top of refused work
is not held back by it.

- **The past.** `P(v)` is `v`'s parents joined with `(w, s − 1)`, and the
  **past** of `v`, `down(P(v))`, is every version of `C` at or below
  `P(v)`, writer by writer, that applies at all: what `v` was made over,
  whatever arrived since.
- **Parents bound to packets.** Before a merge version applies, each parent
  `(y, t)` that applies at all is checked against the packet held at
  `(y, t)`: it waits while none is held, and is refused for good
  (`Refusal::Parent`, next step `None`) when the parent carries no digest or
  the packet held there has another digest. A mismatch means the version
  was not made over what this reader holds: its writer named a packet that
  does not exist, or `y` signed two packets at `t` (an equivocation;
  readers holding different packets at `(y, t)` differ there already).
  Every reader holding the same packets decides alike, in any arrival order
  and with no clock.
- **The past every reader sees.** `down(P)` holds the versions at or below
  `P` not refused by their key (a cut that does not list them, a key no
  writer, a revocation, an issuer no longer trusted), admitted, held sealed
  or held and refused for what they carry, which every reader holds before
  it judges a version over them. A version refused by its key is in no
  past, held here or not (a late reader never fetches it): it supersedes no
  version and none is made over it.

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
    audience, whose merge needs no more. The same holds of the record in
    force once a record of a revision is taken onto the one below it
    (**Across revisions**, below): it lists a reader no held record naming
    its epoch lists when the epoch kept is that of another record than the
    one adding the reader, and is then resolved in the epoch kept.
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
  applied as history only: they order later versions (§5) and never
  enter the new rule's state. A state of `C` after the change has an `at`
  covering `Since`.

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
  folders above, another meaning), or leaves a sealed folder no reader (it
  would unseal it). With no
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

**A rule withholding.** The register is code every reader runs under one
name (§5): a program whose rule behaves otherwise than another's under the
same name breaks determinism; the defence is the versioned name — a change
of meaning is a new name. Nothing it does hides a version: it reads no
bytes, so no writer's bytes make it refuse another's, and a head that
loses stays held, served and listed.

**Choosing the digest.** The winner among concurrent heads is the one with
the highest digest (§5), and a writer signs freely: it can vary its
version until its digest is the highest of the heads it knows, so its
write wins a concurrency it is part of. It does no more than any member
may — write over what it has applied — and every reader holding the same
versions reads the same winner. A write that must not lose to one it
knows is made over it.

**A stale writer and a rule change.** An operation made for one rule could
mean something else under the next. A merge version names the rule it was
made for (§4), and a reader refuses one naming another rule than the one
in force (`Refusal::OtherRule`), except history inside `Since`: a writer
that had not heard of the change loses that operation, and writes it again
under the new rule; it is never read under a rule it was not made for.

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

**Seq reuse across collections.** A writer's log is one sequence, and a
collection holds a subset of it, so a writer can sign a second entry at a
seq it used, in another collection: a new name, unseen by a reader that
follows only the first collection. Nothing that matters trusts such a
seq: a cut, removal or revocation, accepts a seq only in the collection it
lists it under (§6.1, §8, §8.1), so a removed writer cannot inject an entry
at a seq its cut kept elsewhere. Readers report any equivocation they hold
(`Change::Equivocation`), inside the folder or not.

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
readers. What a removed reader opened it keeps (invariant 9).

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

**Unknown-rule downgrade.** No one can make a reader compute a collection
under another rule than the one its record names: names match exactly,
never by prefix or by nearest version, and an unknown name answers
`RuleUnknown` with nothing computed (§5). The name is in the owner-signed
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
  log entries of `S` and of every collection under it, with their pieces;
  the signal run
  headers of `P`'s devices about `S` or a collection under it (§20); and
  the summary roots, nodes and pages of `P`'s devices whose subject lies
  under `S` or on the way to it (a prefix of `S`: the root of `S`'s
  namespace, the folders above `S`). Every other packet of `P` — about
  another folder, about a collection of `P`'s own, about the device's own
  collections — is judged by the device's validator, which refuses it
  while `P` is not held (trust-context.md §4.5.6 note 4), but for the
  packets of one device of a listed writer below. `P` is no
  namespace of a name here (§3): a device of `P` owns nothing at the
  reader, so no members record `P` signs is taken.
- **A listed writer's own devices (round 11).** One more kind of packet of
  `P` is judged by the adopted context, so that two writers who never met
  can exchange signed asks (§16.1): the packets of **one device** of `P` that
  the ask exchange is made of, and exactly these, by name —
  `<P>/<role>/<dev>/32=seal/<pk>` (the device's seal key, `<pk>` its 32
  octets) and `<P>/<role>/<dev>/32=ask/<binding>` (the proof an asker sends
  with its ask, §16.1) — with exactly two components, `<role>` and `<dev>`,
  between `P` and the keyword, and `<role>` a role `P`'s context names: one of the
  layout's (`admin`, `member`, `node`, `guest`) or one the context lists in
  `DataRequiresCut` or its link policy. The device does this
  (`judge_device_packet`, apart from the scope above, whose names it does
  not widen) only while **a members record in force here lists `P` as a
  writer** — a writer prefix of a record of any subject; a prefix a removal
  cut alone keeps is no writer — and `P` is adopted. The signature is then
  checked as every signature of `P` is, by the adopted context and its
  chain, with `P`'s revocations and the every-role `DataRequiresCut` rule
  applied, and it MUST be a key of **that very device**
  (`device_of(key) = <P>/<role>/<dev>`): a packet signed by another device
  of `P` is refused, whatever its name says. Of what verifies:
  - **a seal key** is taken only if its content is the `<pk>` its name
    carries, and is kept (as any verified seal key is, §9) only while a
    record in force lists `P` as a writer: the record that drops `P` drops
    every seal key kept for its devices (at once, under the same lock as
    the record), and one that arrives after is not kept;
  - **an asker's proof** authenticates the device for the granter or
    offering device that receives it, as every asker's proof does (§16.1);
    what it may then ask is decided by the records.

  Why it is safe. Nothing vouches for a key but a certificate chain to the
  genesis `P` hashes: only `P`'s owner can make a key that verifies here,
  and a record's owner already named `P` a writer for the subject. A copied
  seal key gives the copier nothing: the ask's associated data binds the
  signer's name, and the proof's binding the signer's device and the
  ephemeral key. A grant is made only to the epoch's audience, as it was
  (§9: the seal key only tells where to wrap).
  What stays: `P`'s owner may make devices at will, as for any listed
  writer. Nothing else of `P` is judged by this: not a log entry about a
  subject no record lists it for, not a summary
  outside the scope, not a members record (`P` is no owner here).
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

## 7. Summary — slice 1

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
  every version, whatever the collection's rule;
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
FreshnessPeriod 0 so that discovery always reaches the writer: a forwarder's
Content Store takes a Data with no FreshnessPeriod or a zero one as stale at
once, never fresh for a MustBeFresh Interest, whatever its clock reads later
(a clock stepped back does not make it fresh again; a writer's forwarder
would otherwise answer for it with the root it had signed before). A writer
SHOULD sign a new root only when one is asked for and the tree changed.

A writer MUST serve every node and page that any root it signed
lists, for as long as it holds the log entries that node lists — a writer
never drops its own entries, so always, across its own restarts too. Keeping them
costs no storage: a node's content is fixed by the log up to its head, so
a superseded node is rebuilt from the log when asked for; a writer MAY
keep recently superseded packets ready. A writer MUST answer an Interest
for a summary name that none of its roots listed with a Nack.
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
- fetches the entries the visited nodes list that it does not hold. A node,
  page or entry its writer does not answer is asked of the devices
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
    restarts and every new record — so the
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
  in `C` it keeps — versions and members records
  (§16.1). The prefix is per collection because a writer's seqs are one
  sequence across its collections: a cut by seqs alone would let a thief
  sign an accepted seq again under another collection, a new name.
- **What it refuses.** Every log entry of `K` outside the cut, whatever its
  date or seq, and every other packet `K` signed — summary roots,
  seal keys, grants, an asker's proofs — since no cut
  ever lists those (§8.6 says what this costs a thief and an honest
  reader).
- **The cut is the listing.** `K`'s summary roots are refused
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
  answer either. Nodes of `K`'s summary verified before the reader held the
  cut stay verified (they still say which seqs exist, §5), but none is
  taken after it. An entry of `K` in `C` that the cut neither accepts nor
  re-admits never applies, so `K`'s later entries and other writers'
  versions naming it as a parent do not wait for it (§5).
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
    collections are left out). At least one MUST be
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
  others.
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
- **Expiry of a device.** A key of a role the trust context lists in
  DataRequiresCut — every role, by default — fails closed once its
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
and guests do not renew; a member, admin or node device renews before its
certificate lapses, so one that did not is gone, lost or no longer
trusted. For a role the trust context lists in
DataRequiresCut (trust-context.md §3.3.13; every role, in every context
`ndn-fwd init` makes), a version signed by such a key is accepted only
while a certificate of that key is valid by the reader's clock, or once
the key is revoked with a cut, which then decides alone. In between it is
refused, fail-closed, as revoked without a cut: the key's certificate
lapsed and the owner's cut is awaited. The owner's root device makes that
cut bounded at the certificate's NotAfter and signs it (§8.4), and it
accepts what the device wrote while trusted, as far as the root saw it.
The clock can only refuse here: a fast
reader clock refuses a lapsed key's versions early until the cut arrives; a
slow one accepts them a little longer, as a reader that has not adopted a
revocation does; neither makes a reader accept what a cut refuses. A
device that renews (member, admin, node) is refused only when its renewal
fails, so an honest one never waits. A context made before this default
lists `guest` alone and keeps doing so, since a context is root-signed
data; `ndn-fwd status` names the command that lists the other roles.

**What the root's clock does: the bound of a cut.** The producer of a cut
reads its own clock twice: when it first verifies an entry, and when the
owner marks a key suspected or answers when it was lost (§8.1). Both are
the root's own observations, never a date the key wrote. A wrong root
clock moves which entries a cut lists; the producer prints what it leaves
out, and readers never read that clock.

**What still uses a clock, and why that is safe.**

- In this layer: a version's date (display) and the age `get` reports. None
  decides whether a version is valid; a wrong clock moves only a date shown
  and an age reported. The root's clock bounds the cuts it makes
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
  verified it; have a summary, head, seal key or grant
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

- *The signer's* moves only the dates it writes, which a host shows. It
  cannot make a version valid or invalid; a stolen key's backdated version
  is outside the cut.
- *The reader's* moves only its own waiting and reported ages, its live
  exchanges (a context whose anchor it thinks
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
DataRequiresCut (every role, by default), its versions are refused once its
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
forward ciphertext.

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
  force no longer admits, who holds its key), nor in one that has
  undergrown it (the record in force lists a reader that no held record
  naming the epoch lists, so the epoch's key is never granted to it: a
  merge not resolved yet, §6); `put` answers `NotReady` (next step
  `RetryLater`) until a record moving the collection to a new epoch, or
  naming the epoch with that reader, is held. A reader opens it with that epoch's key; a payload that
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
  Of the asks that pass, `G` works on at most `GRANTS_PER_ASKER` (32) of one
  asker device at once, counted before anything is fetched; one more is
  refused at once (a Nack, and a trace saying why), and an honest asker's
  next round asks again (round 12 review H1: a granted reader could send
  distinct asks, each naming a seal key of its device that never comes, and
  have a task and a fetch slot wait on each). A grant already kept is
  answered before the count.
  It then fetches and verifies the asker's seal key (signed by the asker's
  device key) — one ask in place, within the asker's wait; when it misses,
  up to `FETCH_TRIES` asks more in the background, one run per seal key, at
  most `SEAL_LEARNING_PER_ASKER` (2) runs of one asker device and
  `SEAL_LEARNING_MAX` (64) in all, a run beyond them not started and traced
  (the asker's next ask starts it once one ends), the
  key kept once verified, so the asker's next round is answered at once
  (round 3, faulty case r7: a lossy path to the asker made every
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
  (§6.1), and nothing is sealed in its outgrown epoch meanwhile.
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
  keep, the writer's date — and the ciphertext's size;
  seal keys; and who asks whom for which epoch's key (the grant's name
  names the asker's seal key, the collection or folder and the epoch), and
  when.

## 10. Type — slice 1

A type is a named, versioned content schema (`/types/note`, revision 2).
Revisions only add fields. Content is a set of named fields with opaque
values.

- A version sets fields: each field it carries is set to its value, and a
  field carried with an empty value is removed. A writer that knows only
  revision 1 writes back the revision-2 fields it does not know
  (invariant 8).
- The type is recorded in the version for readers and lenses; it never
  changes how a collection's rule reads the version.

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

**A face comes up (normative).** A device announces its state vector in a
group again (the announcement a join makes) when a route that covers the
group's prefix `<O>/32=sync` — at the group, at `O`, or above — comes up
on a face that is not a local application's (round 11, a commit made
while no link was up). An announcement of a change made with no link
reached no one, and the group's next period is half a minute on; the
link coming up is when someone can hear it. Every group the device
joined that the route covers is announced, whether or not the device
has anything of its own to tell in it: the vector carries the devices it
heard, an announcement that brings a member nothing newer is answered by
no one, and one that finds a member behind (or ahead) is how each end of
the new link learns what it missed. The announcement is the one `hail`
and `herald` send: an outgoing Sync Interest, which sets no device
heard (§13.5) and no freshness (§15, a read is confirmed only by a Sync
Interest that arrived); suppression is the driver's, and the
announcement restarts the group's period as a join does.

- *Trigger.* The forwarder's RIB tells every face a route has newly put
  into its FIB at a prefix (`ndn_engine::Rib::route_events`, a
  `RouteUp { prefix, face }`: generic, it names no protocol; told after
  the route is installed, so the announcement finds it; a route that was
  already there, one removed, and a face the FIB was given directly are
  not told). An embedded engine's connection (`ndn_app::Connection::routes`,
  given by `app_face`) hands the device those on faces that are not its
  own, not a local application's and not a management socket's — the kinds
  whose scope is always local — so the device's own registration of its
  group (a FIB write on its own face) and a local application's route
  through the management interface announce nothing. The device
  subscribes through the `sync` connection it already holds.
- *Coalescing and the total bound.* A batch of routes that arrive together
  announces a group once, however many of them cover it; at most once a
  second per group: the first at once, a later one at the end of the second
  since the last, once however many came meanwhile, so the last face up is
  told and a link that flaps costs two announcements, not one per route;
  and at most **32 announcements in any second across every group**
  (`TOTAL_PER_SECOND`, a sliding window of the last second's announcements,
  not a refilling bucket, so no second holds more than 32). A subscriber
  that fell behind and lost events announces every group joined, and so
  does a route at `/` or above every group: with 300 groups joined that is
  32 at once and the rest in the seconds that follow (about 9 s for 300),
  each waiting for room in the window and none dropped, so the commit of
  any group is still shared; a group the cap defers past its own period of
  half a minute (over 960 groups at once) is announced by that period as
  any group is, which is enough: the periodic announcement already shares
  a commit with whoever is heard, and this one only moves the time. The
  total bound is chosen over sending only on the face that came up
  because the device has one send: its packet goes through its single
  sync connection and the forwarder's strategy picks the faces (multicast
  for a group), so a per-face send would need one the sync driver
  (`MultiSvs`) does not have, would not bound a batch whose events were
  lost (no face is named), and would still announce every group a route
  covers, only on one face; a gate on the one send bounds every case.
- *Over IPC.* A connection to an external forwarder over its Unix socket
  (`ndn_app::IpcConnection`) tells the same routes by following the
  daemon's `/localhost/nfd/rib/notifications` stream (`ndn_ipc::events`;
  `ndn_mgmt_wire::events::RibEvent`; mgmt-trust.md "Notifications"). The
  daemon publishes there each `RouteUp` of its RIB on a face that is not
  always local (a link, a tunnel, a radio: the filter of the embedded
  connection, `ForwarderEngine::face_reaches_off_host`), however the route
  got in (its link layer, configuration, a routing protocol, a
  registration through its management interface), as a `route-up` event,
  and a `routes-missed` event when its own feed fell behind. A
  client behind the stream's ring is told to resync, which it takes as
  lost events too. The stream is local to the host (`/localhost`: no
  remote face is answered, and nothing serves it under `/localhop`), and
  tells no local application's or management socket's route. The
  connection follows it over its own control face, so its prefix
  registrations do not wait behind the long-poll; if the daemon cannot be
  followed (the connection is gone) the periodic announcement alone
  runs, and the change announced run of §17.1 still covers the group
  once a member is heard.
- *Decides nothing.* The announcement only moves the time a member
  learns of a change; what it fetches is judged as always (invariant 1).

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

### 12.1 A notice names no entry (round 12)

A group counter says only "moved": it names neither the collection nor the seq of the log entry that moved it, and one announcement can cover several entries of several collections. So a reader answers every notice with the walk of §12 (root, summary nodes, entry), and a new 1 KiB version costs a watcher six asks one after the other (the root, four nodes, the entry). Taking the named entry directly would need the announcement to carry the names (the application data of the Sync Interest's `MappingData`), unsigned and deciding nothing, and the summary that lists the entry would still have to be read: `Change::Summary`, the listing of entries not held, and the root and nodes a holder answers a reader that missed the notice with (§13.5) all come from the walk. Round 12 built that shape (kept on the ndn-rs branch `r12-direct-fetch`) and did not ship it: under packet loss it failed conformance case r7 on 6 of 160 fault seeds, for a cause not found in time. The direct fetch comes with the data layer's next crate, whose notice names the entry by construction.

## 13. Large payloads and what a device serves — slices 3, 6

### 13.1 Large payloads

A version's payload `P` — `Fields` and `MergeOp` as §16.2 encodes them, or
its sealed ciphertext (§9) — of more than 6,144 octets (`INLINE_MAX`)
travels in pieces, in a log collection. A merge collection's version
carries its bytes inline: `put_op` of more answers `TooLarge`, and a reader
refuses a merge version whose payload is in pieces (`Refusal::Rule`, next
step `None`).

A payload carries at most 64 MiB (`PAYLOAD_MAX`, 67,108,864 octets) per
version, as a reader assembles it whole:
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
  whole on `get` of its name (or of a log collection's newest):
  each piece from its store, else by name, else from the devices that serve
  it (§13.5) by the Interest `<D>/32=held/<Name TLV>`, which the device
  answers (DigestSha256) with the packet inside; a piece that is not
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
  assembles (at most `PAYLOAD_MAX`).

### 13.5 What a device serves — slice 6 (round 3)

Any holder of a signed packet may answer for it: a packet is trusted for
its signature and the digests that name it, never for who sent it (§1).
So a device serves every entry it holds verified, of every writer — its
own, other devices of its namespace, other namespaces — not only its own
log. Before, a device served only its own log: a person whose phone writes
and goes away had their work reach
others only while the phone was online (ndf's REPLY-12 §1; case h10).

**What it serves.** By name and, asked under its own name, by
`<D>/32=held/<Name TLV>` (answered DigestSha256, the packet inside, §13.1):

- every log entry of another device it holds verified: a version, opened
  or held sealed — a sealed one as the ciphertext its writer signed —, and
  every record (members, folder); stored, or
  waiting in memory (pending, locked);
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

**What it never serves.** Nothing refused or withdrawn here: by the record in force (`NotMember`,
`OutsideCut`), a revocation cut or an untrusted chain (§8) or the rule (a merge
version in pieces, §13.1) — another reader would refuse it too, and serving it would
only cost that reader a verification. This holds for every collection the
device follows: it keeps outsiders' versions and packets withdrawn after it
stored them, and serves none of them (round 3, review L3). Nothing it holds
unverified: a packet that did not verify is never kept (§4). An own entry
above the durable head stays unserved as before (§4.2). An ask for an entry
the device does not hold costs it one lookup by name, whatever it holds of
the collection (ndn-data: `St::held` indexes every entry held, waiting or
refused included), so asks for made-up seqs cost no scan under its lock.

**Asking for a writer who does not answer.** A reader asks the writer
first, by name, as before. When the writer does not answer, it asks, in
order, for pieces, the other devices it hears for the namespace (§12: heard in its
group, or writing into it by the records held) that signed data it
holds vouches for as members of the namespace — a summary
root of theirs for it verified (in this run or kept from an earlier one),
a version of theirs applied in a collection of it, or a members record in
force of a collection or folder of it listing their device or one of their keys (a
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
  a digest names, when it asks by one), a piece against its manifest.

A device that holds nothing of it answers with a Nack, at once. The writer
asked first, a reader that reaches it never waits on another device.
Outside a walk, a reader that does not reach the writer asks the devices
once the writer's asks missed (§17.1), all at once, so one that is away too
costs no more than one of them, and only for what the writer did not
answer. A piece of a version being read is asked as a walk's packets are:
once the writer's first ask missed, beside its later asks, the devices
whose versions are made over it in turn, then the other devices at once;
the first answer that checks is taken. So a device that holds nothing — its
Nack lost or held back on the way — costs the read no time beside the
writer's own asks (round 3: asked after them, such a device cost every
piece the writer's lost asks missed `FETCH_TRIES` lifetimes more).

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
  collections.
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
  source, is the equivocation §4 reports. A
  holder cannot make one: it cannot sign for the writer, and the same
  signed region under another signature value, which an ECDSA signature
  leaves malleable, is no second thing the writer signed (§4). A removal
  cut bound to bytes (§8) decides which packet stays, whoever serves it.

## 15. Verbs — slices 1–3, 6, host surface slice 7

| Verb | Shape | Slice |
|---|---|---|
| `get` | `get(name) → version or state + age` | 1 |
| `put` | `put(collection, content, {type, keep}) → (writer, seq)` | 1 |
| `put_op` | `put_op(collection, bytes, {type, keep}) → (writer, seq)` | 6 |
| `watch` | `watch(collection, since F) → summary, new versions…` | 1 |
| `share` | `share(collection, {rule, readers, writers})` | 1 (adding), 2 (removing, the rule) |
| `share_folder` | `share_folder(folder, {rule, readers, writers} \| change)` | 6 |
| `members` | `members(folder \| collection) → {rule, writers, readers}` | 6 |

`put_op` is a form of `put`, `share_folder` of `share`,
and `members` reads what they signed, as a `get` reads a version: the
verbs stay four. Code mostly uses `get`, `put` and `watch`.
`share` runs on host policy, or on the person's
gesture. Exposure over forwarder management and the mobile FFI is slice 7. A device
answers a verb or option of a later slice with an error that names the
slice. Beside the verbs, a `Device` makes and takes introductions (§19):
`offer(folder, {role, until, tries}) → code` and `close_offer(offer)` on
an owner device, and `join(code) → {folder, role, inviter}` on the
joiner's; the joiner then uses the folder with the verbs as any member.

- **`get(C)`** of a merge collection answers its state now — `State` with
  the collection, `at` and the value (the register's, §5: the winner's
  `by ‖ bytes`, no bytes at all while nothing was written); of a log
  collection, its newest version
  (§5) — with `Age::Newest`: the time since the device last knew nothing
  newer was outstanding in `C`'s sync group, measured on its monotonic
  clock: it finished a refresh that reached the writer's state with no
  other pending — as of when the writer's root came to that refresh, not
  of when its descent ended: the descent may fetch for long what the root
  lists, after the writer left —, or heard one of the group's Sync Interests
  (`<O>/32=sync/v=N`, admitted as the group's driver admits it) with none
  pending whose state vector carried no device's counter above what
  notices brought here and no refresh of that device ended short of (round
  4 review; before, any Interest under `<O>/32=sync` confirmed, signals of
  §20 included, so a stream of them kept the age near zero whatever was
  outstanding). Signals and every other Interest under the group's prefix
  confirm nothing. The
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
  step `UpdateProgram`), §5.
- **`get(log entry name)`** answers the version (`Age::Exact`),
  fetching it when not held; a members record is not a version
  (`NotFound`); a refused entry answers `Refused` with the reason; a
  version sealed to an audience the device is not in, `Sealed`.
- **Every `Version` a host receives** — answered by `get`, delivered or
  listed by `watch`, carried whole in an equivocation — MUST carry
  `digest`, the implicit digest of its packet (SHA-256 of the whole Data
  wire: the name a parent's `Digest` uses and the register's tie-break,
  §4, §5), and `op`: the `MergeOp` octets of a merge version, exactly
  as the register applied them, or nothing under the log rule. A merge
  version's `op` is absent too while its operation is not open here —
  sealed in an epoch whose key the device does not hold. A host keeping
  versions for history so reads their bytes, with no index of its own.
- **`put(C, content, {type, keep})`** signs the next entry of the
  device's log with parents = the state's `at`, applies it, and publishes
  it (§12).
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
  in the state (§5).
  Into a merge collection whose rule the device does not know it answers
  `RuleUnknown` (§5); into one whose rule it knows, the register,
  `BadRequest` (next step `FixRequest`: use `put_op`).
- **`put_op(C, bytes, {type, keep})`** is the register's write (§5), in a
  merge collection whose rule the device knows: the bytes, which ride in
  the version as its `MergeOp`, become the value; parents = the state's
  `at`, past = `down(at)`, so the version supersedes every version the
  device had applied. The device signs the version, applies it, stores and
  publishes it. Empty bytes are a removal; a payload of more than
  `INLINE_MAX`, sealed or not, answers `TooLarge` (§13.1), nothing signed.
  Into a log collection it
  answers `BadRequest` (next step `FixRequest`: `put_op` is for merge
  collections); under a rule the device does not know, `RuleUnknown`. It
  answers as `put` does otherwise: refused after the edit, it leaves no
  trace, nor, for a new collection, is its default record signed (§5).
- **A put never waits on other devices** (round 4). `put` and `put_op`
  return once the version is applied
  locally and queued behind the durability barrier; publishing after the
  barrier is the only wait. (1) A collection under a folder whose members
  record this device holds, its own folder or another's, and that has no
  record of its own here, inherits the folder's record: no look runs
  before the put and no record of its own is signed — once every device
  of its namespace known here has been walked toward the folder. A device
  not walked yet may hold a record of the collection of its own, which
  narrows who reads or writes it (§6.1), and a version sealed or written
  under the folder's record meanwhile would reach readers that record
  leaves out, for good: until then the put answers `NotReady`
  (`RetryLater`) at once, `why` naming the devices and saying to put again
  once they are reached, or to mark a lost key suspected or revoke it; the
  walk runs in the background. This is judged before the record admitting
  a writer of another namespace, so a joiner's put waits for it too: which
  is why `join` returns only once it passes for the folder joined (§19.3
  step 6), and its first put is not `NotReady`. Once
  the folder was walked the put returns at once, and so does one into a
  collection that has a record of its own here: it is written under the
  record in force over it, its own narrowed by the folders above (§6.1).
  (2) A collection of this namespace under no held record, not yet
  followed, whose namespace has a device not walked yet: `NotReady`
  (`RetryLater`) at once, `why` naming the device whose summary may hold a
  record over it; the walk runs in the background, its result arrives
  through `watch` as the record (or its absence) is learned, and when the
  walks are done and no record governs it the owner device signs its
  default record with the first version. An owner device that has not
  walked its namespace never signs a default record that could narrow a
  line it has not seen (§6.1). (3) A namespace with no other known device
  has nothing to walk: the put proceeds and signs the default. (4) A
  collection of another namespace whose members record, or the epoch's
  key, is not held yet: `NotReady` at once, the walk or the grant asked in
  the background; a device an offer admitted (§19.3 step 6) is never
  answered `AskOwner` in that window. (5) `share_folder` creating a
  folder's first record keeps one bounded look (at most `first_look`): only
  that call waits, never the puts after it. (6) `get` is unchanged: a read
  may look and wait for what it reads.
- **`watch(C, since F)`** reports every held version of `C` (or of the
  collections under folder `C`, which may be `<O>/32=data`) outside `F`,
  then every version applied later, the summaries of §7, each outside `F`,
  every equivocation (§4), and every version withdrawn (§8); it starts a refresh of every
  device known to write into the namespace. The stream ends when the
  device stops. A folder's watch is one stream for every collection under
  it, including each collection created after the watch began — by this
  device, or by any writer whose versions reach it (§7: the folder is
  followed, so the new collection's branch is descended into on the next
  notice) — with no further call. Every change MUST name the collection
  it is about (`Change::collection`): a version or withdrawal reports its
  version's collection; a
  summary the node it summarises (the watched name or one below it); an
  equivocation the collection it is told for — when the two entries at one
  seq are in two collections it is told once for each, tagged with each,
  carrying its own version whole and the other by name and id only (§4),
  so a watcher of both gets it twice, once per collection. The listing
  also reports the equivocation evidence held about what is watched,
  whatever `F`. The listing
  reports what is applied; a version held but not applied yet
  (it waits for an earlier one or its key) is not listed and
  comes once it applies,
  so the stream delivers no version twice (a version withdrawn and taken
  back comes again, after its `Withdrawn`). `F` filters every collection
  alike, by writer and seq, as a watch of that collection with `F` would;
  within one collection a writer's versions come in seq order, across
  collections in no common
  order — one may wait for its key while another applies — so a frontier
  joined from a folder's deliveries may cover a version of another
  collection still to come: a host resuming a whole folder passes the
  empty frontier (its listing is local), or resumes collections one by one
  from their own frontiers.

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
  its own name or with a members record of its
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
- **`share(C, {rule, writers, readers})`** signs the next members revision
  (`C` of the device's own namespace only, §3: else `NotOwner`), with the
  cuts, epoch and `Since` of §6 — of a collection's first own record under
  a folder, against the effective record (§6.1). A record removing a
  writer first walks that writer's known devices, as far as they are
  reachable, and cuts over what is held then (§6).
  A collection sealed to a group moves to a
  new epoch when the group drops a reader, signed by a device of the
  collection's own namespace (§6), whoever owns the group.
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
- A verb given a name it cannot take answers `BadName` (§3).

## 16. Wire format — slices 1–3, 6 (slice 5 adds none)

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
| version, members record (a folder's too, `<D>/32=log/<F>/seq=<n>`, §6.1) | `<D>/32=log/<C>/seq=<n>` | device key |
| summary root of `O` | `<D>/32=summary/<O>/32=root/seq=<head>`, FreshnessPeriod 0; discovered by `<D>/32=summary/<O>/32=root` (CanBePrefix, MustBeFresh), which no node or page name extends, so only a root answers it | device key |
| summary node of `X` | `<D>/32=summary/<X>/seq=<head>` | DigestSha256 |
| summary page of `X` | `<D>/32=summary/<X>/32=page/<buckets>/seq=<head>` | DigestSha256 |
| sync group | `<O>/32=sync` (State Vector Sync Interests) | — |
| seal key | `<D>/32=seal/<public key>`, Content `SealKey` | device key |
| grant | `<G>/32=grant/<GrantAsk TLV>`, Content `Grant` | the granter's device key |
| chunk of version `V` | `<V>/seg=<i>` | DigestSha256 |
| manifest node of `V` | `<V>/32=manifest/seg=<k>`, Content `Digest*` | DigestSha256 |
| cut manifest node of members record `R` (§8) | `<R>/32=cut/seg=<i>`, the root `seg=0`, Content `CutManifestNode` (trust-context.md §3.3.12), FreshnessPeriod 1 h | DigestSha256 |
| held packet (answer: the packet) | `<H>/32=held/<Name TLV>` (also a joiner's fetch of an offer from its device, §19.3) | DigestSha256 |
| asker's proof (inside an introduction ask or answer, never fetched) | `<A>/32=ask/<binding>`, empty Content, FreshnessPeriod 0 | the asker's device key |
| offer, use mark (§19.1) | `<D>/32=log/<F>/seq=<n>` | device key |
| introduction ask and answer (§19) | Interest `<D>/32=intro/<ParametersSha256Digest>`, ApplicationParameters `IntroAsk`; answer named the same, Content `IntroAnswer` | DigestSha256 (the answer carries the offering device's proof inside) |
| hint record of a short code (§19.2) | `<D>/32=hint/<token>`, `token` one GenericNameComponent of 16 octets, Content `IntroHint`, FreshnessPeriod 5 s; made on request, only for a token of one of `D`'s own offers | device key |
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
  no keyword); the last component is `seq=<n>`; what lies between is a
  collection name.
- **Signal run header.** `D` is the components before the first
  `32=signal` (`D` has no keyword); the last component is a
  GenericNameComponent of 16 octets, the next-to-last `32=run`; what lies
  between is a folder or collection name, the scope (§20).
- **Summary.** `D` is the components before the first `32=summary`; a last
  `seq=` component is the head; a `32=page` then the next-to-last
  component is the page. What remains is the subject: a namespace (the
  root) or a folder or collection name. A root's subject is followed by
  `32=root`, and only the discovery name `<D>/32=summary/<O>/32=root` lacks
  the head — a namespace never ends in `seq=` — so a node or page name
  always carries it, and the subject's own last component is never read as
  the head. A subject without a marker is a namespace, never a node under
  one.
- **Cut manifest.** The last component is `seg=<i>`, the next-to-last
  `32=cut`, and what precedes them is a log entry name with a collection:
  the members record whose cuts the manifest binds. A reader fetches its
  packets only by full name, as `CutBytes` names the root and each node
  its children (§8).
- **Seal key.** `D` is the components before the first `32=seal`; one
  GenericNameComponent of 32 octets follows, the X25519 public key, equal
  to the `SealKey` the packet carries. A device also answers an Interest for
  its own `<D>/32=seal` with CanBePrefix by that packet.
- **Grant.** `G` is the components before the first `32=grant`; one
  GenericNameComponent follows whose value is one `GrantAsk` TLV: a seal key
  name, a collection Name (or, for a folder epoch, the folder's, §9) and a
  `SealEpoch`.
- **Asker's proof.** `A` is the components before the first `32=ask`, a
  device name; one GenericNameComponent of 32 octets follows, the binding:
  SHA-256 of the protocol's label, then the offering device's Name TLV
  followed by the ask's fields before its `Asker`, or the answer's fields
  before its `Asker` (§19.3). The labels, ASCII each ending in a zero octet
  so none is a prefix of another, are `ndn-data intro ask\0` and
  `ndn-data intro answer\0`. A receiver computes the binding with the
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
- **Hint record.** `D` is the components before the first `32=hint`, a device
  name; exactly one GenericNameComponent of 16 octets follows, the token
  (HMAC-SHA256 of the offer's secret, §19.6), and nothing after it. A longer
  name, a token of another length or a token that is any other component type
  is no hint record.

### 16.2 TLV-TYPE numbers

The data layer uses 0x0520–0x057F, and 0x05B0–0x05BF for an introduction
code's link hint and a short code's hint record (below), registered in
[README.md](README.md#tlv-type-numbers). The block 0x05E0–0x05FE is freed and
quarantined, not reused (the old spec is kept in
[history/data-layer-events.md](history/data-layer-events.md)). The numbers
0x0557 and 0x0559 are freed and quarantined too, not reused (the old spec
is kept in [history/data-layer-groups.md](history/data-layer-groups.md)). The numbers 0x0525, 0x0527, 0x0529, 0x052B, 0x052D, 0x052F, 0x0533, 0x0535, 0x0537, 0x0539, 0x053D, 0x0541, 0x0543 and 0x0551, which carried custody (the hold, lease and prune records, the hold and audit asks, the audit answer and its fields), are freed and quarantined too, not reused (the old spec is kept in [history/data-layer-custody.md](history/data-layer-custody.md)). The numbers 0x0530, 0x0545, 0x0547, 0x0549, 0x054B, 0x054D, 0x054F and 0x0553, which carried streams (the keep for the last `n`, a block and its entries and offsets, a one-key head and its freshness, the time range of a range name, and a summary node's expiry runs), are freed and quarantined too, not reused (the old spec is kept in [history/data-layer-streams.md](history/data-layer-streams.md)). The number 0x0550, which carried the snapshot record (the names a snapshot pins), is freed and quarantined too, not reused (the old spec is kept in [history/data-layer-merge.md](history/data-layer-merge.md)). A number is even unless the notes
below say it is odd: a decoder MUST skip an unknown even TLV inside these records
and MUST refuse an unknown odd one, so a later revision can add fields old
readers pass over (and fields they must not).

| Type | Name | Value |
|---|---|---|
| 0x0520 | VersionRecord | Name (collection), Frontier (parents, each entry with its tip's Digest), TypeId, Seal, Keep, Dated, [Rule] (merge: the rule the operation was made for, §5), then Fields, MergeOp — or Chunks (§13.1; in a log collection) — or, sealed, Sealed |
| 0x0522 | Frontier | FrontierEntry*, by writer (in a version's parents, one per writer) |
| 0x0524 | FrontierEntry | Name (writer key), Seq; in a version's parents, then Digest (the implicit digest of that writer's packet at that seq) |
| 0x0526 | Seq | NonNegativeInteger |
| 0x0528 | TypeId | Name, Revision |
| 0x052A | Revision | NonNegativeInteger |
| 0x052C | Keep | KeepForever |
| 0x052E | KeepUntil | NonNegativeInteger, ms since the Unix epoch; an introduction offer's expiry (§19.1) |
| 0x0532 | KeepForever | empty |
| 0x0534 | Seal | Audience* |
| 0x0536 | Audience | AudienceKind, Name |
| 0x0538 | AudienceKind | NonNegativeInteger: 0 person, 1 device, 2 group |
| 0x053A | Dated | NonNegativeInteger, ms since the Unix epoch |
| 0x053C | Fields | Field*, by name |
| 0x053E | Field | FieldName, FieldValue |
| 0x0540 | FieldName | UTF-8 |
| 0x0542 | FieldValue | octets; empty removes the field |
| 0x0544 | MergeOp | octets: the bytes a `put_op` wrote, the register's operation (§5); empty is a removal |
| 0x0546 | MembersRecord | Name (collection, or with Folder the folder), [Folder] (§6.1), Revision, Rule, Writers, Readers, [Cuts], [SealEpoch, KeyCheck], [RuleSince], [Seq, Digest] (the parent, from revision 2: its revision, one below this record's, and the SHA-256 of its `MembersRecord`, §6) |
| 0x0548 | Rule | RuleKind [Name (a merge rule: its full, versioned name, matched exactly; the one built-in is `/ndf/merge/newest/v=1`, §5)]; in a merge `VersionRecord`, kind 2 and the rule its operation was made for (§4) |
| 0x054A | RuleKind | NonNegativeInteger: 1 log, 2 merge (0, which was one key, is not assigned: a record carrying it is malformed) |
| 0x054C | Writers | Name* (key-name prefixes) |
| 0x054E | Readers | Audience* |
| 0x0552 | SummaryNode | Name (subject), Writer, Seq (head), [PagePath], [Entries], [MembersEntries], [Children \| Pages] |
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
| 0x0531 | Nonce | 16 octets, fresh random per ask |
| 0x053B | Asker | octets: the asker's proof, the Data packet `<A>/32=ask/<binding>` (§16.1) |
| 0x053F | Proof | 32 octets: HMAC-SHA256 under the proof key an offer's secret yields, over the fields of an introduction's ask or answer before it (§19.3, §19.6) |
| 0x0555 | Folder | empty; in a MembersRecord right after its Name: the record governs the folder Name and every collection strictly under it (§6.1) |
| 0x055B | CutBytes | Name: the full name, ending in its ImplicitSha256DigestComponent, of the root of a cut manifest (`<R>/32=cut/seg=0`, §16.1; trust-context.md §3.3.12) listing, under `<D>/32=log/<C>`, the seq and implicit digest of every version the cut keeps; in a Cut right after its Name, ascending, once each; never in a cut that keeps nothing (§8) |
| 0x055F | CutIn | Name (a collection strictly under the folder), then per key it keeps versions of in that collection, by key: Writer, Entries (exactly those seqs); in a folder record's Cut only, once per collection (§6.1, §8) |
| 0x0561 | IntroOffer | Name (the folder), Role, KeepUntil (its expiry), Tries, Digest (the commitment to its secret), SealKey (the offering device's); a log record (§19.1) |
| 0x0563 | IntroUsed | Name (the offer), then Writer and Digest (the asker key it was used by and its public key's digest) when used, neither when closed; a log record (§19.1) |
| 0x0565 | IntroAsk | EphemeralKey, Ciphertext (a content key wrapped to the offer's SealKey), Ciphertext (the AskBody — Name (offer), Nonce, Proof, Credentials, Asker — sealed under it); an ask Interest's ApplicationParameters (§19.3) |
| 0x0567 | IntroAnswer | Name (offer), Writer (the asker key), Digest (its public key's digest), then Name (folder), Role, optional Revision (0x052A: the members revision in force on the offering device once the asker was admitted; the joiner's note of the admission lets go at a held record of that revision or later that leaves it out, §19.3 step 6; an answer without it releases the note on expiry only), Credentials, Asker (the offering device's proof), Proof — or IntroRefused, with no Proof; an answer's Content (§19.3, §19.4) |
| 0x0569 | Role | NonNegativeInteger: 0 reader, 1 writer |
| 0x056B | Tries | NonNegativeInteger: in an offer, the wrong tries that close it (≥ 1); in a refusal, those left |
| 0x056D | IntroRefused | NonNegativeInteger: 1 unknown, 2 used, 3 expired, 4 closed, 5 wrong proof (then Tries, left), 6 conflict (the code a joiner's own `Hint` refusal, §19.5, would have: it is never sent) |
| 0x056F | Credentials | octets: whole Data packets, a signed trust context then the certificates of its signer key's chain to that context's anchor, at most 8 |

The introduction code's link hint (§19.2) uses two even numbers of the
block 0x05B0–0x05BF. They are the value of the `intro` envelope's
`LinkHint` field (0x0478, [trust-envelope.md](trust-envelope.md)), not of a
log record; a reader skips an unknown even TLV among them. A short code's
hint record (§19.2) uses five more of the block, all even: the Content of
the Data `<D>/32=hint/<token>` (§16.1), with the same reader rule.

| Type | Name | Value |
|---|---|---|
| 0x05B0 | LinkKey | 32 octets: SHA-256 of the inviter device's public key as a certificate carries it (an Ed25519 key's 32 octets); the key a link handshake must prove (ndn-link.md §3.3); exactly once |
| 0x05B2 | LinkCandidate | one octet of kind (0 host, 1 reflexive, 2 advertised, 3 mapped), the IP address (4 octets for IPv4, 16 for IPv6), the UDP port (2 octets, big-endian); 7 or 19 octets; repeatable, at most 8 kept, in order of preference (§19.2) |
| 0x05B4 | IntroHint | a hint record's Content (§19.2), one TLV and nothing after it: `HintOffer`, `LinkKey`, `LinkCandidate`*, `HintRelay`*, `HintUntil`, `Credentials` (0x056F) in this order — or, for an offer no longer served, `HintGone` then `Credentials` and nothing else |
| 0x05B6 | HintOffer | one Name TLV: the offer record's name; exactly once |
| 0x05B8 | HintRelay | one Name TLV: a relay device that reaches the inviter; repeatable, at most 8 (a record with more is refused) |
| 0x05BA | HintGone | NonNegativeInteger: 3 expired or 4 closed (the codes of `IntroRefused`); with `Credentials` (0x056F, the inviter's, as a record carries them) the whole of a gone mark, which is verified as a record is (§19.3 S5) |
| 0x05BC | HintUntil | NonNegativeInteger: the offer's expiry in milliseconds; informational (the offer judges its own); exactly once |

Slice 3's numbers are odd — critical — because the even ones of the block
are taken and because a reader that does not know them must not pass over
them: a version in pieces read as one without a payload would be wrong,
not stale.

Slice 6's numbers are odd for the same reasons. A reader passing over
`Folder` would take a folder's record as the record of a collection named
like the folder, and judge every collection under it without it: a writer
the folder removed would be admitted there — wrong, not stale. One
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
Effective records are not on the wire.

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
`MembersRecord`; a
writer's namespace adopted for one folder (§6.3) is fetched by the trust
context's own names; asking again (§17.1) and the faulty mode (§18.1) put
nothing on the wire. The odd numbers 0x0571–0x057F stay free.

### 16.3 Why these encodings

- **Reused:** the Name TLV, NonNegativeInteger, typed name components
  (keyword, SequenceNum), DigestSha256 and the implicit digest, ndn-svs v2
  for the notice, the hierarchical trust schema and the existing validator.
- **New records** because nothing existing carries them: a frontier (no NDN
  encoding of a version vector exists outside SVS's unsigned state vector),
  a version's parents/type/seal/keep/fields/operation, a members record and a
  Merkle summary node. SVS-PS mapping data was not
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
- **The asker's proof is a signed Data packet** (`<A>/32=ask/<binding>`)
  rather than a signed Interest, so the existing validator and trust
  schema check it like any packet of `A`, and its key locator names the
  claimed asker before any signature is checked, which is what lets a
  device that is asked drop a stranger's ask for the cost of a parse. Its binding opens
  with a protocol label because every protocol's proofs share one name
  shape and one key: without it, only the first TLV type of each
  protocol's fields tells them apart, and a later protocol whose fields
  happen to start alike would let one protocol's proof stand for
  another's.
- **A members record's parent** reuses `Seq` and `Digest`, the pair a
  summary's child and page name their packet by, in a position of its own
  rather than a new number: both are even, so a reader of the previous
  revision of this format passes over them and merges concurrent records
  by intersection, as it did. The digest is of the parent's Content
  because the record in force may be a merge no packet carries (§6).
- **Rules by exact, versioned name** (§5), not a rule kind with
  parameters or a name matched by prefix: the name in the owner-signed
  record is the whole policy, a device either runs exactly it or computes
  nothing, and a change of meaning gets a new name, so no two programs
  compute different states under one name and no reader falls back to
  another rule. The one built-in function is `/ndf/merge/newest/v=1`; a
  record naming any other, the Yjs rule of the slice-2 records included,
  is held and served and computes nothing (`RuleUnknown`).
- **A folder record is the existing members record with a flag** (§6.1),
  not a new record: the owner rule, revisions, parents, the merge of
  concurrent records, cuts, epochs, key checks and `Since` all carry over
  unchanged, and the folder's summary node already lists its members
  entries. The flag is odd so that a reader that does not know it refuses
  the record rather than read it as a collection's (§16.2). The effective
  record is not on the wire: it is a function of signed records every
  reader holds, and a second, carried copy could only disagree with them.
- **Pieces in the version, not references to log versions** (§13.1), as
  agreed with ndf-rs (`handoff-ndf-rs/REPLY-3.md`): a reference to a
  version of another collection would leave open whether its readers and
  epoch match the collection's, who may write there, and what happens
  when the referenced version is dropped while the version still needs
  it. Pieces in the version itself raise none of these: they verify through
  the version's own signature and stay sealed in its epoch.

## 17. Failure model

| Failure | Required behaviour | Rests on |
|---|---|---|
| Partition / offline | Reads and writes continue locally under each device's key; collections reconcile from summaries when a path returns. | §4, §7 |
| Lost device | The devices that hold its entries keep serving them (§13.5); the owner marks its key suspected on the root device, says when it was lost, and revokes it with a cut of what the root first verified before then; the entries left out are printed, and any honest one is re-admitted by exact name and digest. | §8.1, §8.2, §13.5 |
| Compromised key | The revocation cut keeps exactly the versions it lists, with the bytes its manifest lists, and refuses the rest, whatever dates they claim; the key's summaries, heads, seal keys and grants are refused; sealed data re-keys forward. | §8.1, §9 |
| Bad or lying clock | Never makes a version accepted: Data is judged without certificate validity periods, and the cut, not a date, ends a key; for a role listed in DataRequiresCut (every role, by default) a reader's clock only decides when a lapsed key's versions start being refused until its renewal or its cut. Under expiry it moves only that device's own retention: a slow clock holds and serves longer, a fast one drops its own copy early; a writer's clock moves only its own dates and listing; the root's clock moves only which entries the cuts it makes list, and it prints those left out. A wrong clock refuses live exchanges, loudly. | invariant 1, §8.1, §8.5, §14.1 |
| Thief writes between the theft and the revocation | Writes the root first verified before the loss time the owner states stay accepted (residual); later ones are left out of the cut and refused everywhere; once the key is marked suspected, the root takes none. | §8.1, §8.6 |
| Thief backdates or fills a gap with a revoked key | Refused wherever the revoking version is held: the cut lists names, and no date or seq outside it counts. | §8.1 |
| Thief reuses an accepted seq in another collection | Refused: the cut's ranges are per collection prefix. | §8.1 |
| Thief signs other bytes at an accepted name | Refused by every reader and forwarder under a cut with a manifest: only the bytes it lists are accepted, and in-cut versions are fetched by full name. Under a cut made before manifests, a reader holding the honest version keeps both and reports the equivocation; one holding neither may take whichever answers first (residual of old cuts). | invariant 2, §8.1, §8.6 |
| Manifest packets withheld | The versions they list stay pending, never accepted with other bytes; they are fetched from another holder. | §8.1 |
| Revocation arrives after a thief's version was accepted | On adopting the revoking context the reader withdraws it and tells every watcher; in-cut versions stay. | §8.3 |
| Issuer revoked after its keys' versions were held | On adopting the revoking context, and on restore, every held version is judged again with the whole walk; those whose chain passes the revoked issuer are withdrawn, saying an issuer refuses them (no re-admission). | §8.3 |
| Honest work outside the cut | Refused and reported with its full name and digest; the root re-admits it by exact name and digest, and every device holding or following it then applies it; no neighbour seq and no other bytes come with it. | §8.2 |
| Certificate renewed, or expired | The key's versions verify alike under the old and the new certificate, before and after either expires; the log continues. A key whose certificate lapsed without a renewal is the exception, for every role the context lists in DataRequiresCut (all of them, by default): its versions are refused until its renewal or its cut. | §8.4, §8.5 |
| A device's certificate lapses without renewal | Its versions are refused, fail-closed, whatever its role (a guest, member, admin or node), until the key is renewed or the root's revocation with a cut bounded at the NotAfter, which keeps what it wrote while trusted. A device that renews before expiry is never refused. | §8.4, §8.5 |
| Device key replaced by a new enrollment | Its versions stay accepted until the owner ends it: the root's tools list it with the cut to make (bounded at the replacement's enrollment), and `ndn-fwd end-keys` revokes it with that cut. | §8.4 |
| Leaked key, certificate expired, never revoked | For a role not listed in DataRequiresCut (every role is, in a context `ndn-fwd init` makes now; an older context lists `guest` alone), never replaced, its thief's versions are accepted (residual), and nothing lists it: revocation with a cut ends it. | §8.5, §8.6 |
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
| Holder rolls back | A summary older than one already seen is refused, also by a reader that restarted since. | invariant 3, §7 |
| Writer never pauses | Each descent finishes against the root it started from, whose nodes the writer keeps serving; the reader then continues from there and keeps up. | §7 |
| Writer equivocates | Both entries are kept and reported (`Change::Equivocation`), at one name or at one seq in two collections or of two kinds. | invariant 2, §4 |
| A writer names a parent seq that does not exist yet (a version over another's future) | Its parent's digest matches no packet at that seq: refused `Refusal::Parent` once the genuine one is held; the other writer's versions apply. | §4, §5 |
| A stale writer's operation made for an earlier rule | Refused `Refusal::OtherRule`; never read under the rule in force. | §5 |
| Writer offline, another device holds its work | Readers ask the other devices they hear for the namespace, under their own names, for the writer's newest root, summary nodes, entries and pieces; each answers with the writer's own packets (sealed as ciphertext), verified as from the writer. Nothing pruned, expired, refused or unverified is served. | §13.5 |
| Holder behind, or withholding | Its older root is not taken below the head verified; the reader gets less, never wrong data, and asks the writer first again once reachable. | §7, §13.5 |
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
| Writer behind on a seal | Its unsealed version is refused `Unsealed`; its later sealed versions do not wait for it. | §5, §9 |
| Relay or repository of another person | Carries ciphertext and grants wrapped to one device each; reads no payload and no key, and sees the metadata §9 lists. | §9 |
| Member offline | Its newest verified summary is what the reader is complete against; it catches up when the member returns. | §7 |
| Lossy link (packets dropped, delayed past the lifetime) | Every fetch that missed is asked again while the device's durable state still owes what it was for — a walk of a summary and what it lists, an epoch key, a removal cut's manifest packet — with a pause doubling from 250 ms to 4 s, never waiting for a new sync notice and never one try per granter; within one ask, an Interest nothing answered is expressed again under a fresh nonce after a retransmission timeout from the round trips the device measured (at least 250 ms, doubling, at most 3 times within the lifetime), so a lost packet costs about that timeout rather than the lifetime; at 20 % loss a sealed folder's first version reaches a reader's watch in seconds. Bounded: at most `FETCH_TRIES` asks of at most 1 + `REEXPRESS_MAX` Interests each per owed packet and source per lifetime plus pause. | §17.1 |
| Device lacks a collection's merge rule | It holds, verifies, serves and lists every version, applies none, and answers `RuleUnknown` (`UpdateProgram`); it never computes a state under another rule. | §5 |
| Reader removed at folder level | One new folder epoch for every inheriting collection; collections in their own epoch listing the reader move to new epochs of their own, and until such a record is held no writer seals in the outgrown epoch (`NotReady`, `RetryLater`). | §6.1, §9 |
| Collection takes its first own record under a folder | Starts from the effective record: a rule change or a first seal sets `Since`, a writer the folder admitted gets a cut, the folder's cuts carry over; its history stays readable and its writers' past admitted. | §6, §6.1 |
| Owner device puts into a new collection before it synced the folder above | No default record is signed while a known device of its namespace was never walked toward the collection's folder, or is known at a newer root than the one walked (the head and the names walked toward are kept across restarts): `NotReady` (`RetryLater`), naming the devices; the folder's record, once held, governs the collection. A device merely offline since a walk toward that folder holds nothing back, nor does one nothing signed held vouches for once its walks spent their `REFRESH_TRIES` tries unreached; one a faulty path kept from a few walks is still waited for. | §5, §6.1, §13.5 |
| Put into a collection that would inherit a folder's record before a device was walked toward the folder | `NotReady` (`RetryLater`) at once, naming the devices, and nothing is signed or sealed: a device not walked yet may hold a record of the collection of its own that narrows who reads or writes it, and a version sealed under the folder's record meanwhile would reach readers that record leaves out. The walk runs in the background; put again once it ends, or mark the lost key suspected or revoke it (it is not waited for then). Once the folder was walked, the put inherits its record and returns at once. | §6.1, §15 |
| Reader holds sealed data before the record admitting it (lost on the way, or not walked to yet) | `get` answers `NotReady` (`RetryLater`), naming the devices, while a known device of the collection's namespace was not walked toward its folder; `Sealed` only once every one was walked and no record held admits the reader. Nothing is read meanwhile: reading takes a record admitting the device and the epoch key it grants. A name a stranger announced in the group delays the refusal by its walks' tries at most (nothing signed vouches for it), never turns it into a read; a device marked suspected or revoked is not waited for. | §5, §9, §15 |
| Write refused after the edit (too large) | Nothing signed or stored, no default record, the log head unmoved; the collection is read again, so the refused edit is not in the state. | §5, §15 |
| Removed writer keeps its devices unreachable | The owner walks the writer's known devices as far as they are reachable and signs the cut over what it holds then; the removal is never held off, and versions only the unreachable devices hold fall outside the cut. | §6, §6.2 |
| Collection record wider than its folder | `share` refuses it; one signed anyway widens nothing: every reader intersects the levels. | §6.1 |
| Collection created under a watched folder, by this device or another writer | Reported on the folder's one watch with no further call, every change tagged with its collection; finding it costs the new branch only (the root, the nodes on the way, the folder node or its changed page, the new collection's node and entries), never a walk of the folder. | §7, §15 |
| Version listed by a watch while it waits (for an earlier version or its key) | Not listed: it comes once it applies, so no watch is handed a version twice. | §15 |
| Folder watch resumed from a frontier joined across its collections | May skip a version of another collection still to come: a writer's versions come in seq order within a collection only. A host resumes a whole folder from the empty frontier (the listing is local) or each collection from its own frontier. | §15 |
| Watcher reads slower than changes come | Its queue holds what its listing queued and `Config::watch_queue` changes more; then `Change::Lagged`, and every change after it is dropped until the watcher read the queue empty — memory bounded, the gap told in order, never silent. The watcher reads again from its frontier. | §15 |
| Folder writer creates collection after collection | It makes a follower follow at most `Config::writer_collections` collections of a namespace outside its own; past it, its new collection is neither fetched nor taken, and the folder's watchers are told `Change::Untracked` naming the writer and what to do (follow the collection by name, or have the writer removed). Counted from what is held, so a restart grants no new allowance. | §15 |
| Owner lists thousands of persons' namespaces | A reader adopts, refreshes, carries in transit and joins the groups of at most `SCOPE_PER_SUBJECT` (64) for one subject and `SCOPE_NAMESPACES` (256) in all; no group of a namespace not adopted is joined; the rest are logged and told `Change::NotAdopted` with what to do, their versions waiting. | §6.3, §12 |
| After a restart, a path serves only an older version of a member's context, or a thief's branch numbered past the one held | The newest version adopted is kept in the store, signed, held again at start and refreshed from by continuity: an older version, that number with other content, or a branch not descending from it is refused and asked again later, so a key a newer version revoked never writes again. | §6.3 |
| Equivocation across two folders | Each collection's watchers are told with their own version whole and the other by name and id only: no watcher learns content of a collection it does not watch. | §4, §15 |
| Reader that predates slice 6 | Refuses folder records (odd TLVs) and waits for them — stale; it applies a collection's own record alone, without a folder's narrowing, until updated. | §16.2 |
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
| A link hint that does not read, names no key, or whose addresses all fail | Ignored: the join goes on by relay hints, else by name; a hint never makes a join fail, and nothing it says is trusted. | §19.3 step 0, §19.7 |
| An address of a link hint that answers with another key | No link: the handshake proves the key the hint names; the other addresses are tried at once. | §19.3 step 0, §19.7 |
| A joiner asks a closed offer again after the new member's answer was lost | Answered the acceptance it was given, until the offer expires, then `Expired`; any other key `Closed`. | §19.4 step 4 |

### 17.1 Asking again under loss

A fetch **misses** when nothing answers within the Interest lifetime
(`Config::lifetime`, 2 s by default), the forwarder refuses the packet for
now (a certificate on its chain not to be had yet), a Nack with reason
Congestion comes that asking again soon did not mend ("A Nack for rate", below;
any other Nack is an answer, not a miss), or what
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
  cut or otherwise refused — then lies in a branch no walk
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
  the first look of `get`, `watch` or `put` (§15) — runs on its
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
- **A group heard from no one (normative).** A first look (§15) that
  finds no device heard that writes into the
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
- **A version a `get` fetches by name** (§15) — asked as a walk's versions
  are, up to `FETCH_TRIES` asks of its writer's device. A refusal kept
  against the name is not asked again.
- **Inside a walk of a version's pieces** (§13.1) — a read — each piece
  is an owed fetch, asked in
  place up to `FETCH_TRIES` asks per source, at most `Config::window` of
  one walk's pieces at once; a piece that missed at every source leaves
  the others to be fetched and kept, and the walk ends without the
  payload. A read asks again as its caller does.
- **A removal cut's manifest packet** a version waits for (§8) — by its full
  name, from any device, while a version waits for it: asked when the
  version comes to wait, on whatever path admits it (an entry taken, a key
  obtained opening it, a descent ended, pieces arrived, a start), then
  after the pause above. Re-admitted entries, the entries a revocation
  cut accepts (§8) and the bytes a cut keeps (§8.2) keep their own
  schedule (`READMIT_TRIES` asks, the pause doubling from 500 ms), and are
  asked again at every group refresh.
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
`RTO` reaches it and an ask is one Interest, as without re-expression.
A granter that sees two Interests of one grant ask
answers both with the one packet it keeps for that name (§9). Re-expression
is liveness only: it decides nothing (invariant 1), and what is held or
counted never depends on its timing.

**A Nack for rate (normative).** A Nack with reason Congestion says the
Interest it carries was dropped for rate — a link's quota, ndn-link.md — and
nothing about the packet: the packet may well be there. An ask that gets one
MUST NOT take it as an answer ("not there"); it expresses the Interest again,
a fresh nonce and the lifetime left as its InterestLifetime, after a pause of
between half of and all of 20 ms (`CONGESTION_PAUSE`), the ceiling doubling
per Nack to at most 160 ms (`CONGESTION_PAUSE_MAX`), so the first retry comes
well under `RTO_MIN` and at about the time one token of a 100-frames-a-second
bucket returns. The jitter is taken from the ask's first Interest's nonce and
the retry count, never from a clock or a random source. **Bound:** at most
`CONGESTION_RETRIES` (8) retries per ask — at most 940 ms of pauses (20, 40, 80
and five of 160 ms) — and a retry only while at least `RTO_MIN` of the lifetime
is left after its pause, so a Nack that never stops costs an ask 1 + 8
Interests and under a second, never more than its lifetime. A pause is no
lost-Interest wait: it does not use up a re-expression of `RTO` (the timer
starts again for the new Interest) and the ask that needed a retry gives no
sample of the round trip. When the retries end, the last Nack ends the ask
as a miss asking again may mend, not as an answer: the owed fetch asks again
after its pause, `FETCH_TRIES` asks in all, so a link that Nacks Congestion
for ever costs one owed packet `FETCH_TRIES` · (1 + 8) = 27 Interests per
(lifetime + pause) — and, where Interests are also lost, at most
`FETCH_TRIES` · 11 = 33 at the defaults: an ask's re-expressions after `RTO`
and its retries after a pause add, so one ask is at most
1 + `REEXPRESS_MAX` + `CONGESTION_RETRIES` = 12 Interests, and within the
default 2 s lifetime and 250 ms `RTO` (gaps of 250, 500 and 1000 ms, pauses of
at least 470 ms in all for the 8 retries, each needing `RTO_MIN` of the
lifetime left) at most 11: the eight retries and the first two re-expressions,
never the third. Every other reason keeps its meaning: no
route, not yet, duplicate or any other code is an answer — the packet is not
to be had from that face now — and ends the ask at once. A Nack reaches an
ask only from a forwarder that accepted it: a Nack is accepted only from a
face holding an out-record of the Interest with the same nonce, any other is
dropped (local-refusal.md §5), so it speaks for an upstream the Interest went
to, not for any face that knows the name. Like
re-expression it is liveness only: it decides nothing (invariant 1).

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
cut, its collection or folder no
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
ask is of at most 1 + `REEXPRESS_MAX` Interests within one lifetime — at
most 1 + `REEXPRESS_MAX` + `CONGESTION_RETRIES` (12) when Nacked for rate as
well, 11 at the defaults ("A Nack for rate") — and
every fetch holds one of the device's `Config::in_flight` slots (256 by
default), waiting for it at most one Interest lifetime: a fetch that gets
none is a miss asking again may mend, not "not there". So one owed packet
costs at most `FETCH_TRIES` asks — `FETCH_TRIES` · 12 = 36 Interests, 33 at
the defaults, and `FETCH_TRIES` · (1 + `REEXPRESS_MAX`) = 12 where no Nack for
rate comes — per source per
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
A verb's own asks are bounded per call: a verb waiting for an epoch key
waits for at most `FETCH_TRIES` rounds of its ask, one ask per granter each.
Grant asks are bounded per asker (§9): a granter works on at most
`GRANTS_PER_ASKER` (32) of one asker device at once, each holding one fetch
slot for at most the wait for its seal key, and keeps at most
`SEAL_LEARNING_MAX` (64) background runs for seal keys, so however many
distinct asks one granted reader sends, its tasks, its slots and the runs it
starts stay bounded — one asker's flood leaves the granter's own fetches the
rest of the slots — and a fetch that waits for a slot waits at most one
lifetime (above).

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
`HEARD_MAX` + 1 entries, and such a name holds back a default record or a
refusal until its walks spent their tries (§5):
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
(5) Re-expression is timed by what the device measured itself and bounded
per ask: nothing another party sends makes one ask carry more than 1 +
`REEXPRESS_MAX` Interests. A party that delays replies — or a slow
producer — raises `RTO`, or, by answering only after re-expressions, keeps
it doubled; either lowers how often the device re-expresses. A forger that
answers one of the Interests ends the ask with a packet refused as in (3).
(6) Nothing another party sends ends a walk that is owed: owing is judged
from the roots, records and versions the device verified and what it
follows, never from whether an ask was answered. A relay answering with an
older root its writer signed (§13.5) cannot stand in for the writer's
state — no newer than the head walked, or answering a notice of the
writer, the writer counts as not reached — nor can an old copy of the
writer's own root that a party on the path delays or replays: in a walk
answering a notice it is asked past, at most `FETCH_TRIES` root asks. A
reader that stops waiting cuts no walk short; each costs at most the
bounds above, never a version left unasked.
(7) Nothing another party sends makes a device stop asking for a walk: a
root is left unasked only while no trust context held here judges its
namespace, decided from the contexts held, never from a refusal or a
forged root (a forged root that names an anchor nobody holds is refused,
as in (3), and asked again); and the adoption that ends it owes the walk
without waiting for a notice, so a namespace adopted after its writer
fell quiet is still read.
(8) Only a first look of the device's own announces again in a group
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
`/home/bob`),
c8 (a laptop back after four months: 10,000 notes, 37 changed), o4
(a reader keeps up with a writer that never
pauses: it holds everything written before it looked, then every later
moment's versions, while the writer keeps putting and a second reader
makes it sign a new root many times a second) and o5 (a sealed folder
converges under loss: with one packet in five dropped on its way into each
device, the first version Alice seals reaches Bob's folder watch, opened,
within 10 s of virtual time, §17.1). The slice-2 cases are c2
(Bob removed while offline: his later edit is refused whatever its date),
c4 (a note sealed to Alice opens for her host, and a device outside the
audience cannot read it), c9 (a family chat under the log rule: members'
messages reach every member, a non-member's post reaches no one), o1 (a
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

The slice-3 case is h1 (a photo of hundreds of pieces read whole and
verified).

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

The slice-6 cases are h10 (a device serves the versions it holds that
another device wrote: Alice's phone writes a path of a sealed folder and
goes away for good, no cache keeping what it served; her laptop answers
for the phone's root, summary nodes and sealed entry, exactly as the phone
signed them, and Bob reads the value the phone wrote),
f1 (a folder of 1,000
collections: a reader asks one grant per folder epoch, not one per
collection), f3
(a collection taking its first own record under a folder: a writer it
drops keeps its earlier versions, cut at what the owner held, and a seal
keeps what was written unsealed before readable, at every reader) and f4
(Carol and Bob join a note by codes; the owner's `members` and folder
watch show both with no gesture of hers; she lets Carol go with a change
naming Carol alone, and Bob stays a member, writing and reading, his
device holding the same record, while Carol no longer reads what follows).
Their features are `FolderMembers` and, for f4, `Introduction`.

The folder-watch case is w1 (a note of 1,000 paragraphs, one register
collection each, under one folder shared by `share_folder` with a second
person as writer and reader; both watch the folder once. The other person
adds a paragraph — a collection created after the watch began — and the
watcher's stream reports its version tagged with the new collection; the
same the other way round, and for the watcher's own add; no watch is
handed one version twice. The Interests the watching device sent from
each add to its delivery, and the time, are measured, not asserted). Its
feature is `FolderWatch`. Focused tests in `ndn-data`'s
`device/watch_tests.rs` hand a device crafted entries: a collection
created under a watched folder delivers its version, and a
cross-collection equivocation once per collection, each tagged; an
equivocation across two folders shows a watcher nothing of the other
folder's content; a version waiting for an earlier one
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
each store instance has its own barrier. The batching cases (§4.2, one batch
per put) are d4 to d8: d4 (a batch, `DataStore::apply` or
`SyncBackend::write_batch`, that returned survives `kill -9`, with nothing
written after it) and d5 (a child killed at a random moment inside a large
batch: after reopening each batch is whole or absent, in order) run on both
engines in `ndn-sync`'s `tests/durability.rs` and `ndn-data`'s
`device/batching_tests.rs`; the power-loss case d2 also commits `apply`
batches. d6 (a put reaches the store as one batch, markers before pieces
before the entry; for
every prefix of a batch on a store that does not apply it atomically a
restarted device is sound) and d7 (a burst of puts reaches the store in seq
order and is served identically after a restart) are in `ndn-data`'s
`device/batching_tests.rs`; d3's in-process check also covers a burst, whose
batches are all stored before any `put` returns and none published before
its flush. d8 runs in the conformance runner, clean and `--faulty`: a burst
of puts, each one batch, converges among devices and survives a
restart.

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
again with the code, before and after the inviter restarts: answered the
acceptance it was given — the removal closed the offer, which still
answers its user, §19.4 step 4 — and never reads what the owner writes
afterwards), i11 (a stranger spending its own wrong tries is
refused `Closed` while the code's holder still joins; on a used offer a
stranger's guesses are refused `Used`, counted nowhere, and the user
asking again is answered), i12 (not among strangers, so the owner's
other device reads the member's writes: a member removed by that device,
which closes nothing, asks the offering device again: answered, never
admitted again), i13 (the owner closes an offer as soon as the member
appears: the member asking again is answered, another key is refused
`Closed`, and after the offer's expiry the member is refused `Expired`),
i15 (round 6, §19.8: an offer's admission tells the inviter's host of one
grant naming the admitted key, the asker's namespace, the folder and the
offer's role, with no date; `Device::grants` lists it; the same key
asking again, another key refused, a code forged without its secret, and a
host whose policy has `grant_for` `Some(ZERO)` tell the host nothing and move
no end), i16 (round 6, §19.8: a held members record signed by another
device of the inviter's person that leaves a granted person out ends that
grant, once, and the other person's stays; after a restart of the inviter
`Device::grants` lists the same grants less the ended, and the host is told
nothing again), i17 (round 6, §19.8 rule 6: a held record signed by
another device that demotes a granted writer to a reader changes the grant:
`Device::grants` lists it as a reader's, the host is told it again, once,
with the reader's role and never that it ended, and after a restart the
grant is the reader's and the host is told nothing again), i18 (round 7,
rule 13: two offers to one person are two grants, and a record that leaves
them out of one folder ends that folder's grant alone), i19 (rules 14 and
15: a person let go while offline takes the record that let them go, and
their device then lists them no more and takes no more writing), i20 (rule
16: two writers invited apart read each other's pages through the inviter)
and i21 (round 7 fix, rule 16: a member let go and invited again joins the
sealed folder — the walk descends into the folder's node while the new
admission is pending — and writes and is read again). Their feature is
`Introduction`; their provider surface is
`Provider::link_grants` and `Provider::link_key`, and a plan may give a
device a policy of no grants (`Plan::no_link_grants`).
`ndn-data`'s `intro.rs` unit tests check the records, asks and answers
round-trip, that malformed ones are refused, that each proof binds every
field it covers (another offer, key, digest, nonce or secret fails it),
and the default `IntroPolicy`; its device tests (`device/intro_tests.rs`)
check that only the certificates of the verified chain are cached, that a
joiner whose key is its own anchor is answered, that an offer is not spent
when the host does not adopt the asker, that a closed offer refuses its
user too, and that asks past `asks_queued` get no answer at once; and the
grant (§19.8): one grant per admission for the admitted key with the
asker's namespace and the offer's role (writer and reader), none for a
retry (its end not moved), for any ask refused or not completed, or with
`grant_for` `Some(ZERO)` (no note kept); a grant with no date (the default)
outlasts the clock and follows the record, and one with a date is not in force
past it and is not announced as revoked; a held record that leaves the
person out — signed by this device or by another device of the inviter's
person — ends the grant once, durably, with the other person's grant
standing, across a restart, and a person readmitted by a later record is not
granted again; the host's `end_grant` and `renew_grant` are durable across a
restart (a renewal only of a grant a held record admits, to a date after the
clock); a note changed in the store (the `ended` flag cleared, a date
extended or removed) fails its MAC and is not read, so no grant is
resurrected; a writer demoted to a reader is granted as a reader at once and
the host told again once; and the host is told of an end before it is
durable (a frozen disk does not delay it).

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
  nonces) change what it sends, never its order or timing. A task that
  waits on several sources at once (its shutdown, a timer, what the
  application hands in, what the network sends) polls them in one fixed
  order, `biased`, so two ready at the same virtual instant are taken in
  the same order in every process, never in the order the runtime's
  unseeded random draw picks. The order is shutdown, timers, what the
  node's own application hands in, then the network, so a flood from the
  network delays inbound work and nothing else; a timer is re-armed to a
  later deadline each time it fires, so none stays ready to starve the
  rest. The sets a Sync reply is made from (PSync's held Interests,
  stored segments, and the names a reconcile offers) are ordered by name
  or hash, so the names in a Sync Data and the Interests answered by one
  publication come out in one order.
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
  120 s of virtual time (the harness's `AGAIN_PAUSE`, `AGAIN_FOR`); it does
  not on any other answer. Asking again is liveness only: a `RetryLater`
  refusal decides nothing, and what the verb answers when it succeeds is
  judged as on a first try.
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
Interest with it, whichever face the forgery came on: a forwarder validates
Data on a TCP, UDP or WebTransport face even to a loopback address, so a
member's connection on the same host is no exception (trust-context.md
§6.6). Nothing is kept against its name: a forged copy never
makes a device refuse the genuine packet at that name, never counts as
evidence (an equivocation or a refused version), and never stops
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
A duplicated packet is idempotent: a version, grant,
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
used — or neither — a **closing mark**: the offer admits no one new from
then on, and answers its user alone, until it expires (all askers' wrong
tries at the device's cap, §19.4; `close_offer`, §19.2; or a record it
signs removing the member the offer brought, §19.7). The
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
3. Returns the code only once the offer, the wrapped proof key and, when
   there is a short code, its wrapped hint token are durable (§4.2): before,
   a power loss could take the record and give its seq to another.

The **code** has three forms, which `offer` makes together (`Code { offer,
link, words, short, short_why }`; `Code::share()` is the short code when
there is one, else the link: what a host shows):

- the **link**, a trust-envelope `intro` link
  ([trust-envelope.md](trust-envelope.md)) or its https mirror, in the
  compact form below: the inviter's namespace, its anchor fingerprint
  (SHA-256 of its root anchor's public key, whole), the offer's name, the
  secret, the inviter's link hint (below), and as many relay hints — the
  relays the inviter's trust context advertises, by device name
  (`/<namespace>/<role>/<device>`, §3; its certificate is
  `/<namespace>/<role>/<device>/KEY/<key-id>/<issuer>/<version>`) — as
  `IntroPolicy::code_relays` allows and one QR holds; the secret, the offer
  and the fingerprint are never dropped;
- the **words form**: the offer's name, then 24 BIP39 English words
  encoding the secret followed by the fingerprint's first 16 octets (its
  checksum catches a mistyped word); the words carry no hint and no relay;
- the **short code**: one line, the inviter's device name, a first contact
  and 20 or 36 words. It names no offer: a signed hint record the inviter
  serves does (below).

`join` tells them apart by the text alone, before it does anything else
(§19.3). A text that starts with `/` is the words form when the number of
words after its first token is exactly 24 (a second token that starts with
`/`, `[` or a digit is a first contact and is not counted), and a short code
otherwise; a short code with a count other than 20 or 36 is refused, saying
how many words it found and which counts exist (§19.5). Any other text is
read as a link. The three forms of one offer carry the same secret and
fingerprint (the short code's, a prefix of it for a named namespace); the
link and the words form are made always, the short code only when the
conditions below hold.

The **link hint** is what lets a joiner with no daemon, no route and no
peer entry reach the inviter's device by its key. A host that listens for
links gives it (`Introducer::link_hint`, once per `offer` and once for each
hint record made on request, below): the device's
**link key** — SHA-256 of its public key as a certificate carries it, 32
octets, the fingerprint a link handshake proves (ndn-link.md §3.3) — and
at most `LINK_HINT_CANDIDATES_MAX` = 8 **candidates**, the addresses of its
listening link socket, most promising first (an address another computer can
reach, then one of a bridge or container interface, then loopback and
link-local ones; ndn-link.md §14.2), each a kind (ndn-link's: host,
reflexive, advertised, mapped, §14.2), an IPv4 or IPv6 address and a UDP
port. It is the value of the envelope's `LinkHint` (0x0478): the TLVs
`LinkKey` (0x05B0, the 32 octets) and `LinkCandidate` (0x05B2, once per
candidate: one octet of kind — 0 host, 1 reflexive, 2 advertised, 3 mapped —
then the address, 4 or 16 octets, then the port, 2 octets big-endian).
Even types: a reader skips what it does not know. A writer encodes each
distinct dialable candidate once, up to the bound. A reader keeps the first
8 distinct candidates whose kind it knows and whose address is dialable
(not unspecified, multicast or broadcast, and port ≠ 0) and, unless its
policy allows them (`IntroPolicy::local_candidates`, off by default), not
loopback (`127.0.0.0/8`, `::1`) or link-local (`169.254.0.0/16`,
`fe80::/10`): the inviter's own gathering never offers those to a device
elsewhere, and a stranger's code must not make a device send datagrams to
services on itself or on its link. A device that is the inviter's on one
machine (tests, a demo) turns the policy on. A reader refuses a hint that
names no key or two, or a candidate that is not 7 or 19 octets: the
join then goes on without the hint, which only helps to reach.

**What the inviter's links serve.** A host that listens for links serves
introductions over a link a stranger dialled through the device's
**introduction surface** (`Device::introductions()`, held weakly, so the
host's links never keep the device alive). The surface is **open** while an
offer of the device has not expired by its clock — a closed offer counts,
since it still answers the writer it admitted until it expires. With no
offer open, a stranger is refused a link as any device nobody knows. Over
the link it **carries** an Interest only for the ask (`<D>/32=intro/…`),
while open, for the offer's own record (`<D>/32=held/<e>`, `e` an
unexpired offer in the device's own log), and for a short code's hint
record (`<D>/32=hint/<token>`, `token` that of one of the device's own
offers with a short code, whether the offer is open, closed or expired:
the answer is then its gone mark): no other log entry, summary root
or packet the device holds by name crosses it, though the device serves
them to its members, and no other name of the `32=hint` family (the prefix
alone, a token the device does not hold). This replaces serving the whole
`<D>/32=held` and `<D>/32=intro` prefixes for good. A link is made only
while an offer is open (above), so a joiner that dials after the last offer
expired meets no link, not a gone mark (§19.3).

**The full link, compact.** One encoder writes the link's body
([trust-envelope.md](trust-envelope.md) §4.3): the inviter's namespace once,
as a Name (`IntroNamespaceWire`, 0x0490) and not as text; the offer's name
(`IntroOfferWire`, 0x0492) and each relay (`IntroRelayWire`, 0x0494, in the
order of the trust context) as a **relative name** — one octet `k`, how many
leading components it shares with the namespace, then its remaining
components as wire — so a self-certifying component is 34 octets, not 96
characters of escapes, and appears once beside its repeats; the secret and the
whole fingerprint; the link hint (0x0478, as above), at most
`IntroPolicy::code_candidates` candidates (default 3, the first ones); and
at most `IntroPolicy::code_relays` relays (default 2), **by name, not by
key**: a key alone gives a joiner nothing to route or dial by, and a relay's
name is what a ForwardingHint is. The names a link carries are in the
canonical text of `Name` (`Introduction::check`; the data layer's keyword
`32=log` is written `keyword=log`). The old text tags (Namespace 0x0489,
Offer 0x0475, RelayHint 0x0476) are read, never written: a link made before
this form still joins, to the strings it carried. A joiner needs no hint
record from a link: the link names the offer and, with its link hint, the
key to dial.

The link stays within one QR (`ndn_trust_envelope::qr::MAX_TEXT_LEN` = 2331
characters). A hint costs 34 octets and 9 (IPv4) or 21 (IPv6) per
candidate, a third more as base64url. When a link does not fit, the maker
drops relay hints first, all of them, then the hint's last candidates one
by one, then the hint itself; an offer name so long that the link does not
fit without them is `Local`. The measured sizes are in the table below.

**The short code.** One line a person can read aloud or type
(`ShortCode::encode`, `ShortCode::parse`):

```
short      = device SP [ contact SP ] word{20}     ; a named namespace: 10 octets, the fingerprint keyed by the code's secret
           | device SP [ contact SP ] word{36}     ; the whole 32 octets of the fingerprint
device     = an absolute NDN URI of the inviter's device D, not the root: /alice/member/laptop
contact    = "[" IPv6 "]" ":" port                 ; [2001:db8::7]:4433
           | IPv4 ":" port                         ; 192.0.2.7:4433
           | relay-name                            ; an absolute NDN URI, starting with "/"
word       = a BIP39 English word, 11 bits
```

1. **Tokens.** Whitespace of any amount separates the tokens. The first is
   the device. The second is the contact when it starts with `/`, `[` or an
   ASCII digit — no word of the list does — else there is none. All the rest
   are words, and exactly 20 or 36 of them. Case and spacing do not matter
   in the words; a device or relay name is case-sensitive.
2. **`161=*`.** A component written `161=*` (type 0xA1, the single octet `*`)
   stands, in the device name and in a relay name, for the self-certifying
   component equal to the anchor's whole fingerprint: the 32 octets are in
   the words, not written a second time as 96 characters of escapes. It is
   valid only with 36 words; with 20 it is refused (`Placeholder`, below). A
   writer MUST write `161=*` for every self-certifying component of the
   device and of a relay name that equals the whole fingerprint, and writes
   the whole fingerprint exactly when the device's namespace is the
   self-certifying one it is the digest of; it MUST refuse a name that has a
   literal `161=*` component. A reader that finds `161=*` reads the name with
   the fingerprint in its place and names the namespace as the device's
   prefix up to that component. A 36-word code without `161=*` is valid: the
   names are literal.
3. **Words and checksum.** `payload = secret (16) ‖ fingerprint (10 or
   32)`, the 10 octets being the **keyed fingerprint** (below); the words
   encode `payload ‖ checksum (12 bits)`, eleven bits to a
   word (trust-envelope.md §5.8): 26 octets are 220 bits, **20 words**; 48
   octets are 396 bits, **36 words**. The checksum is the first 12 bits of
   SHA-256(`ndn-trust/intro-short/1` ‖ the **bound text** ‖ `0x00` ‖
   payload). The bound text is the canonical text of what precedes the words:
   the device name re-rendered from the parsed Name (each component as
   `Name` writes it, `161=*` where item 2 says), then, when there is a
   contact, one space and the contact re-rendered (a parsed socket address in
   its standard form, or a relay name as the device). So spelling that parses
   to the same name and address (case of hex digits, an expanded IPv6
   address) does not matter, and **a typo anywhere** — a word, a digit of the
   port, a letter of the device name — is caught with probability 1 − 2⁻¹².
   Words of the 24-word form are unchanged and still read.
4. **No correction.** 12 bits cannot single out one repair among the
   20 × 2047 single-word edits (about ten of them satisfy the checksum), so
   a typo is refused with the text that names what to check, never repaired.
5. **The contact.** An address MUST NOT have port 0, be unspecified,
   multicast or (IPv4) the broadcast address: the code is then refused
   (`Contact`). A loopback (`127.0.0.0/8`, `::1`) or link-local
   (`169.254.0.0/16`, `fe80::/10`) address is refused (`Local`) unless
   `IntroPolicy::local_candidates` is on: a code from a stranger is not made
   to send datagrams to services on the joiner's own machine or link, as for
   a link hint. A relay is a device name; nothing is dialled for it.
6. **Order of refusals.** The reader refuses, in this order, a device name
   that is no name (`Device`), a contact that is neither (`Contact`), a word
   count other than 20 or 36 (`Words`), `161=*` with 20 words
   (`Placeholder`), a word off the list (`UnknownWord`, by position among the
   words, from 1), a checksum that does not match the words, the device name
   and the contact (`Checksum`), an address no device can dial (`Contact`),
   and a loopback or link-local address (`Local`). Each is a `BadRequest` of
   the joiner's `join`, before anything is dialled, with the text of §19.5.

The words are the one thing that cannot be fetched beside the code's few
facts: the secret (16 octets, never fetched, never on a wire in clear;
128 bits stay, because an offer's commitment is public in the inviter's log,
and a shorter secret could be searched offline) and the anchor's
fingerprint. The device name is in the text because the hint record is
fetched at its name and an Interest is routed by it; the contact is the only
way to reach the inviter before the record is held.

**The fingerprint a short code carries.** A named namespace's code carries
`keyed_fingerprint(secret, anchor) = HMAC-SHA256(key = secret,
"ndn-data/intro/fp/1" ‖ anchor)[..10]`, `anchor` being the 32-octet
fingerprint of the namespace's anchor (§19.6), not the first octets of
`anchor` itself. It is the same number of octets and words as a plain
truncation. The joiner computes it again from the whole fingerprint of the
anchor the verified credentials carry and compares in constant time
(`Mac::verify_truncated_left`; a tag of any other length is no match).
The code of a self-certifying namespace carries the whole 32 octets: they
are the namespace's name, not a truncation of it. A code made before the
keyed fingerprint carries the plain first 10 octets, which no longer match
any anchor: it is refused as an anchor mismatch that says so (§19.5). The
old 24-word form, which a link and `Code::words` also give, carries a plain
16-octet prefix, and is judged as a prefix of the anchor's fingerprint,
compared in constant time. Why 80 keyed bits, and why 128 plain bits for
the words form, are in §19.7.

**The hint record.** What the joiner fetches by the code's first contact,
and the only thing a short code's offer names: a record the inviter makes
**on request** and signs.

1. **Name.** `<D>/32=hint/<token>` (§16.1), `token = HMAC-SHA256(key =
   secret, "ndn-data/intro/hint/1")[..16]` (`hint_token`; `hint_name`,
   `hint_prefix`, `parse_hint_name`; `HINT_TOKEN_LEN` = 16). It is
   unguessable without the code (128 bits of an HMAC key), and it reveals
   nothing of the secret, which is never in a name or on a wire. The offer's
   own name is not used: its `seq` is guessable.
2. **Data.** Signed by the device key, as it signs every packet it serves,
   with `FreshnessPeriod` 5 s (`HINT_CACHE`): a cache does not hold an
   address past the time the device would give it. Its Content is one
   `IntroHint` (0x05B4, §16.2): `HintOffer` (0x05B6), the offer's name, so
   that the signed record is bound to the offer at a name only the secret's
   holder can ask for; `LinkKey` (0x05B0) and at most
   `LINK_HINT_CANDIDATES_MAX` (8) `LinkCandidate` (0x05B2), the host's
   current `Introducer::link_hint` (with no hint from the host: the
   device's own key and no candidate); `HintRelay` (0x05B8), the device
   names of the relays the namespace's trust context advertises, in its
   order, at most `HINT_RELAYS_MAX` (8); `HintUntil` (0x05BC), the offer's
   expiry, informational; and `Credentials` (0x056F), the inviter's signed
   trust context and the certificate chain of the signing key, as an answer
   carries them, which is what lets the joiner verify the signer with
   nothing but the code's fingerprint. A reader skips an unknown even TLV;
   it refuses a record that repeats a field, names no offer, key, expiry or
   credentials, has more than 8 relays, or has content after the `IntroHint`;
   candidates are read as a link hint's are (§19.2 above: at most 8
   distinct dialable ones, loopback and link-local only under
   `local_candidates`).
3. **Gone mark.** For an offer no longer served, the same Data holds
   `IntroHint { HintGone, Credentials }`: `HintGone` 3 expired, 4 closed (any
   other refusal of the offer is written as 4), and the inviter's
   credentials as a record carries them, signed alike. It carries nothing
   else and is a clear refusal where there would be silence. Its Data has
   **`FreshnessPeriod` 0**: a cache holds a record for `HINT_CACHE`, never a
   mark, so a party on the path cannot leave a forged mark in a cache to
   answer the joiner's retries. The joiner verifies a mark as it does a
   record (§19.3 S5): a mark that does not verify is anyone's, and ends
   nothing (§19.5 `GoneUnproven`). A reader refuses a mark without
   credentials, or with anything else of a record.
4. **On request.** The device makes the record when the Interest comes, from
   the host's link hint and the namespace's relays as they are then, so a
   restarted inviter or a moved address is current. It signs one record per
   token and keeps it 5 s, answering the same Data again while the offer's
   state (record, or which gone mark) is unchanged (a gone mark too is kept
   5 s by the inviter; its Data's `FreshnessPeriod` is 0, item 3); a change,
   a closing mark included, is signed at once. A device with no introducer,
   or whose credentials cannot be made, answers nothing.
5. **Served while the offer is open.** The record is served while the offer
   is open (not expired by the device's clock, not closed: a closing mark
   held, or the overall wrong tries at the cap, §19.4 step 4), and a gone mark
   after, when `IntroPolicy::hint_while_open` is on (the default). With it off
   the record is served until the device stops, with no gone mark. Either
   way the offer answers by its own rules (§19.4): a hint that outlives its
   offer joins no one.
6. **Unknown tokens.** An Interest for a hint name of this device whose token
   is not one of its own offers' is answered as every unanswerable name is,
   by a Nack (`NoRoute`): the same for every token a prober can try, so
   nothing of any token is revealed, and a joiner with a mistyped but
   checksummed code fails its tries at once. Over an introduction link such
   an Interest is not even carried (above). A name of another device is not
   answered either.
7. **What the device keeps.** `offer` makes the token from the secret, wraps
   it to the device's recipient key under a local name beside the offer's
   proof key (the same kind of note: a writer of the store cannot make one
   read), and keeps `token → offer` in memory, rebuilt from the store at
   start for the offers it holds (a note not wrapped to the device's key is
   ignored, and its offer publishes no hint). The offer record and the log
   hold nothing of the hint. A hint record exists only for an offer that
   was given a short code. The token, one name per offer, and its durable
   note stay for as long as the offer record is held — offers are never
   pruned — because item 5 gives a gone mark to the token of a closed or
   expired offer, across a restart too; what is kept of the **signed
   packets** lives `HINT_CACHE` and no more: a packet older than that is
   dropped whenever a hint Interest is answered or refused (an unknown
   token's too), a token is kept, or an offer closes, and a closing
   drops the packet kept for that offer's token at once. Nothing a prober
   asks for grows what the device keeps.

**The surface and the prefixes.** `IntroductionSurface::carries(name)`
gains exactly one exact name family, `<D>/32=hint/<token>` of a token the
device holds (above); nothing else widens. `introduction_prefixes(D)`
returns three names, `[<D>/32=held, <D>/32=intro, <D>/32=hint]`: what a link
dialled for an introduction routes, and no other name of `D`
(ndn-link.md §13.3 rule 3, §13.3A).

**When a short code is made.** `offer` makes the short code, and with it
publishes the hint record, only when `IntroPolicy::short_code` is on (the
default), the host gives a first contact and the line fits
`IntroPolicy::short_width` characters (default 294: three lines of 98
columns, counted in characters with the spaces). The first contacts are, in
order, the dialable candidates of the host's link hint, which is in ndn-link's
order (an address another computer can reach first; loopback and
link-local ones last, and only under `local_candidates`), then the namespace's relays
(up to 8), and the first whose line fits is taken: a longer address or name
gives way to the next. With none, `Code::short` is `None` and
`Code::short_why` says why, naming what to do (give the link, or the words
with the offer's name): policy off (`IntroPolicy::short_code`); no first
contact; or the device name and the number of first contacts tried, and
that the line would be at least so many characters, past `short_width`. A
longer name is the owner's choice; the link still works. Nothing of a hint
is published then.

**Policy.** `IntroPolicy` gains five fields:

| Field | Default | Meaning |
|---|---|---|
| `short_code` | `true` | make a short code and publish its hint record |
| `short_width` | 294 | the most characters of a short code's line |
| `hint_while_open` | `true` | serve the record only while the offer is open, a gone mark after |
| `code_candidates` | 3 | the most link-hint candidates a full link carries (the record serves all 8) |
| `code_relays` | 2 | the most relays a full link names |

**`Introducer::dial_first`.** A short code's address first contact is dialled
by `Introducer::dial_first(inviter, addr, within)`: **one** address, with **no
key to expect** (a short code carries none); `Ok(key)` is the SHA-256 of the
public key the handshake proved. The dial sends an **empty hello** (no
certificate, no membership: ndn-link.md §13.3A), and until the joiner holds
the inviter's namespace the link routes only `introduction_prefixes(inviter)`,
never the names the code claims for the device, and receives from the party
answers under those prefixes and Interests under the joiner's own device names
only. The address is a hint: whoever answers there is linked, and everything it
serves is verified against the code (§19.3); a link whose key is not the
verified record's is taken down at once (§19.3 S6). The default dials nothing
and refuses with a text that says the host has no link layer; the join then
says the first contact could not be reached.

**Lengths (informative; measured, the same secret in each).** Characters of
the one line of a short code (device name, contact, words), and of the
compact link (`ndn-trust://intro/…`), with the names of the code's tests:

| Short code | Characters | Words |
|---|---:|---:|
| IPv4 `192.0.2.7:4433`, `/alice/member/laptop` (named) | 167 | 20 |
| IPv6 `[2001:db8:1234:5678:9abc:def0:1234:5678]:65535` (the longest), named | 201 | 20 |
| relay `/alice/node/relay`, named | 171 | 20 |
| no contact, named | 154 | 20 |
| IPv4, `/user/161=*/member/laptop` (self-certifying) | 273 | 36 |
| IPv6 `[2001:db8:1:2:3:4:5:6]:4433`, self-certifying | 288 | 36 |
| relay `/user/161=*/node/relay`, self-certifying | 281 | 36 |
| the longest IPv6, self-certifying | 305, over `short_width`: no short code | 36 |

| Compact link | Characters |
|---|---:|
| named, no hint, no relays | 202 |
| named, 2 relays | 293 |
| self-certifying, no hint, no relays | 285 |
| self-certifying, 3 IPv4 candidates | 388 |
| self-certifying, 3 IPv6 candidates | 436 |
| self-certifying, 3 IPv6 candidates, 2 relays | 489 |
| self-certifying, 2 IPv4 and 1 IPv6 candidate, 2 relays (the text encoding wrote 1056) | 457 |

Words average about 5 characters, so a different secret moves each figure by
a few characters. The checksum, for the fixed corpus of the code's tests (a
payload of 26 octets, then 48): of 40 940 substitutions of one word, 8 went
undetected (chance expects 10), and of 73 692, 22 (chance 18); of 19 and 35
adjacent swaps, none; of 304 single-character edits of the device name and
address, none.

`close_offer(offer)` on the device that made the offer signs its closing
mark and returns once it is durable: the offer admits no one new — every
ask by a key other than the one it was used by is refused `Closed`, even
with the right secret — and still answers the key it admitted, with the
acceptance kept for its use and nothing else, until the offer expires
(§19.4, step 4). A host that closes an offer as soon as it sees the new
member needs no pending close of its own for a joiner whose answer was
lost. A record the offering device signs that drops the namespace an
offer's user was admitted as closes the offer the same way (§19.7). What
the offer granted stays until a members record removes it. Another
device's offer, or a name that is no offer held, is `BadRequest`; closing a
closed offer does nothing more. The hint record of a closed offer is its
gone mark (above).

### 19.3 Joining

`join(code)`, a short code, the link (or its https mirror) or the words. Before it dials,
fetches or asks anything, the code is judged — the dial gives whoever holds
the code's key a link, and the device name a code claims is only a claim:

- A code that names a namespace the offer's device `D` is not under is
  altered: `Forged`. Ask the inviter for a new code.
- The namespace a code names is judged as in step 4.
- A device `D` under a namespace this device already trusts is refused
  `InviterConflict { inviter: <that namespace>, why }` (`AskOwner`: do not
  use the code) unless the code names that very namespace, or none, and its
  fingerprint — or the prefix of one a short code or the words carry — is that of one of that namespace's anchors this device holds: the
  same anchor is a party known already, and a second invitation from it is
  welcome. Without the exception a code could claim a device of a namespace
  this device trusts, and the link, with that namespace's Interests, would
  go to whoever holds the key.

Then:

0. **Dials the inviter by the code's link hint**, when the link form of the
   code carries one, before any Interest: `Introducer::dial(hint, D,
   within)`, `within` being `Config::first_look`, once per `join`. The
   host's link layer tries the hint's candidates and links only to the
   device whose key the hint names. Until that device shows a certificate
   of a namespace this device holds, the link routes only `D`'s
   introduction prefixes (`<D>/32=held`, `<D>/32=intro`) — never `D`'s other
   names, which only the code claims (ndn-link.md §10, §13.3); once this
   device holds its namespace the link is made again and the device is
   identified. `Ok`: the Interests of the steps below go over
   that link by name, with no ForwardingHint. An error — the host has no
   dialer, no candidate answered within the bound, an address presented
   another key — is not a refusal: the join goes on at once as it would
   without a hint, by the relays the code names, else those its own
   namespace's trust context advertises, else by name. A hint that does
   not read is ignored the same way. The dial carries no secret and judges
   nothing of the code (§19.7). **A join that fails after its dial
   succeeded** — for any reason, `NotReady` included — calls
   `Introducer::undial(hint, D)` before it returns: the host takes down the
   link the dial made, unless it was up before the dial or has been
   identified since (the default does nothing: a host with no link layer
   dialled nothing). A retry dials again.
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
   is the code's (whole for a link and a 36-word short code, a prefix for the words and a 20-word short code), whose namespace is
   the code's (when it names one) and a prefix of `D`; the inviter's proof
   packet `<D>/32=ask/<binding>`, the binding SHA-256 of the intro-answer
   label (§16.1) and the answer's fields before it, and the offer record
   are both signed by a key of `D`
   that chains to that anchor through those certificates; the offer's
   commitment is the code's secret's; the folder and role are the offer's.
4. **The inviter's namespace is no other's**, judged by this device (the
   words and a short code of a named namespace name none, so it is judged here for them too): not the root, not
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
   5's look. The note holds the offer's expiry and the members **revision**
   the acceptance carries. It lasts until a members record held admits the
   device (a write went through, or `join` returned), so a put in that
   window is `NotReady`, never `AskOwner` (§18.1) — and no longer: it lets go
   when the offer has expired by this device's clock (an inviter that never
   sends the record cannot keep a retrying program waiting for good), and
   when the folder's record held here is of that revision or a later one and
   does not admit the device (it was removed since; a removed joiner who
   joins again, answered as it was, is told so, not to wait). A put is then
   refused as for any device no record admits (`AskOwner`, or `Sealed` under
   a record that leaves it out of a sealed audience). It then waits, for at most
   `Config::first_look * 3 + Config::lifetime` (the bound of every wait of a
   join), for the things a write needs: the members record over `F`
   that admits it — for a writer role, one that lists its key as a writer;
   for a sealed folder, one whose audience admits its device —, when sealed,
   the key of the epoch it seals in (the grant, §9), and, for a writer, the
   walk of every device of `F`'s namespace known here toward `F`. The walk is
   the gate a put's inheriting of the folder's record has (§15, 2): a device
   not walked yet may hold a record of a collection under `F` that narrows
   `F`'s, so the writer's first put into a new collection there would be
   `NotReady`; `join` waits for it so that it is not. While the record is
   missing or a walk is owed it walks the summaries of the devices known to
   write into the inviter's namespace and the inviter's own, in the
   background; while the key is missing it asks for the grant (§9); no wait
   ends the others' asks. `Ok(Joined)` therefore means: the offer answered
   **and** all of them are held, so a put in `F` is refused for want of none.
   When the bound passes: `NotReady { name: F, why }` with next step
   `RetryLater`, `why` naming which is missing ("the members record of `F`
   is not held here yet", "… held here does not admit this device yet", "the
   epoch key of the folder (its grant) is not held here yet", "has not yet
   walked the summary of `<device>`") and what to do: join again with the
   same code, or put again; both are safe; a device that is lost is marked
   suspected or revoked, and is not waited for then. **`join` is idempotent
   for the same code**: a second call by the key an offer admitted asks
   the offer again, which answers it as it answered the first (§19.4: the
   same key asking again is answered again, and a closed offer still
   answers the writer it admitted until it expires, §19.2), and then waits
   for the same things; it never
   answers "already used" to the device it admitted. A reader waits for the
   record over `F` and, sealed, the key, the same; it needs no walk to read.

**Joining by a short code.** A short code names no offer and no key, so steps 0
and 1 above are replaced by the steps below, in this order; steps 2 to 6 then
run as written, with the offer's name from the verified record. A link or the
words form fetches no hint record. Until the record has named it, a refusal
or a `NotReady` carries the inviter's device name in place of the offer's,
never the token.

- **S1. Read** the code (§19.2). A code that does not read is a `BadRequest`
  (§19.5) and nothing is dialled, fetched or asked. A 36-word code whose
  device name has the self-certifying component equal to the fingerprint
  also names its namespace, the device's prefix through that component, so
  that it is judged as a link that names one is.
- **S2. Judge before any dial**, as above, with a fingerprint that may be a
  prefix: a device of this device's own namespace is `BadRequest` ("the code
  offers a folder of this device's own namespace: it is yours already");
  a namespace the code names (a 36-word code with `161=*`) over a whole
  fingerprint is judged as in step 4, `InviterConflict`; a device under a
  namespace this device trusts already, `InviterConflict` unless an anchor
  of that namespace begins with the code's fingerprint. **What waits for the
  record.** The refusals that need the inviter's namespace itself — the
  policy's (`IntroPolicy::refuses`), a namespace that lies over or under one
  this device trusts, one that overlaps this device's own through a prefix of
  it — run before the dial only for a code that names the namespace (a link;
  a 36-word code over a whole fingerprint). A short code names none: any
  prefix of the device's name may be its namespace, so judging a prefix
  would refuse an inviter whose namespace is longer. Those refusals run on
  the verified record (S5 check 10), before the record's key is dialled and
  before anything is asked. They disclose nothing of the joiner: the first
  contact's hello is empty (S3).
- **S3. Reach the first contact.** *An address:* `Introducer::dial_first(D,
  address, Config::first_look)` (§19.2), once. An error is `NotReady`
  (`RetryLater`), not a refusal of the code: the address may be wrong or the
  inviter's device off. The dial sends an **empty hello** — no certificate,
  no membership (ndn-link.md §13.3A): whoever holds the address learns
  nothing of the joiner, and the inviter, which gives an introduction link to
  a device with no certificate while an offer is open, still answers.
  Whoever answers is linked with the three
  introduction prefixes of `D` as its only routes (ndn-link.md §13.3A), and
  the key it proved is the link's name, nothing more. An address dialled
  after the inviter's last offer expired meets no link (§19.2: the inviter
  refuses it as any device nobody knows), so the join reports the first
  contact did not answer. *A relay:* nothing is dialled; the relay's device
  name is the ForwardingHint of the fetch below. **Decision: a relay by
  name, not by key.** A key alone gives the joiner nothing to route or dial
  by, and 32 octets would cost 24 words; a name is what a ForwardingHint is
  and what the joiner's forwarder already routes through a relay it uses.
  The relay serves nothing new: it forwards `<D>/32=hint/<token>` toward `D`
  as it forwards the offer fetch and the ask, and the inviter's link to it
  carries those names because the surface says so (§19.2). The joiner's
  forwarder MUST reach the relay's name (a relay it is linked to, or a name
  its routes cover), the precondition of every relay fallback (below); a
  join that cannot says so. *No contact:* the Interests go by name.
- **S4. Fetch** the record `<D>/32=hint/<token>` (§16.1), as often as the
  offer is fetched (step 1: up to 8 tries of `Config::lifetime`): over an
  address first contact by name over its link; over a relay with the relay as
  ForwardingHint. None came: `NotReady` (`RetryLater`), and the first link,
  if any, is taken down.
- **S5. Verify**, before anything else is sent, in this order, and
  **nothing is dialled, asked or adopted** on a failure. A failure is one of
  two kinds, because only damage in flight is worth a retry. Up to the
  signature (checks 1–4), a packet damaged in flight and an impostor's packet
  fail alike, so the refusal is `Hint` (`RetryLater`, as `Forged` is: the
  host's retry fetches it again). Once the signature is good — the packet is
  authentic, made by a key that credentials which open vouch for — what fails
  is no damage in flight but a record of another party: `HintMismatch`
  (`AskOwner`, no retry: do not use this code's first contact; ask for a new
  code):
  1. the Data's name is exactly the one asked, else `Hint` (`wrong name`);
  2. its Content decodes as a hint record or gone mark (§19.2), else `Hint`
     (`wrong record`);
  3. its credentials open — a trust context signed by one of its own anchors,
     valid now, then certificates (§19.4 step 2) — else `Hint`
     (`credentials`);
  4. its signature is good by the public key of a certificate that the
     credentials chain to their anchor (`Opened::authentic_signer`: the
     signer's own chain and the signature, not the trust schema), else `Hint`
     (`signer`);
  5. the context's namespace is a prefix of `D` and, when the code names one,
     equals it, else `HintMismatch` (`namespace`);
  6. the anchor's fingerprint is the code's: equal when the code carries 32
     octets, the prefix when it carries the words form's 16, the keyed
     fingerprint (§19.2) when it carries a short code's 10 — all in constant
     time — else `HintMismatch` (`anchor`), whose text says that the code may
     have been made before the keyed fingerprint and that the inviter has to
     give a new one;
  7. the signing key is a key of device `D`, and the context's trust schema
     lets it sign this name, else `HintMismatch` (`signer`);
  8. **a gone mark** that passed 3–7 ends the join as it says, `Introduction`
     `Closed` or `Expired` (`AskOwner`), and no further step runs. A gone
     mark that failed any of 3–7, or does not read, is `GoneUnproven`
     (`RetryLater`) — "the first contact says the offer is closed but can't
     prove it: retry, or ask the inviter" — never `Closed` or `Expired`:
     anyone on the path can make a mark that proves nothing (§19.7);
  9. the record's offer is a log entry of a folder of `D`, else
     `HintMismatch` (`offer`);
  10. the namespace is judged as an inviter's (step 4), now that the
     fingerprint is whole and proven, before the record's key is dialled:
     `InviterConflict`.

  **Retries are bounded.** `Hint` and `GoneUnproven` say `retry at most
  3 times` (`HINT_RETRIES_MAX`), and a host that retries by itself on
  `RetryLater` MUST stop there for the same code and tell the user to ask the
  inviter for a new code: each retry dials the first contact again, and a
  first contact that
  damages the same record four joins in a row is broken or hostile. Three: one
  retry meets a single corrupted packet intact, a second a burst, a third is
  the margin. A user's own retries are not counted.
- **S6. Keep or take down the first contact's link, then dial.** The first
  contact's link was made with no key to expect, so whoever holds the address
  completed its handshake: it is kept only when the key it proved is the
  verified record's key. When it is, and nothing more is dialled, the
  Interests go by name over that link. When it is not — whatever the record
  offers: candidates or none — the link is `undial`led **at once**, before the
  offer is fetched or the ask is sent, and it is used for nothing more: not
  its routes, not a fallback if the dial below fails. Then, when the record
  has candidates, `Introducer::dial(record link, D, Config::first_look)` as in
  step 0; an error is not a refusal, and the join goes on by forwarding hints.
  The ForwardingHint of the Interests, when no link carries them, is the
  first contact's relay, then the record's relays, else the joiner's own
  namespace's relays (as in step 0); none, routed by name. A link of a key
  other than the record's therefore never outlives the verified record in any
  join: a party at the address that relays the genuine record, and drops the
  dial to the record's key, gets neither the offer fetch nor the ask, nor a
  link or route once the join is over (§19.7).
- **S7. The offer.** The offer's name now comes from the verified record. The
  joiner fetches it (step 1) and, **before it seals the ask**, refuses
  `Introduction { Forged }` (`RetryLater`) when the offer entry is not signed
  by a key of device `D` that chains to the anchor of the record's verified
  credentials (the record's opened credentials judge the entry as they judged
  the record's own signature, S5 check 7): with the commitment public, a party
  on the path could otherwise substitute the offer's `seal_key` together
  with a commitment copied from the genuine entry, and read the ask. It then
  refuses `Introduction { HintMismatch { why: "offer: <offer> was not made
  with this code's secret" } }` when the offer's commitment is not the code's
  secret's — judged only on an entry the record's credentials vouch for: a
  short code's secret is whole and checksummed, so a mismatch means the record
  named another offer, and an ask would only count a wrong try. The link and
  the words form keep step 3's order (a mistyped secret there is `WrongProof`;
  nothing vouches for the entry before the answer, whose credentials judge it
  as step 3 says). Then steps 2 to 6 run, every check of today's flow
  included: the answer proves the secret, the commitment is the code's, the
  fingerprint matches the answer's credentials, the device is under the
  inviter's namespace.
- **S8. A join that fails** after a dial calls `Introducer::undial` for the
  record's key, and for the first contact's key when that link is still up
  (it is up only when it is the record's key, S6), as step 0 does: the first
  link, which proved no certificate until the namespace is held, is not kept
  (it is taken down by the key the handshake proved). A join that succeeds
  keeps only a link whose key is the verified record's.

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
`Config::asks_verifying` at once (8 by default), before any unwrapping. It
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
4. **Not closed to this key.** An offer is *closed* when a closing mark is
   held of it, or when at least `Config::intro.wrong_tries_max` wrong
   tries are counted toward the overall cap. A closed offer admits no one
   new: it answers `Closed`, except to the key a use mark names (not a use
   a stop interrupted, which was never completed), which it answers as step
   6 says — the acceptance kept for its use, and nothing else — while the
   offer has not expired by this device's clock, and `Expired` after. So
   closing never makes an offer answer more than it did: an open offer's
   user is answered whenever it asks (step 6), a closed offer's until the
   offer expires.
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
    `Config::intro.shared` (by default `/user` and the broad top-level
    names `/com`, `/org`, `/net`, `/edu`, `/gov`, `/mil`, `/int`, `/info`,
    `/biz`, `/arpa`, `/ndn`, `/example`, `/test`, `/local`, `/invalid`: a
    name under one is a person's, so `/user/<hash>` and `/com/acme` are
    fine and `/user` and `/com` are not; a deployment frees a name by
    removing it from the list); not the
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
| `Closed` | closed to everyone but the key that used it: this key's wrong tries spent, all askers' at the device's cap, `close_offer`, or the member it brought removed by a record the offering device signed (the key the offer was used by is still answered, until the offer expires, step 4) | `AskOwner` | no |
| `WrongProof { left }` | the proof of the secret is wrong; counted against this key, `left` more allowed it | `FixRequest` (check the code) | no |
| `Conflict` | the asker's namespace overlaps the inviter's or one the inviter trusts, is one it trusts under another anchor, or one the policy refuses (§19.4 step 10); or, for a self-certifying asker namespace adopted from its genesis, the presented credentials carry an anchor the held context does not; or the asker's proof does not verify under the context the inviter's device holds (a key it revokes, shown with an older version) (§19.4, the use) | `FixLocal` (renew the device's certificate when it is the last) | no |
| `InviterConflict { inviter, why }` | the joiner refuses the inviter's namespace (§19.3 step 4; never on the wire): `why` says what it overlaps; or, for a self-certifying inviter namespace adopted from its genesis, the answer's credentials carry an anchor the held context does not; or the inviter's proof or offer entry does not verify under the context the joiner holds (§19.3 step 5) | `AskOwner` (do not use the code) | no |
| `Forged` | an acceptance fails a check of §19.3, step 3 (never on the wire) | `RetryLater` | yes |
| `Hint { why }` | what answered at a short code's first contact came damaged or does not prove itself (§19.3 S5, checks 1–4; never on the wire; its code, were it sent, is 6): `why` begins with the check that failed — `wrong name`, `wrong record`, `credentials`, `signer` (the signature is not good by a key the credentials chain to their anchor). Damage in flight fails these checks as an impostor's packet does, and the packet is intact the next time, as a corrupted answer is (`Forged`) | `RetryLater`: retry at most 3 times (`HINT_RETRIES_MAX`), then do not use this code's first contact: ask for a new code | yes, bounded |
| `HintMismatch { why }` | a record that **verifies** (its signature is good by a key that credentials which open vouch for) but is not the inviter this code names (§19.3 S5, checks 5–7 and 9; S7; never on the wire; code 6): `why` begins with `namespace`, `anchor` (also: the code was made before the keyed fingerprint), `signer` (not a key of the code's device, or not one the schema lets sign this name) or `offer` (no log entry of a folder of the device, or not made with the code's secret). No damage in flight does this | `AskOwner` (do not use this code's first contact: ask for a new code) | no |
| `GoneUnproven { why }` | a gone mark that fails any check of §19.3 S5 (3–7), or does not read: anyone on the path can make one (never on the wire; code 6) | `RetryLater`: retry at most 3 times, or ask the inviter | yes, bounded |

The inviter unreachable is `NotReady { name: <offer> }` (`RetryLater`): the
offer waits. A code that does not parse is `BadRequest`; a host without an
introducer, or one that refuses an adoption, is `Local`.

A short code adds the refusals below (§19.2, §19.3). Each says why and what
to do; `D` is the inviter's device name, which stands for the offer's name
until the record names it.

| Situation | Error | Says (the text a program shows) |
|---|---|---|
| a word count other than 20 or 36 | `BadRequest` (the root) | `the code has N words; a short code has 20 or 36 words, today's words form 24: the code was cut off or has extra words: copy it again whole` |
| a word off the list | `BadRequest` | `word N is not a BIP39 English word: check word N` (N from 1, among the words) |
| the checksum does not match | `BadRequest` | `the code does not read (a word, the address or the device name is mistyped, or two words are swapped): check each against what you were given; the inviter's device name and address are part of the check` |
| a first contact that is neither an address nor a relay's name, or no device can dial it | `BadRequest` | ``the code's first contact `x` is neither a dialable address (`192.0.2.7:4433`, `[2001:db8::7]:4433`) nor a relay's name (starting with /): check it against what you were given`` |
| `161=*` with 20 words | `BadRequest` | ``the device name uses `161=*`, the whole fingerprint, which only a 36-word code carries: the code was cut off, or copied from a code of another shape; copy it again whole`` |
| a loopback or link-local first contact, `local_candidates` off | `BadRequest` | ``the code's first contact A is an address of this machine or its link; this device does not dial one from a code (`IntroPolicy::local_candidates`): ask for a code with an address of the inviter's device that can be reached from here, or allow it in the policy for two devices of one machine`` |
| a device name that is no name | `BadRequest` | ``the code's device name `x` is not an NDN name (starting with /, not the root): check it against what you were given, or copy the code again whole`` |
| the address does not answer the dial | `NotReady` (`RetryLater`) | `the first contact A did not answer (reason): check the address and that the inviter's device is on, then retry; or ask for a new code` |
| the hint record is not fetched in its tries | `NotReady` (`RetryLater`) | `the inviter's hint for this offer was not fetched from the first contact (offline, wrong address or relay, a relay this device cannot reach, or the offer is closed): retry, check the code, or ask for a new code` |
| a gone mark that verifies | `Introduction` `Closed` or `Expired` | the texts of the rows above |
| the record does not verify: damage or no proof | `Introduction` `Hint { why }` (`RetryLater`) | `what answered at the first contact does not prove it is the inviter's, or came damaged (why): retry at most 3 times; if it is refused every time, do not use this code's first contact: ask the inviter for a new code, and check the code was copied whole` |
| the record verifies but is not the code's inviter's | `Introduction` `HintMismatch { why }` (`AskOwner`) | `what answered at the first contact proves itself, but not as the inviter this code names (why): this is not damage in flight and a retry will not change it: do not use this code's first contact, ask the inviter for a new code, and check the code was copied whole`; for `anchor`, `why` ends: `or the code was made before the keyed fingerprint: ask the inviter for a new one` |
| a gone mark that does not verify | `Introduction` `GoneUnproven { why }` (`RetryLater`) | `the first contact says the offer is closed but can't prove it (why): retry, or ask the inviter; retry at most 3 times, then ask the inviter for a new code` |

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

A short code adds two derivations and one checksum. The **hint token** is the
first 16 octets of HMAC-SHA256 under the secret as key over
`ndn-data/intro/hint/1`: an HMAC output reveals nothing of a 128-bit key, so
the name made of it is unguessable without the code and tells nothing of
it. The **checksum** of a short code's words is the first 12 bits of
SHA-256(`ndn-trust/intro-short/1` ‖ the bound text ‖ `0x00` ‖ payload)
(§19.2). It detects a typo; it is no authenticator (it has no key, and
anyone can compute it for a code of their own), and nothing is trusted on
its account. The **fingerprint** is SHA-256 of the anchor's public key (an
Ed25519 key's 32 raw octets, trust-envelope.md §4.4). A short code of a named
namespace carries not that but its **keyed fingerprint**: the first 10 octets
of HMAC-SHA256 under the secret as key over `ndn-data/intro/fp/1` ‖ the
whole 32-octet fingerprint (§19.2), which the joiner computes again from the
anchor of the verified credentials and compares in constant time
(`Mac::verify_truncated_left`). The whole fingerprint is carried plain by a
self-certifying namespace's code and by a link, and a plain 16-octet prefix
by the words form; they are compared in constant time too.

### 19.7 Threat notes

- **Code theft.** The code is a bearer secret until used: whoever presents
  it first, within its expiry, joins with its role. One use binds it to one
  key (step 6); the owner sees who joined in the folder's members record
  and removes them as any member (§6). The removal lasts: a used offer's
  user asking again — a fresh ask, before or after a restart — is answered
  the acceptance kept for its use and never admitted again (step 6), and
  no other key can use it, whichever owner device removed the member. A
  folder record the offering device signs removing a namespace also closes
  every offer of that device a key under it used (or was using): the offer
  then admits no one new, and its user alone is still answered, until the
  offer expires, the acceptance kept for its use and nothing else (step 4):
  nothing is adopted or signed, so asking does not make a removed member a
  member again, and what the answer shows is what the code's holder already
  had — the folder's name, the role and the inviter's public credentials.
  A record another device signed closes nothing (only the offering device
  marks its offers). `close_offer` closes an offer to everyone new at any
  time, and keeps answering its user so: a host that closes an offer as
  soon as the new member appears loses no joiner whose answer was lost.
  Keep expiries short.
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
  carries (128 bits of it in the words form, 80 in the short code of a named
  namespace, the whole 32 octets in a link and in the short code of a
  self-certifying one: see the note on the short code's fingerprint below); a party that served a
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
  stranger is; the owner sees which one joined. A broad name would be the
  joiner's root over every name under it the inviter does not trust yet,
  so by default a stranger cannot claim `/com`, `/org` or any other name
  of the default `Config::intro.shared` list (§19.4 step 10); a name under
  one (`/com/acme`) is a person's and is refused `Conflict` only while
  this device trusts an overlapping namespace under another anchor. A
  deployment whose people's namespaces sit under a prefix not on the list
  adds it to `Config::intro.shared`.
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
- **Unauthenticated hints.** Relay hints in the code, the joiner's own
  namespace's relays and the link hint's addresses are reachability only: a
  lying hint fails to reach, and nothing a relay or a dialled address
  carries is trusted — the offer, the ask and the answer are judged by the
  checks above.
- **The link hint: the key is authenticated, the address is not.** The
  dial's handshake proves the key (§19.3, step 0): an address whose device
  presents another key is no link. So a joiner reaches the device holding
  the key its code names, or nobody; an address an attacker substituted in
  a code can only make the dial fail, or reach a party that lacks the key
  and fails the same handshake. A code altered to name another key reaches
  that key's holder, which is the inviter-impersonation case above: the
  party learns the joiner's public credentials and can answer nothing the
  code's anchor fingerprint and secret check (§19.3, step 3). The secret
  never leaves in the dial: the dial carries a handshake and a hello, and
  the secret travels only inside the sealed ask.
- **Dialling candidates.** A hint holds at most
  `LINK_HINT_CANDIDATES_MAX` (8) addresses, and a reader keeps no more. A
  hostile code could aim a joiner's dial at third parties: at most that many
  QUIC handshakes' first datagrams per join, every one unanswered unless
  something there speaks QUIC, so nothing is amplified and no more is sent
  than the join's own retries send. Unspecified, multicast and broadcast
  addresses and port 0 are never dialled. The dial is bounded in time
  (§19.3, step 0). A code can have a joiner send a handshake to an address
  of its own host or network; that is all it can make it do.
- **Privacy.** The code shows the inviter's device key, and the addresses
  of its listening socket (its interfaces', reflexive and advertised ones),
  to whoever sees it: the screen showing the QR, the message carrying it.
  A host that does not want that gives no hint (`Introducer::link_hint`).
  A short code shows the device's name and one first contact (an address or
  a relay's name) and no key; the hint record behind it shows the key, up to
  8 addresses and the relays to whoever holds the code, while the offer is
  open (below).
- **The hint's lifetime is the offer's.** The addresses are those of the
  moment the offer was made; once the offer expires (or is closed to
  everyone new) the code admits nobody, whatever the addresses say. A joiner
  dialling a stale address fails within its bound and goes on by relays
  (step 0); an inviter whose address changed makes a new offer.
- **A stranger's link.** The inviter answers a joiner it knows nothing of on
  a link that carries the offer fetch and the ask and nothing else, within
  slots and rates (ndn-link.md §8.6): what that link lets a stranger send is
  what any party can already ask of the device by name, and the ask is
  judged and bounded as §19.4 says.
- **Short code: a relay or a man in the middle cannot substitute addresses.**
  The hint record is signed by `D`'s device key, chained to the anchor the
  code's fingerprint names, named by the secret's token and naming the offer.
  A changed byte fails the signature; an unrelated record fails the name or
  the signer check; a record of another offer of `D` is a different name and,
  presented under this token, names an offer that is not committed to the
  secret, refused before the ask (§19.3, S7); and nothing is dialled before
  all of that passed (S5). A relay or an on-path party may *withhold* the
  record (the join says it could not fetch it) or *replay* an old genuine
  one (below); it cannot make the joiner dial an address of its choosing, nor
  trust a key it chooses.
- **Short code: the first contact is a hint.** It reaches whoever holds the
  address or relay, and that party can serve what it likes; everything it
  serves is verified against the code (the fingerprint, the signer, the
  offer: §19.3, S5) before anything is dialled, asked or adopted, and the
  offer entry it relays is verified by the record's credentials before the ask
  is sealed to its seal key (S7). The link
  made to an address routes the three introduction prefixes of `D` and no
  other name, whatever namespace the party shows (ndn-link.md §13.3A), so a
  stranger at the address is never sent the Interests of a namespace the
  joiner holds; and what the party sends in is bounded: answers under those
  prefixes, and Interests only for the joiner's own device names (the
  inviter fetches the joiner's seal key there), so it cannot make the
  joiner's forwarder ask the joiner's other links for anything under the
  joiner's identity (ndn-link.md §13.3 rule 3). A loopback or link-local
  first contact is refused unless `IntroPolicy::local_candidates` (§19.2), as
  a link hint's candidates are.
- **Short code: the first contact's link does not outlive a wrong party.** The
  dial expects no key, so anyone on the path to the address completes its
  handshake with a key of their own and may relay the genuine hint record,
  which names the inviter's key. Whenever the verified record's key is not the
  link's, the join takes the link down at once and never sends the offer
  fetch or the ask over it, whether the record offers an address (a party
  that blocks the record's key only makes the dial fail, and the join goes by
  the record's relays or by name) or none (S6). After a successful join no
  link or route to such a party remains, so it keeps no path for `<D>/32=held`,
  `=intro` or `=hint` Interests, and a link made again to it, once the joiner
  holds the namespace, is refused when it shows no certificate (ndn-link.md
  §13.3 rule 4).
- **Short code: the party at the first contact learns nothing of who is
  joining but the joiner's address.** A link hint pins the key: a dial to an
  address whose party presents another key fails the handshake before any
  link message. A short code's address is dialled with **no key to expect**
  (`Introducer::dial_first`), so whoever answers there is a stranger, and the
  dial's hello is **empty** (ndn-link.md §13.3A): no certificate chain, no
  memberships. The party learns the joiner's IP address and that a joiner
  with this code's address exists, nothing of its person, device or groups.
  The inviter needs nothing more to answer: it gives an introduction link to
  a device with no certificate while an offer is open (ndn-link.md §8.6),
  also when it admits enrollment links (the link then carries both
  errands), and the ask carries the joiner's credentials sealed to the
  inviter's seal key. The full hello is sent once the joiner holds the
  inviter's namespace, on the link made again to the party the join judged.
  Namespace-level refusals that wait for the record (S2) therefore disclose
  nothing either.
- **Short code: probing.** The hint record's name is derived from the
  secret, so it is unguessable (128 bits) without the code, and the secret
  itself is in no name or wire. A prober who does not hold the code can
  neither fetch nor test for a record: an Interest for an unknown token is a
  Nack, the same for every token (§19.2), and over an introduction link it
  is not carried at all; a known token answers only its record or its gone
  mark. The offer's own name, whose `seq` is guessable, is not used.
- **Short code: the record's lifetime, and what it reveals.** While the
  offer is open the record shows the key, up to 8 addresses and up to 8
  relays that the inviter would give to anyone holding the code; an on-path
  observer of the Interest learns the token and so can fetch the record
  until the offer closes (that observer already sees where the traffic goes),
  and a cache holds it at most its `FreshnessPeriod`, 5 s. Closed or
  expired: a gone mark, nothing more. The record is made on request from the
  host's current hint, so it names no address the host has since lost; it is
  not in the log and not served after the device stops. With
  `hint_while_open` off it is served until the device stops, which is a
  longer exposure of the addresses, not a longer admission (the offer
  answers by its own rules).
- **Short code: replay of an old record.** The record is bound to the offer
  by its name and content; its `HintUntil` and a signature give no time the
  joiner checks. An old genuine record of this offer shows stale addresses,
  which costs a failed dial within its bound (the dial proves the key), never
  a wrong peer; a record of another offer is never accepted for this one. A
  genuine gone mark never turns back into a record: an offer is not
  reopened.
- **Short code: a gone mark proves itself, or ends nothing.** A gone mark
  carries the inviter's credentials and is signed as a record is; the joiner
  runs the same checks on it (§19.3 S5: the credentials open, the signature is
  good under them, their namespace, anchor and signing device are the code's)
  and only a mark that passes ends the join as it says (`Closed`, `Expired`:
  `AskOwner`, for good). An on-path party that answers the token's Interest
  (the token is in the Interest) with an unsigned mark, a mark signed by
  another key, one carrying another namespace's or anchor's credentials or
  none, gets `GoneUnproven`: `RetryLater`, "the first contact says the offer
  is closed but can't prove it: retry, or ask the inviter", bounded to 3
  retries (S5). It cannot make the user throw away a code that is still
  valid. Nothing is dialled, asked or adopted on a mark either way, and the
  offer's own answer alone judges the offer. The mark's Data has
  `FreshnessPeriod` 0, so no cache keeps a forged mark to answer the retries;
  the inviter signs a mark once per 5 s per state and no more (§19.2, item 4).
  What an on-path party can still do is what it can always do: withhold the
  record (the join says it could not fetch it), or replay an old genuine
  mark of this very offer, which an offer that closed does not outgrow.
- **Short code: a typo.** The 12-bit checksum covers the words, the device
  name and the first contact: a mistyped word, a digit of the port or a
  letter of the device name is refused with probability 1 − 2⁻¹² and never
  tried (§19.2). The 1 in 4096 that passes meets the other checks: a
  mistyped secret is an unknown token (a Nack, so the tries end at once), a
  mistyped address or relay is a first contact like any other (the party
  there is verified against the fingerprint, which a typo cannot make
  match).
- **Short code: what the fingerprint is for, and what it costs to beat.** The
  fingerprint ties the answer at the first contact to the inviter's namespace
  before anything is dialled or asked: a party who has seen the code, or only
  its token, cannot steer the joiner to a namespace of its own by a collision
  worked out beforehand. A **named** namespace's code carries not the
  anchor's own octets but `HMAC-SHA256(secret, "ndn-data/intro/fp/1" ‖
  anchor)[..10]` (§19.2). A plain truncation of the anchor's SHA-256 would
  have a **long-lived** target, the namespace's own fingerprint, the same for
  every code it ever makes: one search for a key whose SHA-256 begins with
  those 10 octets could be run offline, without a time limit, once, and its
  result would serve every code of the namespace for good. The keyed tag has
  no such target: it depends on the code's secret, which no one holds before
  that code is made, and which a party who has seen only the token or the
  address does not hold at all. So the search for a key *A′* whose tag under
  this code's secret is the code's can start only **after the code has
  leaked**; it serves **that one code** (a key found for it is useless for
  any other code, of the namespace or another, and for any later one); and it
  has to finish **within that offer's lifetime**, before the offer is used or
  closed. Its success probability is 2⁻⁸⁰ per key, so 2⁸⁰ ≈ 1.2 × 10²⁴ key
  generations in expectation (the median is about 0.7 of that). Assumption,
  not a measurement: 10¹² keys per second, a rate chosen to favour the
  attacker: one code then costs about 1.2 × 10¹² s, some 38 000 years, and an
  offer's hour allows 3.6 × 10¹⁵ keys, a chance of about 3 × 10⁻⁹. The number
  of offers open at once does not make one code cheaper to hit: each
  candidate key must match *this* code's tag, computed with *this* code's
  secret. An attacker who holds the secrets of N leaked codes and is content
  with any one tests each candidate against N tags — N tag computations per
  key, 2⁸⁰ in all — so only the number of key generations falls (to 2⁸⁰/N),
  never the number of tag computations; and each such code is one he could
  have used himself, so what he gains is only to bring that joiner to a
  namespace of his own. The tag is not a second factor beside the secret:
  everyone who holds the secret can compute it, and the joiner's answer is
  proved by the secret alone (S7, the answer's proof, 2¹²⁸ more). A party who
  has only seen the token needs the secret too, which the joiner refuses a
  record without (S7). **A self-certifying namespace** takes all 32 octets
  (its name *is* the fingerprint, so `161=*` writes it once, in the words), as
  a link does: not a truncation, so there is nothing to search for. **The
  words form** (24 words, also `Code::words`) carries a plain 16-octet prefix
  of the anchor's fingerprint and is judged as a prefix, in constant time.
  Its target is a namespace's long-lived fingerprint, so its search is offline
  and unbounded in time, and multiple over namespaces; that is why it is 128
  bits and not 80: 2¹²⁸ ≈ 3.4 × 10³⁸ key generations for one namespace, and
  2⁹⁸ ≈ 3 × 10²⁹ against N = 2³⁰ namespaces, some 3 × 10¹⁷ s, about 10¹⁰
  years, at the assumed rate. A code made before the keyed fingerprint carries
  the plain 10 octets of a named namespace and is refused as an anchor
  mismatch that says to ask for a new code (§19.5). The lengths that fill
  whole words with the 12-bit checksum are 10, 21 and 32 octets of
  fingerprint (16 + n ≡ 4 mod 11): 10 is the shortest, and each octet costs
  about 0.73 of a word.
- **A grant is authority to link, not to read** (round 6, §19.8). It is host
  visible and informs the link layer only: the folder's members record and
  the epoch keys still decide what a link is answered, so a grant never
  widens what the person reads or writes. A leaked code gives its thief the
  one use, and so the membership, whoever uses it first; the grant adds the
  link of that key, and ends with the membership (a removal), by the host's
  end, or by its date if one is set (by default none). A grant names one
  key: a person's other keys, including a stolen second device, have none,
  and the same key presenting another namespace is not granted it (the grant
  lists the asker's namespace alone). A grant that outlives a removal is
  closed three ways: the check on every members record held, whoever signed
  it (the removal need not come from the offering device); its date;
  `Introducer::revoke_grant`, called before the end is durable. A removal
  whose record this device has not yet taken leaves the person linked until
  it is taken (and, with a `grant_for` set, at most until the date). The
  grant's role is re-derived from the record in force, so a demotion narrows
  it at once. The grant note is MAC'd under a key from the device's recipient
  secret: a writer of the data store alone cannot clear its `ended` flag or
  extend it; rollback to an older genuine copy is bounded by the record and
  the use mark (§19.8 rule 11). A grant is never made for an ask refused,
  for a retry or when the policy makes none, and no grant is made from an
  address or a name: only the asker's key that the exchange proved.

### 19.8 Grants — rounds 6 and 7

An offer that admits a person can make the host's link layer link with that
person, with no change of the host's serving policy: an inviter that keeps
the narrow policy (serve devices of the namespaces it holds a certificate
in) still links with the one person it admitted and with no other it merely
holds a context of. The link layer is the host's (ndn-link.md §8.7); the
device only tells it, durably, whom. A **grant** says: the device holding
link key `K` may link, as a person of namespace `N`, in the role `R` the
folder's members record in force gives it, for as long as that record admits
it — and, only if a date `U` is set, until `U`.

```rust
pub struct Grant {
    pub key: [u8; 32],         // the asker key's public-key digest
    pub namespaces: Vec<Name>, // the asker's namespace, as the join adopted it
    pub folder: Name,          // what the offer admitted it to
    pub role: Role,            // the role the record in force gives it NOW
    pub until: Option<Timestamp>, // the inviter's clock; None: no date
}
pub struct Departure {         // round 7: a person let go by a held record
    pub key: [u8; 32],         // the person's device key (the grant's key)
    pub namespaces: Vec<Name>,
    pub folder: Name,
    pub record: Name,          // <signer device>/32=log/<folder>/seq=<n>
    pub until: Timestamp,      // this device's clock: not shown after it
}
trait Introducer {
    fn grant(&self, grant: &Grant) {}                      // default: nothing
    fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {} // names the folder; default: nothing
    fn departure(&self, departure: &Departure) {}          // just before revoke_grant; default: nothing
}
IntroPolicy { grant_for: Option<Duration>
    /* None (default): no date; Some(d): also ends d after the admission;
       Some(ZERO): no grant is made */,
    departure_for: Duration /* default 7 days; ZERO: no mark */, .. }
Device::grants(&self) -> Vec<Grant>                       // one per live note
Device::departures(&self) -> Vec<Departure>
Device::end_grant(&self, key: &[u8; 32]) -> Result<bool, DataError>             // async
Device::end_grant_in(&self, key: &[u8; 32], folder: &Name)
    -> Result<bool, DataError>                                                // async
Device::renew_grant(&self, key: &[u8; 32], until: Option<Timestamp>)
    -> Result<Option<Grant>, DataError>                                       // async
Device::take_departure(&self, from: &Name, folder: &Name, record: &Name)
    -> Result<(), DataError>                                                  // async
IntroductionSurface::grant_carries(&self, folder: &Name, name: &Name) -> bool
ndn_data::{folder_carries, writer_carries, departure_carries}
// round 9: the joiner's end of a grant
Device::joined_folders(&self) -> Vec<JoinedFolder>        // one per live mirror entry
Device::joined_changes(&self) -> tokio::sync::watch::Receiver<u64>
IntroductionSurface::{joined_folders, joined_changes}     // the same two, weak
pub struct JoinedFolder {
    pub inviter: [u8; 32],  // the inviter's device key's digest (the mirror grant's key)
    pub owner: Name,        // the folder's namespace = the inviter's
    pub folder: Name,
    pub role: Role,         // THIS device's role in the record in force
    pub writers: Vec<Name>, // the other writers' namespaces (<= JOINED_WRITERS_MAX = 16)
}
```

1. **When it is made.** A device MUST make a grant when it answers an ask
   with an acceptance for the first time (§19.4 step 6): after the asker's
   anchor is adopted, the asker added to the folder and the acceptance made,
   and as the same durable step that keeps the acceptance and signs the use
   mark. It MUST NOT make one for an ask refused for any reason, for an ask
   whose use fails before the mark (the offer is not spent, §19.4), or when
   `IntroPolicy::grant_for` is `Some(Duration::ZERO)` (nothing is kept,
   nothing is told).
2. **What it names, and its date.** The key is the public-key digest of the
   asker's key as the exchange proved it (§19.4 steps 5–9); `namespaces` is
   the one namespace the join adopted (never one the asker merely claims over
   another); `folder` is the offer's; `role` is the offer's at the admission
   and, from then on, whatever the members record in force makes of the
   namespace (rule 6). **By default a grant has no date** (`grant_for`
   `None`, `until` `None`): it follows the members record, lasting while a
   held record admits the person and ending when one leaves them out, so
   removal is the control and there is no day on which every link silently
   stops. `Some(d)` bounds it as well: its `until` is the device's clock when
   it answered plus `d`, and the host may [renew](#renew) it (rule 10).
3. **Durable before the answer, told after.** The device keeps a grant note
   under `/localhost/ndn-data/intro/grant/<offer's Name TLV>` in its local
   store: the offer, the key's digest, the namespace, the folder, the role,
   whether it has a date and `until`, whether it ended, and a MAC (rule 11).
   The note is written with the acceptance under the barrier the use mark
   waits for, so a durable use mark means a durable note; the device then
   calls `Introducer::grant` once, and only then sends the answer. A note is
   the device's own and never served or published. **No TLV-TYPE is
   registered or used for it:** its value is a fixed-width local form (a
   version octet (3; a version 2 note, written before departure marks, is
   still read as one with no mark), flags (ended, dated, marked), the role,
   `until`, the key digest, three length-prefixed Names, on a marked note the
   mark's date and its record Name (rule 14), then the 32-octet MAC), like the
   other notes under `/localhost/ndn-data/intro/`. A note this version does
   not read, or whose MAC does not check, is ignored, and the device logs
   which and why (a person whose note is ignored has no grant: offer the
   folder to them again).
4. **A retry grants nothing.** An asker answered again (§19.4 step 4: the
   acceptance kept) MUST NOT be granted again and its date MUST NOT move,
   however many times it asks and after any restart or close of the offer.
   Another key presenting a used offer is refused and granted nothing.
5. **Never wider.** A grant informs; it MUST NOT change what the members
   record admits (§6, §19.4), the epoch keys a device may hold (§9) or what
   the layer answers. It names the folder and the role so the host can
   narrow a link (a reader's link sends Interests only), never to admit
   more. The host MUST use a grant only to link with the named key as a
   person of the named namespaces, never for the person's other keys or
   namespaces.
6. **In force, in the role the record gives.** [`Device::grants`] lists the
   grants whose offer this device made and used by the very key the note
   names, that have not ended, whose date (if it has one) has not passed by
   the device's clock, and whose folder's members record in force (as held)
   lists the namespace as a writer or as a reader. Its `role` is **derived
   from that record at every call**: a writer if the record lists the
   namespace as a writer, else a reader — never the role the offer had. When
   a record taken changes the role of a grant, the device updates the note
   durably and calls `Introducer::grant` again with the grant as it now
   stands (the host replaces its grant; ndn-link closes a link made under
   the old scope); a writer demoted to a reader is a reader at once, not at
   the grant's end. It is derived from the notes and the records held, so it
   is the same after a restart, less what ended. While no record of the
   folder is held no grant is in force. A host that links installs the grants
   at start and after each restart (the device does not call `grant` again
   by itself for a grant whose role did not change). One `Grant` is listed
   for each live note (rule 13).
7. **It ends** at its date, if it has one (the link layer judges it by its
   own clock; the device does not announce a lapse), when the host ends it
   (rule 9), or when a members record held for **the grant's own folder**
   leaves the namespace out as both writer and reader (each note is judged
   against the record in force for its folder, so a person left out of one
   folder keeps the grants of their other folders: rule 13). The device checks
   this on every record it takes for a folder, and at start, whoever of the
   folder's owner namespace signed it, not only the offering device. It MUST
   then call, **in memory and first**, `Introducer::departure` (rule 14, when
   a mark is made) and then `Introducer::revoke_grant` once with the key and
   the folder — the safe direction, so that a slow or failing flush never
   delays the link layer's end — and only then mark the note ended (with its
   departure mark) durably: a stop in between leaves a note not yet ended,
   which the next start judges again (the host revokes again, harmlessly),
   never a link that outlives its removal for want of a flush. An ended grant
   never returns: a person readmitted by a later record is no longer granted
   by the old offer (they join again with a new code). A record that drops
   the person also closes the offers that person used (§19.7).
8. **The host's part.** `grant`, `revoke_grant` and `departure` are called from
   the device's tasks and MUST NOT block or call back into the device. A host
   whose link key is not the key the device knows (the asker's *device* key)
   adopts the grant itself with the link key it knows. A host with no link
   layer ignores all three.
9. **The host ends a grant.** `Device::end_grant(key)` marks every grant
   note of that key not yet ended as ended, durably (behind the store
   barrier, before it returns), so a restart does not bring it back; it
   returns `true` if there was one not yet ended (past its date or not),
   `false` if none. It tells the host nothing: the host that calls it ends
   its link layer's grant itself. The person stays a member of the folder —
   removing them is a members record, which also ends the grant. A host that
   only calls the link layer's own revoke (`Links::revoke_grant`) has made an
   in-memory change that a restart undoes; ndn-link's `LinkHints` calls this.
    `Device::end_grant_in(key, folder)` ends only the grants of that key of
    one folder (the person's other folders' stand) and makes no mark.
10. <a id="renew"></a>**The host renews a grant.** `Device::renew_grant(key,
    until)` sets the date of every grant of that key not ended **and** that a
    held members record still admits the person for — one past its old date
    is renewable, one a record left out or the host ended is not (offer the
    folder again) — durably, and returns the grant as it now stands (the first
    by offer when several offers admitted the key) or `None` when there was
    none to renew. `Some(t)` is the new date and MUST be after the device's
    clock (else `BadRequest`, saying so: give a later date, `None`, or end
    the grant); `None` gives it no date, so it follows the record. It tells
    the host nothing: the caller installs the returned grant. ndn-link's
    `LinkHints::grant` calls it when it is given a later date than the one in
    force.
11. **Notes are authenticated.** Of what a grant rests on only the use mark is
    signed (it names the key), not the note's `ended` flag, date or role, so
    the note carries a MAC: HMAC-SHA256 over every octet before
    it under a key derived (HKDF-SHA256, the domain label
    `ndn-data/grant-note/mac-key/1`) from the device's recipient secret, which
    the key store keeps and the data store does not. A party that can write
    the data store but not the key store therefore cannot clear `ended`,
    extend or remove a date, change a role or move a note to another name: the
    note fails its check and is ignored, with a logged warning that says so
    (rule 3) — so a removed person is not resurrected by an edited store. The
    MAC is the choice over deriving the ended state from signed records
    because the host's end (rule 9) has no signed record behind it to derive
    from. **What it does not do:** it does not detect *rollback*. A party
    that restores an older, genuine copy of a note (one whose `ended` flag was
    clear, or whose date was earlier or later) brings back an older state of
    that note. That is bounded by what the device holds besides the note: a
    grant a held members record leaves out is not in force whatever the note
    says (the record, not the note, is the judge, and the end is told again),
    and no note can name a person whose key no use mark names. What rollback
    can bring back is a grant the *host* ended while a record still admits
    the person, or an older date: end it again. A **departure mark** is inside
    the MAC (rule 14): it can be neither added to a note the host ended, nor
    cleared from one a record ended, nor moved (its date extended), without
    the note failing its check and being ignored.
12. **Faulty networks.** A lost answer is the joiner's retry (rule 4); a
    grant is made once per admission, on a clean or a faulty network; a
    departure's record is fetched by name like any record, asked again under
    loss (§17.1).
13. **A set of grants per person** (round 7). Each admission makes a note of its
    own, so two offers — of two folders, or of one — to the same key make two
    grants of one key that differ in `folder`, and [`Device::grants`] lists
    **one `Grant` per live note**, sorted by key, then folder. The device
    judges **each note against the members record in force for that note's
    folder** (rule 7): a record that leaves the person out of folder `F` ends
    `F`'s grant and `F`'s note and no other, and `Introducer::revoke_grant(key,
    F)` names `F`. A host's link layer MUST therefore keep, per key, a **set of
    (folder, role) entries**: a grant adds the entry of its folder or replaces
    the entry of the same folder, and never closes a link while another entry
    of the key stands; a `revoke_grant(key, F)` ends the entry of `F` and
    closes the key's links only when it was the last (ndn-link.md §8.7).
14. **A person let go is told: the departure mark** (round 7). When a held
    record ends a grant by leaving the person out (rule 7), and
    `IntroPolicy::departure_for` is not zero (default seven days), the note
    keeps a **departure mark**: the log entry name of a held members record of
    the folder's line that leaves the person out —
    `<signer device>/32=log/<folder>/seq=<n>` — and the date after which the
    mark is no longer shown (`until`, by this device's clock, the end's time
    plus `departure_for`). The record is chosen so that the choice depends
    only on the records held, and is **the record that first left the person
    out of the run that stands**: reading the revisions held from the highest
    down, while a revision holds a record whose own writers and readers leave
    the person's namespace out (lowest signer key first), that record is the
    candidate; the run ends at the first revision below whose records all list
    the namespace — where the person was last a member — and the lowest
    revision of the run is the record. A later record of the run that leaves
    them out too may list others admitted since (a membership the person must
    not be handed), and a record that readmits them ends the run and is never
    named (let go again by a later record, the person is let go by that one).
    When no record leaves the person out by its own lists (the merge removed the
    person through a cut: one record removed the writer, another the reader),
    the same over the records that carry a cut of a prefix of the namespace,
    from the highest revision that has one; when no held record does either,
    **no mark is made** and the link layer just closes (a fallback that is
    never an open link). A mark is made **only when a held record ends the grant**:
    `Device::end_grant` and `end_grant_in` (the host's end, which no record
    lets the person go by) make none, and a host that wants none for any end
    sets `departure_for` to `Duration::ZERO`. The note's version is **3** (rule
    3): the mark is inside the MAC (rule 11). `Introducer::departure` is
    called **once, just before `revoke_grant` of the same grant** (in memory,
    before the note is durable, so a link layer that narrows its link at its
    last entry's end already holds the mark), and never when no mark is made.
    `Device::departures()` lists the marks **in force**: of ended notes whose
    MAC checks and whose use mark bears them out, whose `until` has not passed
    by the device's clock, and **not superseded** by a live grant of the same
    key for the same folder (the person was invited again); sorted by key,
    then folder. A host that links installs them at start
    (`Introducer::departure` for each), as it installs the grants. Two notes
    of one key keep a mark each. A mark's record is **named, never carried, by
    the data layer**: `departure_carries(record, name)` (a pure function of two
    names: the record's entry name with or without its implicit digest, its
    pieces `<record>/seg=<i>` and `<record>/32=manifest/seg=<k>`, its cut
    manifests `<record>/32=cut/seg=<i>`, nothing else) is what a link layer's
    departure link filters by (ndn-link.md §8.8).
15. **The departed person's side** (round 7). `Device::take_departure(from,
    folder, record)` is what the person's host calls when its link layer was
    told, by the inviter's, which record let it go (`Departure`, ndn-link.md
    §8.8). `from` is the **authenticated device of the peer that told it**
    (the link layer's: a full link, whose peer's certificate validated in a
    namespace this device holds; never an enrollment or introduction link). It
    fetches `record` by name, from the link it came over or from the devices of
    its namespace, and takes it **as any held record**: the signature and chain
    are validated, the record is merged and judged as ever, so this device's
    own folder then no longer lists it, it withdraws what it wrote after the
    cut and takes no more writing there. **The name carries no authority**; the
    call MUST refuse (`DataError::BadRequest`, saying why and what to do)
    unless (a) `folder` is a folder name, (a2) `from` lies under the
    namespace of `folder` (`<namespace>/32=data[/<path>]`: only a device of the
    folder's own namespace lets a member go of it; checked first, so a refusal
    costs the fetch slot and the minute's bound nothing), (b) `record` is a log
    entry whose subject is `folder`, (c) this device holds a members record
    line of `folder` (it is, or was, a member), (d) the record's device lies
    under a namespace this device holds a trust context of, and (e) what is
    fetched is a members record of `folder`'s line. A record already held is
    `Ok` at once (for a `from` that passed (a2)). At most **one take of a folder
    is in flight** and at most **six begin
    a minute** (the device's clock; a bound on a hostile inviter's stream of
    hints, not a correctness rule): the call is `DataError::NotReady` — ask
    again — for either, and when the record could not be fetched. Correctness
    never depends on timing: the person's own folder keeps being judged by the
    records it holds, whether it was told or not.
16. **Co-writers** (round 7). `IntroductionSurface::grant_carries(folder, name)`
    is what a link layer asks, per packet, for a grant link:
    `folder_carries(folder, name)` or `writer_carries(folder,
    writer_namespaces(folder), name)`, the writers read **live, on every call**,
    from the members record in force for `folder` (no cache), so a writer the
    record no longer lists drops out at the next call and one it lists appears
    at the next. The namespace `W` of a writer prefix `p` is **derived by the
    device, once, for every use** (`IntroductionSurface::writer_namespaces`):
    the namespace of the trust context governing `p` here (for a person's
    self-certifying name, the person's namespace once adopted for a folder),
    or `p` itself when no context is held; kept when `p` is `W` or lies under
    it, the folder's own namespace excluded (it is `folder_carries`'s). The
    data-layer functions take these namespaces, never the writers' names, and
    match a name's namespace **whole**: a writer `/home/carol/member/x`, for
    which no context is held, unlocks the root and the sync group of
    `/home/carol/member/x` — never of the broader `/home` its name merely
    starts with (round 7 review L6: the summary roots and sync groups were
    matched by prefix of the writer's name, so they disagreed with the
    namespaces whose trust context, sync group and certificate names the link
    layer carries). `writer_carries` adds only the **summary root**
    (`<D>/32=summary/<W>/32=root`, with or without its head) of each such
    namespace `W`, so that a writer who was invited by an invitation of
    its own can walk to the other writers' devices through this device's copy,
    and the **seal keys** of their devices (the exact name
    `<W>/<role>/<device>/32=seal/<public key>`: exactly two components below
    `W`, the first a role of the layout), so that one can ask the other's
    device (ndn-link.md §8.7 rule 20). `folder_carries` carries a seal key
    only of a device of the folder's own namespace in that same exact form,
    not of every device's (round 11 review I1: the clause carried the
    seal key of any namespace's device, so a stranger's crossed a link whose
    record did not list her).
    A **grant ask** (`<G>/32=grant/<GrantAsk>`, §9) is carried the same way,
    for a collection under the folder and only to a granter `G` that can hold
    a key of the folder: `folder_carries` carries it to a device of the
    folder's own namespace (the epoch's creator, or another device of the
    owner's), `writer_carries` to a device of a namespace the record lists as a
    writer (a co-writer reads in the epoch too, so the asker's granter list
    names it, §9), in the same exact device form, and no other (round 12
    review H1: the clause carried an ask to any device, so a member could make
    the owner's forwarder relay grant asks of its choosing to devices that
    never held the key, over the owner's own links). The folder's owner is not
    the only granter, so the rule is the namespace, not the one device.
    A walk asks a device that answers for a writer for that writer's root
    wrapped as a held packet (`<H>/32=held/<D>/32=summary/<W>/32=root`): such a
    name is carried when the root it wraps is, nested to the depth
    `folder_carries` unwraps held names to, and not deeper. The member also
    needs to hear the other writers' devices, which it learns from their
    namespaces' sync groups, so `writer_sync(folder, namespaces, name)` adds
    `<W>/32=sync[/…]` for each such namespace `W` (both ways; the
    folder's own namespace's group is the host's), derived from the record on
    every call like the roots. To validate what those writers wrote the member
    also needs their device certificates, so the link layer carries, for the
    same namespaces `writer_namespaces(folder)` lists, the namespace's **sync
    group, trust context and key and certificate names** as it carries them
    for the grants' own namespaces (ndn-link.md §8.7 rules 10 and 13): public
    by design, bounded to listed writers, and out at the next packet when the
    record drops the writer. A device that was **let go** of a sealed folder —
    the record in force for it lists the device neither as a writer nor in the
    audience, **and** a held record of that folder's line admits it (at some
    revision): it was a member and a later record leaves it out — does not
    descend into that folder's summary node when it walks the inviter's summary
    (it reads and writes nothing new there, and a link layer that let it go no
    longer carries the node), so the namespace's other folders are not held back
    as "not walked". A **joiner not yet admitted** is never let go: the sealed
    record it holds from before the offer admitted it lists it nowhere, no held
    record of the line admits it, and the revision that does is still to be
    fetched from that node, so its walk MUST descend. **A device invited again
    is not let go either while the new admission is pending** (round 7 review
    M1): it holds the record that once admitted it (r1) and the record that
    left it out (r2, in force), so the rule above would skip the one node that
    lists the record the new offer admits it by (r3), and its join would stay
    `NotReady` for good. The join keeps a durable **joined note** per folder
    (the offer's date, the revision the answer says admitted the device, the
    role: for a writer *and* a reader); the admission is **pending** while the
    note exists and the folder's record in force here is of a revision below the
    one the answer named (none held counts as below), or, when the answer named
    none, while the offer's own date has not passed. A record held at the named
    revision or above settles it either way: it admits the device, or it is the
    removal that undid the admission and the device is let go once more. The
    note ends with the join (`join` returns once the record that admits the
    device, the epoch's key and the walks are held). **A join waiting for its
    record while the admission is pending also makes the walks of the folder's
    namespace descend again, once, as the wait begins**: a walk that ended
    before (a notice of the inviter's new entries heard while the answer was
    still on its way) skipped the folder's node as one let go of and recorded
    the inviter's root as taken in full, and the same root again is answered
    with nothing walked; the record would never be fetched while the root stood.
    The device forgets, for every device of the namespace, the root and the
    nodes on the way to the folder, and a walk under way since before records
    none as taken (not again at every round of the wait: that would keep a walk
    from ever recording its progress). The rules read signed, durable data held
    here (the line's records and the note), no flag and, where the answer named
    a revision, no clock.
    Nothing of a writer outside the folder is added: the other writers'
    entries, pieces, heads, cut manifests and summary nodes of the folder are
    already carried because the *collection* is under the folder, whatever
    device wrote them. A prefix only a cut keeps is not a writer. A reader-role
    grant gains nothing by it: the link layer's push scope stays the person's
    own devices'.
17. **The mirror grant: the joiner's end** (round 9). A grant was built at one
    end only, and a device that joined a folder could not be linked to by the
    person who invited it once that person's address changed (REPLY-18, F4).
    A successful `join` therefore keeps, after the record that admits the device
    is held (`await_admission`), a **mirror note** — durable before `join`
    returns, the host told after (`Introducer::grant`): the inviter's **key**
    (the digest of the key that signed the answer, which the join verified
    belongs to the offering device under the anchor the code named), the
    **folder**, and the inviter's namespace as the folder's **owner**. It is the
    mirror of the inviter's note (rule 2) and is kept the same way: a fixed-width
    local value under `/localhost/ndn-data/intro/mirror/<folder's Name TLV><key>`
    (never served, never on the wire, **no TLV-TYPE registered**), ending in an
    HMAC-SHA256 under a key derived (HKDF) from the device's recipient secret
    **with labels of its own** (`ndn-data/mirror-note/mac-key/1`,
    `ndn-data/mirror-note/mac/1`), so a mirror note is never read as an inviter's
    note nor the reverse; a note that fails its check, or is of a version not
    read, is ignored with a warning that says why and what to do (join again with
    a new offer). The note names **no role the device trusts**: the entry's role
    is **re-derived from the record in force at every judgement** — the
    inviter's: a writer when its namespace has a listed writer prefix, else a
    reader, never wider than the record says — and the entry **stands only
    while the record in force lists this device**, by the predicates a join
    waits on (§19.3: a writer when a listed writer prefix is a prefix of its
    key, else a reader; a sealed folder also needs the record's audience to
    admit it; an unsealed folder lists every device as a reader). No record held
    for the folder: no entry (nothing to judge by, so nothing is granted). The
    note is kept **only for a folder under the inviter's own namespace**
    (`namespace_of(folder) == owner`): a hostile offer that names a folder of the
    joiner's own namespace — whose record lists the joiner — would otherwise
    grant the inviter a link into it; the join says so and keeps nothing.
    `Device::grants()` lists a live mirror entry like any grant (key = the
    inviter's, `namespaces = [owner]`, `folder`, the inviter's role, `until =
    None`: it follows the record); `Introducer::grant` is called once the note is
    durable and again when a record changes the inviter's role;
    `Introducer::revoke_grant(key, folder)` when a held record leaves this device
    out (in memory first, then the note is marked ended durably);
    **`Introducer::departure` is never called for a mirror**: the person who is
    let go is told by the inviter (rules 14–15), and a mirror only admits the
    inviter's own link. The entry **ends** with the record that no longer lists
    this device, or with the host: `Device::end_grant(key)` ends the key's
    inviter notes *and* mirror notes, `end_grant_in(key, folder)` those of the
    folder (durable, no mark, the host is not told, as for the inviter's notes);
    `renew_grant` never touches a mirror (it has no date). One entry for each
    `(inviter key, folder)`: a second join of the same folder by the same key
    replaces the entry (a re-invitation after a let-go starts it again), another
    key of the same person is another entry, and the entries of other folders
    stand (round 7's per-entry ends; the link layer closes the link when the last
    entry of the key ends, ndn-link §8.7 rule 6). **Mutual invitations**: Ann
    invites Bob to A and Bob invites Ann to B; each device holds an inviter's
    note of one folder and a mirror note of the other for the same peer key, and
    they are entries of different folders (a folder has one owner, so an
    inviter's note and a mirror of one `(key, folder)` cannot both exist):
    neither replaces the other, `end_grant_in` ends one, `end_grant(key)` ends
    both. A host whose link key is not its device key calls `Links::grant` for
    the inviter's link key itself, as it does for the grants it makes.
18. **The folders joined, and what the link routes for them** (round 9).
    `Device::joined_folders()` lists, for each live mirror entry whose record in
    force still lists this device, a `JoinedFolder`: the inviter's key, the
    owner, the folder, **this device's** role, and the **other writers'
    namespaces** the record lists — `writer_namespaces_of` (rule 16) **minus**
    the owner's, this device's own namespace and every namespace **above or
    below** it (a hostile inviter's record cannot make the joiner route its own
    names, or `/` or a broad parent of them, toward the inviter), **and minus
    every name that could take a name from a better route of this device's
    own.** A writer prefix in a record is free-form and the inviter's word, and
    a forwarder takes the longest matching prefix first, so a route at a name
    beats every shorter route for the names under it, whatever its cost. A name
    `W` is therefore listed only when `IntroPolicy::refuses(W)` says nothing
    against it (not the root, not `/localhost` or `/localhop`, not a broad
    shared name such as `/user` or `/com`, not fewer than `min_components`);
    **and** it names itself: it is the namespace of a trust context held here
    (`namespace_of_name(W) == W`) or a self-certifying person's namespace
    (`personal_namespace_of(W) == Some(W)`), never a free-form prefix (a writer
    `/dave/member` of a `/dave` this device reaches without holding its context
    is not listed); **and** it lies neither above nor below any namespace held
    here or adopted for a folder, except an exact match (the same prefix, where
    cost decides). Only names that are namespaces, at most `JOINED_WRITERS_MAX`
    (16) in the order of `Name`, sorted by folder then inviter. It is **derived
    on every call** from
    the record in force and the MAC'd note, never cached, and carries no
    authority: the link layer routes by it (ndn-link §8.7 rule 18: the prefix
    `W` of each writer namespace over the link of exactly that inviter, and,
    **only when this device's role is writer**, `<W>/32=sync` beside it — the
    writers' groups are the writer-push route, and a reader is routed `W`
    only), and the inviter's per-packet filter still decides what crosses.
    `Device::joined_changes()` is the **change notification**: a
    `tokio::sync::watch::Receiver<u64>` whose value is raised, and never repeats
    within a run, whenever the list derived differs from the one the value stands
    for — at a join, after every record taken (where the grants are judged:
    `judge_grants` now runs for a device with no host introducer and no offer
    used, since a joiner's routes follow the record on their own), at a host's
    end — and **only then** (a settle that changed nothing moves nothing). A
    watcher reads `joined_folders()` after each change; a surface whose device
    is gone yields a receiver whose sender is dropped (`changed()` errors at once
    and ends the watcher). The existing grants have a pull surface
    (`Device::grants()`) and a push the host forwards (`Introducer::grant` /
    `revoke_grant`); the joiner's routes need no host forwarding, so a host that
    already calls `LinkHints::serve(&device)` does nothing more.

Threat notes (round 7):

- **The departure as an oracle.** The mark is a hint of which name to fetch and
  is only ever shown to a key whose handshake proved the key, whose identity
  validates in a held namespace, and whose grant note — MAC'd — holds a mark. A
  key with no note has no mark and is told nothing; one whose mark is expired
  or used up is refused as a key whose grant ended with none. The record is
  signed data any reader of the folder can fetch.
- **A hostile inviter cannot make a person fetch an arbitrary name:**
  `take_departure` accepts only a members record name of a folder the person is
  a member of, under a namespace they hold, told by a device of the folder's
  own namespace, and validates what comes back (rule 15); the bounds on
  in-flight and per minute cap the cost. **A connected peer of another
  namespace** (a stranger, another person, a device of the person's own
  namespace) is refused before it can hold the folder's fetch slot or drain the
  minute's bound: only a device of the folder's namespace lets a member go of
  it.
- **A mark is not a way back in.** It names one log entry and its pieces and cut
  (rule 14); it expires; it is looked up only for a key whose note's MAC
  passed. An edited store cannot add, clear or move a mark (rule 11).
- **Writers' names widening the grant** (rule 16): only roots of namespaces the
  record in force lists as writers of this folder, derived per packet, no
  cache; a removed writer is out at the next packet; a name outside the folder
  stays refused. The disclosure is the names, heads and digests a root signs
  for anyone who asks; Bob learns the collections of Carol's namespace beside
  the folder (names and counts, never a payload), as the folder's namespace
  root already does for Alice's. The sync group, trust context and key and
  certificate names of a listed writer's namespace cross too; they are public by
  design (a hello already carries the chain), carry no data and name no
  collection, and are bounded the same way (ndn-link.md §13.5).

Threat notes (round 9):

- **Can a writer of a folder make Bob route a name he should not?** A writer
  cannot change the record: only devices of the folder's own namespace sign its
  members records (§19.4), and the device derives `writers` from the record in
  force, whose signatures it verified. But the owner can list any writer
  prefix, and **a route is not safe because its cost is high**: longest-prefix
  match decides before cost, and cost decides only among routes for the same
  prefix. The first round-9 filter (drop only Bob's own namespace and what lies
  above or below it) let a record list `/com`, `/user`, `/localhop`,
  `/localhost` or an unheld `/dave/member`, and Bob's Interests for those names
  would have gone to the inviter's face instead of to the routes Bob already
  had. The device now lists a name only when it names itself (a held context's
  namespace or a self-certifying person's), is not refused by
  `IntroPolicy::refuses`, and is neither above nor below a namespace held here
  or adopted for a folder (rule 18). That is what makes longest-prefix match
  safe here: every listed name is one Bob holds trust for or is a person he can
  verify by its own name, and none shadows a route he has for another name. The
  link layer adds that it never routes `/localhost`, `/localhop` or the root,
  and that each inviter has an equal share of the 16 folders and 64 namespaces
  (ndn-link §8.7 rule 18, §13.5). A hostile inviter can still make Bob send
  Interests for a namespace Bob holds (or a self-certifying person) and the
  names under it toward her: she can blackhole them, or answer with data Bob
  validates by that namespace's own trust, which nothing she answers can fake.
- **Can the inviter's link, as Bob holds it, be used by a different key?** No:
  the mirror holds one key (the one that signed the verified answer); the link
  is admitted only when the handshake proves that key *and* an identity that
  validates in the owner's namespace (ndn-link §8.7 rule 3). The MAC keeps a
  writer of the store from adding an entry.
- **Can a hostile inviter use the mirror to make Bob serve more than the
  folder?** The grant is for her own key and the folder, kept only for a
  folder under her own namespace; the link carries the folder's names (live,
  from Bob's record), the public names of the namespaces and her own devices'
  names; her pushes pass only under her own devices unless the record lists
  her namespace as a writer. A hostile inviter who also signs a record that
  lists other writers makes Bob carry their public names and roots toward her:
  names, heads and digests that those writers make public, nothing of Bob's
  own collections outside the folder. In an **unsealed** folder every device
  counts as a reader, so a reader-role mirror stands while a record is held and
  the folder is unsealed; it ends with the host (`end_grant`) or when the folder
  is sealed and the record leaves the device out.
- **The mirror note.** MAC'd under a key derived from the recipient secret (in
  the key store, not the data store), with labels of its own; a store-writer who
  changes it makes it unread and the device admits no one on its account (join
  again with a new offer); rolling back to an older genuine copy cannot widen,
  because the entry exists only while the record in force lists this device.

No wire TLV is added by this section: grants and marks are local notes and host
calls, and the registry (README) is unchanged.

### 19.9 Host notes — round 6

A host that embeds a device sometimes has a small thing to keep that the
device's store keeps well: the addresses its link layer reached peers at
(ndn-link.md §17C), say. `Device::local_notes(area) -> LocalNotes` gives it
that: small values by key, in the device's own store, durable once the call
that wrote them returns. It is a **local, unauthenticated key-value surface
of the host's**, not a data-layer record.

1. **Names.** A note is stored at `/localhost/ndn-data/host/<area>/<key>`,
   `area` and `key` each one generic name component, its value the note's
   octets as given. `area` and `key` MUST be 1 to 64 octets, with no `/` and
   no control character; a call with another is refused with
   `DataError::BadRequest`, naming the rule and the limits (`local_notes`
   itself reads and writes nothing; each call checks).
2. **Bounds.** A value is at most 4 096 octets; an area holds at most 1 024
   notes. A `put` that would break either is refused with
   `DataError::BadRequest` (`remove one before keeping another`); the count
   and the write are one step, so two concurrent puts cannot both take the
   last place. Replacing a note is no new note.
3. **Operations.** `get(key)` and `list()` (every note of the area, by key)
   read the store now. `put(key, value)` and `remove(key)` return **only
   after the store's durability barrier passed** (the one every own entry
   waits for, §4.2): a note a `put` returned for survives a power loss, and a
   removal that returned is not undone by one. `remove` of a note that does
   not exist is no error. A call on a device that stopped is
   `DataError::Local`.
4. **Never served, announced or trusted.** The name is under `/localhost`,
   which no device serves: the device's producer is registered under its own
   name only, and no function that answers an Interest knows the name (a note
   is never answered, whatever the Interest asks, `CanBePrefix` included).
   Nothing in the layer reads a note back as an entry, a record, a key or a
   grant; the restore of a store skips them. A note is never a summary,
   never listed and never sent.
5. **What a note is worth.** **A note is local, unauthenticated host data**
   and a host MUST treat it as a *hint*: whoever can write the device's store
   already holds the device, and a note is not signed, so nothing may be
   *admitted* or *trusted* because a note says so. (The link memory of
   ndn-link §17C is built so: a record there names a key and an address to
   dial, and every dial is judged again by the handshake and by admission.)
   A host that needs integrity keeps its own.
6. **Threats.** A note that grows the store is bounded by rule 2; the area
   and key names are bounded by rule 1, so a note cannot name another prefix
   of the store (`/` is refused) nor collide with the layer's own local names
   (`/localhost/ndn-data/<other>/…`): the layer's prefix is `host`. A note is
   not secret: public keys, device names and addresses belong there; a secret
   does not (the device keeps its own secrets in its key store, not in notes).
7. **Notes are in the clear, at rest.** Rules 5 and 6 are about integrity and
   about what a note may decide; confidentiality is not a property of a note.
   A note is written to the device's store as its octets, and the link
   memory's notes (ndn-link §17C.4) hold each peer's key, its device name and
   the addresses it was last seen at: whoever can read the store reads who
   this device talks to and where. **The permissions of the file or database
   the store lives in are the host's to set** (this crate has none to set: the
   only `DataStore` it brings is `MemoryStore`), readable by the device's own
   user only. A host that does not want the addresses on disk gives the link
   memory `MemoryOptions::persist_addresses = false` (ndn-link §17C.6), which
   writes the notes without them; it does not make the rest secret, and a
   host that needs a note encrypted encrypts it before `put`.
8. **The listening port** (round 7). The link memory keeps one more note, in
   its area `link-memory`, key `listen-port`: the port the host's link socket
   listens on, 2 octets, big-endian (ndn-link §17C.4, §17D.2), so a restarted
   host listens where its peers last found it. It is a note as any other:
   within rules 1 and 2, never served, a hint (a port below 1024 or 0 is never
   bound again), in the clear like the addresses and under the same
   `persist_addresses` option (off: it is not written, and one written
   before is removed). The link memory's record notes carry the peer's
   last-known port too (record version 2; version 1 notes are still read).
9. **Round 9: what a host keeps, and does not.** The mirror note (rule 17 of
   §19.8) is the device's own and lives under `/localhost/ndn-data/intro/mirror/`,
   not in a host's `local_notes` area: a host cannot write it. A host keeps no
   FIB entry for the folders its device joined: `LinkHints::serve(&device)`
   follows `Device::joined_changes()` and the link layer routes the other
   writers' namespaces over the link of the inviter (ndn-link §8.7 rule 18);
   a host whose link key is not its device key maps `JoinedFolder::inviter` to
   its link key itself and calls `Links::set_joined_routes` and `Links::grant`.
   The link memory brings a peer's record **up to date** from a link the
   identified peer opened to this device, with the port the record holds (the
   source port of an accepted link stays unrecorded), under the same
   `persist_addresses` option and bounds (ndn-link §17C rule 7): a host does
   nothing for it.

No wire TLV is added by this section; the registry (README) is unchanged.

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
  layer is, so the trust context governing its name is the signer's. The
  header's name is the one place a scope's Name travels in a signal: the
  transport's packets after it name the scope by a 16-octet digest of it
  (signals.md §4.1, §13.9), so the header binds the run to its scope.
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
- **The sequence counter and the time hint.** The two things of a signal the
  device keeps are numbers, no packet. The **sequence counter**:
  `signal_sequence_floor()` is a number above every sequence a transport gave
  a signal, held in the store under `/localhost/ndn-data/signal-clock` (8
  octets big-endian) and read at start (0 on a device that never gave one).
  `signal_sequences(upto)` answers the counter once it is at least `upto`
  and durable: at or above it already, it answers at once and writes
  nothing; below it, the device writes `upto` plus a block of 2^20
  (`Device::SIGNAL_SEQ_BLOCK`), the store's barrier (§4.2) passes, and only
  then does it answer. So a crash never leaves a restart at or below a
  sequence given, and no sequence is given twice. A transport asks for the
  next block once half of one is left. The refusal is `Local` (the device
  stopped, or the store could not make the write durable). Before the
  counter, the same name held a time in µs above every sequence an older
  version gave (they were µs times): read as a counter it is above every
  sequence of a run held from before the upgrade. The **time hint**:
  `signal_time_hint()` is the time, µs since the Unix epoch, a transport last
  dated signals by, held under `/localhost/ndn-data/signal-time` and read at
  start (0 when never written). `note_signal_time(us)` holds `us` as the
  hint once it differs from the hint by a second or more, upward or
  downward, and writes it to the store; it returns at once, never waits for
  the barrier and reserves nothing, so after a crash the hint may be as old as
  the last barrier and quick restarts cannot move it ahead of the clock that
  dated them. It is a hint: the transport does not keep one that is more than
  its run lifetime ahead of its raw clock (signals.md §3.5, §13.8). Neither
  number is a packet, version or record, and nothing is served or counted
  for them (signals.md §3.3, §3.5, §13.8).
- **Nothing kept.** A device MUST NOT store, serve, count or list anything
  of a signal but the two numbers above: no run header is kept in the store or a summary, given a
  seq, counted as a version, a write or a holder's evidence, or answered
  to an Interest, and no signal packet reaches the layer at all. A signal
  never becomes a version; a commit of live work is an ordinary `put`.
