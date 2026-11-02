# Data layer: named, signed, versioned data

- **Status:** Skeleton (slice 0). Each section names the slice that fills it.
  A section marked *open* has no normative content beyond what is stated.
- **Scope:** the data model shared by files, databases and network
  exchanges — versions, collections, members, summaries, cuts, snapshots,
  custody, prune, seals and types — and the seven verbs over it. The Rust
  contract is the `ndn-data` crate (`crates/app/ndn-data`); conformance cases
  are `ndn-data-conformance` in ndn-sim.
- **Out of scope:** views and lenses above the layer; trust-context encoding
  ([trust-context.md](trust-context.md)); link admission
  ([ndn-link.md](ndn-link.md)).
- **Wire formats:** none is defined yet. Names, TLV types, signature
  placement and encodings are to be specified by the slice that implements
  each section. Nothing in this document assigns a TLV number or a name
  component.

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

## 3. Version — slice 1 (blocks: slice 4)

A version is an immutable record signed by one key. It carries
`(writer, seq)`, parents, type, seal, keep and a payload.

- A writer is one key, never a person. A device's key MUST NOT share a
  sequence space with any other key.
- `seq` MUST increase with every version of that writer; it never goes back.
- Parents name, as a frontier, what the writer had seen.
- The date a version carries is its signer's clock reading. A reader MUST
  NOT use it to accept or refuse the version.
- A payload is one entry or a block: many entries under one signature with a
  digest per entry, each entry verifiable on its own. A producer that
  batches states the delay it accepts (slice 4).

Wire form: to be specified in slice 1 (entry) and slice 4 (block).

## 4. Collection and rule — slice 1 (log: slice 2, one key: slice 4)

A collection is a named, growing set of versions with a rule and a members
record. It exists when its first version is put.

| Rule | Meaning |
|---|---|
| one key | One key writes; the newest is its signed head with a freshness bound. |
| log | Each member key appends; the collection is the union of exactly its members' logs. |
| merge | Member logs plus a named merge function every reader runs alike. `get` returns the merged state at a frontier. |

The collection, not the application, decides what "newest" means.

## 5. Members — slice 1 (owner only), slice 2 (several people)

The members record is signed by the collection's owner. It lists the key
prefixes that may write, the audience that may read, the cuts in force and
the versions re-admitted after a cut.

- A reader MUST accept into a collection only versions by keys the members
  record lists and the trust schema allows under that prefix.
- Only the owner's key MAY sign a members record. Removing a writer MUST add
  a cut (§7).

## 6. Summary — slice 1 (shared summaries: slice 2)

A summary is a collection's signed state: its frontier and the mapping from
sequence numbers to names.

- Summaries nest: a collection of collections lists each child by the digest
  of the child's summary. `watch` MUST descend only into children whose
  digest changed.
- *Open (slice 2):* with many writers each signs its own summary and
  completeness is per writer, gathered by the members record. Whether that
  suffices for large shared folders is to be measured by the reference
  implementation.

Wire form: to be specified in slice 1.

## 7. Cut — slice 2 (removal), slice 5 (revocation)

A cut is a signed "up to here" for a key or for a member's keys: everything
inside its accepted frontier stays valid; anything else by those keys MUST
be refused, whatever date it claims.

- A cut replaces clock-based signing-time validity.
- *Open (slice 2):* when a cut arrives, a reader MUST re-check everything it
  already accepted from the cut's keys and withdraw what the cut refuses.
- *Open (slice 5):* a cut can drop honest work (a stolen device's unseen
  offline edits). The owner MAY re-admit specific versions by signing them
  into the members record.

## 8. Seal — slice 2

A seal is a read policy over people, devices and groups. An application is
never a seal audience: lenses hold no keys, and the host opens only what the
person pointed at. Holders without the key store and forward. Erasure is the
destruction of the key. Removing a reader moves reading to a new epoch.

## 9. Type — slice 1

A type is a named, versioned content schema. Revisions only add fields. A
writer editing content of a type it understands in part MUST keep every
field it does not know; the type declares how such fields merge.

## 10. Snapshot — slice 2

A snapshot is a signed version naming exact versions or exact states.
Publishing it is the atomic multi-object change. A name pinned by a snapshot
MUST resolve to the same content however the collection grows later.

## 11. Custody — slice 3

A custody lease is a holder's signed promise to keep what matches a prefix
until a date.

- A lease MUST NOT extend beyond the data's keep.
- A lease ends for anything an authorised prune covers.
- The owner audits leases by fetching random pieces; a lease nobody can
  serve counts as broken and repair starts.

## 12. Prune — slice 3

A prune is a signed record dropping the pruner's own versions under a prefix
up to a point. It spreads like data.

- A prune MUST cover only versions the pruner may write. Removing another
  writer's data in a shared collection is a merge edit every reader applies.
- A reader that knows a prune MUST report "pruned" for what it covers, not
  the data. Copies already made are the forward-only limit (invariant 9).

## 13. Verbs — slices 1–3, host surface slice 7

| Verb | Shape | Slice |
|---|---|---|
| `get` | `get(name) → version or state + age` | 1 |
| `put` | `put(collection, content, {type, keep}) → (writer, seq)` | 1 |
| `watch` | `watch(collection, since F) → summary, new versions…` | 1 |
| `snapshot` | `snapshot(names \| collections) → snapshot` | 2 |
| `hold` | `hold(prefix, {copies, until}) → custody` | 3 |
| `prune` | `prune(prefix, upto)` | 3 |
| `share` | `share(collection, {readers, writers})` | 2 |

Code mostly uses `get`, `put` and `watch`. `hold`, `prune` and `share` run
on host policy, or on the person's gesture. A function's answer is a `get` on
its name (slice 6). Exposure over forwarder management and the mobile FFI is
slice 7.

## 14. Failure model

| Failure | Required behaviour | Rests on |
|---|---|---|
| Partition / offline | Reads and writes continue locally under each device's key; collections reconcile from summaries when a path returns. | §3, §6 |
| Lost device | Its leases lapse; repair copies elsewhere; a cut ends its key at what others had seen. | §7, §11 |
| Compromised key | The cut keeps what was signed before it and refuses the rest; sealed data re-keys forward. | §7, §8 |
| Bad or lying clock | No effect on validity. | invariant 1 |
| Member removed mid-edit | Edits inside the removal cut merge; later ones are refused. | §5, §7 |
| Holder withholds | The summary shows what is missing; fetch from another holder. | invariant 4 |
| Holder rolls back | A summary older than one already seen is refused. | invariant 3 |
| Writer equivocates | Both versions are kept and reported. | invariant 2 |
| Old software writes | Unknown fields survive its edit. | invariant 8 |
| Poisoned cache | Verification fails; the version is dropped and fetched elsewhere. | invariant 1 |
