# Answers: named, checkable readings over signed data

- **Status:** Draft (round 5, item F). Normative once built; a section marked `[PENDING F-QUESTIONS #n]` has no normative content beyond its text until the owner answers that question.
- **Scope:** an **answer** is the result of a definition or a function read over exact, signed versions of the data layer, published under a name that binds what was asked and what was read, signed by one device, and sealed to the readers of everything it read. This spec defines:
  - the two kinds of answer, **pure** (any holder of the definition and the inputs can recompute it) and **provider** (trusted because of the provider's authority);
  - the read set, its canonical bytes and its digest;
  - the binding, the answer id, the name and the signed record;
  - evaluators, named and versioned like merge rules, and provider functions;
  - sealing to the audience of the read set, and what a removal does;
  - the verb: how a reader names an answer, and how one `get` returns the same typed result whether it was computed, cached or fetched;
  - recompute-or-trust, the policy that picks signers, and the evidence a mismatch makes;
  - limits, errors, the wire format, threat notes, conformance cases and the edits to other specs.
- **Implementation:** `ndn_data::answer` and `Device` (ndn-rs `crates/app/ndn-data`). The Rust shapes are `handoff-ndf-rs/SHAPES-R5.md` §F. Nothing in a forwarder, link or trust-context library treats answers specially. Evaluators are programs the host brings, as merge rules are.
- **Related specs:** [data-layer.md](data-layer.md) (names §3, durability §4.2, rules and states §5, §11, members §6, seals §9, pieces §13.1, what a device serves §13.5, verbs §15, wire §16, the gate §20 for the definition of a member), [trust-context.md](trust-context.md) (revocations and cuts), [signals.md](signals.md) (a sibling item built on the same seals).
- **Replaces:** the interim of the study's slice 8, a service that `put`s its answer into a collection of its own that it shares with its input's audience (conformance case c12, part 2). A collection grows, has a rule, a members record and a seq per answer; an answer is one immutable packet named by what it read.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119], [RFC 8174]) when, and only when, they appear in all capitals, as shown here.

---

## 1. Terminology

| Term | Meaning |
|---|---|
| definition | Signed data a pure evaluator reads first: a version, or the state of a merge collection, named exactly (a `ReadRef`, §3.1). A formula, a view, a query. |
| evaluator | A named, versioned pure function of (definition, the contents of a read set) with a closed set of operations (§4.1). Brought by the program, like a merge rule (data-layer.md §5.1). |
| function | A provider's named, versioned function (§4.2). Its code is the provider's; its inputs are signed data. |
| read | One exact thing an evaluation or a function read: one version, or one merge collection's state (§3.1). |
| read set | The set of every read, in canonical order (§3.1). Its **digest** names it (§3.1). |
| binding | What an answer is an answer to: its kind, its definition (pure), its evaluator or function, and the digest of its read set (§3.2). |
| answer id | A 32-octet identifier of a binding: its digest, or, when anything read is sealed, its keyed digest (§3.2). |
| answer | The Data packet `<D>/32=answer/<id>`, signed by device `D`'s key, whose content is an `AnswerRecord` (§3.4). |
| signer | The device key that signed an answer. |
| pure answer | An answer of kind pure: evaluator and definition named. Any device that knows the evaluator and holds the reads recomputes it. |
| provider answer | An answer of kind provider: function named, no evaluator. Only the provider computes it (§4.2). |
| question | A name `<X>/32=question/<AnswerAsk>` that `get` takes (§7.1). Local: never sent, like a state name (data-layer.md §11). |
| audience key | The key an answer is sealed under, derived from the epoch keys of every sealed collection it read (§5.2). Only a device in every one of those audiences holds it. |
| recompute | Run the evaluator over exactly the read set, with nothing else readable (§7.3). |
| policy | Which signers a reader trusts without recomputing, and which devices are the providers of a function (§9). Data the host holds; mechanism is code. |
| evidence | A signed answer together with what contradicts it: kept, reported as `AnswerEvidence`, never silently dropped (§8). |

## 2. Model

1. **An answer is immutable and named by what it read.** One binding has one id. The id never changes meaning: an answer says what it read, and a reader who reads something else asks for another answer, with another id.
2. **Only readings over signed data are published.** A read names a signed version, or a state computed from signed versions the reader holds verified, each bound by digest (§3.1). Work that exists only in one runtime's memory or local log has no read, so it cannot be named by a read set and cannot be published (§6.1).
3. **Nothing is trusted that can be checked.** A device that knows the evaluator MUST recompute a pure answer and compare, unless its policy says, for that evaluator, to take a trusted signer's answer (§7.3). A device that does not know the evaluator takes a signer's answer only by policy, and says so in the result (`Provenance`); otherwise it answers `CannotCheck` (§12). Silence is never acceptance.
4. **A mismatch is evidence, and the reader fails closed.** A recomputation that differs from a signed answer is evidence against the signer (§8). The reader's own recomputed value is what it returns.
5. **Pure answers do not inherit the provider trust model.** A provider answer is trusted because of the provider's authority: only it can compute the function, and the policy names which devices are providers of which function. A pure answer is trusted because anyone holding the definition and the inputs can check it. A policy that trusts a signer for pure answers is an optimisation the reader chose, never a property of the answer (§7.3, §13.4).
6. **Answers ride the sealing of what they read.** A reader needs no more access than the read set, and nobody learns through an answer what they could not read: the answer is sealed under a key only a device in the audience of every sealed collection read holds (§5). Its name leaks nothing and cannot be computed by anyone outside that audience.
7. **A reader neither knows nor cares whether an answer was computed or fetched.** `get` of a question returns one typed result, with the same refusals, from a recomputation, from this device's store or from the network (§7.5).
8. **No clock decides anything.** An answer carries no date. What it read is exact; how old it is follows from the ages of what it read (§7.6).
9. **Forward only, as everywhere in the layer.** Removing a reader stops future answers over new versions from reaching them; an answer they could open stays open to them (§5.5, data-layer.md invariant 9).
10. **Published means durable.** A device serves, announces or lists an answer only once it is behind the durability barrier (§6.2; data-layer.md §4.2).

## 3. What an answer is

### 3.1 Reads, the read set and its digest

A **read** is one of two things, each a TLV (§11.2):

- **`ReadVersion`**: one version, named by its log entry name `<D>/32=log/<C>/seq=<n>` (a name `C` of a collection, §3 of data-layer.md) and bound to the implicit digest of its packet (SHA-256 of the whole Data wire; the version's content address, data-layer.md §4). Used for log and one-key collections, for definitions that are one version, and for a specific version of a merge collection.
- **`ReadState`**: the state of **merge collection** `C` at a frontier. It carries `C`, the merge rule's full name the state was computed under (`Rule`, §16.2 of data-layer.md, kind 2), the frontier **with the digest of every tip** (`Frontier` with a `FrontierEntry` and `Digest` each, as in a version's parents), and the **applied-set digest**: SHA-256 over the octets `"ndn-answer/1 applied\0"` followed, for every version of `C` the state is computed from, in ascending order of the octets of the writer's key Name TLV and then of `seq`, by the writer's Name TLV, `seq` as 8 octets big-endian and the version's implicit digest (32 octets). "The versions the state is computed from" are exactly the versions data-layer.md §5.2 says a state's frontier `at` names: every version of `C` inside the frontier that applies, after an applied checkpoint dropped what it covers; held but not counted ones are in it, versions that never apply are not.

Why the extra bindings: a state name carries no digests (data-layer.md §11), so a frontier alone does not say which bytes were read; the tip digests bind each tip and, in a merge collection, everything the tip was made over (every parent of a merge version carries a digest, data-layer.md §4); the applied-set digest binds the set a cut or a refusal may have changed since; the rule binds what the versions mean. A read of a collection whose frontier would be empty is not a read.

**Empty and unreadable reads.** A device MUST NOT make a read of a version or state it does not hold verified, or one that data-layer.md refuses (`Refused`, `Pruned`, `Expired`) or cannot open (`Sealed`, `RuleUnknown`): the read answers that same error to the evaluator (§4.1), and the evaluation fails with it.

**The read set** is a list of reads in **canonical order**: ascending by the octets of each read's complete TLV encoding (type, length, value), no two equal, at most one `ReadVersion` per version name and at most one `ReadState` per collection. It is a *set*: the order in which an evaluation made its reads never shows. It has at most `READS_MAX` (65,536) reads and its encoding is at most `PAYLOAD_MAX` octets; a reader refuses one that breaks any of this (`Answer` / `ReadSet`, §12).

**The read-set digest** is SHA-256 over the octets `"ndn-answer/1 readset\0"` followed by the `ReadSet` TLV (§11.2) as it is on the wire: TLV-TYPE `0x05CB`, minimal TLV-LENGTH, and the reads in canonical order, each in the minimal encoding, names in the minimal encoding of the Name TLV `0x07`. The octets hashed are the octets a reader receives; a read set decoded from an answer and encoded again MUST give the same octets, and a reader MUST refuse one that does not (non-minimal lengths, an unsorted or repeated read).

**The definition is a read.** For a pure answer the definition's `ReadVersion` or `ReadState` MUST be one of the set's reads: an evaluator reads its definition like any other input, so the epochs, digests and validity checks below cover it.

### 3.2 The binding and the answer id

The **binding** is the `AnswerBinding` TLV (§11.2), in order:

1. `AnswerKind`: 0 pure, 1 provider;
2. for a pure answer only, the **definition**: a `ReadVersion` or a `ReadState`: the definition's exact version (*the definition's version*);
3. `AnswerBy`: the evaluator's full, versioned name (pure) or the function's (provider): *the evaluator's version* or *the function's version*;
4. `Digest`: the read-set digest (§3.1).

So the binding of a pure answer names the definition's version, the digest of everything read, and the evaluator's version; the binding of a provider answer names its function's version and the digest of the inputs it read, with no evaluator, as REPLY-6 agrees. The binding is short whatever the read set is.

An evaluator or function name is matched by **exact equality of names**, never by prefix, a part of the name or the nearest version, as a merge rule is (data-layer.md §5.1). By convention its last component is a version (`/ndf/eval/v=3`); a change of meaning is a new name.

The **answer id** is 32 octets:

- **no sealed read** (§5.1: the read set's epoch list is empty, so every collection read is unsealed): `SHA-256("ndn-answer/1 id\0" ‖ AnswerBinding TLV)`;
- **otherwise**: `HMAC-SHA256(name_key, "ndn-answer/1 id\0" ‖ AnswerBinding TLV)`, where `name_key` is the name key of the audience key derivation (§5.2).

The keyed id is what makes the name leak nothing and unguessable by anyone outside the audience (§5.6): a device that cannot derive `name_key` cannot compute the id of any sealed answer, even knowing the definition, the evaluator and every version read, all of which appear in the clear in names and summaries. Two devices in the audience derive the same key and so the same id for the same binding.

### 3.3 The name

An answer is the Data packet

```
<D>/32=answer/<id>
```

`D` is the **signer's device name**, and `<id>` is one GenericNameComponent of the 32 octets of the answer id. It carries no FreshnessPeriod (it is immutable), ContentType is BLOB, and the signature is the device key's, as the data layer signs everything.

Why this layout:

- **Under `D`.** Every packet a device signs MUST be named under it, so any forwarder's hierarchical schema admits it, a validator picks the trust context by the name, and Interests for it route to the device (data-layer.md §3). A name under the owner's namespace `<O>/32=answer/…` signed by a device of `O` would break that rule; so the full name of one answer differs by signer, and the **id is what two devices agree on**: the same binding gives the same id on every device in the audience, under each signer's own prefix.
- **A keyword component `answer`**, like `log`, `summary`, `grant` and `held`: the layer's own names are marked by keyword components (data-layer.md §16.1) and no collection component is one. `32=answer` marks nothing else.
- **No content words.** The name has the device name, a keyword and 32 octets. It carries no collection name, no field, no definition path, no evaluator name and no input. The things a name would reveal about the question (which formula over which folder) are in the binding, which is in the content, sealed whenever anything read is sealed.
- **One component, not three.** The definition's version, the read-set digest and the evaluator are bound inside the one id, so a name is of fixed length however long the read set is, and no component says what kind of question it answers.

Anyone may serve an answer they hold: a device that holds a verified answer serves exactly the packet it holds, under its own name as `<H>/32=held/<Name TLV>` (data-layer.md §13.5), and a cache serves it by name.

### 3.4 The record

The content of an answer is an `AnswerRecord` (§11.2):

```
AnswerRecord = AnswerKind
               ( AnswerBody                              ; no sealed read, ≤ INLINE_MAX
               | AnswerSealed                            ; sealed, ≤ INLINE_MAX
               | Chunks                                  ; no sealed read, in pieces (§5.4)
               | AnswerSealed(no Ciphertext) Chunks )    ; sealed, in pieces
AnswerBody   = AnswerBinding ReadSet Result
AnswerSealed = SealEpoch+ [Ciphertext]
```

- `AnswerKind` is in the clear, so a holder knows how to judge the packet without opening it.
- `AnswerBody` is the **plaintext**: the binding, the read set and the `Result` octets. When anything read is sealed, `AnswerSealed` carries the `Ciphertext` of the `AnswerBody` (§5.3), and **the read set listing is inside it**.
- `Result` is the evaluator's or function's output octets. The layer does not interpret them; the evaluator defines them, like the value of a merge rule. They MUST be canonical: one evaluation, one octet string.
- The seal epochs (`SealEpoch+`) are the epochs of the read set (§5.1), ascending.
- A reader MUST refuse an answer whose `AnswerBody` does not decode exactly, whose read set digest is not the binding's, whose definition (pure) is not one of the reads, whose kind in the record is not the binding's, whose binding does not give the id in the name (§3.2; keyed ids can be checked only by a device holding the audience key), or whose epoch list is not the one the reads give (§5.1). Each is `Answer` with `Malformed`, `ReadSet` or `Binding` (§12), and the last two are also evidence (§8).

The **result digest**, used where results are compared and in evidence, is `SHA-256("ndn-answer/1 result\0" ‖ Result)` when nothing read is sealed, and `HMAC-SHA256(name_key, "ndn-answer/1 result\0" ‖ Result)` when something is: a device outside the audience can then not confirm a guess of a result from a digest that reaches it.

## 4. Evaluators and functions

### 4.1 Evaluators

An **evaluator** is a named, versioned function

```
evaluate(definition, read set contents) → Result octets, or an error
```

of the definition and of the contents of exactly the reads in its read set. It MUST be a pure function of them: every device that knows the evaluator's name MUST compute the same `Result`, byte for byte, from the same definition and the same contents. So an evaluator:

- reads nothing but its arguments: no clock, no randomness, no environment, no file, no network, no other local state, no unsigned data, no data of the layer that is not in its read set;
- has a **closed set of operations**: the program that registers the name defines the set, and the same name MUST mean the same set on every device that registers it. Anything that changes any result is a new name;
- iterates in an order that depends on the contents alone (never on a hash map's order, thread timing or arrival order), and encodes its result canonically;
- is total over its input: an input it cannot evaluate is an error (`EvalError`), the same on every device, never a panic or a partial result.

**Two phases.** An evaluator makes its reads in a **plan** phase, which may wait for data (reads fetch, ask for keys, open sealed versions through the layer's own `get`s), and computes in an **evaluate** phase that does no I/O at all. Planning records every read it makes in the read set; the layer then evaluates over exactly the recorded contents, held in memory. A plan MUST make exactly the reads its evaluate makes. A **recompute** (§7.3) replays both phases against a given read set: planning may read nothing outside it, `current` of a collection answers the set's one read of it, and evaluate may use exactly the set's reads, each of which MUST be used. A read outside the set (`OutsideReadSet`) or a read of the set that is never used means the read set is not the reading of this definition under this evaluator.

**Resources.** An evaluation is bounded by the host's budget (§10: reads, octets read, result octets). A budget the evaluation exceeds is no result: `OverBudget` (§12), never a different result. Budgets bound availability, never answers: two devices with different budgets answer the same or one of them answers `OverBudget`.

**Registration.** An evaluator is brought by the program, in the device's configuration, as a merge rule is (ndn-data: `Evaluators`, as `MergeRules`): by its full name. A device that does not hold an evaluator under a name cannot recompute an answer that names it (§7.3) and answers `CannotCheck` where nothing else decides (§12). It MUST NOT recompute under any other evaluator, a newer or older version of the same name included. This spec defines no evaluator.

### 4.2 Provider functions

A **provider** is a device (or a namespace of devices) that computes a function whose code or inputs are not open to the reader: a summariser that holds a model, a service with private state, a function with effects. Its answer binds the function's full versioned name and the digest of the inputs it read, with **no evaluator and no definition**: the function name is the whole of what the reader can know about the code.

- **The inputs are the read set.** A provider's read set lists exactly the signed versions and states the answer was computed from, in the form of §3.1. A reader asks by stating the inputs (§7.1), so the id is computable by it without the provider's help.
- **Authority, not recomputation.** A reader takes a provider answer only from a signer its policy names as a provider of that function (§9). Nothing in the format proves the provider read nothing else: that is the trust the reader places in the provider, and the reason policy, not the answer, names who is trusted.
- **Determinism is required where it can be had, and enforced where it can't.** A provider's answer binds the function version and the inputs read. Its function SHOULD be a function of them. A function that is not (a model sampled at a temperature, a live sensor, a clock, an effect) MUST include in its read set a read that tells two calls apart: the version that **asks for it**. That is the lamp pattern of the model: the requester puts a request as a signed version into a collection of its own, and the provider's read set names that version, so two requests have two names. And it MUST keep every answer it signed (§6.2), because a second, different result at one name is equivocation (§8.1) whatever the reason.
- **A provider is not a merge rule or an evaluator.** Nothing here makes a function's code known to the reader; a registry of functions in the layer would only be a registry of names.

### 4.3 Unknown evaluators

An answer whose evaluator this device does not know is held, verified, stored and served as any answer is, and read as §7.3 says. A device never guesses at an unknown name's meaning, never treats a name that merely begins like a known one as that one, and never recomputes under another.

## 5. Sealing and access

An answer is sealed whenever any collection it read is sealed (§5.1), to exactly the readers of every sealed collection it read, at the epochs read. Everything below derives from the epoch keys the layer already has (data-layer.md §9); no new key is distributed, and no new grant is asked.

### 5.1 The epochs of a read set

A version is sealed in an **epoch** `(D, n)` (`SealEpoch`: the device that signed the record starting it and that record's seq): its `Sealed` payload names it, and the epoch is that of a collection's own record or of a folder's (data-layer.md §9). The **epochs of a read** are:

- of a `ReadVersion`: the epoch its version's payload is sealed in, none when the payload is not sealed;
- of a `ReadState`: the epochs of every version the state is computed from (§3.1), a set.

The **epochs of a read set** are the union over its reads, ascending by the octets of the creator's Name TLV and then by seq, once each. A read set with no epoch has **no sealed read**: its answer is unsealed (§5.3). It has at most `SEAL_EPOCHS_MAX` (256) epochs; a device refuses to make an answer over more (`TooLarge`), because an audience of more than that many intersected epochs is empty in practice and the list rides in the clear.

A reader recomputing or checking an answer computes the epochs of its read set from the versions it holds and MUST refuse an answer whose epoch list is another (`ReadSet`, and evidence, §8): a signer that lists fewer epochs than it read would let a device with fewer keys open the answer, and one that lists more only makes its own answer harder to open.

### 5.2 The audience key

A device that holds the content key of every epoch of the read set derives, from them alone:

- `PRK = HKDF-Extract(salt = none, IKM = k₁ ‖ k₂ ‖ … ‖ kₙ)` (RFC 5869, HKDF-SHA256), `kᵢ` the 32-octet content key of the i-th epoch of the set in the order of §5.1: the keys are of fixed length, so the concatenation is unambiguous;
- `seal_key  = HKDF-Expand(PRK, info = "ndn-answer/1 seal\0" ‖ E, 32)`;
- `name_key  = HKDF-Expand(PRK, info = "ndn-answer/1 name\0" ‖ E, 32)`;

where `E` is the exact encoding of the answer's `SealEpoch*` list (the TLVs of §5.1, in order). Two different keys come from one `PRK`; the `seal_key` encrypts (§5.3), the `name_key` keys the id (§3.2) and the result digest (§3.4); neither is used for anything else.

**This is exactly the audience intersection.** A device holds an epoch's key only if it was granted it by the rules of data-layer.md §9: it is in the audience that epoch's records name and the record in force admits it. So a device derives `seal_key` exactly when it is in the audience of **every** sealed collection read, at every epoch read, and no device outside any one of those audiences can derive it, however many other keys it holds. Nothing can be read through an answer that could not be read from the data, because the answer is a function of the data. A collection that is not sealed contributes no key and no restriction: its readers are everyone.

A key that is not held is asked for as a sealed read asks (data-layer.md §9, §17.1): a device that is to open or make an answer and lacks the key of an epoch of its set asks for it through the same grant, from the devices that grant it; the answer is `NotReady` (retry) while it asks and `Sealed` once the epoch's creator and the devices that grant it refuse.

### 5.3 What is sealed, and what is clear

When the read set has an epoch, the signer encrypts the **plaintext `AnswerBody`** with ChaCha20-Poly1305 under `seal_key`, a random 96-bit nonce and as associated data the octets of `"ndn-answer/1 aad\0"`, the answer's own name as a Name TLV, the `AnswerKind` octet and the `SealEpoch*` list `E`; `Ciphertext` is `nonce ‖ tag ‖ ciphertext` as in data-layer.md §9. Binding the name, the kind and the epochs to the ciphertext means none of them can be changed, moved to another name, or replayed under another signer's name by a holder without breaking it (they are also signed; the AEAD makes a holder who cannot sign unable to splice). A payload that does not open under the key is refused as `BadSignature`, as for a version.

In the clear, in a sealed answer: the Data name (`D`, `32=answer`, 32 octets); the kind; the epoch list; the ciphertext's size; the signature and the signer's key name. Inside the ciphertext: the binding (definition, evaluator or function name, read-set digest), the read set (every collection read, versions, frontiers, digests, the merge rule), and the result. In an unsealed answer all of it is in the clear, as the data it was made from is.

### 5.4 Pieces

An `AnswerBody` (or its ciphertext) of more than `INLINE_MAX` (6,144) octets travels in pieces exactly as a version's payload does (data-layer.md §13.1), with the answer's name `A` in place of the version's `V`: chunk `i` is the packet `<A>/seg=<i>`, manifest node `k` the packet `<A>/32=manifest/seg=<k>`, every piece DigestSha256-signed, and the `AnswerRecord` carries `Chunks` (`Size`, `Digest` of the root node) in place of the body (after an `AnswerSealed` without `Ciphertext`, when sealed). The limits of §13.1 hold: at most `PAYLOAD_MAX` octets, a reader refuses a `Chunks` whose `Size` is not above `INLINE_MAX` or is above `PAYLOAD_MAX`. A reader fetches pieces as §13.1 and §17.1 say (a window at once, each an owed fetch), from the answer's signer and from the devices that hold it. **No custody applies to answers**: no hold record, lease, audit or release names an answer; an answer in pieces is a cache entry of every device that holds it.

### 5.5 Removal, epoch changes and erasure

An answer is immutable and its name is by what it read, so:

- **A new epoch is a new name.** When a reader is removed from a collection, the collection moves to a new epoch (data-layer.md §9); versions written after it are sealed in it. An answer over a state that includes any such version has that epoch in its read set, so a different read-set digest, a different epoch list and a different audience key: **a new id**, a new name, and a key the removed reader does not and cannot hold. Nothing needs to be re-sealed and nothing is revoked.
- **Old answers stay as readable as they were.** An answer over versions all written before the removal has the same read set, the same epochs, the same key and the same id as before: a removed reader who kept the old epoch's keys can still open it, and, being unable to open anything of the new epoch, cannot open any answer whose read set includes one. That is the forward-only rule (invariant 9); a spec does not claim to recall what was opened.
- **A reader added by a record that only adds** is of the epoch it keeps and reads that epoch's history (data-layer.md §9); it is granted the epoch's key by the same rules and so opens every existing answer over that history, with no change to the answer. A reader added by a record that starts a new epoch is granted that epoch's key only: it does not hold the older epochs of a collection whose records never listed it, so it opens no answer whose read set has one of them. Answers over such a collection's older versions are closed to it, as the versions are.
- **Erasure.** Erasing a collection's or folder's epoch destroys its key once every version sealed in it is pruned or cut (data-layer.md §14). An answer that has that epoch in its read set is then sealed under a key no device can derive: erased with the epoch. A device that holds such an answer MAY drop it and MUST NOT claim to open it.
- **Epoch lists never grow stale.** An answer is not made over "the epoch in force"; it is over the epochs its reads were written in. A reader asking a question after a removal plans over the state it holds now (§7.2) and so asks for the id of the new read set.

### 5.6 Refusals that do not distinguish

A refusal MUST NOT tell a device more than a plain `get` of what the answer read would tell it:

- **A question** is judged by planning (§7.2), which reads the collections the evaluation reads: a device outside the audience of any of them gets the error `get` of that collection answers (`Sealed`, or `NotReady` while a grant or a record is awaited, data-layer.md §15), before any answer is looked for. It is told nothing about whether an answer exists, who signed one, or what it read beyond what it has already named itself.
- **A name** `<D>/32=answer/<id>` of a sealed answer cannot be derived by a device outside the audience (§3.2), so it cannot probe for the existence of an answer. A device that is *handed* the name (it saw it in a relay's Interest) and asks for the packet gets what any holder serves: the ciphertext, as for a version of a sealed collection, and `Sealed` as it cannot open it; or `Unavailable` when no holder answers. The packet's existence is therefore known to anyone who can see the name. It is not known to anyone who cannot, and the existence of a sealed version is known to such parties anyway (names and summaries are clear, data-layer.md §9).
- **A provider asked to compute** (`[PENDING F-QUESTIONS #1]`) for a read set the requester cannot read MUST answer exactly as a plain `get` of the first read the requester may not read would, in canonical order, and MUST NOT compute (§13.2).
- **Absence is not told by timing**: a question's refusal for lack of access is local and immediate; the network is asked only after planning has passed, which only a device in the audience can do.

## 6. Making an answer

### 6.1 Only signed data

A runtime makes an answer only through the layer's `Reads` (§4.1), whose every read is of a version or a state the layer holds verified, bound by digest (§3.1). There is no read of unsigned local state, of a program's own values, of a transaction log not yet committed or of a version waiting for its group, so there is nothing a read set could name that is not signed. A runtime that evaluates over such state (an editor's uncommitted live work) holds the result as its own, **unpublished**: the layer offers no way to sign it, and a function (`Device::provide`, §6.2) that is given an input it does not hold verified refuses it (`BadRequest`: "this input is not a signed version held here: commit it first, then ask again").

**When a commit changes this.** A commit turns local work into versions (`put`, `put_op`, `put_group`; data-layer.md §15). The same question asked after the commit plans over the new versions: its read set names them, so its binding and id are new, and the answer is publishable under that name. The layer knows because the read set can only be built from signed reads: a plan that read an input not yet a version never produces a read for it. A host that keeps a result computed from uncommitted state compares it with the answer the committed question gives and, if equal, publishes that one; the layer does not carry results across a commit, because a result of an input that was not signed is not bound to the bytes a commit signed.

A **group** (data-layer.md §5.5) of versions that is incomplete, refused or waiting is not read: a state is computed from versions that apply, and a group counts all or none.

### 6.2 Publishing

To **publish** an answer a device signs the `AnswerRecord` as the Data packet of §3.3 with its device key, stores it, and serves it. It MUST:

- make it durable before it serves, announces or lists it: the packet is written, and the store's barrier (`DataStore::sync`, data-layer.md §4.2) has passed. The reference group-commits it with the version entries. Until then the device may use the answer itself and answers nothing for it to others;
- have verified the answer before it signs it: the binding's digest is the read set's, every read is one it holds verified (§6.1), the definition is one of the reads, and the epochs are the read set's (§5.1);
- never sign two different results at one name (§8.1). A device that finds it already holds, or has already signed, an answer at the name keeps that one. For a **pure** answer the results are equal when it is honest, so a second signing under the same name is harmless but SHOULD NOT happen; the device reuses its stored answer. For a **provider** answer whose function is not reproducible (§4.2) the device MUST keep the answer it signed, behind the barrier, and MUST NOT sign another result at that name: after a restart, a power loss included, it serves what it signed, or nothing;
- hold what it signed for as long as it serves that function: such an answer is not dropped to make room (§10), and a device that cannot keep a new one refuses to make it (`Busy`) rather than drop an old one;
- not make an answer over more than `READS_MAX` reads, `SEAL_EPOCHS_MAX` epochs or `PAYLOAD_MAX` octets (`TooLarge`).

A device **never publishes without being told to**: whether a device publishes what it computed is the host's configuration (§10), never a consequence of a `get`.

## 7. Getting an answer

The seven verbs stay seven: an answer is read with `get`, as data-layer.md §15 has always said ("a function's answer is a `get` on its name").

### 7.1 Questions and exact names

`get` takes two names of answers, and answers `Got::Answer` (§7.4) to both:

- **An exact name** `<D>/32=answer/<id>` (§3.3): the answer with that id by `D`, when its reader has the id from somewhere (another answer's listing, a link, a snapshot's note, a host). The result has `Age::Exact`.
- **A question** `<X>/32=question/<AnswerAsk>`, one GenericNameComponent whose value is exactly one `AnswerAsk` TLV (§11.2), nothing else, at most `QUESTION_MAX` (65,536) octets. It names *what is asked*, not which signer answers, and is never sent: like a state name it is local (data-layer.md §11). A question has the `AnswerAsk`'s:
  - `AnswerKind`;
  - for pure, the **definition**: the `ReadVersion` or `ReadState` of the exact version (or merge state) of the definition the asker means; `X` is the definition's collection;
  - `AnswerBy`: the evaluator's name (pure) or the function's (provider); for a provider `X` is the **provider device** the asker asks of;
  - optionally the **read set** the asker states: what it holds of the definition and the inputs, as exact reads (§3.1). **A provider question MUST state it**: a provider's inputs are named by whoever asks. A pure question MAY state it, to name an answer without evaluating (for a reader that holds the definition and the inputs and does not know the evaluator, or does not want to plan); without it a pure question is **planned** (§7.2): the evaluator makes the reads from the state this device holds.

Reading a pure question without a stated read set means "the answer of this definition, over the data as this device holds it now", and has `Age::Newest` (§7.6); with a stated read set, or by exact name, `Age::Exact`. A reader that wants a historical answer states the old reads or uses the old name.

A name that is none of these (a `32=question` name whose last component is not one `AnswerAsk`, whose `X` is a collection for a provider or a device for a pure question, whose kind and `X` disagree, or an `AnswerAsk` that names a definition outside `X`) answers `BadName` (`NextStep::FixName`), saying how the name is formed. A host that wants the id a question resolves to (to hand to another device, or to build the exact name `<D>/32=answer/<id>` of any signer) asks the device for it (ndn-data: `Device::answer_id`); that is steps 1 to 4 of §7.2 and nothing more.

### 7.2 Resolving a question

A device resolves a question in this order. Each step that fails answers the error stated there and goes no further.

1. **Parse.** `BadName` (§7.1).
2. **The read set.**
   - If the question states it: validate it (§3.1: canonical, within limits, the definition one of the reads), `BadRequest` otherwise; check that each read names a version or state this device holds verified, or can fetch (it asks as a `get` does); an input it cannot read is that `get`'s error (`Sealed`, `NotReady`, `Unavailable`, `Refused`, `RuleUnknown`, …), in canonical order of the reads, the first.
   - Else (a pure question, not stated): the evaluator named must be known (`CannotCheck` if not: "this program does not know the evaluator, so it cannot make the reads; state the reads, or run a program that knows it"). It **plans**: it makes its reads through `Reads`, from the state this device holds, which records the read set. A read the layer refuses answers that read's `get` error, and the question answers it, naming the collection or version: that is the same error and, for a sealed collection, no more than a plain `get` of it says (§5.6).
3. **The keys.** Compute the epochs of the read set (§5.1) and the audience key (§5.2). A key not held is asked for (§5.2); `NotReady`, then `Sealed`.
4. **The binding and the id** (§3.2): the keyed id of a sealed read set, the plain one otherwise. This is the one place that computes ids, and only a device holding the keys gets here.
5. **Look for signed answers**, in this order, each judged by §7.3:
   - the device's own store, by id, under any signer;
   - the **candidate signers**: for a pure answer, the devices its policy trusts that this device knows (the devices of its own namespace known to write into it, at most `RELAYS_ASKED`, and the devices the policy lists by name, `Signers::Devices`); for a provider answer, the devices its policy names as providers of the function. Each candidate `D` is asked for `<D>/32=answer/<id>`, and, by the device that holds it, `<H>/32=held/<Name TLV>` (data-layer.md §13.5). Asks are owed fetches (data-layer.md §17.1: at most `FETCH_TRIES` per candidate, each tried in turn, a capped backoff), and an answer is **never computed on a candidate's behalf**: asking a device for an answer it has not made makes no work for it (§13.2). A pure question whose evaluator is known and `Check` is `Recompute` (§7.3) does not wait for them: it recomputes.
6. **Decide** by §7.3, and answer §7.4.

### 7.3 Recompute or trust

For a **pure** answer, the reader chooses, by this order:

1. **The evaluator is known and `Check` is `Recompute`** (the default for every known evaluator). The reader recomputes: it holds or fetches every read (as `get` does, subject to the same errors), replays planning and evaluation against exactly the read set (§4.1), and obtains `Result'`.
   - If it holds verified signed answers for the id: each signed result is compared by digest. Equal: the answer is **confirmed** by that signer. Different: the signer's answer is **evidence** (§8.1): the reader keeps it, reports it, and **uses its own recomputed value, not the signed one** (fail closed). The reader MUST NOT return the signed result.
   - If it holds none, `Result'` is the answer (the device computed it), published only if its host says so (§6.2).
   - If the replay reads outside the set, or leaves a read of the set unused, or the evaluator refuses these reads, the signed answer's read set is not the evaluator's reading of its definition: evidence of the `ReadSet` kind, the answer is refused (`Answer` / `ReadSet`), and nothing is returned for it. (A question with **no** signed answer whose evaluator refuses its own plan answers `BadRequest` with the evaluator's reason: the definition is not one it takes.) If the reads cannot be had, the error is that of the read, or `NotReady`: **an unavailable input never turns a recomputation into trust**.
   - If the read set no longer holds here (§7.3.1), `Answer` / `ReadsChanged`.
2. **`Check` is `Trust` for this evaluator**, or the evaluator is **not known**. The reader needs a signed answer, and accepts one only from a signer **its policy trusts for pure answers** (§9). It then returns that answer's result with `Provenance::Trusted { signer, unverified_reads }`, naming the signer and how many of the reads it did not hold here (§7.3.2). No signed answer held from a trusted signer, and none asked for in the rounds the device spends: `Unavailable` (RetryLater) if no candidate answered, and **`CannotCheck`** if the only answers it holds are of signers its policy does not trust, or the evaluator is unknown and no policy trusts any signer (§12): "this program does not know the evaluator and trusts no signer for it; run a program that knows it, or name a signer in the policy". An unknown evaluator is **never** silently accepted: the result a host reads names how it was obtained.

For a **provider** answer there is no recomputation. The signer MUST be a signer the policy names as a provider of exactly that function name (§9); another signer's answer at the id is refused, `Answer` / `NotProvider`, naming the function and the signer, and the next step is to change the policy or ask the provider. The result is `Provenance::Provider { signer, unverified_reads }`.

Whichever path, a reader first applies the checks of every answer (§7.3.3).

#### 7.3.1 Read sets that no longer hold

A signed answer is over exact reads. A reader that holds a read's version with **another digest** than the read lists has evidence that the signer lied about or confused what it read: `Answer` / `ReadSet` and evidence (§8.1). A reader whose own state differs from the read for a reason that is no fault of the signer returns `Answer` / `ReadsChanged`, no evidence: a `ReadState` whose rule in force here is not the read's, whose applied-set digest here is not the read's because a version in it was withdrawn (a cut, a revocation), pruned or expired since the answer was made, or a `ReadVersion` the device has since refused. The answer is **correct for what it read** and not for what this device now accepts: the reader asks the question again, which plans over what it holds now.

#### 7.3.2 Unverified reads

When a reader takes an answer on trust it MAY not hold every read. It MUST check each read it does hold (digest, rule, applied set) and refuse the answer on a conflict (§7.3.1), and it MUST count the reads it did not hold into `unverified_reads`. It does not fetch them: fetching all would be the recomputation's cost without its check. A host that wants every read checked sets `Check::Recompute`.

#### 7.3.3 Checks of every answer

Before anything of an answer is used, in this order, a reader:

1. verifies its signature by its trust context as a log entry is verified (data-layer.md §4: the key locator names a key of `D`, the context governing `D`, the chain; a revoked key or issuer **refuses it** whatever it carries, §13.9). `Answer` / `Untrusted` or `BadSignature`;
2. decodes it exactly (`Malformed`), checks the kind against the question;
3. opens it with the audience key (§5.3), or answers the error of §5.2;
4. checks the binding against the name's id, the read-set digest, the definition among the reads, the epoch list (§3.4, §5.1);
5. checks the reads it holds (§7.3.2);
6. only then applies §7.3.

An answer that fails 1 to 5 is refused as that packet, **not as the name**: whoever answers an Interest can make a packet of any name, so the reader drops it, keeps nothing against the name except a verdict it keeps as evidence (§8), and asks the next source (data-layer.md §4). The genuine answer is taken when it comes.

### 7.4 The result

```rust
Got::Answer(Answered)
```

`Answered` carries: the answer's **exact name** (the signed answer used, or the name this device's own signature gives or would give); the id; the kind; the binding; the read set (always, opened); the `Result` octets; the result digest (§3.4); and `Provenance` (§7.3): `Recomputed` (with the signers that confirmed, and those that disagreed), `Trusted { signer, unverified_reads }` or `Provider { signer, unverified_reads }`. `Answer.age` is §7.6.

The result **is the same type** whatever it came from. `Provenance` tells a program how it was obtained; it is information, never a different shape, and a program that ignores it still never reads a value that was not checked as §7.3 requires.

### 7.5 Reader transparency

A reader neither knows nor cares whether an answer was computed or fetched. The following MUST hold, and conformance checks them (§14, a10):

- `get(question)` returns an `Answered` with the **same `result`, `reads`, `binding` and `id`** from this device's recomputation, from a signed answer in its store and from one fetched from the network, whenever each is possible;
- it returns the **same error** for the same cause in each: `Sealed` for a device outside the audience, `NotReady` while a key or a record is awaited, `RuleUnknown` for a state of a collection whose rule it does not know, `Refused` / `Expired` / `Pruned` for a read that is one, whether the answer would have been computed here, found in a cache, or fetched;
- it does not ask the network for an answer a recomputation answers (§7.3, a known evaluator under `Recompute`), and does not recompute for one it takes on trust (§7.3, unknown evaluator or `Check::Trust`);
- nothing in the result says *where* it came from beyond `Provenance`.

### 7.6 Age

An answer is immutable and cannot be stale: `Age::Exact` for an exact name and for a question that states its read set. For a **planned** question the answer is the newest this device can make: `Age::Newest { unconfirmed_for }` where `unconfirmed_for` is the **greatest** `unconfirmed_for` among the ages of the collections its plan read (data-layer.md §15: the time since the device last knew nothing newer was outstanding there, on its monotonic clock), so a reader is told how old the input it relied on may be. No answer ever uses a date.

## 8. Evidence

### 8.1 What counts

Evidence is a **verified** signed answer (it passed §7.3.3 steps 1 to 4) together with what contradicts it. Five kinds:

| Kind | Definition |
|---|---|
| `Mismatch` | A reader that knows the evaluator recomputed the read set and got a result with a different digest than a signed answer's. Evidence: the signed answer, its signer, the id, the read-set digest, both result digests, the evaluator. |
| `Equivocation` | **Two verified answers at one name, by one key, whose opened results have different digests.** A name has one result (§2.1). Two packets that open to the same result (a sealed answer made twice has different nonces and so different bytes) are not equivocation. A device that cannot open an answer cannot tell. |
| `Conflict` | Two verified answers with **one id**, by **two signers** a reader's policy trusts, with different results, where the reader cannot recompute (§7.3). A reader that can recompute has `Mismatch` for whichever is wrong. |
| `Binding` | A signed answer whose content does not give the id in its name (§3.4): the signer put a binding in a name that is not its. |
| `ReadSet` | A signed answer whose read set is not canonical, whose digest is not the binding's, whose epoch list is not its reads', or that conflicts with a version the reader holds (§7.3.1), or whose reads are not the reads the evaluator makes (§7.3, 1). |

The first reader to find it keeps it (below); another that holds the same two packets finds the same. A signer cannot bind one name to two results without leaving both signed packets in the hands of whoever served them: that is the evidence. Evidence is **against a key**, not a device: a thief's answer signed by a stolen key before the key was revoked is evidence against that key, and the owner revokes it (data-layer.md §8.1).

### 8.2 What a device does with it

- It **keeps** the evidence before reporting it: the answer packet(s) whole, stored (ndn-data: under `/localhost/ndn-data/answer-evidence/<digest of the answer's name and the kind>`), so it survives a restart and a later watch lists it (as equivocation of versions is kept, data-layer.md §4).
- It **reports** it as the device-wide event `AnswerEvidence` (SHAPES-R5 §D, device-wide events; the variant is specified in SHAPES-R5 §F), once, with the answer's full name, its signer key, the id, the read-set digest, and the kind with its result digests (§3.4: keyed, so an event that reaches a device outside the audience confirms no guess of a result). Evidence carries the **whole signed packet** too, so another device in the audience can check it from the packet alone.
- It **never serves** an answer it holds evidence of, and **never takes it again**: a later `get` that meets the same packet or the same signer's answer at the same name is not used (`Answer` / `Equivocal` for the second and later of two at one name; a mismatching answer is refused), until the host or owner decides. A device that finds evidence MUST NOT drop the signer from its policy by itself: the owner decides, the host sees the event.
- It **never lists a result** of evidence to a device that cannot open it.

Evidence is **forward only**: an answer already used was used. The event tells the host which results to distrust.

## 9. Policy

Policy says **which signers a reader trusts without recomputing**, and **which devices are the providers of which function**. It is data the host holds and passes (`AnswerPolicy`), never something the layer infers from the answers it meets, and never part of an answer. The defaults are computed from signed records the device already holds.

- **Pure signers.** The default is `Signers::OwnAndMembers`: a signer `S` is trusted for a pure answer when its device is of **this device's own namespace** (a device of the person, data-layer.md §3: the namespace of the trust context governing it, the same as this device's), or when it is a **member** of every collection in the answer's read set by the record in force over each, held here (a writer prefix covers its key or the audience admits its device, and no context held revokes the key: the definition of data-layer.md §20), the folder's record for a collection that inherits it. A collection whose record is not held here makes the second test fail: the reader does not guess. Other values: `Signers::None` (trust nobody: recompute or `CannotCheck`), `Signers::Own`, `Signers::Devices(names)` (the listed device names and namespaces).
- **Providers.** `providers: Vec<(function name, Signers)>`. No default: a provider answer is refused unless a policy entry names its function, by exact name, and the signer is covered by that entry's device names (a device name matches itself and, as a prefix, the devices under it). A host that wants "the person's own devices provide function F" says so.
- **Check.** `Check::Recompute` for every known evaluator unless the policy lists it in `trust` (evaluators for which this host takes a trusted signer's answer without recomputing): an explicit, per-evaluator, per-host choice for evaluators whose recomputation is costly. It is never inferred.
- **The default is a choice made with eyes open.** Under the default, an answer signed by one of the person's own devices under an evaluator this program does not know is taken as `Trusted`, because the person's devices are the person (data-layer.md §3). A host that refuses that sets `Signers::None`.
- **Policy lives in data.** The layer takes a value; where the host keeps it (a collection it reads, the person's settings) is the host's. Whether the layer should define a signed record of its own for it is `[PENDING F-QUESTIONS #2]`.

Policy is read at the moment an answer is used and never cached across a change of the records it is computed from (a member removed stops being trusted at the next question once the record is held).

## 10. Limits

| Name | Value | Meaning |
|---|---|---|
| `READS_MAX` | 65,536 | Reads in one read set. |
| `SEAL_EPOCHS_MAX` | 256 | Distinct epochs in one read set. |
| `PAYLOAD_MAX` | 67,108,864 | Octets of an `AnswerBody` or its ciphertext (data-layer.md §13.1). |
| `INLINE_MAX` | 6,144 | Octets of an answer carried in one packet (data-layer.md §4.1). |
| `QUESTION_MAX` | 65,536 | Octets of an `AnswerAsk`. |
| Budget (host) | reads 65,536; octets read `PAYLOAD_MAX`; result octets `PAYLOAD_MAX` | What one evaluation may spend (`Budget`); exceeded is `OverBudget`, never a different result. |
| Held answers (host) | per signer 1,024 answers and 64 MiB; all 1 GiB | What a device keeps of others' answers (`AnswerStore`); past it, the oldest not-recently-asked of a signer is dropped first, never one it signed that is not reproducible (§6.2). |
| Answers signed (host) | 16 per second per device | A limit on a device's own signing (a flood of its own questions). |
| Asks | `FETCH_TRIES` per candidate; at most `RELAYS_ASKED` (8) candidates | As §7.2 step 5 and data-layer.md §17.1. |

The host's values are `Config::answers`; the layer enforces what is above, never a value that changes a result.

## 11. Wire format

### 11.1 Names

`D` is a device name, `X` a collection or device name, `A` an answer's name.

| Packet | Name | Signature |
|---|---|---|
| answer | `<D>/32=answer/<id>`, Content `AnswerRecord`, no FreshnessPeriod | device key |
| piece of an answer in pieces | `<A>/seg=<i>`; manifest node `<A>/32=manifest/seg=<k>` (data-layer.md §13.1) | DigestSha256 |
| question (never fetched) | `<X>/32=question/<AnswerAsk TLV>` | — |
| held answer | `<H>/32=held/<Name TLV of A>`, answered with the packet inside (data-layer.md §13.5) | DigestSha256 |

Every name parses one way, and a reader MUST refuse one that does not:

- **Answer.** `D` is the components before the first `32=answer` (`D` is a device name: no keyword, no digest component, data-layer.md §3); exactly one GenericNameComponent of 32 octets follows, the id, and nothing else.
- **Piece of an answer.** The last component is `seg=<i>` (a SegmentNameComponent), the next-to-last `32=manifest` for a manifest node; what precedes is an answer name. This extends the parse of a piece name (§16.1, §13.1 of data-layer.md), whose `V` is a log entry name, to an answer name.
- **Question.** `32=question` is the next-to-last component; `X` precedes it; the last is one GenericNameComponent whose value is exactly one `AnswerAsk` TLV. For a pure `AnswerAsk`, `X` is a collection name (§3 of data-layer.md) and equals the collection of the definition read; for a provider, `X` is a device name.

### 11.2 TLV-TYPE numbers

Answers use `0x05C0`–`0x05DF`, registered in [README.md](README.md#tlv-type-numbers). **Every number is odd**, because every field changes what an answer means: a reader that passes over a `ReadState` field would check an answer against less than it read, one that passes over `Digest` of a read would accept bytes it did not read, one that passes over an `AnswerKind` would judge a provider answer as a pure one. A decoder MUST refuse an unknown TLV in these records, so a reader that does not know a field cannot decode, check or use an answer that carries it; it drops it as a packet it cannot read (data-layer.md §16.2, §17) and asks the next source, and a question that no source can answer for that reason ends `Unavailable`.

| Type | Name | Value |
|---|---|---|
| 0x05C1 | AnswerRecord | AnswerKind, then one of: AnswerBody; AnswerSealed with a Ciphertext; Chunks (0x0521); AnswerSealed without a Ciphertext, then Chunks. An answer's Content |
| 0x05C3 | AnswerKind | NonNegativeInteger: 0 pure, 1 provider |
| 0x05C5 | AnswerBody | AnswerBinding, ReadSet, Result. The plaintext sealed in AnswerSealed |
| 0x05C7 | AnswerBinding | AnswerKind, [ReadVersion \| ReadState] (the definition, pure only), AnswerBy, Digest (the read-set digest) |
| 0x05C9 | AnswerBy | Name: the evaluator (pure) or function (provider), full and versioned, matched exactly |
| 0x05CB | ReadSet | (ReadVersion \| ReadState)*, canonical order (§3.1), at most `READS_MAX` |
| 0x05CD | ReadVersion | Name (the version's log entry name), Digest (the implicit digest of its packet) |
| 0x05CF | ReadState | Name (the merge collection), Rule (0x0548, kind 2 and the rule's name), Frontier (0x0522, every FrontierEntry with its tip's Digest), Digest (the applied-set digest) |
| 0x05D1 | Result | octets |
| 0x05D3 | AnswerSealed | SealEpoch+ (0x056E), ascending (§5.1), at most `SEAL_EPOCHS_MAX`; then [Ciphertext (0x0574): the AnswerBody, §5.3] |
| 0x05D5 | AnswerAsk | AnswerKind, [ReadVersion \| ReadState] (the definition, pure), AnswerBy, [ReadSet] (the read set the asker states, §7.1); in a question name only, never on a packet |
| 0x05D7 | AnswerEvidence | Name (the answer's full name), Name (the signer's key), Digest (the id), Digest (the read-set digest), AnswerFault; a record of the device's own event store (§8.2), never on a packet |
| 0x05D9 | AnswerFault | FaultKind, then by kind: 0 `Mismatch`: Digest (signed result), Digest (recomputed), AnswerBy; 1 `Equivocation`: Digest (the other result); 2 `Conflict`: Name (the other answer), Name (the other signer's key), Digest (its result); 3 `Binding`: nothing; 4 to 8 `ReadSet`, nothing more: 4 not canonical, 5 digest not the binding's, 6 epochs not the reads', 7 conflicts with a version held, 8 not the evaluator's reads |
| 0x05DB | FaultKind | NonNegativeInteger, 0–8 as above |

`0x05DD`–`0x05DF` are held for the ask exchange (§15). `Digest` (0x055E), `Frontier` (0x0522), `FrontierEntry` (0x0524), `Rule` (0x0548), `SealEpoch` (0x056E), `Ciphertext` (0x0574), `Chunks` (0x0521), `Size` (0x0523) are reused as data-layer.md §16.2 defines them. Names are the Name TLV (0x07). Inside a record fields appear in the order the table lists them; lists are sorted as stated, so equal content encodes to equal bytes and equal digests. `AnswerEvidence` and `AnswerFault` are records of the device-wide event store (SHAPES-R5 §D.4: `/localhost/ndn-data/events/`), local to that store and never served; D's own event records use `0x05E0`–`0x05FE`, so the two blocks do not meet.

Round 5's other items add their own numbers elsewhere; answers add no name-component type.

### 11.3 Cryptography

Every primitive is an audited crate the layer already uses: SHA-256, HKDF-SHA256 (RFC 5869), HMAC-SHA256, ChaCha20-Poly1305, Ed25519 (the device key's signature). No primitive is new, and no key is made, stored or granted for answers: the audience key is derived from epoch keys the layer already holds. Labels are ASCII, each ending in a zero octet so none is a prefix of another: `ndn-answer/1 readset\0`, `ndn-answer/1 applied\0`, `ndn-answer/1 id\0`, `ndn-answer/1 result\0`, `ndn-answer/1 seal\0`, `ndn-answer/1 name\0`, `ndn-answer/1 aad\0`. A digest made for one purpose never verifies as another's, whatever its fields.

**The signature domain** is the Data signature (name, MetaInfo, Content, SignatureInfo, as the layer signs everything) by the signer's device key. The name's keyword `answer` and the first TLV `0x05C1` of its content separate an answer from every other signed packet of the layer: no other packet has that name form or that content type. The binding and the read-set digest lie inside the signed content, so the signature covers what was read and what it was an answer to.

## 12. Errors

Each says why in its message and what to do in `DataError::next()`; `retry()` tells whether the same call can succeed later. They are the layer's own errors (data-layer.md §15): a read the layer refuses answers the same error (`Sealed`, `NotReady`, `Unavailable`, `Refused`, `Expired`, `Pruned`, `RuleUnknown`) for a question as for the plain `get` of that read.

| Error | When | Next step |
|---|---|---|
| `CannotCheck { name, evaluator, why }` | The evaluator is not known here and no trusted signer's answer is available to take on trust (§7.3, §4.3): "can't check here" | `UpdateProgram` |
| `Answer { name, why: AnswerRefusal }` | An answer is refused, or a question can't be made, for one of: | |
| ↳ `Malformed(String)` | It does not decode exactly, or breaks a grammar rule (§3.4, §11) | `None` |
| ↳ `Binding` | Its content does not give the id in its name (§3.4); evidence | `None` |
| ↳ `ReadSet(String)` | Not canonical, wrong digest, wrong epochs, definition missing, a conflict with a held version, or not the reads of the evaluator (§3.1, §5.1, §7.3); evidence | `None` |
| ↳ `ReadsChanged(String)` | A read no longer holds here (§7.3.1): ask again | `RetryLater` |
| ↳ `NotProvider { signer, function }` | A provider answer by a signer the policy does not name for the function (§7.3) | `SetPolicy` |
| ↳ `Untrusted { why }` | Its signer's key or issuer is revoked, or the chain no longer verifies (§7.3.3, §13.9) | `AskOwner` |
| ↳ `Equivocal` | Two answers at this name by this key have different results (§8.1) | `AskOwner` |
| ↳ `TooLarge { what, size, limit }` | More reads, epochs or octets than §10 allows | `FixRequest` |
| ↳ `OverBudget { what }` | An evaluation would exceed the host's budget (§4.1, §10) | `FixLocal` |
| ↳ `Busy` | A provider answer that must be kept cannot be (§6.2) | `FixLocal` |
| ↳ `AlreadySigned` | This device already signed a different result at this name (§6.2): it serves that one, and signs no other | `None` |
| `Sealed { name }` | Not in the audience of a sealed collection read, or of the answer (§5.2, §5.6) | `AskOwner` |
| `NotReady { name, why }` | A key, a record or a walk is awaited (§5.2) | `RetryLater` |
| `BadRequest { name, why }` | A stated read set is not canonical or not held, the definition is not among the reads, a function is given an input it does not hold verified (§6.1), a stated read set is not the evaluator's reads, or the evaluator refuses its definition or inputs (its reason in `why`) | `FixRequest` |
| `BadName { name, why }` | The question's or answer's name is malformed (§7.1, §11.1) | `FixName` |

`NextStep` gains `SetPolicy`: "change the host's answer policy, or ask the person who sets it" (a signer to name for a function). `DataError::next` and `DataError::retry` gain the arms above.

## 13. Threat notes

### 13.1 Name binding: can a signer bind one name to two results?

It can try, and it leaves evidence. A name is `<D>/32=answer/<id>`; the id binds the definition's version, the evaluator or function, and the digest of every read. Two different results at that name by the same key are **equivocation** (§8.1) and are routed to events (§8.2). A holder in the audience sees it when it holds both. A holder outside it sees two ciphertexts it cannot tell apart from one answer made twice (nonces differ) and cannot judge: it relays both, and the first reader inside the audience that holds both reports it. A signer that wants to give two readers two results can: each sees one packet. A reader that recomputes (pure) catches it alone; a reader that trusts a provider (provider kind) catches it only when both packets reach it, which is why provider answers MUST carry in their read set whatever tells two calls apart (§4.2) and why a provider MUST keep what it signed (§6.2). Providers are trusted on exactly this: that they sign one result per name.

### 13.2 The recompute oracle: cost and access

- **A device that recomputes on request is a cost oracle and an access oracle.** So a device **never computes for a remote requester** in this spec: it computes only for its own host's `get` (the host's own CPU), and a device asked by name for an answer it does not hold makes no answer (§7.2 step 5). This closes the cost oracle: a stranger cannot make a device work by asking.
- **Where computation on request is ever specified** (`[PENDING F-QUESTIONS #1]`), it MUST be bound by: (a) the request authenticates the requester's device (the asker's proof of data-layer.md §13.2), (b) the provider checks that device is in the audience of **every** read of the set at the epochs read, by the records it holds, before it reads or computes anything, and answers a requester outside it exactly as a plain `get` of the first read it cannot read would, in canonical order, never computing (§5.6), (c) a per-requester and global rate and a budget (§10), (d) the answer is the one a holder in the audience would get: nothing is added to it.
- **Timing and size.** A refusal for lack of access happens before any read of the data and before any network traffic (§5.6). The size of a sealed answer is visible (§13.3).

### 13.3 Access leaks

| What | Leaks? |
|---|---|
| The name | No. A device name, a keyword and 32 octets; no content word. The id of a sealed answer is keyed by the audience key, so a device outside the audience cannot compute it, test a guess of a binding, or enumerate answers (§3.2). |
| The read set | Not outside the audience when anything read is sealed: it is inside the ciphertext (§5.3). An answer whose reads are all unsealed has its read set in the clear, as the data it read is. |
| The result | No, same. The result digest in evidence is keyed (§3.4). |
| Size | The ciphertext's size is visible, as a sealed version's is (data-layer.md §9). An evaluator whose result length depends on secret content SHOULD pad its canonical result; the padding is part of the result. |
| Existence | To a device that cannot derive the id, no (§5.6). To anyone who sees the name asked, yes: they see a packet exists. |
| Timing | A refusal for lack of access is local and happens before any lookup (§5.6). |
| The epoch list | **Yes, to every relay: an answer's epochs, in the clear (§5.3).** A relay learns that some answer reads in these epochs, which it already knows for each version it carries (data-layer.md §9), and it learns that these epochs are read together. It does not learn the collections, whose names are inside the sealed binding and read set. Accepted and stated: the epoch list is what lets a reader find the keys without opening the answer. A deployment for which "these epochs are read together" is too much can arrange that an answer reads in one epoch. |
| The signer | Yes (the name and the signature). |

### 13.4 Provider trust does not carry over to pure answers

A provider answer is accepted for the provider's authority (§7.3). A reader that took any signed pure answer from a device it merely trusts for something else would reintroduce an evaluator that must be trusted, which "readers evaluate pure expressions" (REPLY-5 §4) removed. Hence: a **known** evaluator is recomputed by default; a pure answer is taken on trust only by an explicit entry of the policy (`Check::Trust`, per evaluator) or when the evaluator is not known, and then `Provenance` says so; a provider's signer is never chosen by the answer or by the data's folder, only by the policy for a function name.

### 13.5 Downgrade of the evaluator version

An attacker names an evaluator version this reader does not know, to force trust-by-policy (the reader cannot recompute, so it falls back). The defences are in the design, and the limits are stated:

- A reader that asks a question **names the evaluator it means**, and the id binds it (§3.2): an answer under another evaluator name is another id, never an answer to the question.
- Names are matched exactly (§4.1, §4.3): `/ndf/eval/v=2` is not covered by `/ndf/eval/v=3`, so a reader that knows v=3 is not forced to treat a v=2 answer as checkable or to ignore it; it asks for v=3.
- The unknown-evaluator path is taken only for **signers the policy trusts** (§9). An attacker who cannot sign as one gets `CannotCheck`, not acceptance.
- **A mismatch with a known evaluator is detected only for known ones.** For an evaluator this program does not know, nothing is checked, by design: the trust is the signer's. A host that cannot accept that sets `Signers::None`. The default (`OwnAndMembers`) trusts the person's own devices and the folder's members, who could equally write wrong data into the folder.
- A version of an evaluator is never "upgraded" by name: a program that adds a newer evaluator under a new name changes nothing for answers of the old.

### 13.6 Replay of old answers under new definitions

The definition's version, a read of its exact version or state with its digest, is in the binding and in the read set, so an old answer is an answer **to the old definition**. A reader that asks with a new definition version computes another id and never meets the old answer; an attacker who replays the old answer under the old name gets exactly the old definition's reading, still correct as such. An old answer's `Provenance` is that of the check it passed; nothing makes it newer. A definition read as a merge state binds the applied-set digest and rule, so an old state of the definition is not the new one either.

### 13.7 Stale read sets

An answer says what it read; it never claims to be current. A reader that wants the current one asks a planned question (§7.1), which plans over what it holds now and so asks for the id of the current read set, `Age::Newest` with the age of the inputs (§7.6). A cache that replays an old answer for a question can only answer the old id. A signer that publishes an old read set after newer data exists is not wrong, only old; the age says how old.

### 13.8 A provider answering over unsigned inputs

The format cannot list an unsigned input: a read is a version name with its digest or a state of signed versions (§3.1). A provider that **read** something else (a private store, a model state, a live value) and lists only signed reads claims what the format cannot check: that is the provider's trust, which policy chose (§4.2). Two things the layer does check: the provider's listed reads must be ones **it holds verified** when it signs (§6.1), and a reader MUST check the reads it holds against their digests (§7.3.2) and refuse one that conflicts: a provider cannot list a version that does not exist where the reader holds another, and the reader counts the reads it could not check (`unverified_reads`). A host that must not trust a provider's claims about inputs recomputes with an evaluator, which a provider's function is not.

### 13.9 A signer's key revoked after the answer was published

A revocation cut lists the log entries of the revoked key that stay valid (data-layer.md §8.1); an answer is not a log entry and has no seq, so **no cut lists one**: it is in the same class as a summary root, a head, a seal key or a grant, all of which a revocation refuses once held (§8.1 of data-layer.md). So:

- A reader that holds the revocation **refuses** every answer signed by the revoked key (`Untrusted`) at its next check, fail closed, whatever the answer's age and whatever a cut accepts of the key's log entries. A device that holds such answers stops serving them as soon as it holds the revocation.
- **Nothing is lost that cannot be remade.** A pure answer is recomputed by anyone, so the audience loses nothing but the cache entry; a recomputing reader never used the signature. A provider answer is lost until another device of the provider (or the provider after re-keying) signs the function over the same inputs: a new signer, a new name, the same id; a reader's policy then names the new signer.
- A provider key lost to a thief is also a risk **before** revocation: the thief signs wrong provider answers. The evidence of §8 and the owner's revocation are the response; the cut's bound does not help because answers have none.

### 13.10 Flooding with answers

- A device **never fetches** an answer nobody asked for: answers are asked for by name, from candidates the question's policy names (§7.2), and answers travel in no notice or sync group. A forged answer reaches a reader only as the reply to its own ask, and is checked (§7.3.3).
- A signer's answers a device **keeps** are bounded per signer and in total (§10); a signer cannot push its own out. What a device **signs** is bounded (§10).
- Checking is cheap before it is dear: name parse, signature, then the open and the digests; a flood of answers from signers a device's policy does not trust costs a verify each and is dropped at §7.3, nothing stored.
- Large read sets and bodies are bounded (§10); pieces fetched only for answers asked for.

### 13.11 Cheap forgeries of ids

An id of a sealed answer is a keyed MAC: only an audience member can make or check one. A forger outside it cannot make a packet that a member accepts (the signature must verify and the id must match the binding the member computes), only a packet that fails §7.3.3 step 4 and is dropped. An audience member can make ids and ciphertext, but not a signature of another device; authority is the signature plus the policy.

### 13.12 A member who signs wrong answers

A member holding the audience key can seal and sign a wrong answer. Pure: any reader that knows the evaluator recomputes it and reports the mismatch with the signer's key; a reader that does not know it, and whose policy trusts members, takes it: the trust placed in members is explicit (§9). Provider: only named providers are accepted.

### 13.13 Durability and equivocation by restart

A provider that restarts, or loses power, between signing an answer and its durable write (or after serving it) must not sign another result at the name: it serves only what is behind the barrier (§6.2), and a non-reproducible provider keeps every answer it signed. The storage cases of data-layer.md §4.2 apply to answers as to log entries.

## 14. Conformance cases

The cases the implementer writes, each failing first on the code before the feature, in `ndn-data-conformance` (ndn-sim), ids `a1`…`a18`, feature `Answers` (case c12 keeps `Functions` and is rewritten to the F surface). All run in the clean and the `--faulty` mode (data-layer.md §18.1).

| Id | Guards |
|---|---|
| a1 | **Same read set, same name and answer, from two devices.** Alice's laptop and phone, one definition, one evaluator, the same versions: each computes and publishes. Both answers have the same id, under `/alice/laptop/32=answer/<id>` and `/alice/phone/32=answer/<id>`, and results with equal digests; a third device (Bob's, in the folder) fetches either and gets the same `Answered`. |
| a2 | **A changed read set is a new name.** After one input version is added, the question resolves to a different id; the old answer still verifies under the old id, now old (`Age::Exact`, not the planned question's). |
| a3 | **The definition's version is bound.** A new version of the definition gives another id; the old answer is never returned for the new question; an old answer replayed for the new definition's name is not found. |
| a4 | **The evaluator's version is bound and matched exactly.** `/ndf/eval/v=1` and `v=2` give different ids; a program that knows only v=2, asked for v=1, answers `CannotCheck` (no policy trusting a signer); v=2's answer is not accepted for v=1. |
| a5 | **A wrong answer from a signer is detected on recompute and raised as evidence.** One of Alice's devices signs a wrong result at the right id; her other device, which knows the evaluator, returns its own value, raises `AnswerEvidence` (kind `Mismatch`) naming the answer, the signer, the read-set digest and both result digests, keeps it across a restart, does not serve the wrong answer onward, and never takes it again. |
| a6 | **A reader without access to the read set can't read the answer.** Bob, outside the folder's audience, gets `Sealed` for the question (the same error `get` of the collection gives), cannot derive the id, and for the exact name, handed to him, gets the ciphertext and `Sealed`. The packet's bytes contain no collection name, field or result, and its name has no content word. |
| a7 | **Audience intersection.** An answer over collections A (Alice, Bob) and B (Alice, Carol) opens for Alice only: Bob and Carol each get `Sealed`; with an A-only answer, Bob opens it. |
| a8 | **The read set is inside the sealed content.** Scanning every packet of the answer (and its pieces) for the collection names, version names, frontiers and the evaluator's name finds none when anything read is sealed; they are all present when nothing is. |
| a9 | **Unknown evaluator.** A device without the evaluator: with the default policy and an answer from the person's own device, `Provenance::Trusted` naming the signer and counting unverified reads; with `Signers::None`, `CannotCheck` naming the evaluator and the next step; an answer from an untrusted signer, `CannotCheck`, never `Ok`. |
| a10 | **Fetching and computing give the same result (reader transparency).** The same question on a device that recomputes, on one that takes it from its store, and on one that fetches it from the network: equal `result`, `reads`, `binding`, `id`; and for a question over a sealed collection the device is outside of, over a rule it doesn't know, over a pruned read: the same error from all three. |
| a11 | **A member removed.** Bob is removed from A; a new answer over the new state has another id and Bob can't open it; the old answer, over versions written before, has the same id and Bob still opens it (forward only); after the epoch is erased, neither opens. |
| a12 | **Provider answers.** A provider function binds its function version and the inputs it read, no evaluator and no definition; a reader whose policy names the provider takes it (`Provenance::Provider`); one whose policy does not (or names another signer) is refused `NotProvider`; two different results by one provider at one name are `Equivocation` evidence. |
| a13 | **Unsigned work is not publishable.** An uncommitted local edit has no read; `provide` over an input not held verified is `BadRequest`; nothing named by it is served; after the commit (a `put`) the question plans over the new versions, has a new id and publishes under it. |
| a14 | **Durable before served.** An answer is not served or listed before the barrier; a provider killed after signing and before the barrier serves, after restart, the answer it signed or nothing, never another result at the name (both stores, as the durability cases). |
| a15 | **A signer's key revoked after publishing.** Holders refuse and stop serving the answer (`Untrusted`), caches drop it, a pure question recomputed gives the same result under another device's signature, and no cut revives the revoked answer. |
| a16 | **Read-set faults.** A read whose digest conflicts with a held version is refused `ReadSet` with evidence; a read set not canonical, a digest not matching, an epoch list too short or long are refused; a version withdrawn by a cut after the answer gives `ReadsChanged`, not evidence. |
| a17 | **Limits.** Over `READS_MAX` reads or `SEAL_EPOCHS_MAX` epochs is `TooLarge`; a budget exceeded is `OverBudget` and not a result; unsolicited forged answers are dropped without being stored; a signer's answers kept are capped; a provider answer that must be kept is refused with `Busy` rather than evicting one. |
| a18 | **Pieces.** A result of 200 KiB, sealed, is made, fetched in pieces and recomputed alike, equal across the three paths of a10, the pieces DigestSha256-verified and no custody asked. |
| a19 | `[PENDING F-QUESTIONS #1]` **No computation for a requester who cannot read.** A device asked for an answer by a requester outside the audience answers as a plain `get` of the first unreadable read would and computes nothing; a requester inside is answered within the rate. Written only if #1 is adopted. |
| unit | Canonical encoding and the digest: every read set round-trips and is independent of the order the reads were made in; two labels never collide; a decoder refuses an unknown TLV, a non-minimal length, an unsorted or repeated read; a keyed id differs for two audiences and agrees for two members; key derivation is order-fixed and gives the same bytes on two devices. |

c12's part 2 (a summary service) is rewritten as a provider answer over the note (a12, a6); its other parts stay.

## 15. Pending decisions

### `[PENDING F-QUESTIONS #1]` Asking a signer to compute

A reader may need an answer from a device that holds the data it does not (a phone asking the person's laptop; a person asking a provider, `summarize` over this note). Nothing in this spec makes a device compute for anyone but its own host: readers fetch by id from signers that have already made the answer, or recompute. The recommended addition, in `handoff-ndf-rs/F-QUESTIONS.md` #1, is a sealed ask, an Interest `<D>/32=ask-answer/<ParametersSha256Digest>` whose ApplicationParameters is an `AnswerAsk` (§11.2) sealed to the signer's seal key as an introduction ask is (data-layer.md §19.3), carrying the asker's proof (data-layer.md §13.2), answered by the signed answer packet wrapped as `32=held` wraps a packet, under the bounds of §13.2. The numbers `0x05DD`–`0x05DF` are held for it. Until the owner decides, none of it is implemented, `a19` is not written, and a device that wants an answer from another device waits for that device to publish it.

### `[PENDING F-QUESTIONS #2]` Policy as signed data

The policy (§9) is a value the host passes. The recommended addition is an owner-signed record, a field of the members record (or a record of its own), saying which devices provide which function for a folder and which signers its readers may trust for pure answers: a reader then takes it from the folder's data and no host decides alone. Until the owner decides the layer takes the host's value and the defaults of §9.

## 16. Cross-references to apply

The implementer applies these when the code lands; this spec edits none of them.

**data-layer.md**

- **Header / Status and Related:** name answers.md as the home of "functions' answers" (slice 8) and drop "named functions whose answers are sealed to their inputs' audience" from the not-yet list.
- **§2 (invariants):** add after 9: *10. Answers say what they read.* "An answer is immutable and named by the exact versions it read; a mismatch with a recomputation is evidence (answers.md)."
- **§3 (names):** the sentence "`get` also takes log entry and state names (§11), and entry and range names (§4.1, §5.4)" gains "answer and question names (answers.md §3.3, §7.1)".
- **§4.2 (durability):** add that an answer is served, announced and listed only behind the barrier like a log entry (answers.md §6.2), and that a provider keeps what it signed.
- **§8.1 (revocation cut), "What it refuses":** add "answers" to the packets a cut never lists, "summary roots, one-key heads, seal keys, grants, audit answers, an asker's proofs, answers".
- **§9 (seal):** a bullet "Answers": sealed under the audience key derived from the epoch keys of the read set (answers.md §5); erasure of an epoch's key erases the answers that read in it; "What a relay sees" gains an answer's name, kind, ciphertext size and epoch list.
- **§11 (state names):** a sentence that a state read by an answer is bound by the digests of its tips and by the applied-set digest (answers.md §3.1).
- **§13.1:** the sentence on pieces gains "or an answer's body (answers.md §5.4), under the answer's name; no custody applies to answers".
- **§13.5 (what a device serves):** add the answers it holds verified, as the packets as signed, never one of a key it holds evidence against, or that a revocation refuses, or one it cannot keep (answers.md §6.2, §8.2).
- **§14:** an answer has no keep; devices drop held answers by their quota (answers.md §10).
- **§15 (verbs):** replace "A function's answer is a `get` on its name (a later slice)" with the two `get` forms of answers.md §7.1, add `get(answer name)` and `get(question name)` bullets, name `Got::Answer`, the new `DataError` variants `CannotCheck` and `Answer` and `NextStep::SetPolicy` (answers.md §12), and the host surface `Device::answer_id`, `publish_answer`, `provide` (SHAPES-R5 §F).
- **§16.1 (names):** table rows for answer, piece of an answer, question (answers.md §11.1) and the parse rules for them; the piece-name rule gains "or an answer's name".
- **§16.2:** one paragraph: "Round 5 adds 0x05C0–0x05DF for answers (answers.md §11.2); every number is odd."
- **§17.1:** an answer asked for by id is an owed fetch (`FETCH_TRIES` per candidate, `RELAYS_ASKED` candidates).
- **§18 (conformance):** list a1–a18 (a19 when #1 lands) and state that c12 is rewritten to the F surface.
- **§20:** none; answers use the gate's definition of a member only for the default policy (answers.md §9).
- **D's section (device-wide events):** add the `AnswerEvidence` event (SHAPES-R5 §F, §8.2 of answers.md).

**README.md**

- *Other specifications* table, a row: `| [answers.md](answers.md) | Answers: named, checkable readings over signed data; pure answers (recomputed by any holder of the definition and the inputs) and provider answers (trusted by the provider's authority); the read set, its canonical bytes and digest, the binding, the keyed answer id, the name `<D>/32=answer/<id>`, sealing to the audience intersection of what was read, evaluators named and versioned like merge rules, the verb (`get` of an exact name or a question), recompute-or-trust, evidence, policy, threat notes; TLV 0x05C0–0x05DF |`
- *TLV-TYPE numbers* table, a row after the `0x05B0–0x05BF` one: `| 0x05C0–0x05DF | [answers.md](answers.md) §11.2 (odd numbers only: every field of an answer is critical. AnswerRecord 0x05C1, AnswerKind 0x05C3, AnswerBody 0x05C5, AnswerBinding 0x05C7, AnswerBy 0x05C9, ReadSet 0x05CB, ReadVersion 0x05CD, ReadState 0x05CF, Result 0x05D1, AnswerSealed 0x05D3, AnswerAsk 0x05D5, and two records of the device's event store, AnswerEvidence 0x05D7, AnswerFault 0x05D9, FaultKind 0x05DB; 0x05DD–0x05DF held for the ask exchange, answers.md §15) |`
- *Name-component types*: no new type; the keyword components `32=answer` and `32=question` are of the layer's own (data-layer.md §16.1).

---

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
