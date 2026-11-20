# Answers: named, checkable readings over signed data

- **Status:** Built (round 5, item F; ndn-rs `ndn-data`, ndn-sim cases `a1`–`a18`; round 8 adds the ask exchange of §15 and the cases `a19`–`a22`; round 11 adds the refusal reason `EvaluatorRefused` and the case `a23`). The two decisions that were open are settled by the owner (2026-11-19): asking another device for an answer is built as the sealed ask exchange of §15 (F-QUESTIONS #1, option (a)), and the policy of §9 stays a value the host passes (#2, option (a)), to be revisited when the first provider is deployed.
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
| question | A name `<X>/32=question/<AnswerAsk>` that `get` takes (§7.1). Local as a name: never sent, like a state name (data-layer.md §11); the `AnswerAsk` it holds travels only inside the sealed body of an ask (§15.2). |
| ask | The sealed Interest `<D>/32=ask-answer/<ParametersSha256Digest>` by which a reader asks a signer for the answer to a question, carrying the asker's proof (§15). |
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

**Resources.** An evaluation is bounded by the host's budget (§10: reads, octets read, result octets, time). A budget the evaluation exceeds is no result: `OverBudget` (§12), never a different result. A call of `Reads::current` is spent from the reads budget like a read of a distinct version or state, whether or not it finds anything new, so a plan cannot call it over and over for nothing. The evaluate phase is host code over up to `READS_MAX` reads: it runs off the executor and within `Budget::time` of wall-clock time, past which it is abandoned (it may check `ReadView::cancelled` between its steps to stop early) and refused `OverBudget`; the clock only ever makes a refusal (§13.10). Budgets bound availability, never answers: two devices with different budgets answer the same or one of them answers `OverBudget`.

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

**An exact name of a sealed answer, as built.** The `SealEpoch` list of an answer names epochs, not collections, so a device that is handed an exact name and holds no key of an epoch in it has no collection to ask a grant for: it answers `Sealed`. A device asks for keys by reading: a question is planned, so its reads chase the keys (§7.2), and a device that read the collections first holds them and opens the exact name.

### 5.3 What is sealed, and what is clear

When the read set has an epoch, the signer encrypts the **plaintext `AnswerBody`, padded as below,** with ChaCha20-Poly1305 under `seal_key`, a random 96-bit nonce and as associated data the octets of `"ndn-answer/1 aad\0"`, the answer's own name as a Name TLV, the `AnswerKind` octet and the `SealEpoch*` list `E`; `Ciphertext` is `nonce ‖ tag ‖ ciphertext` as in data-layer.md §9. Binding the name, the kind and the epochs to the ciphertext means none of them can be changed, moved to another name, or replayed under another signer's name by a holder without breaking it (they are also signed; the AEAD makes a holder who cannot sign unable to splice). A payload that does not open under the key is refused as `BadSignature`, as for a version.

In the clear, in a sealed answer: the Data name (`D`, `32=answer`, 32 octets); the kind; the epoch list; the ciphertext's size; the signature and the signer's key name. Inside the ciphertext: the binding (definition, evaluator or function name, read-set digest), the read set (every collection read, versions, frontiers, digests, the merge rule), and the result. In an unsealed answer all of it is in the clear, as the data it was made from is.

**Padding.** The plaintext that is sealed is the `AnswerBody` followed by one `AnswerPadding` (0x05DD) of zero octets, which makes the plaintext `padded_len(n)` octets for a body of `n` octets: the least size `s ≥ n` that is a bucket and either is `n` or leaves room for an `AnswerPadding` element (a TLV of at least 4 octets, so none of 1 to 3 octets; the length field's width makes none of 257 or 258 octets, and none of 65,542 or 65,543 either). Buckets are the multiples of 128 up to 1,024 and above that the multiples of `2^(⌊log₂ s⌋−3)`, which is at most an eighth of `s`. A body for which the least bucket would leave a gap that no element fills goes to the next bucket. Padding is only in sealed answers, and a sealed answer in pieces (§5.4) carries the padded plaintext's ciphertext as it carries any other. The size of the packet then is the bucket, the 28 octets of nonce and tag, and what is constant or already in the clear (the name, the kind, the epoch list, the signature), so answers of one signer over the same epochs whose bodies are in one bucket are packets of one size. A reader that opens a sealed answer MUST refuse, as `Malformed` and saying so, a plaintext whose `AnswerBody` is not followed by exactly the padding its length is due: none where some is due, one where none is, a length other than the one due or not in its minimal encoding, a non-zero octet, anything else after the body (a second `AnswerPadding` included), or an `AnswerPadding` before it. The AEAD tag covers the padding and the signature covers the ciphertext, so no relay can change it unnoticed; the rule exists so that a signer cannot use the padding to carry anything, and so that an answer has exactly one valid plaintext.

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
- **A signer asked to compute** (§15) for a read set the requester cannot read MUST tell the requester no more than a plain `get` of the first read it may not read would, in canonical order (`NotAudience` with that read's index, §15.6), and only after the requester authenticated: an ask that does not authenticate gets no reply at all (§15.5). It MUST NOT compute (§13.2).
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

A device **never publishes without being told to**: whether a device publishes what it computed is the host's configuration (§10), never a consequence of a `get`. The one other thing that makes a device sign an answer is an authenticated ask it serves (§15.4, §15.7): `AnswerConfig::serve_asks` is the host's choice, and `Off` stops it.

## 7. Getting an answer

The seven verbs stay seven: an answer is read with `get`, as data-layer.md §15 has always said ("a function's answer is a `get` on its name").

### 7.1 Questions and exact names

`get` takes two names of answers, and answers `Got::Answer` (§7.4) to both:

- **An exact name** `<D>/32=answer/<id>` (§3.3): the answer with that id by `D`, when its reader has the id from somewhere (another answer's listing, a link, a snapshot's note, a host). The result has `Age::Exact`.
- **A question** `<X>/32=question/<AnswerAsk>`, one GenericNameComponent whose value is exactly one `AnswerAsk` TLV (§11.2), nothing else, at most `QUESTION_MAX` (65,536) octets. It names *what is asked*, not which signer answers, and is never sent as a name: like a state name it is local (data-layer.md §11); the `AnswerAsk` it holds is what an ask carries, sealed, to a signer (§15). A question has the `AnswerAsk`'s:
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
   - the **candidate signers**: for a pure answer, the devices its policy trusts that this device knows (the devices of its own namespace known to write into it, at most `RELAYS_ASKED`, and the devices the policy lists by name, `Signers::Devices`); for a provider answer, the devices its policy names as providers of the function. Each candidate `D` is asked for `<D>/32=answer/<id>`, and, by the device that holds it, `<H>/32=held/<Name TLV>` (data-layer.md §13.5). Asks are owed fetches (data-layer.md §17.1: at most `FETCH_TRIES` per candidate, each tried in turn, a capped backoff), and a fetch by name **never makes a device compute**: asking a device for an answer it has not made makes no work for it (§13.2). A pure question whose evaluator is known and `Check` is `Recompute` (§7.3) does not wait for them, and never asks: it recomputes. When no candidate has the answer published, and only then, the reader may send each candidate signer the **ask** of §15, in this step's order: the one request that can make a device work, bound as §13.2 says (§15.9).
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

When a reader takes an answer on trust it MAY not hold every read. It MUST check each read it does hold (digest, rule, applied set) and refuse the answer on a conflict (§7.3.1), and it MUST count the reads it did not hold into `unverified_reads`. It does not fetch them: fetching all would be the recomputation's cost without its check. A host that wants every read checked sets `Check::Recompute`. The check is bounded (§10, §13.10): a read set that lists more than `STATE_READS_CHECKED_MAX` reads of merge states is refused whole (`Answer` / `TooManyStates`), and a check that runs past `Budget::time` is abandoned and refused (`Answer` / `OverBudget`); neither is ever trust.

#### 7.3.3 Checks of every answer

Before anything of an answer is used, in this order, a reader:

1. verifies its signature by its trust context as a log entry is verified (data-layer.md §4: the key locator names a key of `D`, the context governing `D`, the chain; a revoked key or issuer **refuses it** whatever it carries, §13.9), and refuses it when the key is **marked suspected** on this device (data-layer.md §8, `Device::suspect`: no new entry of such a key is taken, and nor is an answer, until the mark ends by `unsuspect` or by a revocation). `Answer` / `Untrusted` or `BadSignature`;
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

An answer is immutable and cannot be stale: `Age::Exact` for an exact name and for a question that states its read set. For a **planned** question the answer is the newest this device can make: `Age::Newest { unconfirmed_for }` where `unconfirmed_for` is the **greatest** `unconfirmed_for` among the ages of the collections its plan read (data-layer.md §15: the time since the device last knew nothing newer was outstanding there, on its monotonic clock), so a reader is told how old the input it relied on may be. An answer another device made for an ask that left the reads to it is `Age::Newest` too, with the largest `unconfirmed_for` this device reports: it is over the reads the signer chose, and nothing here confirmed them (§15.9). No answer ever uses a date.

## 8. Evidence

### 8.1 What counts

Evidence is a **verified** signed answer (it passed §7.3.3 steps 1 to 4) together with what contradicts it. Five kinds:

| Kind | Definition |
|---|---|
| `Mismatch` | A reader that knows the evaluator recomputed the read set and got a result with a different digest than a signed answer's. Evidence: the signed answer, its signer, the id, the read-set digest, both result digests, the evaluator. |
| `Equivocation` | **Two verified answers at one name, by one key, whose opened results have different digests.** A name has one result (§2.1). Two packets that open to the same result (a sealed answer made twice has different nonces and so different bytes) are not equivocation. A device that cannot open an answer cannot tell. |
| `Conflict` | Two verified answers with **one id**, by **two signers** a reader's policy trusts, with different results, where the reader cannot recompute (§7.3). A reader that can recompute has `Mismatch` for whichever is wrong. As built, the reader keeps the second as evidence and returns no result: the error is `Answer` / `Equivocal`. |
| `Binding` | A signed answer whose content does not give the id in its name (§3.4): the signer put a binding in a name that is not its. |
| `ReadSet` | A signed answer whose read set is not canonical, whose digest is not the binding's, whose epoch list is not its reads', or that conflicts with a version the reader holds (§7.3.1), or whose reads are not the reads the evaluator makes (§7.3, 1). **Not** when the version the read concerns has **equivocation evidence** here (its writer signed two packets at that name: the signer may have read the other one, and the writer is the one at fault), nor when a read no longer holds here (§7.3.1): the reads are classified before the epoch list, since a version withdrawn since can change the epochs a state is computed from. |

The first reader to find it keeps it (below); another that holds the same two packets finds the same. A signer cannot bind one name to two results without leaving both signed packets in the hands of whoever served them: that is the evidence. Evidence is **against a key**, not a device: a thief's answer signed by a stolen key before the key was revoked is evidence against that key, and the owner revokes it (data-layer.md §8.1).

### 8.2 What a device does with it

- It **keeps** the evidence before reporting it: the answer packet(s) whole, stored (ndn-data: under `/localhost/ndn-data/answer-evidence/<digest of the answer's name and the kind>/<implicit digest>`, the packet behind one octet that says why it is kept: 0 the signed packets alone show it, 1 what this device holds decides it, below), so it survives a restart and a later watch lists it (as equivocation of versions is kept, data-layer.md §4).
- It **reports** it as the device-wide event `AnswerEvidence` (SHAPES-R5 §D, device-wide events; the variant is specified in SHAPES-R5 §F), once, with the answer's full name, its signer key, the id, the read-set digest, and the kind with its result digests (§3.4: keyed, so an event that reaches a device outside the audience confirms no guess of a result). Evidence carries the **whole signed packet** too, so another device in the audience can check it from the packet alone.
- It **never serves** an answer it holds evidence of, and **never takes it again**: a later `get` that meets the same packet or the same signer's answer at the same name is not used (`Answer` / `Equivocal` for the second and later of two at one name; a mismatching answer is refused), until the host or owner decides. A device that finds evidence MUST NOT drop the signer from its policy by itself: the owner decides, the host sees the event.
- **Evidence of what this device holds can end.** Two kinds rest on what this device holds, not on the signed packets alone: a read whose digest differs from the version held (`HeldConflict`) and an epoch list that differs from the epochs of the reads held (`Epochs`). When the answer is met again it is judged afresh (the whole of §7.3.3); if it no longer yields the fault (the version read is withdrawn since, its writer's equivocation is now held, the reads are no longer held at all) the evidence is **lifted**: removed from the store, so a restart does not bring it back, and the answer is judged as any other, including a refusal that is no fault (`ReadsChanged`). While the fault stands the answer is refused as blocked (`Equivocal`) and not told again. The event already told stays until acknowledged. Evidence the signed packets alone show (two results at a name, a binding that is not the name's, a read set that is not canonical, a mismatch with a recomputation, two signers that disagree) never ends.
- It **never lists a result** of evidence to a device that cannot open it.
- It **never raises evidence against an answer it signed itself.** A pure answer this device signed is reproducible. When a recomputation under the evaluator of the same name and version gives another result than the stored one (a host upgrade that changed the output without renaming the evaluator), that is no fault of any key: the stored answer is **dropped**, not kept as evidence, nothing is blocked, no event is raised, and the recomputed value stands (the next `publish_answer`, or `Publish::Computed`, signs it). A copy of such an old answer that reaches this device from elsewhere is refused (`Untrusted`), likewise without evidence. Renaming the evaluator on every change of meaning (§4.1) stays the rule; this only keeps a missed rename from blocking a name for good.

Evidence is **forward only**: an answer already used was used. The event tells the host which results to distrust.

## 9. Policy

Policy says **which signers a reader trusts without recomputing**, and **which devices are the providers of which function**. It is data the host holds and passes (`AnswerPolicy`), never something the layer infers from the answers it meets, and never part of an answer. The defaults are computed from signed records the device already holds.

- **Pure signers.** The default is `Signers::OwnAndMembers`: a signer `S` is trusted for a pure answer when its device is of **this device's own namespace** (a device of the person, data-layer.md §3: the namespace of the trust context governing it, the same as this device's), or when it is a **writer** of every collection in the answer's read set by the record in force over each, held here: a writer prefix the record lists covers its key (a key kept only by a cut does not), and no context held revokes the key (the revocation test of data-layer.md §20), the folder's record for a collection that inherits it. **A member who only reads is not a writer:** the audience of a collection (its readers, and the device that began its epoch) holds the keys to every epoch and can derive the audience key and the keyed id of any answer over it, but it could not have changed what the answer read, so being able to open an answer is no reason to trust one it signed. A host that trusts a reader-only collaborator lists the device (`Signers::Devices`). A collection whose record is not held here makes the second test fail: the reader does not guess. Other values: `Signers::None` (trust nobody: recompute or `CannotCheck`), `Signers::Own`, `Signers::Devices(names)` (the listed device names and namespaces).
- **Providers.** `providers: Vec<(function name, Signers)>`. No default: a provider answer is refused unless a policy entry names its function, by exact name, and the signer is covered by that entry's device names (a device name matches itself and, as a prefix, the devices under it). A host that wants "the person's own devices provide function F" says so.
- **Check.** `Check::Recompute` for every known evaluator unless the policy lists it in `trust` (evaluators for which this host takes a trusted signer's answer without recomputing): an explicit, per-evaluator, per-host choice for evaluators whose recomputation is costly. It is never inferred.
- **The default is a choice made with eyes open.** Under the default, an answer signed by one of the person's own devices under an evaluator this program does not know is taken as `Trusted`, because the person's devices are the person (data-layer.md §3). A host that refuses that sets `Signers::None`.
- **Policy lives in data, and the host holds it.** The layer takes a value; where the host keeps it (a collection it reads, the person's settings) is the host's. By the owner's decision of 2026-11-19 the layer defines no signed record of its own for it: nothing in a folder says who its providers are, each host decides, and two members of a folder may trust different providers. The owner revisits this at the first deployment of a real provider (a summary service), because that is when a folder needs to say who its providers are; the shapes that were weighed, a field of the members record or a record of its own, are in `handoff-ndf-rs/F-QUESTIONS.md` #2. The same value says whom a reader **asks** for an answer nothing published: the signers it names, in the order of §7.2 step 5 (§15.9).

Policy is read at the moment an answer is used and never cached across a change of the records it is computed from (a member removed stops being trusted at the next question once the record is held).

## 10. Limits

| Name | Value | Meaning |
|---|---|---|
| `READS_MAX` | 65,536 | Reads in one read set. |
| `SEAL_EPOCHS_MAX` | 256 | Distinct epochs in one read set. |
| `PAYLOAD_MAX` | 67,108,864 | Octets of an `AnswerBody` or its ciphertext (data-layer.md §13.1). |
| `INLINE_MAX` | 6,144 | Octets of an answer carried in one packet (data-layer.md §4.1). |
| `QUESTION_MAX` | 65,536 | Octets of an `AnswerAsk`. |
| Budget (host) | reads 65,536; octets read `PAYLOAD_MAX`; result octets `PAYLOAD_MAX`; time 10 s | What one evaluation may spend (`Budget`): reads of distinct versions and states and calls of `Reads::current`, octets read, octets of the result, and wall-clock time to evaluate and to check the reads of a signed answer; exceeded is `OverBudget`, never a different result. |
| `STATE_READS_CHECKED_MAX` | 1,024 | Reads of merge states a signed answer may list for this device to check (§7.3.2): each is a replay of the collection's merge up to the frontier the signer chose. Measured in release, per read: 3.6 µs (8 versions held in the collection, newest frontier) and 9.9 µs (a frontier in its past); 28 µs and 0.40 ms (64 versions); 0.21 ms and 24 ms (512 versions): the cost of a past frontier grows about with the square of the versions held. A set of 65,536 reads of states not held here costs 0.37 µs a read (24 ms in all). More than the cap is refused whole (`TooManyStates`); the time budget bounds the sum whatever the collections hold. |
| Held answers (host) | per signer 1,024 answers and 64 MiB; all 1 GiB | What a device keeps of others' answers (`AnswerStore`); past it, the oldest not-recently-asked of a signer is dropped first, never one it signed that is not reproducible (§6.2). |
| Answers signed (host) | 16 per second per device | A limit on a device's own signing (a flood of its own questions). |
| `EVIDENCE_PER_SIGNER_ANSWERS` | 64 | Answer names a device keeps evidence at against one signer (§8.2): past it the oldest evidence of that signer is dropped, and with it its block. |
| `EVIDENCE_PER_SIGNER_BYTES` | 262,144 (256 KiB) | Octets of evidence packets kept against one signer; the oldest is dropped first. |
| `EVIDENCE_SIGNERS` | 256 | Signers a device keeps evidence against: past it, all the evidence of the signer whose newest is oldest is dropped. At most 256 × 256 KiB = 64 MiB of evidence is kept in all. |
| `EVIDENCE_PACKETS_PER_ANSWER` | 8 | Packets kept at one answer name of one signer: past it the block stands and the event still carries the packet, but no more is stored. |
| Fetches | `FETCH_TRIES` per candidate; at most `RELAYS_ASKED` (8) candidates | As §7.2 step 5 and data-layer.md §17.1. |
| Asks served (host) | per asker 1 in progress; `asks_at_once` (default 4, at least 1) for all askers together, of which other namespaces take at most half and one other namespace at most half of that (at least 1) | `Busy` beyond any (§15.7). `retry_after` is 1 s. |
| Asks held while opened (host) | `asks_queued` (default 32); their proofs are verified `Config::asks_verifying` (default 8) at a time, on a budget of their own | Past it the ask gets no reply (§15.4 step 1). |
| Signing for asks (host) | half of `sign_per_second` (default 16), rounded up, apart from the device's own | `Busy` beyond it (§15.7). |
| State reads in an ask (host) | `STATE_READS_CHECKED_MAX` (1,024) | `OverBudget` beyond it (§15.7). |
| Provider asks queued (host) | 64 distinct calls | Calls awaiting the host on `Device::provider_asks` (§15.10); the same call waits once, and is delivered again after `Budget::time` without a result; one more distinct call is `NotProvided`. |
| Asks sent (asker) | at most 3 attempts per signer on `Busy` or `Pending`, each waiting the stated `retry_after` (at most 10 s); at most 3 sends of one ask when nothing replies | §15.9. |
| Where checks and evaluations run (host) | `inline_work` (default `false`: the runtime's blocking pool) | A simulation on a paused clock sets it, so the work runs on the executor's thread and a run replays exactly: a pool thread's finishing is an event of real time that lands among the tasks ready meanwhile. It changes no result and no bound (`Budget::time` still stops the work at its own checks). |

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
| ask for an answer | Interest `<D>/32=ask-answer/<ParametersSha256Digest>`, ApplicationParameters `AnswerAskEnvelope`; the reply is Data of this exact name, FreshnessPeriod 0 (§15) | device key of `D` (the reply) |
| seal key | `<D>/32=seal/<public key>` (data-layer.md §9, §16.1); also served for `<D>/32=seal` with CanBePrefix (§15.8) | device key |

Every name parses one way, and a reader MUST refuse one that does not:

- **Answer.** `D` is the components before the first `32=answer` (`D` is a device name: no keyword, no digest component, data-layer.md §3); exactly one GenericNameComponent of 32 octets follows, the id, and nothing else.
- **Piece of an answer.** The last component is `seg=<i>` (a SegmentNameComponent), the next-to-last `32=manifest` for a manifest node; what precedes is an answer name. This extends the parse of a piece name (§16.1, §13.1 of data-layer.md), whose `V` is a log entry name, to an answer name.
- **Question.** `32=question` is the next-to-last component; `X` precedes it; the last is one GenericNameComponent whose value is exactly one `AnswerAsk` TLV. For a pure `AnswerAsk`, `X` is a collection name (§3 of data-layer.md) and equals the collection of the definition read; for a provider, `X` is a device name.
- **Ask.** `D` is the components before the first `32=ask-answer`, a device name; exactly one ParametersSha256DigestComponent of 32 octets follows, the SHA-256 of the Interest's ApplicationParameters TLV, whose value is one `AnswerAskEnvelope` (§15.2); nothing else. A name whose digest is not that of its parameters is no ask and gets no reply (§15.5).

### 11.2 TLV-TYPE numbers

Answers use `0x05C0`–`0x05DF`, registered in [README.md](README.md#tlv-type-numbers). **Every number of a field of an answer is odd**, because every field changes what an answer means: a reader that passes over a `ReadState` field would check an answer against less than it read, one that passes over `Digest` of a read would accept bytes it did not read, one that passes over an `AnswerKind` would judge a provider answer as a pure one. A decoder MUST refuse an unknown TLV in these records, so a reader that does not know a field cannot decode, check or use an answer that carries it; it drops it as a packet it cannot read (data-layer.md §16.2, §17) and asks the next source, and a question that no source can answer for that reason ends `Unavailable`. The two numbers of the ask exchange, `0x05DE` and `0x05DF`, are even: each is the whole value of one message (an Interest's parameters, a reply's Content) and no field of an answer, and a decoder of either refuses an unknown TLV inside it (§15.2, §15.6), so an even number makes nothing skippable.

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
| 0x05D3 | AnswerSealed | SealEpoch+ (0x056E), ascending (§5.1), at most `SEAL_EPOCHS_MAX`; then [Ciphertext (0x0574): the AnswerBody and its AnswerPadding, §5.3] |
| 0x05D5 | AnswerAsk | AnswerKind, [ReadVersion \| ReadState] (the definition, pure), AnswerBy, [ReadSet] (the read set the asker states, §7.1); in a question name, and inside the sealed body of an ask (§15.2); never on a packet a device signs |
| 0x05D7 | AnswerEvidence | Name (the answer's full name), Name (the signer's key), Digest (the id), Digest (the read-set digest), AnswerFault; a record of the device's own event store (§8.2), never on a packet |
| 0x05D9 | AnswerFault | FaultKind, then by kind: 0 `Mismatch`: Digest (signed result), Digest (recomputed), AnswerBy; 1 `Equivocation`: Digest (the other result); 2 `Conflict`: Name (the other answer), Name (the other signer's key), Digest (its result); 3 `Binding`: nothing; 4 to 8 `ReadSet`, nothing more: 4 not canonical, 5 digest not the binding's, 6 epochs not the reads', 7 conflicts with a version held, 8 not the evaluator's reads |
| 0x05DB | FaultKind | NonNegativeInteger, 0–8 as above |
| 0x05DD | AnswerPadding | zero octets; only in a sealed answer's plaintext, once, after the AnswerBody, of exactly the length §5.3 gives |
| 0x05DE | AnswerAskEnvelope | EphemeralKey (0x057C, 32 octets), Ciphertext (0x0574, the content key wrapped to the signer's seal key), Ciphertext (0x0574, the sealed `AnswerAskBody`). An ask Interest's ApplicationParameters (§15.2) |
| 0x05DF | AnswerAskRefusal | reason code (1 octet, 1 to 8), number (8 octets, big-endian), explanation (UTF-8, to the end). A reply's Content (§15.6) |

`Digest` (0x055E), `Frontier` (0x0522), `FrontierEntry` (0x0524), `Rule` (0x0548), `SealEpoch` (0x056E), `Ciphertext` (0x0574), `EphemeralKey` (0x057C), `Chunks` (0x0521), `Size` (0x0523) are reused as data-layer.md §16.2 defines them. Names are the Name TLV (0x07). Inside a record fields appear in the order the table lists them; lists are sorted as stated, so equal content encodes to equal bytes and equal digests. `AnswerEvidence` and `AnswerFault` are records of the device-wide event store (SHAPES-R5 §D.4: `/localhost/ndn-data/events/`), local to that store and never served; D's own event records use `0x05E0`–`0x05FE`, so the two blocks do not meet.

Round 5's other items add their own numbers elsewhere; answers add no name-component type.

### 11.3 Cryptography

Every primitive is an audited crate the layer already uses: SHA-256, HKDF-SHA256 (RFC 5869), HMAC-SHA256, ChaCha20-Poly1305, Ed25519 (the device key's signature). No primitive is new, and no key is made, stored or granted for answers: the audience key is derived from epoch keys the layer already holds. Labels are ASCII, each ending in a zero octet so none is a prefix of another: `ndn-answer/1 readset\0`, `ndn-answer/1 applied\0`, `ndn-answer/1 id\0`, `ndn-answer/1 result\0`, `ndn-answer/1 seal\0`, `ndn-answer/1 name\0`, `ndn-answer/1 aad\0`. A digest made for one purpose never verifies as another's, whatever its fields.

The ask exchange (§15) uses the primitives of an introduction's ask (data-layer.md §19.3) and nothing else: an X25519 wrap of a content key to the signer's seal key, ChaCha20-Poly1305, SHA-256 and the device keys' signatures. It is the one place a key is made for answers: a fresh content key and a fresh ephemeral X25519 key for each ask, which nobody keeps after it. Its proof's binding opens with the label `ndn-data answer ask\0` of the asker's proofs (data-layer.md §16.1).

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
| ↳ `Equivocal` | Evidence is kept against the answer at this name: its result differs from another answer's at this name by this key (§8.1), from a recomputation (a mismatching answer is refused, §8.2), or two trusted signers disagree and the reader cannot recompute. Never served, never taken again | `AskOwner` |
| ↳ `TooLarge { what, size, limit }` | More reads, epochs or octets than §10 allows | `FixRequest` |
| ↳ `OverBudget { what }` | An evaluation would exceed the host's budget (§4.1, §10): reads (calls of `current` included), octets read, result octets, or the time to evaluate or to check the reads of a signed answer | `FixLocal` |
| ↳ `TooManyStates { states, limit }` | A signed answer lists more reads of merge states than this device checks (§10): it is not used; ask its signer for fewer, or ask the question so that this device recomputes it | `FixRequest` |
| ↳ `Busy` | A provider answer that must be kept cannot be (§6.2) | `FixLocal` |
| ↳ `AlreadySigned` | This device already signed a different result at this name (§6.2): it serves that one, and signs no other | `None` |
| ↳ `AskRefused { signer, why: AskRefusal, said }` | A signer that authenticated this device's ask refused it (§15.6): `why` is its reason (`NotAudience`, `Busy`, `Pending`, `CannotCheck`, `NotProvided`, `OverBudget`, `NotServed`, `EvaluatorRefused`), `said` the fixed text of that reason (`AskRefusal::explain`: why, and what to do; the explanation the signer wrote is not shown, §15.9), except for `EvaluatorRefused`, whose `said` is the evaluator's own reason, cleaned and quoted by this device (`AnswerAskRefusal::said`, §15.9) | by reason: `NotAudience` `AskOwner`; `Busy`, `Pending` `RetryLater`; `CannotCheck`, `NotProvided`, `NotServed` `SetPolicy`; `OverBudget`, `EvaluatorRefused` `FixRequest` |
| `Sealed { name }` | Not in the audience of a sealed collection read, or of the answer (§5.2, §5.6) | `AskOwner` |
| `NotReady { name, why }` | A key, a record or a walk is awaited (§5.2) | `RetryLater` |
| `BadRequest { name, why }` | A stated read set is not canonical or not held, the definition is not among the reads, a function is given an input it does not hold verified (§6.1), a stated read set is not the evaluator's reads, or the evaluator refuses its definition or inputs (its reason in `why`) | `FixRequest` |
| `BadName { name, why }` | The question's or answer's name is malformed (§7.1, §11.1) | `FixName` |

`NextStep` gains `SetPolicy`: "change the host's answer policy, or ask the person who sets it" (a signer to name for a function). `DataError::next` and `DataError::retry` gain the arms above.

An ask that no signer replies to is `Unavailable`, and a signer whose seal key this device cannot obtain is `NotReady` (§15.8, §15.9). `retry()` is true for an `AskRefused` of `Busy` or `Pending`.

## 13. Threat notes

### 13.1 Name binding: can a signer bind one name to two results?

It can try, and it leaves evidence. A name is `<D>/32=answer/<id>`; the id binds the definition's version, the evaluator or function, and the digest of every read. Two different results at that name by the same key are **equivocation** (§8.1) and are routed to events (§8.2). A holder in the audience sees it when it holds both. A holder outside it sees two ciphertexts it cannot tell apart from one answer made twice (nonces differ) and cannot judge: it relays both, and the first reader inside the audience that holds both reports it. A signer that wants to give two readers two results can: each sees one packet. A reader that recomputes (pure) catches it alone; a reader that trusts a provider (provider kind) catches it only when both packets reach it, which is why provider answers MUST carry in their read set whatever tells two calls apart (§4.2) and why a provider MUST keep what it signed (§6.2). Providers are trusted on exactly this: that they sign one result per name.

### 13.2 The ask oracle: cost and access

A device that works on request is a cost oracle and an access oracle. A fetch by name never makes a device compute: a device asked for `<D>/32=answer/<id>` or `<H>/32=held/…` for an answer it does not hold makes no answer (§7.2 step 5). The one request that can make a device work for a remote requester is the ask of §15, and it MUST be bound by these four things, each a check the signer makes before it spends what the next would cost:

1. **The requester is authenticated by a proof (§15.3), and is of a namespace this device serves.** An ask whose proof does not verify as a key of the asker's device, for this signer, this question and this envelope, that claims a device of a namespace the signer does not serve (`serve_asks`, §15.7), or that arrives while the signer already holds `asks_queued` asks being opened, gets no reply at all (§15.5). The cost such an ask puts on the signer is bounded: the signer holds at most `asks_queued` of them while it opens the envelope and verifies the proof, verifies at most `Config::asks_verifying` at a time on a budget of its own (a crowd of them slows no introduction, hold ask or audit ask) and within the Interest's lifetime, and it reads the claimed asker from the proof's KeyLocator first and **fetches no certificate for a device of a namespace it does not serve**. No read, no computation, no answer.
2. **The audience is checked before anything is computed (§15.4).** The signer judges, by the members records it holds, that the asker is of the audience of **every** read of the set, at the epochs read, and answers a requester outside it `NotAudience` with the index of the first read it may not read, in canonical order (§5.6), never computing. When the asker states the read set, the check precedes every read the signer fetches and is made **again once the reads are held**, on the reads the signer computes from, since the records of a collection it had not synced are held only after the fetch; a read whose version or records are not held is never admitted (`Pending`), for the record in force is no stand-in for an epoch not held. When the asker leaves the reads to be planned, the definition is judged first, the evaluator's plan, which makes the reads and never the result, runs next within `Budget::time`, the planned set is judged, and the question is computed **stating that set**, so the set judged is the set computed. The check holds the device's state lock one read at a time, runs off the executor within `Budget::time`, and refuses an ask that lists more than `STATE_READS_CHECKED_MAX` reads of merge states.
3. **Caps and rates (§15.7).** One ask in progress per asking device; `asks_at_once` for all askers together, of which devices of other namespaces take at most half and one such namespace at most half of that, so a collaborator who enrols many keys cannot keep the person's own devices waiting; planning and computing each end at `Budget::time` (§10) and give the caps back; signing for asks has a rate of half of `sign_per_second`, apart from the signer's own. Beyond a cap or a rate the ask is refused `Busy`. No other rate is specified.
4. **The answer is the one a holder in the audience gets (§15.5).** The reply is the signed answer packet unchanged, sealed under the audience key when anything read is sealed, or a refusal that carries a code, a number and a fixed explanation. Nothing is added to the answer: no plaintext about the reads, and no result in a refusal.

A provider's function is computed by the signer's **host**, never by the layer: the layer hands the call to the host (§15.10) only for an authenticated asker of the audience of every input, when it holds no answer for it, and the host's result becomes a signed answer through `Device::provide` under §6.2 and §8.

- **Timing and size.** A refusal for lack of access happens before any evaluation of a result and, for stated reads, before any read of the data and before any network traffic of the signer's (§5.6). The size of a sealed answer is visible (§13.3).

### 13.3 Access leaks

| What | Leaks? |
|---|---|
| The name | No. A device name, a keyword and 32 octets; no content word. The id of a sealed answer is keyed by the audience key, so a device outside the audience cannot compute it, test a guess of a binding, or enumerate answers (§3.2). |
| The read set | Not outside the audience when anything read is sealed: it is inside the ciphertext (§5.3). An answer whose reads are all unsealed has its read set in the clear, as the data it read is. |
| The result | No, same. The result digest in evidence is keyed (§3.4). |
| Size | **The bucket of the body, not its length.** A sealed answer's plaintext is padded to a size bucket (§5.3), so the packet's size tells a relay which bucket the body (binding, read set and result together) is in, and so not how many reads it has: two answers of one signer over the same epochs are packets of one size when their bodies, whatever their read counts, are in one bucket. What stays visible is the bucket (a multiple of 128 octets up to 1,024, then eighths of a power of two: eight sizes for each doubling), the epoch list (below) and the signer. The cost is paid in octets of every sealed answer: up to 127 octets to a multiple of 128 up to 1,024 (131 when the body is within 3 octets below a bucket, where no padding element fits and it goes up one bucket); at most 12.5% above 1,024; and 25% in the worst case, a body that leaves 1 to 3, 257 or 258 octets (or 65,542 or 65,543) to its bucket going up one bucket more, which for 2,046 octets is 2,560. The AEAD's 28 octets and the record's framing are constant and are not padded. A plain answer is not padded: it exposes its read set anyway. An evaluator whose result length depends on secret content SHOULD still pad its canonical result to a size of its own: the bucket hides the number of reads, not a result that fills a bucket by itself. |
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
- **A mismatch with a known evaluator is detected only for known ones.** For an evaluator this program does not know, nothing is checked, by design: the trust is the signer's. A host that cannot accept that sets `Signers::None`. The default (`OwnAndMembers`) trusts the person's own devices and the folder's **writers**, who could equally write wrong data into the folder: only a writer is trusted by it. A member who only reads the folder, however many keys it holds, is not trusted by default (§9); a host that trusts one names its device.
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
- **A suspected key, before any revocation.** The owner who fears a key lost marks it suspected on a device (`Device::suspect`, data-layer.md §8), which takes no new log entry of it. An answer is treated the same: a reader refuses an answer of a suspected key (`Untrusted`, §7.3.3 step 1) and a device does not serve one it holds, until the mark ends by `unsuspect` or because a revocation is held (the paragraph above then decides). Otherwise following the advice of an evidence event, "suspect the key", would change nothing for answers.
- **Nothing is lost that cannot be remade.** A pure answer is recomputed by anyone, so the audience loses nothing but the cache entry; a recomputing reader never used the signature. A provider answer is lost until another device of the provider (or the provider after re-keying) signs the function over the same inputs: a new signer, a new name, the same id; a reader's policy then names the new signer.
- A provider key lost to a thief is also a risk **before** revocation: the thief signs wrong provider answers. The evidence of §8 and the owner's revocation are the response; the cut's bound does not help because answers have none.

### 13.10 Flooding with answers

- A device **never fetches** an answer nobody asked for: answers are asked for by name, from candidates the question's policy names (§7.2), and answers travel in no notice or sync group. A forged answer reaches a reader only as the reply to its own ask, and is checked (§7.3.3).
- A signer's answers a device **keeps** are bounded per signer and in total (§10); a signer cannot push its own out. What a device **signs** is bounded (§10).
- Checking is cheap before it is dear: name parse, signature, then the open and the digests; a flood of answers from signers a device's policy does not trust costs a verify each and is dropped at §7.3, nothing stored.
- Large read sets and bodies are bounded (§10); pieces fetched only for answers asked for.
- **Evidence is bounded too (§10).** A hostile signer that answers every ask with a faulty packet adds a record of evidence per distinct name, whole packets in the store. What is kept against one signer is capped in records and octets, the signers evidence is kept against are capped, and the oldest goes first. What is dropped is no longer blocked: the packet is judged again when met, and the fault found again if it stands, at the cost of one verify and one judgement. A signer that can mint many keys under a namespace the reader accepts (a collaborator who is her own authority) can push the evidence of older signers out; the events of §8.2 are bounded separately (SHAPES-R5 §D), and the host that has acted on an event needs nothing more of the packet.
- **CPU is bounded too (§4.1, §10).** The work a signed answer makes a device do is the evaluation (host code over up to `READS_MAX` reads) and the check of the reads the device holds, each read of a merge state a replay of the collection's merge up to a frontier the signer chose, which a hostile member can make dear by adding versions to the collection. So: (a) `Reads::current` is spent from the reads budget like a read, so a plan cannot call it over and over for nothing; (b) an answer that lists more than `STATE_READS_CHECKED_MAX` reads of merge states is refused whole, `TooManyStates`; (c) the evaluation and the held-reads check run on a thread of their own, never on the executor, within `Budget::time`, past which they are abandoned (the thread stops at its next check of the cancellation flag, `ReadView::cancelled`, and what it returns is discarded) and refused `OverBudget`; on wasm32, which has no threads, they run inline and only the checks bound them; (d) the check holds the device's state lock for one read at a time, so a check of many reads does not hold up every other operation of the device. **The wall clock bounds work here only because it produces a refusal**: it never decides what is true or trusted. A check or evaluation over its time is `OverBudget`, never a result and never trust; the answer is judged again the next time it is met. The clock is the wall clock and not the runtime's (a paused or virtual runtime would otherwise run it out while the thread works). A check reads each read at the moment of its own check, and what moves meanwhile (a version withdrawn, an equivocation found) is judged again by the rejudging of answers (§8.2); the one fact that joins reads, the epochs, is checked twice before it is evidence against the signer, and a state that moved between the two passes is `ReadsChanged`, no fault.
- **Where that work runs.** On the runtime's blocking pool where there is a tokio runtime (a thread of its own where there is none; inline on wasm32). On a paused or virtual tokio clock, tokio does not advance time while a blocking task runs, so a simulated run (the conformance suite) is as deterministic with this work as without it; a plain thread would let the virtual clock run on while it works and change costs and round trips between a case run alone and in the suite.

### 13.11 Cheap forgeries of ids

An id of a sealed answer is a keyed MAC: only an audience member can make or check one. A forger outside it cannot make a packet that a member accepts (the signature must verify and the id must match the binding the member computes), only a packet that fails §7.3.3 step 4 and is dropped. An audience member can make ids and ciphertext, but not a signature of another device; authority is the signature plus the policy.

### 13.12 A member who signs wrong answers

A member holding the audience key can seal and sign a wrong answer, whether or not it can write: a reader-only member has every key it needs to derive the keyed id. Pure: any reader that knows the evaluator recomputes it and reports the mismatch with the signer's key; a reader that does not know it takes it only if its policy trusts the signer, and the default policy trusts a **writer** of every collection read, not a member who only reads (§9). Naming a reader-only member in the policy is the host's explicit choice. Provider: only named providers are accepted.

### 13.13 Durability and equivocation by restart

A provider that restarts, or loses power, between signing an answer and its durable write (or after serving it) must not sign another result at the name: it serves only what is behind the barrier (§6.2), and a non-reproducible provider keeps every answer it signed. The storage cases of data-layer.md §4.2 apply to answers as to log entries.

### 13.14 Asks for answers

- **Unauthenticated asks get silence.** An ask whose digest is not its parameters', that arrives while the signer holds `asks_queued` asks being opened already, whose envelope does not open or decode, whose body is malformed, that claims a device of a namespace the signer does not serve (before any proof is verified), or whose proof does not verify as the asker's for this very ask (a stranger's key, no signature, a proof made for another signer, another question, another envelope or another protocol, a revoked key) gets no Data and no Nack (§15.5), and a line at `debug`. A prober learns nothing from a signer's answer to it, not whether the device serves asks, holds a function or reads a collection. What a prober can still do is cost the signer one open and, when the envelope opens and claims a device of a namespace this signer serves, one proof verification, which may fetch a certificate (§13.2, 1): the signer's seal key is public, so anyone can seal an envelope that opens. That cost is bounded: at most `asks_queued` (32) asks are held while they are opened and the rest dropped; their proofs are verified `asks_verifying` (8) at a time on a budget of their own and within the Interest's lifetime, so a crowd of such asks slows no introduction, hold ask or audit ask; and a certificate is never fetched for a device of a namespace the signer does not serve.
- **`NotAudience` tells an authenticated asker only what a plain `get` of that read tells it** (`Sealed`, §5.6), and a position: read `index` is sealed to an audience the asker is not in. When the asker states the read set it named the read itself. When it leaves the reads to be planned, the index is a position in the set the **signer** planned, which the asker did not state: it learns that the plan has at least `index + 1` reads and that the first of them it cannot read is that one, and no name. That is stated and accepted. `NotServed`, given before any read is judged, says nothing about reads, except under `OwnAndMembers`, where it says an asker of another namespace is not a listed writer or reader of some collection read. **`CannotCheck` tells an authenticated asker which evaluators the signer knows**, so it is told only to an asker who may read the question's definition: the definition is judged first (and read here when it is not held), and an asker outside its audience is refused `NotAudience` and learns nothing of the evaluators. **`EvaluatorRefused` tells an authenticated asker the evaluator's own words** about the definition or the reads, so it is given only past the same first judgement: of the asker's stated reads every one is judged before anything is planned or computed, and of a question that leaves the reads to be planned the definition is. The words are the evaluator's, and the evaluator MUST NOT put the contents of an input in them (`EvalError::Refused` says so): when the reads were left to the signer, the inputs the plan reads past the definition are judged only after the plan (§15.4 step 6, second pass), so a refusal made during the plan is told before them. That is stated and accepted, as `NotAudience`'s position is.
- **The reply is not sealed to the asker.** A refusal is Data content in the clear, so a relay that sees the reply sees its code, its number and its explanation (a fixed text for the code, with the index or the wait; for `EvaluatorRefused`, the evaluator's own words, 512 characters at most): never a name, a read or a result, unless the evaluator wrote one into its reason, which it MUST NOT (`EvalError::Refused`). An answer packet in a reply is as sealed as the published one is (§5.3): a relay that holds no key of the epochs learns what the published packet already tells it (§13.3).
- **Asks cannot make a device compute for a non-audience asker.** The audience check (§15.4 steps 5 and 6) precedes the computation (`Device::publish_answer`'s) and the call to the host, and is made again on the reads the signer has read, which are the reads computed: a question that leaves the reads to be planned is computed stating the planned set. Case `a20` counts evaluations and finds none. The one thing an asker outside the audience, with a valid proof, can make a signer do when it leaves the reads to be planned is the definition's read and the evaluator's plan, within `Budget`, never the result; and not beyond the caps (a refused ask holds them only until it is refused).
- **Pending work is bounded by the caps and by `Budget::time`.** Planning (which fetches the reads not held) and computing each run for at most `Budget::time`: past it the work is abandoned, the asker's slot and its place among `asks_at_once` are given back, and the ask is told `Pending` (planning: what was fetched is held, and the next ask goes on from there) or `OverBudget` (computing). A computation that outlives the Interest goes on in a task that holds the asker's slot and one of `asks_at_once` until it ends or `Budget::time` passes. A re-ask during it gets `Busy`; a re-ask after it gets the stored answer at once, with no second evaluation. A provider ask holds the caps only while the signer waits for the host (at most `min(lifetime − 200 ms, Budget::time)`); once it has answered `Pending` the host's work is no longer counted by them, and the same call (function and inputs) is delivered to the host once while it waits, so one slow host and one retrying asker fill one of the 64 places of the stream, not all of them (a full stream of distinct calls is `NotProvided`).
- **A flood of asks from one device is limited to one in progress.** Another ask of that device, while one is worked on, costs the signer an open, a proof verification and a signed `Busy`, and no work. The counter is the one hold asks use (data-layer.md §13.2): a hold ask in progress counts, and an answer ask in progress delays that device's hold ask, which waits at most a hold ask's lifetime.
- **Replay of an envelope is harmless to what it asks, and no more than a nuisance to the asker.** An ask carries neither a nonce nor a date, so a copy of an Interest a relay saw verifies as the asker's again, for as long as its key stays valid. The proof binds the signer's name, the question and the envelope's ephemeral key, and the envelope's sealing binds the name `<D>/32=ask-answer`, so a copy cannot be turned into another question, another signer's ask or another protocol's. What a replayer gets is the reply, signed by the signer: the published answer (sealed under the audience key when anything read is sealed, so unreadable to it, and otherwise what any holder serves) or a refusal. The signer judges the replay afresh, by the records it holds when it arrives: an asker since left out of an audience or of `serve_asks` is refused `NotAudience` or `NotServed`. A replayer also learns whether the asker is of the audience of a read now (`NotAudience` against an answer); that is derivable from the signed members records, and no secret. A computation a replay starts is the computation the asker's own ask would have started, and the computation is idempotent, so one id is computed once however many replays come. What a replayer can do is occupy the asker's one slot while the work goes on, so that the real asker's ask is told `Busy` and asks again after `retry_after` (§15.9): bounded by the work (`Budget::time`) and no stronger than a flood from the asker's own device. The slot is the one hold asks use, so it also delays that device's hold ask, which waits at most a hold ask's lifetime. The reply of an ask has FreshnessPeriod 0 and each attempt of an asker carries a fresh envelope, so a cached `Busy` or `Pending` is never what the next attempt meets.
- **One collaborator's many keys cannot keep the person's own devices waiting.** A person of another namespace who is a writer of a collection can enrol as many device keys as it likes, and each is served under `OwnAndMembers`. Their asks take at most half of `asks_at_once` together and one namespace at most half of that, so the signer's own namespace always has room (§15.7); and a key's ask for reads the signer must fetch holds its place for `Budget::time` at most, not for the fetches' own time.
- **Asks cannot drain the signer's own signing.** Asks have a signing rate of half of `sign_per_second`, apart from the signer's own answers (§15.7): an asker who may read older versions and names many read sets cannot exhaust the signer's own rate, and when the rate for asks is spent the asker is told `Busy` and when to ask again, not to state a smaller read set. Every answer an ask makes is stored and the store evicts the oldest first (§10), so a signer that rations what asks sign rations that churn too.
- **The reads an ask makes the signer compute are the reads it judged.** The audience is judged before the fetch and again once the reads are held, and the question is computed stating the set judged: data that changes between two plans lets no second read set through, and an epoch whose records the signer does not hold is not admitted (§15.4).
- **A guest's key is not served by default.** `ask_roles` (§15.7) lists `admin` and `member`: a short-lived key of a friend, which is of the person's namespace, and a relay (`node`) are refused `NotServed`, unless the host lists their role. The role is read from the device name, which the CA's schema ties to the role of its certificate. A name that carries no role is served only in a namespace that does not declare the role layout (its trust context lists no role in `DataRequiresCut`), where there are no roles to tell apart. In a namespace that does declare it, a role-less name (`/<ns>/<device>`) is no device the CA issued (its role policy issues `/<ns>/<role>/<device>` only) but a key the root signed by hand, and it is refused `NotServed` like a role the policy leaves out, so that a role-less key is neither served as the person's own nor outside the lapsed rule (trust-context.md §3.3.13).
- **The read set goes only to devices that could be trusted for it.** The asker sends the question, its reads and its definition, sealed to each signer; under `OwnAndMembers` it sends them to no device of another namespace that is not a writer of every collection read, whose answer would be refused (§15.9).
- **What a signer says is not shown, but for one reason.** The asker shows the fixed text of the refusal's code and never the explanation the signer wrote (§15.9): the control characters and escape sequences of a compromised signer do not reach a terminal. `EvaluatorRefused` is the one reason whose explanation is shown, because it is the one thing the asker cannot know and needs to fix the definition; it is shown cleaned (no control character, no bidirectional override or isolate, at most 512 characters with the cut marked by an ellipsis inside the cap, no double quote) and **inside this device's own quoted frame**, so that nothing a signer sends reads as this device's own words (§15.6).
- **A signer that regenerates its recipient key is found again.** An asker whose held seal key opens nothing there (three sends unanswered) fetches the seal key packet again and sends once more under a new key (§15.9).

## 14. Conformance cases

The cases the implementer writes, each failing first on the code before the feature, in `ndn-data-conformance` (ndn-sim), ids `a1`…`a23`, feature `Answers` (case c12 keeps `Functions` and is rewritten to the F surface). All run in the clean and the `--faulty` mode (data-layer.md §18.1).

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
| a17 | **Limits.** Over `READS_MAX` reads or `SEAL_EPOCHS_MAX` epochs is `TooLarge`; a budget exceeded is `OverBudget` and not a result (calls of `current` spend the reads budget like reads; an evaluation or a held-reads check that runs past `Budget::time` is abandoned and refused, and a device operation completes while either runs); a signed answer listing more than `STATE_READS_CHECKED_MAX` reads of merge states is refused `TooManyStates`; unsolicited forged answers are dropped without being stored; a signer's answers kept are capped; a provider answer that must be kept is refused with `Busy` rather than evicting one. |
| a18 | **Pieces.** A result of 200 KiB, sealed, is made, fetched in pieces and recomputed alike, equal across the three paths of a10, the pieces DigestSha256-verified and no custody asked. |
| a19 | **A phone asks the laptop of the same person.** A phone with no evaluator and no inputs, whose policy names the person's laptop, asks it a pure question: the ask is sealed to the laptop's seal key and proves the phone's key, the laptop plans, computes and signs, and the phone returns `Got::Answer` with the result, reads, binding and id a device holding everything gets, and a provenance of `Trusted` by the policy, naming the laptop. With the evaluator known on the phone, it recomputes what the laptop signed and agrees. |
| a20 | **A device outside the audience is refused and nothing is evaluated.** A device outside the audience of one read of a question asks the laptop for it: it is refused `NotAudience` (next step `AskOwner`) with the index of that read, and the laptop's evaluation counter is unchanged. |
| a21 | **One ask in progress.** Eight concurrent asks from one device for one slow computation: one is in progress, the rest are refused `Busy`, and every one is answered within 3 retries. |
| a22 | **A forged proof gets silence.** An ask with a forged proof (a stranger's key, or a proof that does not name the ask) gets no Data within the Interest's lifetime, and the signer's evaluation counter is unchanged. |
| a23 | **A definition the evaluator refuses is refused with its reason.** Alice's phone asks her laptop for the answer to a definition that has no field `inputs`: the laptop's evaluator refuses it, and the phone is refused `EvaluatorRefused` (`FixRequest`, no retry) with the evaluator's words, quoted in the asker's own text, with no control character; the laptop evaluated nothing and signed no answer; the same ask under an evaluator the laptop does not know is still `CannotCheck`; once the definition is mended the same phone is answered. |
| unit | Canonical encoding and the digest: every read set round-trips and is independent of the order the reads were made in; two labels never collide; a decoder refuses an unknown TLV, a non-minimal length, an unsorted or repeated read; a keyed id differs for two audiences and agrees for two members; key derivation is order-fixed and gives the same bytes on two devices. |
| unit (ask) | The envelope, its body and every refusal round-trip and a decoder refuses what is not exact; a provider ask is delivered on `provider_asks` and answered once the host provides; `Pending` and then a re-ask returns the stored answer with no second evaluation; an unserved namespace (`serve_asks` `Off`, or `Own` and another namespace) gets silence, no certificate fetch and no permit; a flood of junk proofs claiming unserved namespaces leaves every permit of introductions, holds and audits; the asks held while opened are bounded by `asks_queued` and the rest dropped; proofs of asks for an answer are verified on a budget of their own; an ask waiting for a fetch gives its caps back within `Budget::time`; a collaborator's four devices cannot make the person's own device `Busy`; asks have half the signing rate and the signer's own is untouched, and a rate is `Busy` and not `OverBudget`; a guest's key and a relay are `NotServed` by default and a relay is served when `ask_roles` lists `node`; an ask over more than 1,024 states is `OverBudget` without the state lock; an unheld read is `Pending` once the reads are to be held, never admitted; the reads computed are the reads judged when the data moves between two plans; a signer's words are never shown (control characters) but for `EvaluatorRefused`; a definition, or an input, that the evaluator refuses is `EvaluatorRefused` with its reason (control characters removed, 512 characters at most, quoted by the asker whatever the signer sent) and `FixRequest`, also when the signer planned the reads and when the asker stated reads that are not the evaluator's, while an evaluator the signer does not know is still `CannotCheck`; an answer over reads the signer chose is `Age::Newest`; the same provider call is delivered once while it waits and a duplicate is never `NotProvided`; a regenerated seal key is fetched again; a silent signer's error says a lapsed certificate can be the cause; `asks_at_once` bounds all askers together; only devices the policy could take an answer from are sent the reads; a proof of another signer's or another question's does not verify. |

c12's part 2 (a summary service) is rewritten as a provider answer over the note (a12, a6); its other parts stay.

## 15. Asking another device for an answer

A reader may need an answer from a device that holds the data it does not: a phone asking the person's laptop, a person asking a provider (`summarize` over this note). Readers fetch by id from signers that have already made the answer (§7.2 step 5), or recompute; a signer that has not made one publishes nothing for them. The **ask** is the one request by which a device makes an answer for another. It is sealed to the signer, authenticated by the asker's proof, and bound as §13.2 says. It is built by the owner's decision of 2026-11-19 (F-QUESTIONS #1, option (a)). The Rust shapes are `ndn_data::{AnswerAskEnvelope, AnswerAskBody, AnswerAskRefusal, AskRefusal, AskServing, ProviderAsk}`, `Device::ask_answer` and `Device::provider_asks`, and the settings are `AnswerConfig::serve_asks`, `ask_roles`, `asks_at_once` and `asks_queued`.

### 15.1 The exchange

1. The asker holds a question (§7.1) and names a signer `D`, a device its policy names (§15.9). It has `D`'s seal key (§15.8), builds an `AnswerAskBody` (§15.2) of the question's `AnswerAsk`, its own device name and its proof (§15.3), seals the body to `D`'s seal key, and sends one Interest named `<D>/32=ask-answer/<ParametersSha256Digest>` whose ApplicationParameters are the `AnswerAskEnvelope`.
2. `D` decides by §15.4 and replies with one Data packet named exactly as the Interest, signed by `D`'s device key, with FreshnessPeriod 0, whose Content is the signed answer packet (§15.5) or an `AnswerAskRefusal` (§15.6); or it does not reply at all (§15.5).
3. The asker judges what came back as it judges an answer it fetched (§15.9). Nothing in an answer is taken because it came as the reply to an ask.

### 15.2 The name, the envelope and the body

- **The name** is `<D>/32=ask-answer/<ParametersSha256Digest>` (§11.1): `D` the signer's device name, then the SHA-256 of the Interest's ApplicationParameters TLV as a ParametersSha256DigestComponent. It is the Interest's name, and the reply's (so a reply is for this ask and no other).
- **The envelope**, the value of the ApplicationParameters, is one `AnswerAskEnvelope` (0x05DE): an `EphemeralKey` (the asker's ephemeral X25519 public key, 32 octets), a `Ciphertext` (a fresh content key wrapped to `D`'s seal key, as an epoch grant wraps one, data-layer.md §9) and a `Ciphertext` (the body, sealed under that content key). These are the fields and the encoding of `IntroAsk` (data-layer.md §19.3), and the code that seals and opens is the same. A decoder refuses an unknown, missing or repeated field.
- **The sealing.** The body is encrypted with ChaCha20-Poly1305 under the content key; the associated data of both the wrap and the encryption is the Name TLV of `<D>/32=ask-answer`, the Interest's name without its digest. An envelope therefore opens only with `D`'s recipient key and only as an ask of `D`'s: moved to another device's name, or to an introduction ask, it does not open.
- **The body** is, in this order and with nothing after, the `AnswerAsk` TLV (0x05D5, §11.2: the kind, for a pure question the definition, the evaluator or function, and the read set when the question states it), the asker's device `Name` TLV, and the asker's proof, one whole Data packet (§15.3). A body that does not decode exactly gets no reply (§15.5). A provider question MUST state its read set (§7.1); one that does not is refused `NotProvided`.

### 15.3 The asker's proof

- **The proof** is the packet `<A>/32=ask/<binding>` (data-layer.md §13.2, §16.1) with empty Content and FreshnessPeriod 0, signed by a key of the asker's device `A`, the device named in the body. It carries no nonce: it is tied to its ask by its binding alone.
- **The binding** is the SHA-256 of: the label `ndn-data answer ask\0` (the label of this protocol among those of data-layer.md §16.1), the Name TLV of the signer `D`, the `AnswerAsk` TLV as the body carries it, and the 32 octets of the envelope's ephemeral public key. So a proof made for one signer, one question and one envelope verifies for that and no other: not as an ask of another signer, not for another question, not carried in another envelope, not as a hold, audit or introduction ask.
- **The signer verifies** that the proof's name is `<A>/32=ask/<binding>` for the binding it computes from what it opened, and that the signature verifies by the trust context of `A` as every signature does (a revoked key does not verify), by a key of the device `A`; at most `Config::asks_verifying` proofs of asks for an answer are verified at once, on a budget of their own (introductions, hold asks and audit asks have theirs), within the Interest's lifetime. The proof's certificates are fetched only for a device of a namespace this signer serves (§15.4 step 2). Anything else is silence (§15.5).

### 15.4 The signer's order

A device that receives an Interest under `<self>/32=ask-answer` decides in this order, and each step that fails answers what it says and goes no further:

1. **The digest and the envelope.** The name's digest is the digest of the parameters; this device holds fewer than `asks_queued` asks that are being opened or verified; the envelope decodes and opens with this device's seal key and the associated data of §15.2; the body decodes exactly. Otherwise: silence.
2. **The proof** (§15.3). The device the proof's KeyLocator names is read first, unverified, and must be the device the body names; an ask whose claimed device is of a namespace this device does not serve (`serve_asks` `Off`; under `Own` another namespace than this device's; under `OwnAndMembers` a namespace it holds no trust context for) is silence, and **no certificate is fetched for it**. Then the proof is verified, on a budget of its own and within the Interest's lifetime (the ask is dropped when it passes). Otherwise: silence. After this step the asker is **authenticated**: its device name is known to be a device whose key signed this ask.
3. **Serving** (§15.7). Past step 2 the asker's namespace is served. An asker of this device's namespace whose role `ask_roles` does not list is `NotServed`; so is an asker of another namespace, under `OwnAndMembers`, that is not a listed writer or reader of every collection read (step 5).
4. **The caps** (§15.7). The asker has an ask in progress here, or this device works on `asks_at_once` asks, or the asker's namespace (when it is not this device's) has taken its share of them: `Busy`. They are taken together and given back together, wherever the work ends, and no later than `Budget::time` after the planning or the computing began.
5. **The audience of the reads.** The asker MUST be of the audience of every read, of the set it states or, when it leaves the reads to be planned, of the definition it names, **before anything is fetched or planned**: for `OwnAndMembers` and an asker of another namespace, a listed writer or reader of every collection read by the record in force over it, else `NotServed`; then, for every read in canonical order, of the audience of the read (below), else `NotAudience` with the index of the first it is not. This first pass reads nothing from the network and computes nothing; it holds the device's state lock one read at a time and runs off the executor within `Budget::time`; an ask that lists more than `STATE_READS_CHECKED_MAX` reads of merge states is refused `OverBudget` before it is judged (§15.7). The second pass is step 6's.
6. **Planning.** The signer resolves the question as `get` does up to the id (§7.2 steps 1 to 4: it reads the reads a question states, or plans the reads of one that does not, never evaluating), within `Budget`, and for no longer than `Budget::time`: past it the ask is `Pending`, and what was fetched is held. A pure question that states no reads, with an evaluator this device does not know, is `CannotCheck`, after its definition is read here (a fetch within `Budget::time`) and judged as step 5 judges it, so that `CannotCheck`, which tells an asker which evaluators this signer knows, is told only to an asker who may read the definition. A refusal here is mapped: a size or state limit is `OverBudget`; a rate (the signing rate of §15.7) is `Busy`; a read or key not yet to be had is `Pending`; the refusal of a **known** evaluator, of its definition or its inputs (`EvalError::Refused`, which `get` answers as `BadRequest`), or of the reads the question states because they are not its reading (`EvalError::NotItsReads`, likewise), is `EvaluatorRefused`, with the evaluator's reason in the explanation (§15.6); anything else, `CannotCheck` for a pure question and `NotProvided` for a provider one. **Second pass of step 5:** the set the signer will compute, the reads it planned or the reads stated as they are held now, is judged again as in step 5, every read held (the data and the records of a collection fetched in step 6 are held now), before the evaluator runs or the host is called.
7. **The stored answer.** An answer this device signed at the id, durable and served (§6.2), is the reply at once: no computation, whoever asks.
8. **Computing.** *Pure:* the signer computes the question **stating the reads judged**, the planned set when the asker left them open (`Device::publish_answer`'s computation over exactly that set, idempotent), in a task of its own that holds the caps until it ends or `Budget::time` passes, whichever is first, and waits for it for `wait`; the signature is made within the signing rate for asks (§15.7); the answer is the reply; if it is not ready, `Pending`, and the work goes on, so a re-ask finds it; a computation that exceeds `Budget::time` is abandoned and refused `OverBudget`. If the data moved so that the planned reads are no longer the evaluator's reading, the ask is `Pending` (it plans again at the next); the evaluator's own refusal of its definition or inputs is no such thing (the reads are exact versions and an evaluation is a pure function of them, so asking again changes nothing) and is `EvaluatorRefused`. *Provider:* the signer hands a `ProviderAsk` to the host (§15.10), unless the same call (function and inputs) is waiting for the host already, and waits, for `wait`, for the answer it finds at the id once the host has provided it; if it does not appear, `Pending`; no host that took the stream, or a full stream of 64 distinct calls, is `NotProvided`.

`wait` is the shorter of the Interest's lifetime less 200 ms (4 s less 200 ms when it states none) and `Budget::time`.

**The audience of a read.** An asker is of the audience of a read when it may hold the key of every epoch the read is sealed in, by the members record that started the epoch and by the record in force, never by the record in force alone, which could admit a reader later than the read (data-layer.md §9). The test is the one that decides whether this device would grant the asker the key (data-layer.md §9), so the audience of an ask is the audience of a grant. A read whose version is held with no epoch has nothing sealed, and admits anyone. A read the signer **cannot judge** is never admitted: a version not held, or an epoch whose records this device does not hold (a collection it has not synced yet), is `Pending` once the reads are to be held (the second pass of step 6), and the record in force is never a stand-in for an epoch not held, which would admit everyone when no record is held and a later reader when one is. Before the fetch, a read not held yet is left to the second pass.

### 15.5 The reply, and silence

- **The reply** is one Data packet named exactly as the Interest (digest included), signed by `D`'s device key, with FreshnessPeriod 0. Its Content is exactly one of:
  - **the signed answer packet**, a whole Data TLV (0x06), the packet this device serves as `<D>/32=answer/<id>` (§3.3), unchanged: an answer over sealed reads is the packet sealed under the audience key (§5.3), and the reply adds nothing about the reads;
  - **an `AnswerAskRefusal`** (0x05DF, §15.6).
- **The asker takes a reply** only if its name is the ask's and its signature verifies as a key of the signer `D`; anything else is dropped as no reply.
- **Silence** is no Data and no Nack: the Interest is dropped and goes unanswered. It is the signer's only answer to an ask whose digest is not its parameters', that arrives while it holds `asks_queued` asks already, whose envelope does not open or decode, whose body is malformed, that claims a device of a namespace it does not serve, or whose proof does not verify (§15.4 steps 1 and 2); it is logged at `debug` (at `warn` for an ask past `asks_queued`) and nothing else is done. A signer that is not reached is silent too, and so is a signer whose certificate lapsed by a clock, or whose asker's did: so an asker cannot tell these apart, and ends `NotReady`, which says so (§15.9).

### 15.6 Refusals

The Content of a refusal is one `AnswerAskRefusal` (0x05DF): a **reason code** of one octet (1 to 8), a **number** of eight octets big-endian, and the **explanation** in UTF-8 to the end of the value (what happened and what to do). The number is the index for code 1 and the wait in milliseconds for codes 2 and 3; for 4 to 8 it is 0, and a reader refuses a refusal whose number is not. A reader also refuses a code outside 1 to 8, a value shorter than 9 octets and an explanation that is not UTF-8.

| Code | Reason | Number | A signer says it when | `NextStep` of the asker |
|---|---|---|---|---|
| 1 | `NotAudience` | the index, from 0, of the first read in canonical order the asker is not of the audience of (§15.4) | step 5, or step 6 for a planned set | `AskOwner` |
| 2 | `Busy` | `retry_after`, 1000 | the asker has an ask in progress, the signer works on `asks_at_once`, the asker's namespace has taken its share of them, or the signing rate for asks is spent | `RetryLater` |
| 3 | `Pending` | `retry_after`, 1000 | the answer is not ready within `wait`, planning did not finish within `Budget::time`, or a read, a record or a key it needs is not yet held (the signer fetches, and judges again at the next ask) | `RetryLater` |
| 4 | `CannotCheck` | 0 | a pure question the signer cannot plan or compute: its evaluator is unknown here and the reads are not stated, or planning failed for another reason (no evaluator's refusal: that is 8); told only to an asker who may read the question's definition (§15.4 step 6) | `SetPolicy` |
| 5 | `NotProvided` | 0 | a provider ask this device cannot have computed: no host took `provider_asks`, its stream is full, the inputs were not stated, or planning failed for another reason | `SetPolicy` |
| 6 | `OverBudget` | 0 | planning or computing would exceed the signer's `Budget`, `PAYLOAD_MAX` or `READS_MAX`; the ask lists more than `STATE_READS_CHECKED_MAX` (1,024) reads of merge states; the check of the reads ran past `Budget::time`; never a rate (that is `Busy`) | `FixRequest` |
| 7 | `NotServed` | 0 | the asker is of this device's namespace and of a role `ask_roles` does not list (or has no role in a namespace that declares the role layout, §15.7), or `OwnAndMembers` and the asker is of another namespace and not a listed writer or reader of every collection read (`Off`, and an asker of another namespace under `Own`, get no reply: §15.4 step 2) | `SetPolicy` |
| 8 | `EvaluatorRefused` | 0 | the signer **knows** the evaluator the question names and the evaluator refuses what it is given: its definition or an input it reads (`EvalError::Refused`), or the reads the question states, which are not its reading of the definition (§15.4 steps 6 and 8). It is no matter of policy: the definition is what is wrong, so the asker fixes it. Never for an evaluator the signer does not know (that is 4) | `FixRequest` |

**The explanation of code 8 carries the evaluator's reason**, the one explanation an asker shows (§15.9). The signer writes it as `the signer's evaluator refused the definition, in its words: "<reason>"; fix the definition and ask again`, where `<reason>` is the evaluator's text with every control character removed (all of Unicode's `Cc`: newlines, tabs, the escape of an ANSI sequence, the C1 controls), the bidirectional controls U+200E, U+200F, U+202A to U+202E and U+2066 to U+2069 removed, each double quote made a single quote, and cut to **512 characters**, counted as characters and cut on a character boundary: past 512, the first 511 and an ellipsis (U+2026), so the ellipsis is within the cap. Every other code's explanation is the fixed text of the reason (`AskRefusal::explain`), as before.

A refusal is told only to an authenticated asker (§15.4 step 2). It is signed Data of the ask's name, and it tells no more than a plain `get` of the same read tells (§5.6, §13.14).

### 15.7 Serving, and the caps

- **`AnswerConfig::serve_asks`** (`AskServing`, default `Own`) says whose asks a device answers:
  - `Off`: none; no ask is answered (the asker is not told: §15.4 step 2).
  - `Own`: asks of devices of this device's own namespace, the namespace of the trust context that governs the asker's name here (the person's other devices, data-layer.md §3).
  - `OwnAndMembers`: also a device of another namespace that is a listed writer or reader of every collection the ask reads, by the record in force over each, held here.

  Serving is judged before the caps, so an asker that is not served takes none. An ask whose claimed device is of a namespace this device does not serve is not answered at all (§15.4 step 2).
- **`AnswerConfig::ask_roles`** (default `admin`, `member`) lists the device roles of this device's own namespace that are served under `Own` and `OwnAndMembers`: the role is the name component after the namespace in `/<ns>/<role>/<device>` (the layout of personal namespaces, as the trust context's `DataRequiresCut` reads it), taken from the device name the proof verified, so a device cannot choose it. A device of another role (a guest's short-lived key, or a `node` relay unless the host lists it) is refused `NotServed`, with the reason and what to do. A name that carries no role is served only where the namespace does not use the role layout, that is, where its trust context lists no role in `DataRequiresCut` (there is no role to refuse); where it does, a name `/<ns>/<device>` is refused `NotServed` too, since the namespace's CA never issues one (`SignedTrustContext::is_role_less_device`). A role the host wants served is added to the list.
- **`AnswerConfig::asks_at_once`** (default 4, at least 1) is the most asks this device works on at once, all askers together. Each asker also has **one ask in progress** at most; the counter is the one hold asks use (data-layer.md §13.2), so an answer ask in progress delays that device's hold ask, which waits at most a hold ask's lifetime. This device's own namespace may use all of them; devices of **other namespaces** together at most half (rounded down), and one other namespace at most half of that (rounded up, at least 1): a collaborator who enrols many devices fills no more than its share, and the person's own devices are always left room. Beyond any of these the ask is refused `Busy` with `retry_after` of 1 s. The work an ask holds them for lasts at most `Budget::time`, planning and computing each (§15.4 steps 6 and 8): past it the work is abandoned and the caps are given back.
- **`AnswerConfig::asks_queued`** (default 32) is the most asks this device holds while it opens them and verifies their proofs; past it an ask is dropped without a reply, and its asker asks again. Their proofs are verified `Config::asks_verifying` at a time on a budget of their own, so a crowd of strangers' asks slows no introduction, hold ask or audit ask.
- **Signing for asks has a rate of its own**: half of `AnswerConfig::sign_per_second` (rounded up), counted apart from the answers this device signs for itself (a `get` that publishes, `publish_answer`, `provide`), which keep all of theirs. An ask that would be signed past it is refused `Busy` with `retry_after` of 1 s, never `OverBudget`: a rate that passes with the second is no read set to state smaller.
- **Reads of merge states in an ask are capped**: an ask that lists more than `STATE_READS_CHECKED_MAX` (1,024) of them is refused `OverBudget` before any is checked, saying to state a smaller read set; the check of the audience runs off the executor within `Budget::time` and holds the device's state lock one read at a time, as the check of a signed answer's reads does (§7.3.2).
- **No other rate is specified.** These caps, the signing rate for asks and `Budget::time` (§10) bound what an authenticated asker can make the signer spend, and the layer has no token bucket of its own.

### 15.8 The signer's seal key

An asker seals to the signer's seal key, the packet `<D>/32=seal/<public key>` signed by `D`'s device key (data-layer.md §9, §16.1). A device answers an Interest for `<D>/32=seal` with CanBePrefix for its own `D` with that packet, so an asker that does not know the key fetches it by the device's name alone. The asker takes the key only from a packet that names `D` and is signed by a key of `D`, held already or fetched, never from the reply to an ask; a device whose key it cannot obtain is `NotReady` (`RetryLater`): "the signer's seal key is not held yet". The packet is asked for as every small signed packet the layer needs is (data-layer.md §17.1: up to three rounds, a pause between them), not once: at 20 % loss in each direction a single Interest has a reply less than half the time, and a call that gave up on the first miss was `NotReady` for most of its callers' tries (conformance fault seeds 61, 77 and 115 of a20, a19 and a21 failed so, eight rounds in a row).

### 15.9 What the asker does

- **When it asks.** A `get` of a question asks only after §7.2 found nothing: when the question is not recomputed here (the evaluator is unknown, `Check` is `Trust`, or it is a provider question) and no answer is published where this device looks or held; and when a pure question that states no reads has an evaluator this device does not know, so it cannot plan, and its policy trusts some signer for pure answers. A question this device recomputes is never asked.
- **Whom.** The candidate signers of §7.2 step 5, in that order, never this device: for a pure question the signers its policy trusts, for a provider question the devices its policy names as providers of the function (§9); and of them only those whose answer the policy could take (§9: under `OwnAndMembers`, a device of another namespace only when it is a writer of every collection the read set names, by the records held here). An ask carries the whole read set and the definition, sealed to its signer, so it is sent to no device whose answer would be refused anyway: a question that joins Bob's collection and Carol's is not told to Bob's devices unless they could be trusted for it. A policy that names none asks none.
- **How.** For each signer it obtains the seal key (§15.8), builds one ask with a fresh envelope and proof, and sends it with the device's lifetime, at most 3 times (the same Interest, so a lost packet costs a send and the signer's work is not repeated). When all 3 sends go unanswered and the key was a held one, the signer may have made a new recipient key and signed a new seal key packet: the asker fetches the packet again and, if the key is another, sends the ask once more under it (one bounded retry). On `Busy` or `Pending` it waits `retry_after` (at most 10 s) and asks again with a fresh envelope, at most 3 attempts per signer. A refusal after that, or any other refusal, ends that signer. Silence after the sends goes to the next signer. The first answer wins.
- **What it does with an answer.** The packet passes the checks of every answer (§7.3.3 steps 1 to 5: signature, decoding, opening, binding, held reads) and the check for equivocation (§8.1), MUST answer the question asked (its evaluator or function, its definition and, when the question states them, its reads are the question's; else `Answer` / `Malformed`, and it is dropped), and is judged as one fetched is (§7.3): recomputed when the evaluator is known and `Check` is `Recompute`, else taken on the policy's trust with `Provenance` saying so. Verification, `CannotCheck` and evidence apply unchanged; a signer the policy does not trust is as untrusted as when it publishes. The result has `Age::Exact` when the question states its reads. When the asker left them to the signer, the signer chose them and nothing on this device confirms they are the newest: `Age::Newest` with the largest `unconfirmed_for` this device reports (as long as 136 years), so the staleness is signalled and an exact age never claimed (§7.6).
- **What it returns when none answers.** The first refusal as `Answer` / `AskRefused` (§12), or the first error of judging a packet a signer gave; else, when none replied, the error the question had before it asked (`CannotCheck`), and, when that was `Unavailable` and some signer was asked and was silent, `NotReady` whose text says that no reply can also mean a lapsed certificate on either side or a signer that does not serve this device (§15.10). The text of a refusal is the fixed text of its reason code (`AskRefusal::explain`, which says why and what to do), never the explanation the signer put on the wire: those are a hostile or compromised signer's own words, and they would reach the user's terminal. The explanation is carried so that a reader of the wire sees it, and ignored. **The one exception is `EvaluatorRefused`**, whose reason is something only the signer's evaluator can say and the asker needs in order to fix the definition: its text is the evaluator's words, **never raw**. The asker takes what lies between the frame the signer writes (§15.6) or, when there is no frame, the whole explanation, cleans it again as the signer does (control characters and bidirectional controls removed, double quotes made single, at most 512 characters, the ellipsis within the cap: the signer's bytes are not trusted to be clean, and cleaning is idempotent), and **writes the frame itself**, `the signer's evaluator refused the definition, in its words: "…"; fix the definition and ask again`. A signer's words therefore always sit inside quotes this device wrote, and cannot close them (no double quote survives), so they cannot read as this device's own text; a refusal that carries no words is the reason's own text. Every other reason keeps the rule above.

### 15.10 The host's surface

- **`Device::ask_answer(signer, question) -> Result<Got, DataError>`** asks one named device, as §15.9 does for each signer and without the policy's loop. `question` is `AnswerAsk::name(None)` (pure) or `AnswerAsk::name(Some(&signer))` (provider); `signer` MUST be another device's name (`BadRequest` otherwise). It returns `Got::Answer`; a refusal as `Answer` / `AskRefused` (with `next()`); silence as `NotReady` (`RetryLater`), whose text says that no reply can also mean that a certificate lapsed (this device's own or the signer's: a lapsed device is silent to the other, and answers nothing) or that the signer serves neither this device's namespace nor its role (§15.7); a seal key not obtained as `NotReady` too.
- **`Device::provider_asks() -> tokio::sync::mpsc::Receiver<ProviderAsk>`** hands a host the calls it is asked to compute: `ProviderAsk { function, inputs, asker }`, delivered for an authenticated asker of the audience of every input whose answer this device does not hold. The stream holds 64; taking it again replaces it, the earlier receiver ends, and the calls it was owed are delivered again. The host computes and calls `Device::provide(function, inputs, result)` (§6.2): the answer is signed, and the asker's next ask finds it. A call is delivered **once while it waits**: the same function over the same inputs (the digest of the read set), asked again by anyone before the host provides the answer, waits for that answer and is told `Pending`, and is delivered again only when `Budget::time` has passed without a result. A host MAY still key its work by `function` and `inputs`.

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
- **§18 (conformance):** list a1–a22 and state that c12 is rewritten to the F surface.
- **§20:** none; answers use the gate's definition of a member only for the default policy (answers.md §9).
- **D's section (device-wide events):** add the `AnswerEvidence` event (SHAPES-R5 §F, §8.2 of answers.md).

**README.md**

- *Other specifications* table, a row: `| [answers.md](answers.md) | Answers: named, checkable readings over signed data; pure answers (recomputed by any holder of the definition and the inputs) and provider answers (trusted by the provider's authority); the read set, its canonical bytes and digest, the binding, the keyed answer id, the name `<D>/32=answer/<id>`, sealing to the audience intersection of what was read, evaluators named and versioned like merge rules, the verb (`get` of an exact name or a question), recompute-or-trust, evidence, policy, threat notes; TLV 0x05C0–0x05DF |`
- *TLV-TYPE numbers* table, a row after the `0x05B0–0x05BF` one: `| 0x05C0–0x05DF | [answers.md](answers.md) §11.2, §15 (odd numbers only for the fields of an answer: every field of an answer is critical. AnswerRecord 0x05C1, AnswerKind 0x05C3, AnswerBody 0x05C5, AnswerBinding 0x05C7, AnswerBy 0x05C9, ReadSet 0x05CB, ReadVersion 0x05CD, ReadState 0x05CF, Result 0x05D1, AnswerSealed 0x05D3, AnswerAsk 0x05D5, and two records of the device's event store, AnswerEvidence 0x05D7, AnswerFault 0x05D9, FaultKind 0x05DB, AnswerPadding 0x05DD; the ask exchange takes 0x05DE `AnswerAskEnvelope` and 0x05DF `AnswerAskRefusal`, answers.md §15) |`
- *Name-component types*: no new type; the keyword components `32=answer` and `32=question` are of the layer's own (data-layer.md §16.1).

---

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
