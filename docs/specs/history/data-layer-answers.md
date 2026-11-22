> Superseded by NAME.md at ndn-rs <commit>. Kept for history; nothing here is normative.

# Answers text cut from `data-layer.md`

## Header, Related (before §1)

- **Answers (round 5, item F):** named, checkable, sealed readings over signed
  data are specified in [answers.md](answers.md) (the interim of slice 8, a
  service that `put`s its answer into a collection of its own, is replaced by
  it); this document names where they touch it.

## §2 Invariants

10. **Answers say what they read.** An answer is immutable and named by the
    exact versions it read; a mismatch with a recomputation is evidence
    (answers.md).


## §3 Names: the `get` sentence also took answer and question names (answers.md §3.3, §7.1)

> `get` also takes log entry and state names (§11), entry and range names (§4.1, §5.4), and answer and question names (answers.md §3.3, §7.1).

## §4.2 Durability

An answer is served, announced and listed only behind the same barrier as a log
entry (answers.md §6.2), and a provider keeps every answer it signed, so after a
restart or a power loss it serves what it signed or nothing, never another
result at the name.


## §6.3 A listed writer's own devices (round 11): the whole bullet, as it was with answers

- **A listed writer's own devices (round 11).** One more kind of packet of
  `P` is judged by the adopted context, so that two writers who never met
  can ask each other for answers (answers.md §15): the packets of **one
  device** of `P` that the ask exchange is made of, and exactly these, by
  name — `<P>/<role>/<dev>/32=seal/<pk>` (the device's seal key, `<pk>` its
  32 octets), `<P>/<role>/<dev>/32=ask-answer/<ParametersSha256>` (the
  reply to an ask), `<P>/<role>/<dev>/32=answer/<id>` (an answer) and
  `<P>/<role>/<dev>/32=ask/<binding>` (the proof an asker sends with its
  ask, §13.2) — with exactly two components, `<role>` and `<dev>`, between
  `P` and the keyword, and `<role>` a role `P`'s context names: one of the
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
  - **a reply** is taken only by the asker whose Interest it answers (its
    name is the Interest's, answers.md §15.5), as before;
  - **an answer** is taken only after it is opened, and only if every read's
    collection lies under a subject whose record in force lists `P` as a
    writer: otherwise it is refused `Untrusted`, saying which read and what
    to do, and no evidence is raised against the device for it;
  - **an asker's proof** authenticates the device for the signer that
    serves its namespace (`OwnAndMembers`): the asker's namespace is `P`
    when no context of it is held and it is adopted and a record lists it
    as a writer; what it may then ask is decided as for any asker
    (answers.md §15.4 steps 3 to 5), by the records.

  Why it is safe. Nothing vouches for a key but a certificate chain to the
  genesis `P` hashes: only `P`'s owner can make a key that verifies here,
  and a record's owner already named `P` a writer, so a signer of answers
  for the subject. A copied seal key gives the copier nothing: the ask's
  associated data binds the signer's name, and the proof's binding the
  signer's device and the ephemeral key. A grant is made only to the
  epoch's audience, as it was (§9: the seal key only tells where to wrap).
  What stays: `P`'s owner may make devices at will, as for any listed
  writer. Nothing else of `P` is judged by this: not a log entry about a
  subject no record lists it for, not a head, a summary or a snapshot
  outside the scope, not a members record (`P` is no owner here).

## §8.1 Revocation cut

**Answers.** A revocation cut never lists an answer (an answer is not a log
entry and has no seq): like summary roots, one-key heads, seal keys, grants,
audit answers and an asker's proofs, answers by a revoked key are refused once
the revocation is held (answers.md §13.9).


## §9 Seal

**Answers (answers.md §5).** An answer over sealed collections is sealed under
an audience key derived (HKDF-SHA256) from the content keys of every epoch of
its read set, so only a device in the audience of every one of them holds it;
erasing an epoch's key erases the answers that read in it. What a relay sees of
an answer: its name, kind, the size of its ciphertext and its epoch list.


## §11 Snapshot and state names

A state read by an answer is bound by the digest of each of its tips and by the
applied-set digest, the versions of the collection inside the frontier that no
applied checkpoint covers (answers.md §3.1).


## §13.1 Large payloads

An answer's body travels in pieces as a version's payload does, under the
answer's name, `<A>/seg=<i>` and `<A>/32=manifest/seg=<k>`
(answers.md §5.4); no custody applies to answers.


## §13.5 What a device serves

A device also serves, under its own `32=held` name, the answers it holds
verified, as signed: never one of a key it holds evidence against, one a
revocation refuses, or one it cannot keep (answers.md §6.2, §8.2).


## §14 Prune

An answer has no keep: devices drop the answers they hold of others by their
quota, per signer and in all (answers.md §10).


## §15 Verbs

`get` of an answer name `<D>/32=answer/<id>` or a question name
`<X>/32=question/<AnswerAsk>` answers `Got::Answer` (answers.md §7); the host
surface adds `Device::answer_id`, `publish_answer`, `provide`, `current_read`,
`read_ref`, `ask_answer` and `provider_asks` (the sealed ask exchange, answers.md
§15); `DataError` gains `CannotCheck` and `Answer`, `NextStep` gains
`SetPolicy`.


## §16.2 TLV-TYPE numbers (round 5)

**Answers (round 5).** Names: an answer `<D>/32=answer/<id>` (one component of 32
octets), a piece of one `<A>/seg=<i>` or `<A>/32=manifest/seg=<k>`, a question
`<X>/32=question/<AnswerAsk>` (never fetched), and a held answer
`<H>/32=held/<Name TLV>` (answers.md §11.1). Round 5 adds the TLV numbers
0x05C0–0x05DF for answers (answers.md §11.2); every number is odd.


## §17 Failure model

An answer asked for by id is an owed fetch: at most `FETCH_TRIES` per candidate
and `RELAYS_ASKED` candidates (answers.md §7.2); each piece of an answer in
pieces is asked in rounds.


## §18 Conformance

Answers: cases `a1`–`a23` (answers.md §14); case `c12` is rewritten over a
provider answer.


## §21.8 Device events: the `AnswerEvidence` event

The device event `AnswerEvidence` (kind `AnswerEvidence`, detail
`EventDetail::Answer`, meaning `AnswerKept`) is the evidence of a signed answer
that a recomputation, a second answer at its name, its binding or its read set
contradicts (answers.md §8). It coalesces per signer key as every event does.

## Sentences taken out of paragraphs that stay

- §16.1 Seal key: "A device also answers an Interest for its own `<D>/32=seal` with CanBePrefix by that packet (answers.md §15.8)." (the serving stays; the reference goes)
- §16.1 Asker's proof: "in an ask for an answer, the signer's Name TLV, the `AnswerAsk` TLV and the ask's ephemeral key (answers.md §15.3)", and the label `ndn-data answer ask\0`.
- §19.4: "asks for an answer have a budget of their own of the same size, answers.md §15".
- §21.2: "(round 5's answers add one for an answer whose result differs from a signed one)".
- §21.5 The cap: "five: equivocation, withdrawal, cut, revocation, answer evidence".
- §21.6 Facts: "An equivocation and an answer's evidence have none".
- §21.8 Flooding: "a later cut, revocation or answer evidence".

## Cut from other specifications

### ndn-link.md §8.7 rule 10, the list of what a grant link carries

    - the ask exchange (`<W>/<role>/<device>/32=seal[/<key>]`, `<W>/<role>/<device>/32=ask-answer/…`) of the devices of the folder's namespace and of the namespaces of the writers the record in force lists, in both directions, none of it pushable, the asks rated apart (rule 20);

### ndn-link.md §8.7 rule 20 (the ask exchange across a grant link)

20. **The ask exchange crosses a grant link to the folder's writers** (data-layer.md §19.8, answers.md §15). A member (Bob, who joined by Ann's code) asks a device of the folder (`Device::ask_answer(&device, &question)`): the asker fetches the signer's seal key packet and sends the ask, an Interest with ApplicationParameters whose reply is the signer's own Data. Until round 11 the filter carried nothing under another person's device, so the fetch of `<Ann device>/32=seal/<key>` was dropped at the link and the ask ended `NotReady` ("the signer's seal key is not held yet") though the folder's data crossed the same link. The link now carries, **in both directions and judged at every packet** (rule 5), for each namespace `W` in {the entry's folder's own namespace (`<O>`: the inviter's devices)} ∪ {`Introductions::writer_namespaces(folder)`, read live from the record in force}, and for each device `<W>/<role>/<device>`:

    - `<W>/<role>/<device>/32=seal`, and `…/32=seal/<key>` (one generic component of 32 octets: the seal key packet's name), the last with or without one implicit digest;
    - `<W>/<role>/<device>/32=ask-answer/<ParametersSha256Digest>` (32 octets), with or without one implicit digest after it: the ask and its reply.

    **The match is component-wise and exact** (`ask_exchange_namespace`): exactly **two** components lie between `W` and the keyword, the first a *generic* component that names a role of the layout (`admin`, `member`, `node`, `guest`: `ndn_cert::Role`), the second a generic component (the device), the keyword is the first keyword of the name, and `W` is **equal** to a listed namespace (never a prefix of the name's front: a writer `/home/carol/member/x` opens `/home/carol/member/x/<role>/<device>/…` or, when its namespace is held, `/home/carol/…`, and never `/home`'s devices; `<W>/member/x/y/32=seal`, `<W>/owner/x/32=seal`, `<W>/member/x/32=log/…` and a collection whose path spells `member/x/32=seal` are no device's). It is **not pushable**: `grant_pushes` is unchanged (Data a peer sends under another device's seal or ask names is dropped as before; asks are Interests, and the replies are this device's own Data sent out, which `names` alone judges). A writer the record drops is out at the next packet; with no record held for the folder the inviter's own devices cross and no other writer's.

    **Readers.** The names are the same for a `Reader` entry: what a reader sends toward this device is Interests, which `receives` carries under the name filter alone (an Interest's ApplicationParameters are not looked at, and the Interest's name carries their digest), and the reply is this device's Data sent out, which `sends` carries under the same filter (`answers_in`, the push filter, judges only Data the *reader* sends). The link does not decide who is answered: the signer's gate does (`AnswerConfig::serve_asks`, `ask_roles`, the asker's proof, and under `OwnAndMembers` a device the members record in force **lists as a writer or a reader** of every collection the question reads: `NotServed` for one it does not list, `NotAudience` for one outside a sealed read's audience). A listed reader is answered under `OwnAndMembers`; under the default `Own` only the signer's own namespace is.

    **The joiner's routes need nothing added** (rules 16 and 18; the cases of §8.9 install no route of their own): the inviter's device is routed over the link by the link's default routes (§10: the peer's device name, at cost 0), and each other writer's namespace `W` by rule 18, so `<Ann device>/32=…` and `<W device>/32=…` reach the inviter's link by longest prefix. The round-9 filter (only namespaces that name themselves, never `/localhost`, `/localhop` or the root; `JOINED_ROUTES_MAX`) is unchanged. The inviter relays an ask for another writer's device by the route the link gives it toward that device (§10, rule 19). Whether the asker's data layer can verify a seal key packet of a third writer's device is that layer's (answers.md §15), not the link's.

    **No other path carries a seal key** (round 11, I1). The folder's own names the data layer carries (`folder_carries`) include a seal key only as the **exact name** `<W>/<role>/<device>/32=seal/<key>` of a device of the folder's **own namespace**, and `writer_carries` adds it only for a device of a namespace the record in force lists as a writer's (exactly two components below `W`, never a namespace that merely starts like it): not every device's. Until round 11 the data layer's clause carried the seal key of **any** device's namespace, so the exact name of a stranger's device crossed the link although the filter above would have blocked it, and the test that said so (`the_devices_of_a_third_party_cross_only_while_the_record_lists_her`) used the prefix `<device>/32=seal`, a name no data layer packet has; it names the exact form now.

    **The asks are rated apart, per link.** The Interests `<W>/<role>/<device>/32=ask-answer/<digest>` a grant link's peer sends (`grants::is_ask_answer`: the shape of rule 20, the keyword `ask-answer`) take tokens from a bucket of their own, `ASK_INTERESTS` (`policy.rs`): **10 at once, refilled at 1 a second**, per link (as the quota of the link's key is, §15.3), after the link's own buckets of frames and bytes (§15.3) and before the namespace's shared one: an ask over it is **dropped without a Nack** (an Interest over the link's frames, bytes or the namespace's share is answered with a Congestion Nack, §8.3 rule 7; an ask over its own bucket is not: a peer that floods the exchange is told nothing), counted in the scope's dropped counter and logged with the reason ("dropped an Interest … over the rate limit of its names: …"), and it takes nothing of the shared bucket, so a flood of asks does not use up the namespace's share. **Why these numbers.** An ask costs its signer more than a fetch: it opens a sealed envelope, verifies the asker's proof and may evaluate. A grant link's frame rate (32,768/s) would let a member that holds a grant send the signer thousands of such Interests a second, each with parameters of its own, all of which the signer's Device must queue and turn away; and what the signer's own gate refuses (`NotServed`, `NotAudience`) is no help once the work of opening them is spent. An **honest** asker has one ask in flight, and `Device::ask_answer` sends the same Interest at most `ASK_SENDS` = 3 times (nothing answered) over at most `ASK_ATTEMPTS` = 3 asks to one signer (the signer `Busy` or the answer `Pending`; each waits the `retry_after` it is told, and sends new parameters), so **at most 9 Interests per signer per question**: a burst of 10 passes a whole question at the worst. A question asked again soon after finds fewer tokens, and an Interest the link dropped is sent again by the asker's own `ASK_SENDS` retries, each after the Interest's lifetime, so it arrives a little later and is not lost; only a peer that sends more than a question's worth at once, again and again, is held to 1 a second. The bucket is a policy of the link layer (`ASK_INTERESTS`, a constant beside `ENROLLMENT_INTERESTS`), and the mechanism is `ndn_face_quic::LinkScope::rated` (`RatedInterests`: a name filter and a `RateLimit`, any link scope's); only grant links set it. The fetch of a seal key (`…/32=seal/<key>`) is not an ask and takes nothing of it.

### ndn-link.md §8.9 conformance paragraph of rule 20

ndn-ext `crates/faces/ndn-link/tests/asks.rs` (rule 20; real QUIC, real data-layer devices on real forwarders; Ann answers asks under `AskServing::OwnAndMembers` with an evaluator both sides know): `a_writer_asks_the_inviters_device_over_his_grant_link_and_is_answered` and `a_reader_the_record_lists_asks_the_inviters_device_and_is_answered` (`Device::ask_answer` to Ann's device over the joiner's own grant link, no route of the test's: the answer is the definition's text), `people_named_by_their_keys_ask_each_other_over_the_grant_link` (the same between `/user/161=…` people, as ndf's peers are), `the_seal_key_of_another_writers_real_device_crosses_the_inviters_link` (a third writer's device over the joiner's route and the inviter's link), `the_devices_of_a_third_party_cross_only_while_the_record_lists_her` (the **exact name** `<W>/<role>/<device>/32=seal/<key>` of a device answering on the inviter's forwarder: blocked, then crosses once the record lists the namespace, then blocked again once it drops it; the data layer's `folder_carries` carries no seal key of another namespace's device, `folder_scope::tests`), `what_is_not_a_device_of_a_listed_namespace_stays_blocked` (a role the layout does not name, three components under the namespace, a namespace the record does not list, `/home`'s device and `/home/carol`'s against a writer `/home/carol/member/other`, all in the exact form) and `every_role_of_the_layout_crosses_and_a_look_alike_does_not`; the matcher itself in `grants::tests` (`the_ask_exchange_of_a_device_is_its_namespace_and_nothing_else`, `what_only_looks_like_the_ask_exchange_of_a_device_is_not`, `the_ask_exchange_follows_the_record_live_and_is_no_push`). The ask rate: `tests/ask_rate.rs` (`a_flood_of_asks_over_a_grant_link_is_held_to_its_rate_at_the_link`: Bob's 100 asks at once reach the signer's Device at most `ASK_INTERESTS` burst plus the refill, every one that crossed is answered, and the fetch of a seal key still crosses; `an_honest_ask_of_nine_sends_in_a_burst_passes`) and ndn-face-quic's `scope::tests::rated_interests_take_a_bucket_of_their_own`.


### trust-context.md (role-less device): the sentence began "A device with no role is likewise not served as one of"

the person's own by an ask for an answer in a namespace that declares the
role layout (answers.md §15.7).

### Sentences taken out of paragraphs that stay (ndn-link.md)

- §8.3 rule 4 (rated classes): "the ask exchange of a grant link (§8.7 rule 20) and"; "(the exchange has a gate of its own and a flood of it deserves no answer)".
- §8.7 rule 5 table: "the ask exchange 10 at once, 1 a second (rule 20)".
- §8.7 rule 10: "nor an answer"; "and the ask exchange of the folder's own namespace's devices"; ", rule 20" after `writer_carries`.
- §15.3 table and text: "The ask exchange keeps its bucket of 10, 1 a second, silent (§8.7 rule 20)"; "Its asks of the ask exchange are held to 10 and then 1 a second (§8.7 rule 20)".
- §20 decision 41: "and the ask bucket"; "The ask exchange's own bucket stays silent: a peer that floods it is told nothing."
- (data-layer.md §15 Verbs, not ndn-link.md) "A function's answer is a `get` on its name (a later slice)."
