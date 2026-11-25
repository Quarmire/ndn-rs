# Channel: ephemeral live data over a space

- **Status:** stage 2 built: the setup (names, the ask, the session, judging at both ends, renewal, re-keying, ending, the announce, limits and refusals, the setup TLVs and their vectors). Stage 3 part 1 built: the frame (§11: header, key schedule and seal, messages, kinds, limits, short frames on L2, vectors, threat notes). The receiver is built (§12: the order of checks before any cryptography, the replay window, the generation check, key epochs, the name table and its 50 ms hold, `HELLO`, standing values, the queues per mode and the gap rule, `Items`, limits, threat notes); the writer's batching and the modes' sender side are added with the rest of stage 3; fan-out in stage 4; checkpoints in stage 5. Where a later stage's text is not here yet, it is not specified yet, and nothing in this file says how it will be.
- **Implementation:** `ndn-heap`, module `chan` (`ndn-rs/crates/app/ndn-heap/src/chan/`): `wire.rs` (the records), `answer.rs` (the sender judges), `ask.rs` (the receiver asks and judges), `channels.rs` (the sender's table), `sessions.rs` (the receiver's store), `hub.rs` (the node's state, the announce, the maintenance task), `standing.rs` (membership, shared with signals).
- **Scope:** an ephemeral **channel**: one device of a writer of a space sends live data (presence, a cursor, a drag) to the devices of the space's readers and writers, without making an entry. This file specifies how a channel is **set up** between two devices by signed NDN: who is answered, how a key reaches only the devices that may hold it, how a session ends, is renewed and is re-keyed; and the **frame** (§11) that carries the data once it is set up: the header, the key schedule and the seal, the messages, the limits and the short-frame rule for raw L2 faces. It builds on [heap.md](heap.md) (names §2, the members record §5, epochs and audiences §6, the lapsed rule §9.3) and uses ndn-link's carrier ([ndn-link.md](ndn-link.md)) for what comes after setup.

The key words "MUST", "MUST NOT", "SHOULD" and "MAY" are as in BCP 14, in capitals only.

## 1. Terminology

| Term | Meaning |
|---|---|
| space | An `ndn-heap` space `<O>/32=data/<c1…c4>` ([heap.md](heap.md) §2.1). Its members record ([heap.md](heap.md) §5) says who writes and who reads. |
| sender | A **writer's device** that emits in a space. A channel has exactly one sender. |
| receiver | A device of a reader or a writer that holds a channel's session. |
| channel | One sender's emissions in one space in one mode, for the life of one session: a random 64-bit **channel id**, one key, one name-id table, one sequence. A sender has at most one channel per (space, mode). |
| session | What the sender's signed Data gives a receiver: the channel id, the key (wrapped), the carriers, the mode, the table. It lives until its lifetime passes or it is re-keyed. |
| ask | The receiver's signed Interest that requests a session. |
| key epoch | A counter of the channel's re-keys (`S_KEY_EPOCH`). The key of a channel changes with it; the id does not. |
| key holder | A device that holds a channel's key: the sender and every receiver it answered. |
| standing | A key **stands** for a space when the person it belongs to is listed by the space's record in the role asked, the key's role is one that may act as an owner device, and the trust context that governs it does not revoke it and this node does not mark it suspected (§4.1). |
| announce | An unsigned Interest a sender pushes into the space's sync group to say it has a channel. A hint, never a proof (§9). |

## 2. Names

- **The ask and its answer** are named `<sender>/32=chan/<ParametersSha256Digest>`, where `<sender>` is the **sender's device name**: the components before the keyword, a device name (no keyword and no digest component). Exactly one component follows the keyword, and it is a ParametersSha256DigestComponent of 32 octets. Nothing else parses as a channel name. The Interest carries ApplicationParameters (§3) and is signed by the **receiver's device key**; the Data of exactly that name is signed by the **sender's device key**.
- **Why the name is under the sender.** Every packet a device signs is named under that device ([heap.md](heap.md) §2.2): the validator picks the trust context, the schema and the anchors by the name, a node serves exactly the prefix of its own device, and one Interest cannot gather one Data from every writer (the PIT is satisfied once). So a receiver asks each sender by that sender's name. The space and the wanted prefix are in the ApplicationParameters, which the signature and the parameters digest cover.
- **`chan` is a core keyword.** The keyword router ([heap.md](heap.md) §2.4) sends `<device>/32=chan/…` to the channel setup; an extension is never given it.
- **The announce** is named `<sync group of the space>/32=chan/<ParametersSha256Digest>`: the space's sync group `<O>/32=sync/<c1>[/<c2>…]` ([heap.md](heap.md) §2.5) followed by the same two components.

## 3. The setup

### 3.1 The ask

The ask is an Interest named `<sender>/32=chan/<digest>`, `MustBeFresh`, InterestLifetime 4 s, ApplicationParameters = one `CHAN_ASK` (§7), at most 8 KiB. It is signed: an `InterestSignatureInfo` with the receiver's device key name as KeyLocator, a `SignatureNonce` and a `SignatureTime`. A node signs no Interest but this one: a signed Interest of a device's key is a command wherever that key is trusted.

The ask names the space, the path prefix the receiver wants (empty: everything), the mode (`Latest`, `Reliable`, `Window`), the receiver's X25519 recipient key (the key `K` is wrapped to), the carriers it can use, the lifetime it wants in seconds, in a sealed space the epoch it holds in force, and up to four certificates (`ASKER_CERT`: 4,096 octets each, 6,144 in all) of its signer's chain, so the sender judges the signature from what is held and carried and **fetches nothing**.

### 3.2 The session

The session is the Content of a Data of exactly the ask's name, signed by the sender's device key, `FreshnessPeriod` 0, carried in an NDNLPv2 packet with `CachePolicy = NoCache`: nothing of a channel's setup is cached. The Content is one `CHAN_SESSION` (§7), at most 8,000 octets. It names the channel id (8 octets, random from the system's CSPRNG), the sender and the space and the mode, the **key epoch**, the key's id (the first 8 octets of HKDF-SHA256 of `K` with info `ndn-channel/id/1`), the **wrapped key**, the AEAD (1 AES-256-GCM when the CPU has AES and carry-less multiplication, else 2 ChaCha20-Poly1305: every receiver supports both), the carriers on offer, the name table bound so far (at most 64 binds and 4 KiB), the checkpoint period, in `Window` mode the window, the lifetime in seconds counted **from receipt on the receiver's monotonic clock**, in a sealed space the audience epoch the sender judged the receiver by, the largest datagram frame, the next sequence the sender will use, and up to four certificates of the sender's chain (`S_CERT`).

- **The key.** `K` is 32 random octets from the CSPRNG per sender, per space, per mode, per session. It is never derived from a space's epoch key (a derivation would hand every member of an epoch every sender's key unasked, and a public space has no epoch key). The epoch decides the **audience** (who is judged in); it does not decide the key. The AEAD of a frame never uses `K` directly: it uses `HKDF-SHA256(K, "ndn-channel/frame/1" ‖ channel id ‖ key epoch)`.
- **The wrap.** `S_WRAP` is the 32-octet ephemeral X25519 public key followed by the sealed key (`nonce (12) ‖ tag (16) ‖ ciphertext (32)`), made as a grant's key is ([heap.md](heap.md) §6.5): X25519 between the ephemeral key and the ask's recipient key, a key-encryption key `HKDF-SHA256(shared, info "ndn-security/confidentiality/x25519-kek/1" ‖ ephemeral ‖ recipient)`, and the AEAD of `K` under it with the **Name TLV of the answering Data as the AAD**. So the key opens only with the recipient's secret and only under that name.
- **One channel, many receivers.** A second receiver's ask for the same (space, mode) is answered with the same channel id and the **current** key.

### 3.3 Judging the asker

The sender judges the ask in this order, cheapest first, so a stranger costs nothing and a member costs one signature verification. The steps that decline without a word answer a Nack and sign nothing.

1. **The name and the size.** The name parses as `<this device>/32=chan/<digest>`; the ApplicationParameters are at most 8 KiB, hash (as the Interest's `ParametersSha256Digest` is made) to the digest, and parse as a `CHAN_ASK`; the Interest is signed and its KeyLocator names a key of a device (`<device>/KEY/<id>`); the space is a space name and is open here as a member. Otherwise a `NoRoute` Nack. An ask over 8 KiB is counted and Nacked unread.
2. **Standing.** The key stands as a **listed** person ([4.1](#41-standing)): a writer or a reader the record lists, a key whose role is owner-capable, not revoked, not suspected, **by the entries held now**. A public space does not make a reader of an unlisted person: **channels need a listed person**, because a channel's key is wrapped to a judged key (kept data in a public space stays readable by anyone; live data does not). Otherwise a `NoRoute` Nack. This is a lookup: no signature is checked for a stranger.
3. **The asker's rate.** A token bucket per asker key: 4 asks a second, a burst of 8. Beyond it a `Congestion` Nack (the asker is known to be a member by now; the Nack says "slower", not "no"). The asker's next step is to ask again later: it is `Busy`, `RetryLater`.
4. **The signature.** The Interest signature verifies by the live rule from the certificates held and the at most four carried, **fetching nothing**; the carried certificates are held only as unverified copies for the hop they answer and dropped again unless the walk reaches a trust anchor. The signer is judged by the trust context of **its own device**, not of the name the Interest is under. A chain not held and not carried is `Pending`: a `NotYet` Nack, which says "ask again when you carry your chain". A signature that does not verify is a `NoRoute` Nack. This is the one expensive step, and a member that forged nothing is the only asker that reaches it.
5. **Replay.** The replay guard of signed Interests (the asker's `SignatureNonce` and `SignatureTime` against what was seen for that key; it remembers the last 512 asks of a key, which is more than 120 s at the rate of step 3) answers a repeated ask with a `Duplicate` Nack. An ask with neither a nonce nor a time is a `NoRoute` Nack. A replayed ask would only yield a session wrapped to the asker's own recipient key, which only it can open, so the guard limits cost and decides no trust. An honest asker signs every ask afresh (a new nonce), so a `Duplicate` it gets is a copy of an ask that already arrived (a retransmission on the path): its next ask is accepted, `Busy`, `RetryLater`.

The asker is now a verified member, and what follows is answered with a **signed** record (a session or a refusal), read again under one lock of the record, as the key that signed the ask:

6. Standing again. The record may have moved while the signature was checked; if the key no longer stands, a `NoRoute` Nack.
7. **This device is a writer** of the space (`standing` for its own key, writers only). It always is, or it would have no channel; if it is not, a `NoRoute` Nack and its channels of that space end.
8. **A sealed space's audience.** The sender's epoch in force must exist (else `NotReady`); if the ask names an epoch that is not the epoch in force, a sender that has never seen it answers `StaleEpoch` and one that has seen it and has moved on answers `NotReady`; the asker's person must be in the audience of the epoch in force (else a signed `NotAudience` refusal: an authenticated asker learns only what a plain read of a sealed path tells it).
9. **The mode needs a stream.** A `Reliable` or `Window` ask whose carriers list no stream is a `NoStream` refusal.
10. **The caps** ([§6](#6-limits-and-refusals)): channels per sender and receivers per channel; else a signed `TooMany`.
11. The channel of the asked mode is found or made; the asker is added to it (§3.5); the key is wrapped; the Data is signed.

### 3.4 Judging the sender

The receiver judges the answer in this order:

1. The Data's name equals the Interest's name.
2. The Data verifies as the sender's by the durable rule ([heap.md](heap.md) §9: the signature and the certificate chain, no clock except for a key whose role needs a cut), from the certificates held and the at most four the session carries, fetching nothing; the key that signed it is a key of the device the name is under. A Data that cannot be judged now is not used.
3. **The sender is a writer now**: its key stands as a writer, not revoked, not suspected. A reader's device never emits: a Data signed by one is `SenderNotWriter`, whatever it holds.
4. A `CHAN_REFUSAL` is told as it is: it is signed, so it is the sender's word.
5. The session names the sender, the space and the mode that were asked.
6. **A sealed space.** `S_AUDIENCE_EPOCH` must equal the epoch in force at the receiver. One the receiver knows and that is no longer in force is a sender that has not caught up: `StaleEpoch`, ask again soon. One the receiver does not hold waits for the record: `NotReady`.
7. **The key opens** under the receiver's recipient secret with the Data's Name TLV as the AAD, and is the key the session names (`S_KEY_ID`).
8. **The session is installed**, its lifetime counted from receipt on the monotonic clock. If a session of the same channel id is held it is **renewed**: the key epoch moves, the lifetime restarts. A session of the same sender and mode with another channel id replaces the old one: the sender began a new channel.

### 3.5 What the sender keeps

The sender's channel table holds, per (space, mode), the channel's id, its key and key epoch, the next sequence, the audience epoch the receivers were judged by, and, per receiver **device**, the key that signed its last ask, the key epoch it was last given, when, and for how long. A session's lifetime is the ask's, clamped to 24 hours, and one hour when the ask names none; it is never refused for this. A receiver is a receiver until its lifetime and 5 s of grace passed since it was last given a key. A channel nobody holds for a default lifetime ends: its key is zeroed.

### 3.6 Ended, renewed, re-keyed

A channel's life is bounded by five things, each a signed record or a local fact, never a timer alone:

1. **The members record, and the trust generation.** The sender re-judges every receiver, offline, in one call, when the space's record changes or a trust context that revokes keys is adopted (both wake the node's maintenance task; it also looks every 250 ms): a receiver that no longer stands (its person left the record, or its key is revoked or suspected) or whose person left the audience of the epoch in force is **dropped**, and the channel is **re-keyed at once**. A channel whose audience epoch moved is re-keyed too. These are two causes, so removing a reader of a **sealed** space re-keys twice: once for the removal, and again when the owner's next epoch (which the removal owes) arrives and moves the audience. Between them the old epoch is no longer in force (a person it names is no longer a reader) and no audience can be judged: a receiver that still stands is kept, none is dropped for the want of an epoch, and the next ask is answered `NotReady`. Nothing re-keys without one of these causes. A sender that is no longer a writer ends its channels of the space. A receiver does the same for every sender it holds, against the writers of the record: a session caches the pair `(trust generation, the space's fold version)` it was judged under and exposes `is_current()` (two atomic loads); when either has moved the sender is judged again from what the node holds before another frame is delivered, and a sender that no longer stands as a writer ends the session with `NotMember` and the reason. A receiver whose own person left the space drops its sessions of it.
2. **A grant** of a link ends the link and so the route (stage 4).
3. **The lifetime.** A session is **usable** until its lifetime and a 5 s grace passed since receipt, counted on the monotonic clock. A session past that is not used and is dropped.
4. **The sender stops answering.** A removed receiver's asks are Nacked; a stopped sender answers none.
5. **The route's lifetime** (stage 4).

**Renewal.** A receiver asks again at 75 % of the lifetime, with the same channel id; the answer carries the same `S_ID`, a new lifetime and, because a receiver that holds the current key and asks after half its lifetime renews, a **new key** (`S_KEY_EPOCH` + 1). An ask sooner than that, or from a receiver that holds an older key, is given the key as it is: no receiver can make the others ask again at will. A renewal that failed is tried again after 10 s.

**Re-keying is pulled.** The sender re-keys at every renewal, at once when a receiver is removed or the trust generation moved, when the sealed space's epoch changed, when a receiver's lease ran out, and before the sequence passes 2^63. It seals under the new key from the next frame and answers asks with it. A receiver that sees a frame under a key epoch it does not hold asks again, **at most once a second per sender**; the sender answers every asker it still judges in and Nacks the removed. **Nothing is pushed to a receiver**: nothing a removed member could be sent, nothing to forge.

**The key before.** A receiver accepts the key before the current one for `REKEY_GRACE` (5 s) after it first saw the new key epoch (in a frame, or in the answer, whichever came first), so frames in flight are not lost. A removed member's forgeries under the old key are bounded to that grace and then to the checkpoint window of stage 5.

**After a removal** the removed member holds the old key and can read what was sealed under it; it cannot open anything sealed after the re-key.

## 4. Who may take part

### 4.1 Standing

`standing(space, key, who)` is the one question both ends ask, and signals ask too ([signals.md](signals.md) keeps its own surface and calls it). It holds when: the key names a device (`<device>/KEY/<id>`); the trust context governing the key (the node's own for a person it holds, else the view adopted for the person while a listing of the space names her) names a person the record lists as `who` says; the key's role is one that acts as an owner device where the namespace declares the role layout (a `guest` or a `node` device is none, [heap.md](heap.md) §9.9); the context does not revoke the key; and this node does not mark it suspected. `who` is **Writer** (a writer; the owner always is), **Reader** (a writer, or anyone for a public space: what signals ask) or **Listed** (a writer or a reader the record lists: what a channel asks of a receiver). The answer is read from what is held at the call: it flips on the first call after the entry that removes a person, or the context that revokes a key, is held.

### 4.2 Who may call what

A device **sends** only as a writer; it **receives** as a reader or a writer the record lists. A follower (a node that follows the space's group but is no member) takes no part. A `guest` or `node` device never sends or receives.

## 5. Surface

On a node's handle: `ask_channel(space, device)` and `ask_channel_in(space, device, mode)` ask a sender and return the session's `ChannelInfo`; `sign_interest(prefix, parameters)` signs the one Interest a node signs (`<device>/32=chan`, refused for any other name). Every refusal is a `ChanError`, which says why and, by `next()`, what to do in the heap's `NextStep` vocabulary. For the frame layer: a session store (`RecvSessions`: `get(id)`, `unknown_epoch(id, low, now)`), a session (`RecvSession`: `frame_key(low, now)`, `usable(now)`, `is_current()`, `recheck(node)`, `terms()`) and the sender's table (`Channels`: `current(space, mode)`, `open`, `note_seq`, `close`), all in `ndn-heap`'s `chan` module.

## 6. Limits and refusals

| What | Limit | Over it |
|---|---|---|
| Ask size / session size | 8 KiB / 8,000 octets | Nacked unread / the sender drops the certificates it carries |
| Asks per asker key | 4 a second, burst 8 | a `Congestion` Nack |
| Channels per sender / receivers per channel | 64 / 256 | a signed `TooMany` refusal, retry in 30 s |
| Session lifetime | 1 h default, at most 24 h, renewed at 75 % | the ask's lifetime is clamped, not refused |
| Lifetime grace / key grace | 5 s / 5 s | the session is not used / the old key is not accepted |
| Asks for an unknown key epoch | once a second per sender | dropped undecrypted |
| Announce-driven asks | one per device per 10 s, 32 in progress per space | ignored |
| Announce | 1 KiB of ApplicationParameters | ignored |

Every refusal a person can see says why and what to do, in the heap's `NextStep` vocabulary.

| Refusal | Code | `NextStep` | Said by |
|---|---|---|---|
| `NotAudience` | 1 | `AskOwner` (ask the owner to add you as a reader, or to write an epoch that lists you) | the sender, signed |
| `Busy` | 2 | `RetryLater` | the sender, signed |
| `NoStream` | 3 | `FixRequest` (ask with `Latest`, or `put`) | the sender, signed |
| `StaleEpoch` | 4 | `RetryLater` (retry in 1 s) | the sender signed; the receiver for a session on an older epoch |
| `TooMany` | 5 | `RetryLater` | the sender, signed |
| `NotReady` | 6 | `RetryLater` (retry in 2 s) | the sender signed; the receiver for a session on a newer epoch |
| `NotAnswered` (a `NoRoute` Nack) | | `RetryLater` | the network: not a member by the entries the sender holds, or no certificate it trusts, or no channel to give |
| `Busy` (a `Congestion`, `NotYet` or `Duplicate` Nack) | | `RetryLater` | the sender: over its rate for this device (`Congestion`), the chain of the asker's key not held and not carried (`NotYet`: carry the chain, the ask does), or a copy of an ask it saw (`Duplicate`: the next ask is signed afresh) |
| `Unreachable` (no answer) | | `RetryLater` | none |
| `SenderNotWriter` | | `FixRequest` (ask a device of a writer) | the receiver |
| `BadAnswer` | | `RetryLater` | the receiver |
| `NotAllowed` | | `AskOwner` | the receiver, for its own device |

## 7. TLV types

The setup's TLV-TYPEs are the block **0x0660–0x06BF**, registered to this file in the [specification registry](README.md#tlv-type-numbers). Odd numbers are critical: an unknown odd type inside these records is a malformed record. Even numbers are skippable and reserved for additive fields, as in [heap.md](heap.md) §3.4: an unknown even type is skipped. Numbers are NonNegativeIntegers. `Name` values are a Name's components, as the value of the TLV. `ASKER_CERT` is heap's 0x063D.

| Type | Name | Value |
|---|---|---|
| 0x0661 | `CHAN_ASK` | `ASK_SPACE`, `ASK_PREFIX`, `ASK_MODE`, `ASK_RECIPIENT`, `ASK_CARRIERS`, `ASK_LIFETIME`, `ASK_EPOCH`?, `ASK_SINCE`?, `ASKER_CERT`* (0x063D) |
| 0x0663 | `ASK_SPACE` | Name |
| 0x0665 | `ASK_PREFIX` | Name: the path prefix the receiver wants (a filter and a hint for the table; the channel carries the whole space's emissions of the sender) |
| 0x0667 | `ASK_MODE` | 1 `Latest`, 2 `Reliable`, 3 `Window` |
| 0x0669 | `ASK_RECIPIENT` | 32 octets: the asker's X25519 recipient key |
| 0x066B | `ASK_CARRIERS` | the carriers the asker can use: a list of kind octets (1 datagram, 2 stream, 3 face-bytes, 4 L2, 5 ring), at most 16 |
| 0x066D | `ASK_LIFETIME` | seconds the asker wants (at most 86,400, clamped) |
| 0x066F | `ASK_EPOCH` | an EpochId (`Name(creator)`, `SEQ` 0x060B): the epoch the asker holds in force (sealed spaces) |
| 0x0671 | `ASK_SINCE` | `Window` only: the first sequence the asker still needs replayed |
| 0x0673 | `CHAN_SESSION` | the Data's Content: the fields below |
| 0x0675 | `S_ID` | 8 octets: the channel id (random, CSPRNG) |
| 0x0677 | `S_SENDER` | Name: the sender's device |
| 0x0679 | `S_SPACE` | Name |
| 0x067B | `S_MODE` | as `ASK_MODE` |
| 0x067D | `S_KEY_EPOCH` | NonNegativeInteger (at most 2^32 − 1), counts re-keys; the frame header carries its low 8 bits |
| 0x067F | `S_KEY_ID` | 8 octets: the first 8 of HKDF-SHA256(K, info `"ndn-channel/id/1"`) |
| 0x0681 | `S_WRAP` | 32 octets ephemeral X25519 key, then `nonce (12) ‖ tag (16) ‖ ciphertext` of `K` (32), wrapped to `ASK_RECIPIENT` (§3.2), AAD = the Data's Name TLV |
| 0x0683 | `S_AEAD` | 1 AES-256-GCM, 2 ChaCha20-Poly1305 |
| 0x0685 | `S_CARRIER` | repeatable: a kind octet, then its parameters |
| 0x0687 | `S_TABLE` | `S_BIND`*, at most 64 binds and 4 KiB (the rest follow on the stream) |
| 0x0689 | `S_BIND` | `B_ID`, `B_NAME` |
| 0x068B | `S_CKPT_MS` | checkpoint period in ms |
| 0x068D | `S_WINDOW` | `Window` mode: `W_MESSAGES`, `W_BYTES`, `W_MS` |
| 0x068F | `S_LIFETIME` | seconds, from receipt, on the receiver's monotonic clock |
| 0x0691 | `S_AUDIENCE_EPOCH` | an EpochId (sealed spaces) |
| 0x0693 | `S_FRAME_MAX` | the largest frame the sender will send on a datagram carrier |
| 0x0695 | `S_SEQ` | the next sequence the sender will use |
| 0x0697 | `S_CERT` | repeatable, at most 4 and 6,144 octets in all, each at most 4,096: a certificate Data of the sender's chain |
| 0x0699 | `CHAN_REFUSAL` | `R_CODE`, `R_TEXT`, `R_RETRY` |
| 0x069B | `R_CODE` | 1 `NotAudience`, 2 `Busy`, 3 `NoStream`, 4 `StaleEpoch`, 5 `TooMany`, 6 `NotReady` |
| 0x069D | `R_TEXT` | UTF-8, at most 256 octets: why, and what to do |
| 0x069F | `R_RETRY` | milliseconds |
| 0x06A1 | `CHAN_ANNOUNCE` | `S_SENDER`, `ASK_MODE`+ (each mode once): the ApplicationParameters of an announce |
| 0x06A3 | `B_ID` | NonNegativeInteger: a name id |
| 0x06A5 | `B_NAME` | Name |
| 0x06A7 | `W_MESSAGES` | messages a window replays |
| 0x06A9 | `W_BYTES` | octets a window replays |
| 0x06AB | `W_MS` | milliseconds a window replays |

The whole `CHAN_ASK` is at most 8 KiB and the whole `CHAN_SESSION` at most 8,000 octets: larger is refused when written and when read. The field order above is the order written; a reader accepts any order and refuses a field twice or a required field absent.

## 8. Test vectors

Hex, one record each, as the implementation writes them (the same octets are asserted in `chan/wire_tests.rs`).

`CHAN_ASK`: space `/alice/32=data/notes`, prefix `/cursors`, mode `Latest`, recipient 32 × `11`, carriers 1 and 2, lifetime 3600, epoch (`/alice/laptop`, seq 3), since 9, one certificate `c0de01`:

```
fd066180fd0663140805616c69636520046461746108056e6f746573fd0665090807637572736f7273fd06670101fd0669201111111111111111111111111111111111111111111111111111111111111111fd066b020102fd066d020e10fd066f16070f0805616c69636508066c6170746f70fd060b0103fd06710109fd063d03c0de01
```

`CHAN_SESSION`: id `0102030405060708`, sender `/bob/phone`, the same space, mode `Window`, key epoch 2, key id 8 × `aa`, a 40-octet wrap of `bb`, AES-256-GCM, carriers 1 and 2 with no parameters, one bind (1, `/cursor/x`), checkpoint 20 ms, window (256, 1,048,576, 10,000), lifetime 3600, audience epoch (`/alice/laptop`, 3), frame limit 1200, sequence 7, one certificate `c0de02`:

```
fd0673f0fd0675080102030405060708fd06770c0803626f62080570686f6e65fd0679140805616c69636520046461746108056e6f746573fd067b0103fd067d0102fd067f08aaaaaaaaaaaaaaaafd068128bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbfd06830101fd06850101fd06850102fd068718fd068914fd06a30101fd06a50b0806637572736f72080178fd068b0114fd068d14fd06a7020100fd06a90400100000fd06ab022710fd068f020e10fd069116070f0805616c69636508066c6170746f70fd060b0103fd06930204b0fd06950107fd069703c0de02
```

`CHAN_REFUSAL`: `NotAudience`, "ask the owner to add you as a reader", retry 0:

```
fd069932fd069b0101fd069d2461736b20746865206f776e657220746f2061646420796f75206173206120726561646572fd069f0100
```

`CHAN_ANNOUNCE`: sender `/bob/phone`, modes `Latest` and `Window`:

```
fd06a11afd06770c0803626f62080570686f6e65fd06670101fd06670103
```

## 9. The announce

A sender pushes, once when it opens a channel, at every change of the space's members, and every 30 s while the channel lives, **one unsigned Interest** `<sync group of the space>/32=chan/<digest>` whose ApplicationParameters are a `CHAN_ANNOUNCE` (the sender's device and its modes), InterestLifetime 1 s, HopLimit 8. Nobody answers it and nothing caches it. It rides the group every member's forwarder already carries ([heap.md](heap.md) §2.5).

A receiver takes it as a **hint only**:

1. The parameters are at most 1 KiB and hash to the digest in the name; the group is a space this device holds as a member.
2. **Offline**, the announcing device's person (the person of the trust context governing it) must be a **writer** of the space. A stranger's announce costs this lookup and nothing else: no ask, no signature, no packet.
3. The device must be **wanted**: this device holds a registration of interest in live data of the space (an `Items` of a `get` in stage 6 holds one). Without one the hint is counted and ignored: a device that wants nothing live asks nobody.
4. Each device is asked at most once in 10 s, and at most 32 announce-driven asks are in progress per space; the rest are ignored. The ask is the setup of §3, one per announced mode, judged as any ask is: the announce decides nothing.

The sync driver never sees an announce: the sync face's reader takes a name of this shape off the face before the driver would see it. (A name under a group whose next component is not a version is not a Sync Interest in any case: the multi-group driver routes an Interest to a group by a trailing `v=` version component and drops one that has none.)

## 10. Threat notes for the setup

- **A stranger's ask.** A person the record does not list gets a `NoRoute` Nack after a table lookup: no signature is verified, none is made, nothing is fetched. A counter of the sender's signature walks proves it. A member that forged an ask (a stranger's key named as a member's) costs one verification and a Nack.
- **A replayed ask.** The guard answers a repeat of a signed ask with `Duplicate` within what it remembers. A sender that forgot (it restarted) answers the replay with a session wrapped to the **asker's** recipient key, which only the asker opens: whoever replays the ask holds nothing.
- **A forged session.** The session is a Data of the sender's device, judged by the durable rule; a Data signed by a key that is no writer is refused. A session on an epoch the receiver does not accept is refused. The wrapped key opens only with the receiver's own secret under the Data's name: a session copied to another name, or another device, opens nothing.
- **A stale or future epoch.** A sender on an older epoch is `StaleEpoch` (ask again soon); one on an epoch the receiver has not seen waits for the record (`NotReady`). Neither installs a session.
- **Removal.** The sender drops a removed receiver and re-keys at once; the receiver's asks are Nacked; it holds the old key and can read what was sealed under it, and nothing sealed after. A removed or revoked sender is dropped by every receiver at the first frame after the node holds the removing record or the revocation.
- **The announce is a hint.** It is unsigned; whoever can reach the sync group can send one. The worst it does is make a device that wants live data ask a writer it would have asked anyway, at most once in 10 s per device and 32 at a time per space; every ask is judged by signature at the sender and every answer by signature at the receiver.
- **Clocks.** No decision about who is a member, which key stands, or whether a session is genuine rests on a clock. Lifetimes are counted on the receiver's **monotonic** clock from receipt, so a clock that steps changes nothing. The only wall-clock reading is a signed Interest's `SignatureTime`, which limits what the replay guard must remember and decides no trust.
- **Cost of an ask.** A stranger: a lookup. A member within its rate: one signature verification at the sender (certificates held and carried, nothing fetched), one signature made, one X25519 agreement and one AEAD seal; at the receiver, one signature verification, one X25519 agreement and one AEAD open. Over its rate a member costs a lookup and a Nack.

## 11. The frame

A channel frame is **not an NDN packet and not TLV**: it is a compact binary record, because it is on the hot path and a relay routes on its first ten octets. It travels as a *side frame* on any face ([ndn-link.md](ndn-link.md) §3.1; the face's `send_side`), is marked by a first octet of `0x00` (TLV-TYPE 0 is not assigned: no Interest, Data, Nack or NDNLPv2 packet starts with it), and is never fragmented, retransmitted or judged by the link service.

Implementation: the routing header and the `UP` record are in `ndn-transport` (`side_header.rs`); the rest of the header, the seal, the messages and the limits are in `ndn-heap` `chan` (`frame.rs`, `aead.rs`, `message.rs`, `varint.rs`, `limits.rs`, and, for the checkpoint hash ring, `ring.rs`).

### 11.1 The header

Cleartext, and authenticated as the AEAD's additional data (§11.2).

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `0x00`, the **marker** |
| 1 | 1 | `ver:3 \| class:1 \| kind:4`, high bit first. `ver` is 1. `class` is 0 for a datagram and 1 for a stream. `kind` is 0 `DATA`, 1 `CHECKPOINT`, 2 `CONTROL`, 4 `UP`. |
| 2 | 8 | the **channel id**, big-endian (for an `UP`, the route id) |
| 10 | 1 | the **key epoch**, low 8 bits |
| 11 | 8 | `seq0`, big-endian: the sequence of the frame's first message |
| 19 | 1 | `count`: the messages in the frame, 1 to 255; 0 for `CHECKPOINT` and `CONTROL`, which take one sequence |
| 20 | … | the body: the AEAD ciphertext, then the 16-octet tag |

A sealed frame has 36 octets of overhead (20 header, 16 tag), spread over every message in it.

The first octets that exist are exactly five: `0x20` `DATA` on a datagram, `0x30` `DATA` on a stream, `0x31` `CHECKPOINT`, `0x32` `CONTROL`, `0x24` `UP`. `CHECKPOINT` and `CONTROL` are always streams and `UP` is always a datagram; a kind on another class is malformed, and so is a kind that is not assigned, a version other than 1 and a marker other than `0x00`.

**What a relay reads.** The first ten octets, and nothing else: marker, `ver|class|kind`, id. A relay forwards a frame on the class it arrived on, routes it by the id, and never opens, re-packs or re-seals it. A relay refuses (drops, counted) a frame that is shorter than ten octets, whose marker is not `0x00`, whose version is not 1, whose kind is not assigned or is on a class it never uses.

**What a receiver of a sealed frame checks, in this order:**

| Check | Refusal |
|---|---|
| at least 10 octets, marker, version, kind and class as above | the routing header is malformed |
| at least 20 octets | `Truncated` |
| kind is `DATA`, `CHECKPOINT` or `CONTROL` (an `UP` is not sealed) | `NotSealed` |
| `count` is 1 to 255 for `DATA` and 0 otherwise | `Count` |
| `seq0` is below 2^63, and so is the sequence of the last message (`seq0` + `count` − 1, or `seq0` for a kind that takes one) | `SequenceExhausted` |
| at least 46 octets | `TooShort` |
| at most the frame limit that applies (§11.6) | `TooLarge` |
| the tag verifies | `Authentication` |
| the messages parse and nothing follows them but padding (§11.4) | the message's refusal |

Every refusal drops the frame; a stream peer that sends more than it was granted is closed with the link's `Protocol` error. A receiver that gets `Authentication` for a key epoch whose low octet it does not hold asks for the session again ([§3.6](#36-ended-renewed-re-keyed)); it never guesses a key.

### 11.2 Key and nonce

- **Channel key** `K` is the 32 random octets of the session (§3.2). It is never used as an AEAD key.
- **Frame key** = HKDF-SHA256 (RFC 5869) with `K` as the input key material, no salt, output length 32, and `info` = the ASCII octets `ndn-channel/frame/1` (19 octets) ‖ the channel id (8 octets, big-endian) ‖ the **full** key epoch as a `u32` (4 octets, big-endian). A key is per channel and per key epoch, so a re-key changes it even with the same channel id.
- **Key id** = the first 8 octets of HKDF-SHA256 with `K` as the input key material, no salt and `info` = the ASCII octets `ndn-channel/id/1` (16 octets). The session carries it so a receiver can match a key to a session.
- **AEAD** (`S_AEAD`, chosen by the sender, fixed for the session): 1 AES-256-GCM, 2 ChaCha20-Poly1305. Both take the 32-octet frame key and a 12-octet nonce and give a 16-octet tag. A sender SHOULD choose AES-256-GCM when its CPU has AES and carry-less multiply instructions and ChaCha20-Poly1305 when it has not (a device with neither, and a WebAssembly build, which has none); a receiver MUST open either, as its session says.
- **Nonce** (12 octets) = the key epoch's **low octet**, three zero octets, `seq0` big-endian.
- **Additional data** = header octets 0 to 19: **all 20 octets** of the header.
- **Plaintext** = the body's messages (§11.4) or, for `CHECKPOINT` and `CONTROL`, the record, then any padding (§11.3). **Ciphertext** is as long as the plaintext, then the 16-octet tag.

**A (key, nonce) pair is never reused, with no durable counter.** A key is fresh for every session and every re-key. Under one key, `seq0` rises for the life of the channel and every frame takes at least one sequence, so two frames never share a `seq0`; `seq0` is below 2^63. The nonce carries only the epoch's low octet, but the key is derived from the whole epoch: epochs 256 apart have the same nonce layout and different keys, so no pair recurs. A receiver MUST NOT hold two epochs of one channel whose low octets are equal: when a session at a new epoch arrives it replaces the older keys of the channel it would collide with. **A frame is sealed once.** A sender that re-packs the messages of a frame that was never sent (because the path's size fell) takes **new sequences** for the new frame; it never seals a second plaintext under a sequence it used.

A sender that reaches sequence 2^63 refuses to emit (`SequenceExhausted`: re-key the channel, which is a new session, before sending more).

### 11.3 Short frames on L2

A NIC pads an Ethernet payload under 46 octets with zero octets, and the receiver cannot tell the padding from the frame; a sealed frame with padding appended has its tag read at the wrong place and fails the AEAD. **So no frame is ever shorter than 46 octets on any carrier**, and a short frame is padded by its sender, in a way that the receiver can tell from content.

1. **Sealed frames (`DATA`, `CHECKPOINT`, `CONTROL`).** When 20 (header) + the plaintext + 16 (tag) is fewer than 46 octets, the sender appends padding **inside the AEAD plaintext**: the octet `0x80` followed by zero octets, the shortest that makes the frame 46 octets (at least one octet). The padding is therefore authenticated, and the tag is still the last 16 octets. `0x80` is the PAD flag (§11.4): a receiver stops parsing at it and requires every octet after it to the end of the plaintext to be zero; any other octet there makes the frame malformed. `count` counts real messages only. A sender MAY pad a longer frame the same way (to hide a length); a receiver accepts any padding of this form.
   - A `CHECKPOINT` or `CONTROL` record is self-delimiting (every field has a fixed size or a length), so the receiver reads the record and then requires the rest of the plaintext to be nothing, or a PAD flag and zeros.
2. **The `UP` record (§11.5), which is not sealed.** It is 11 octets of meaning followed by zero octets to 46. A sender sends all 46. A receiver accepts a frame of an `UP` kind of **11 or more** octets whose octets after the 11th are **all zero**, and refuses any other (`NonZeroPadding`): the same rule reads the record whether the carrier padded it or not.
3. A receiver refuses a sealed frame of fewer than 46 octets (`TooShort`).

### 11.4 Messages

The plaintext of a `DATA` body is `count` messages, then optional padding.

```
message = flags (1) | [original sequence (varint)]  if STANDING or REPLAYED
          | name id (varint) | [name length (varint) | name octets]  if NAMED
          | [stand seconds (varint)]  if STAND | length (varint) | payload
flags:  bit 0 NAMED    the full name rides here (the id is bound by this message)
        bit 1 STAND    the sender lets this emission stand
        bit 2 STANDING a replay of a standing value after a session start
        bit 3 REPLAYED a `Window` replay
        bits 4-6       reserved: zero
        bit 7 PAD      the octet 0x80 and nothing else in it: zero octets to the end of the plaintext
```

- **Varint** is the QUIC variable-length integer (RFC 9000 §16): the two high bits of the first octet give the length 1, 2, 4 or 8 octets, the rest is the value, big-endian, at most 2^62 − 1. A writer uses the shortest form; a reader accepts a longer one and refuses one that runs past the plaintext.
- The message's **sequence** is `seq0` + its index in the frame.
- **STANDING and REPLAYED** carry the *original sequence* the message first went out under, as the varint after the flags. They exclude each other (both set is malformed). An original sequence is a varint, so below 2^62.
- **Name id** is 1 to 4,096. **Name octets** are the Name's components as the value of the Name TLV, at most 255 octets (the empty name is allowed). **Stand seconds** are a varint. **Length** is the payload's length: at most the session's message limit (§11.6).
- A reader refuses (the frame is dropped) a message that runs past the plaintext, a reserved flag bit, STANDING with REPLAYED, PAD with any other bit, a name id outside 1 to 4,096, a name over 255 octets, a payload over the message limit, fewer messages than `count` or a PAD before the `count`th, and octets after the last message that are not padding. Overhead per message is 3 octets while the id is below 64 and the payload below 64 octets, and 4 to 5 beyond.

### 11.5 Kinds

- **`DATA` (0):** messages. On the datagram class for `Latest` messages that fit, on the stream otherwise.
- **`CHECKPOINT` (1):** a signed checkpoint of the frames sent. Always on the stream. Its record is specified with checkpoints (stage 5); the sender records the hash of every frame it sends (`ring.rs`: the first 16 octets of SHA-256 for a frame of at most 2,048 octets and of BLAKE3 above, kept for at most 4,096 frames per channel, the oldest forgotten and counted).
- **`CONTROL` (2):** always on the stream. The plaintext is `op (1) | …`: 1 `BIND` (id, name), 2 `UNBIND` (id), 3 `HELLO` (the first frame after a session starts: the sender's current sequence), 4 `END`, 5 `STANDING_BEGIN`, 6 `STANDING_END`. It takes one sequence.
- **`UP` (4):** the unsealed 11-octet record `0x00 | 0x24 | id (8) | op (1)`, `op` 1 `Keep` or 2 `Unsub`, then zero octets to 46 (§11.3). It is accepted only from a face that is a sink of the route and changes nothing but that face's own entry.

### 11.6 Limits

Each is enforced where the codec is: a writer refuses to build what a receiver refuses, and a receiver refuses what a writer would not build.

| What | Limit | Over it |
|---|---|---|
| Frame, any kind | at least 46 octets | `TooShort` |
| Datagram frame | `min(`the path's maximum datagram size`,` `S_FRAME_MAX)`; sized at send time by the sender | a frame the path's size fell under is re-packed once under new sequences, then its messages go to the stream |
| Stream frame | 1 MiB + 1 KiB by default; `S_FRAME_MAX` raises it to 16 MiB + 1 KiB | the receiver refuses it and closes the link `Protocol` if a peer sends more than it granted |
| Message payload | 1 MiB by default, at most 16 MiB; must fit a stream frame | `TooLarge` |
| Messages per frame | 255 | the next frame |
| Name | 255 octets | `TooLarge` |
| Names per channel | 4,096 (ids 1 to 4,096) | `TooLarge` |
| Sequence | below 2^63 | `SequenceExhausted`: re-key before |

A frame limit counts the whole frame (header, body and tag). The stream limits are the message limits plus 1 KiB (`MESSAGE_FRAME_SLACK`): the room one maximal message takes with its header (at most 280 octets) and the frame's own 36, so that a message at its limit fits a frame at its limit.

### 11.7 Frame test vectors

Hex. Every frame below is asserted by the implementation (`chan/frame.rs`, `chan/aead.rs`, `ndn-transport` `side_header.rs`); the key schedule is cross-checked against `openssl kdf HKDF`, and `ring` and RustCrypto are held to the same octets by a test.

Inputs: `K` = the octets `00 01 02 … 1f`; channel id `0102030405060708`; key epoch 258 (`0x0102`, so the header carries `02` and the nonce starts `02`); `seq0` = `1122334455667788`.

```
key id          62939e166fa5dba1
frame key       91de2d89433d466f77cb1018f68c9fdbba620980522e4ee557c168bbf1a8d196
```

A header (class stream, `DATA`, channel id as above, key epoch octet `ab`, `seq0` as above, `count` 7):

```
00300102030405060708ab112233445566778807
```

**1. `DATA` on a datagram, AES-256-GCM,** two messages: id 1 `hello`, and id 2 NAMED with the name octets `080161` (`/a`) and `world!`. Plaintext, 21 octets:

```
00010568656c6c6f01020308016106776f726c6421
```

Nonce `02000000 1122334455667788`. Frame, 57 octets:

```
00200102030405060708021122334455667788027a717a4fb0a19e51de28cca72d34bb909c205895e5d097a1937e7ce5f579f4fd1c32a18e7f
```

**2. The same two messages, ChaCha20-Poly1305:**

```
002001020304050607080211223344556677880219081b0319ad28f01191a9adb047d8cf9edab2e3b08a19ea53d2b9e33b47704bf5da4b2cf6
```

**3. `DATA` on a stream, ChaCha20-Poly1305,** one message, id 1, empty payload: 3 octets of message, so 36 + 3 is under 46 and the plaintext carries 7 octets of padding (`80` and six zeros), 10 octets in all (`00010080000000000000`). Frame, 46 octets:

```
003001020304050607080211223344556677880119081eeb7cc1449f10937cd4a971a420bf82233f87e8846faf36
```

**4. `CHECKPOINT` on a stream, AES-256-GCM,** a 30-octet plaintext `01 02 … 1e` (a stand-in: the record is specified with checkpoints), `count` 0:

```
00310102030405060708021122334455667788007b727c23d0cbf536d620c4a3215bb2f7e24027e5d13ac14f1f042a165ae413a2371eb6c94c4f120297429b26ee95
```

**5. `CONTROL` on a stream, ChaCha20-Poly1305,** `HELLO` (op 3) carrying the sender's current sequence `1122334455667788` as a varint (`d122334455667788`): 9 octets, so one octet of padding (`80`) makes the frame 46 octets. Plaintext `03d122334455667788` `80`:

```
00320102030405060708021122334455667788001ad83c58389422e898139cdf1fd88c4f66931d9a5f646184dfc6
```

**6. `UP`,** route id `0102030405060708`, `Keep` (`01`) and `Unsub` (`02`), 46 octets each (11 octets of meaning and 35 zero octets):

```
00240102030405060708010000000000000000000000000000000000000000000000000000000000000000000000
00240102030405060708020000000000000000000000000000000000000000000000000000000000000000000000
```

### 11.8 Threat notes for the frame

- **What the tag covers.** The AEAD tag covers the whole header (marker, version, class, kind, channel id, key epoch, `seq0`, `count`) as additional data, and every message (ids, names, flags, lengths, payloads) and the padding as ciphertext. So a relay cannot alter, reorder within a frame, truncate, extend, change the count of, or re-label a frame. It does **not** prove **which key holder** sealed it: every receiver holds the key, so a receiver can forge a frame another receiver accepts. Attributing frames to the sender's device is what signed checkpoints are for; this section makes no such claim.
- **A relay forges or alters.** It has no key. Any change to any octet fails the AEAD at the receiver; a frame moved to another channel fails the key (the channel id is in the key derivation) and the additional data (the id is in the header); a frame copied from another session fails the key. A frame with zero octets appended or removed fails the tag. The padding of a short frame is inside the AEAD for this reason.
- **Cost of a forged frame** to a receiver: a ten-octet routing-header parse, a table lookup by channel id and one AEAD attempt (0.12 µs to seal 64 octets with AES-256-GCM through `ring`, measured; opening is of the same order), bounded by the channel quota. A frame that is oversized, shorter than 46 octets, malformed, or of an unknown channel costs no cryptography. A forged `UP` costs a parse and is dropped unless it comes from a sink face of the route, and then it can only change that face's own entry.
- **A reused nonce** would reveal the XOR of two plaintexts (and, under AES-GCM, the authentication key). §11.2 is why it does not happen: a fresh key per session and per re-key, a `seq0` that rises, no sequence sealed twice. The one hazard is a sender that re-seals different messages under a sequence it used; the codec's writer takes the sequence from the caller, so the caller owns the rule (§11.2).
- **Key material in memory.** The frame key and `K` are zeroed when dropped. `ring` and RustCrypto do not zero their expanded key schedules; a prepared cipher lives no longer than its session.
- **Length.** A frame's length is visible to a relay. A sender that must hide a message's length pads (§11.3 allows a longer pad).
- **A malformed frame never panics the receiver.** Every refusal of §11.1 and §11.4 returns an error; the property tests feed arbitrary octets to the opener, the message reader and the routing-header parser.

## 12. The receiver

What a device does with the frames of the sessions it holds as a receiver (§3.4), from the octets the host read to the `Items` of a `live` call (§12.7). Implementation: `ndn-heap`, `chan` (`rx.rs` the frame path, `replay.rs`, `rx_names.rs`, `latest.rs` and `fifo.rs` the queues, `items.rs`).

The host hands the node one whole frame at a time (a datagram, or one frame of the stream) with an opaque id of the face it came over (`NodeHandle::deliver_frame(frame, ingress)`; the id is kept for the evidence of checkpoints, stage 5). Frames of one channel are taken one at a time and in the order they were handed over; frames of different channels do not wait for each other. No timer task runs for the receiver: what must expire is swept by the next frame of the channel, by a poll of an `Items`, and by the node's maintenance pass.

### 12.1 What is checked, in this order

Each row costs at most the work it names, and **a frame that fails a row costs nothing below it**. Rows 1 to 10 are before any cryptography; row 11 is the first.

| # | Check | Refusal (counted) |
|---|---|---|
| 1 | at least 46 octets (§11.3) | `short` |
| 2 | at most 16 MiB + 1 KiB, the largest frame any session may grant (§11.6) | `oversize` |
| 3 | the header parses (§11.1): marker `0x00` (`marker`), version 1 (`version`), a kind that is assigned, sealed and on its class (`kind`: an unassigned kind, `CHECKPOINT` or `CONTROL` on a datagram, an `UP`), a `count` the kind allows (`count`), a `seq0` and last sequence below 2^63 (`sequence`) | the counter named |
| 4 | a session of this channel id is held | `unknown_channel` |
| 5 | the frame is within the limit of its class: a datagram at most the session's `S_FRAME_MAX` (at least 46, at most 16 MiB + 1 KiB), a stream frame at most the larger of 1 MiB + 1 KiB and `S_FRAME_MAX` (§11.6) | `oversize` |
| 6 | a `Reliable` or `Window` channel's data comes on the stream | `wrong_class` |
| 7 | **back pressure:** a stream data frame of a `Reliable` or `Window` channel waits while an `Items` that blocks (§12.6) has a full queue | none: the host's read of the stream waits |
| 8 | the **generation check** (§12.3): the sender still stands | `not_member`, and the session ends |
| 9 | the session holds the key epoch the header names (§12.3) | `unknown_epoch` (and `epoch_limited`, `epoch_asks`) |
| 10 | the replay window has not seen `seq0` and has not passed it (§12.2) | `replayed`, `too_old` |
| 11 | one AEAD attempt under the key of that epoch | `unauthentic`, counted with every attempt in `aead_attempts` |
| 12 | the tag verified: `seq0` is marked seen (§12.2) | |
| 13 | the messages parse as a whole, or the `CONTROL` record does (§11.4, §11.5) | `malformed`; nothing of the frame is delivered |

A refused frame changes nothing but a counter, except row 8, which ends the session. Every counter is in the node's channel statistics (`Stats.rx`), and a test reads them: *a flood of junk costs a length test, a header parse or a lookup, never an AEAD attempt.*

### 12.2 The replay window

Each channel has a window of the last **4,096 frame sequences** and a bitmap beside the highest `seq0` marked. Frames are keyed by `seq0`: every frame takes at least one sequence and `seq0` rises for the life of a channel (§11.2), so two frames never share one, and a repeated `seq0` is a repeated frame.

- **Check before the AEAD.** A `seq0` the bitmap has set is `replayed`; one at least 4,096 below the highest is `too_old` (the window cannot say whether it was seen). Both are dropped before any cryptography: a flood of copies of a genuine frame costs a comparison each.
- **Mark after the AEAD.** `seq0` is marked only once a frame of that sequence **authenticated**. A forged copy of a genuine frame (the same header, an octet of the body changed) fails the AEAD, marks nothing and so cannot burn the genuine `seq0`. A genuine frame that arrives after a forged copy is delivered.
- **Within a frame** the messages are numbered `seq0` + index (§11.4); the window is not asked about them.
- **Across sessions** a replayed frame fails the AEAD: a key is fresh for every session and every re-key (§11.2).
- No clock is read.

### 12.3 The generation check and the key epoch

- **Generation.** A session holds the pair `(trust generation, the space's fold version)` it was judged under, and every frame compares it with the node's by two atomic loads (`is_current`). When either moved, the receiver judges the sender again **before** the frame is looked at further, offline and synchronously: the sender must still be a writer by the entries held and this device a member (§3.6). If it fails, the session ends with `NotMember` and is dropped, the `Items` are told (§12.7), and **the frame is refused**. So the first frame after the node holds the record that removes the sender is refused; frames the sender sent before the record arrived were delivered. The node's maintenance pass makes the same judgement when it runs; whichever notices first ends the session, and later frames find no session (`unknown_channel`).
- **Key epoch.** The header carries the low octet of the key epoch. The session holds the key of the epoch last given and, for 5 s after the receiver first saw the next epoch, the key before it (§3.6). A frame under an octet the session does not hold is **not tried**: it costs a lookup. The sender is asked again for the session (§3.6), **at most once a second per sender**; frames that arrive meanwhile are dropped (`unknown_epoch`, of which `epoch_limited` did not ask). Nothing is guessed.
- **Frame limits** and the AEAD are those the session's last answer set.

### 12.4 The name table at the receiver

Each channel has a table from name id to name, filled by the session's table (§3.2), by `BIND` records on the stream, and by `NAMED` messages (the id is bound by the message), emptied by `UNBIND`.

- A `BIND` or a `NAMED` message that binds an id to the octets it already has changes nothing and decodes nothing. Another name replaces the old one and is **another binding** of the id: what is queued under the old binding is not mistaken for the new name's.
- An id outside 1 to 4,096, or octets that are not a Name's components, are refused (`bad_bind`).
- **A datagram can overtake the stream.** A message whose bare id the table does not know is **held for 50 ms**. If the bind arrives inside that time (a `BIND` or a `NAMED` message of the id), the message is delivered after it, in the order it was held. If the bind arrives at 50 ms or later, or never, the message is **dropped and counted** (`unknown_name`). At most **64 messages are held per channel**: one that finds 64 held is dropped at once (`hold_full`, and `unknown_name`). A bind that arrives late drops what it finds held instead of delivering it, so the outcome does not depend on when the sweep ran. The hold is swept by the next frame of the channel, by an `Items` poll and by the node's maintenance pass, never by a timer.

### 12.5 `HELLO`, `END` and standing values

- **`HELLO`** records the sequence the sender says its next message takes, and tells every `Items` that takes the channel that **the path works** (`Items::hello_seen`); stage 6's `NoPath` rule reads it. In `Reliable` and `Window` it is also where the receiver's stream begins (§12.6).
- **`END`** ends the session (`Closed`): the `Items` are told once what they hold has been read, and later frames find no session.
- **Standing values.** The messages between `STANDING_BEGIN` and `STANDING_END` carry the `STANDING` flag and the original sequence (§11.4). Each is delivered as an emission whose `seq` is the **original** sequence and whose `stands` is its stand seconds (what is left of the stated lifetime). A `STANDING` message outside the bracket is dropped (`standing_stray`). In `Latest` the original sequence is also what a message is compared by (§12.6): a standing value older than a live message of its name is not delivered.

### 12.6 Modes at the receiver

| | `Latest` | `Reliable` | `Window` |
|---|---|---|---|
| Frames | datagrams, and the stream for what does not fit one | the stream only | the stream only |
| Queue | **coalescing:** the newest message per (channel, name binding), a FIFO of the names that have one, at most **4,096 pairs** per `Items` | a FIFO of at most **1 MiB** (`queue_bytes`) per `Items` | as `Reliable` |
| A newer message of a name | replaces the queued older one in its place | queued after it | queued after it |
| An older or repeated sequence of a name | dropped, even after the newer was read | n/a | n/a |
| A gap in `seq0` | none noticed | `Lagged { missed }` in its place | `Lagged { missed }` in its place, and the sender is asked again from the first missing sequence |
| Queue full | the oldest pair is evicted and counted: `Lagged` | `Block` (default): the stream is not taken until there is room; `Drop`: the oldest messages are discarded and a `Lagged` stands in their place | as `Reliable` |

- **The gap rule.** In `Reliable` and `Window` each stream frame must start where the last one ended: `seq0` equals the previous `seq0` plus the sequences it took (its `count`, or one for a `CONTROL` or `CHECKPOINT` frame). A frame that starts later says that many sequences are missing, and every `Items` that takes the channel is told **in the place** the messages are missing, before the frame's own messages. `missed` counts sequences (a control record takes one like a message does). Where the stream begins is the `seq0` of a first frame that is a `HELLO`; otherwise the sequence the session's answer named (`S_SEQ`), so that frames lost between the answer and the first frame are not silent either. A frame that starts earlier than expected does not move the expectation back.
- **`Window` asks again.** On a gap the receiver asks the sender for the session again with `ASK_SINCE` = the first missing sequence (a full signed ask, §3.1), at most once a second and never while one is in flight; the sender replays what its window holds from there as `REPLAYED` messages on the stream, under new frame sequences. If the window no longer holds the range, the new session's `S_SEQ` says so and the `Lagged` stands.
- **`REPLAYED` messages** carry the original sequence. One whose original was **already delivered** is dropped (`duplicates`); one that was not is delivered as an emission whose `seq` is the original. The receiver keeps the delivered sequences as at most 64 ranges; when a new range would pass the bound, the two oldest are joined, which counts the gap between them as delivered: a replay of a message that old is dropped, never repeated.
- **Coalescing and the bound.** A message is queued under the key (channel, name id, binding). The newest sequence of a key is kept after its message is read, so an older message that arrives later is dropped; those records are forgotten when there are 8,192 of them, so what is forgotten is a name quiet for thousands of other names' messages. A new name when 4,096 are queued evicts the oldest queued name: that is this consumer being slow, and it is told (`Lagged`), unlike a replacement, which is the mode.
- **The FIFO's bound.** A queued message weighs its payload plus 64 octets, so a flood of empty messages is bounded too. With `Block` the bound is checked before a stream frame is taken, so the queue can pass it by the one frame in hand and never by more. With `Drop` messages are discarded from the front until the new one fits (a message larger than the bound is taken when the queue is empty).

### 12.7 `Items`

`Heap::live(Select, GetOptions)` returns an `Items`, a `Stream` of `Result<Got, GetNotice>` (`GetOptions::kept`, `trust` and the kept values are stage 5 and 6; `live` refuses `Live::Off` and `Trust::Verified`, and a follower).

- **Creating it does no I/O.** It takes every message of every session of the space this device holds, in the modes it joined (`Modes`), whose path matches `Select::Path` (exactly) or `Select::Prefix`. While it exists, this device is *listening* to the space (§9): announces of writers' channels make it ask. Asking a sender for a session is the caller's (`NodeHandle::ask_channel_in`) until the verbs of stage 6 do it.
- **`Got`** carries the path (relative to the space), the payload (a slice of the opened frame: **no copy**), the writer's person and device, and `Kind::Emitted { seq, stands }`.
- **Order.** Within a channel as §12.6. Across channels, the order messages were queued in.
- **Notices.** `Lagged { missed }` as above. `LiveEnded(Ended { writer, reason })` when a session ends (`NotMember` when the sender no longer stands, `Closed` for an `END`, `Lapsed`, `Left`), told **after** the messages queued before it; a session replaced by a newer one of the same sender and mode is not told, since the `Items` simply goes on with the new one. `Retracted` is raised by checkpoints (stage 5).
- **`next_batch(&mut Vec<Got>) -> usize`** moves everything queued that is an item into the buffer, under one lock, with no wake per item and no allocation when the buffer has room; it stops before a notice (the next `next()` yields it) and never waits.
- **Back pressure** (§12.6) is applied by the receiver before it takes a stream frame, so it reaches the sender through the stream's flow control. An `Items` that is never read stalls the stream of a `Reliable` or `Window` channel with `Block`; dropping it frees the stream.
- **Dropping an `Items`** cancels its sink: nothing more is queued for it. The stream ends when the node stops.

### 12.8 Limits and counters of the receiver

| What | Limit | Over it |
|---|---|---|
| Frame | 46 octets to 16 MiB + 1 KiB; per class as §12.1 row 5 | `short`, `oversize`, dropped before cryptography |
| Replay window | 4,096 frame sequences per channel | `replayed`, `too_old`, before the AEAD |
| Asks for an unknown key epoch | once a second per sender | `epoch_limited`, dropped untried |
| Messages held for an unbound id | 64 per channel, 50 ms | `hold_full`, `unknown_name` |
| Names per channel | 4,096 | refused (`bad_bind`) |
| `Latest` queue | 4,096 names per `Items` | the oldest name evicted, `Lagged` |
| `Reliable`/`Window` queue | 1 MiB per `Items` (+ 64 octets a message) | back pressure, or the oldest dropped and `Lagged` |
| Delivered original sequences kept for `REPLAYED` | 64 ranges per channel | the two oldest joined |
| `Window` re-asks | once a second per channel, one in flight | the gap stands as `Lagged` until the next |
| Cost of a frame | one allocation, whatever its message count; none per message; `next_batch` none | |

The counters (each a `u64`, in `Stats.rx`): `frames`, `short`, `marker`, `version`, `kind`, `truncated`, `count`, `sequence`, `oversize`, `unknown_channel`, `wrong_class`, `not_member`, `unknown_epoch`, `epoch_limited`, `epoch_asks`, `replayed`, `too_old`, `aead_attempts`, `unauthentic`, `malformed`, `accepted`, `messages`, `unknown_name`, `name_held`, `hold_full`, `bad_bind`, `standing_stray`, `duplicates`, `gaps`, `reasks`, `controls`, `hellos`, `checkpoints`, `no_sink`, `ended`.

### 12.9 Threat notes for the receiver

- **A flood of junk.** A frame that is short, oversize, malformed, of a channel this device holds no session of, a repeat, below the replay window, or under a key epoch it does not hold costs a length test, a header parse or one lookup. None reaches the AEAD (`aead_attempts` proves it). A flood under a key epoch the session does not hold also makes no more than one ask a second per sender.
- **A forged frame of a held channel** costs one AEAD attempt and is refused (`unauthentic`); it burns no sequence, so it cannot make the receiver drop the genuine frame that follows (§12.2). The attempts are bounded by what the link delivers; the replay window drops copies of a genuine frame before the attempt.
- **A forged copy of a genuine `seq0`** is the same: refused by the tag, marks nothing.
- **A held-back bare id cannot grow memory.** At most 64 messages per channel are held, for 50 ms; the 65th is dropped at once; the number of channels is bounded by the sessions (§6).
- **A key holder** can seal frames the receiver accepts (§11.8): it can send a `BIND` that renames an id, a `STANDING` bracket, an `END`, a gap, a `HELLO`. Each is bounded as above (the table has 4,096 ids, the hold 64 messages, the delivered ranges 64) and none changes who the sender is: attributing frames to the sender's device is the work of signed checkpoints (stage 5).
- **A removed sender** is refused at the first frame after this device holds the removing record (§12.3). Frames it sealed before the record arrived were delivered; frames sealed with the old key by a holder after the re-key fail the AEAD.
- **A slow consumer** cannot make memory grow without bound: 4,096 names, or 1 MiB (plus the frame in hand), per `Items`. With `Block` it stalls the stream of a `Reliable` or `Window` channel (the sender is told by flow control); with `Drop`, or in `Latest`, it is told it lagged.
- **Clocks.** No decision about who is a member or what is genuine rests on a clock. The 50 ms hold and the one-second limits are counted on the receiver's monotonic clock and decide only what is kept for a moment and how often a sender is asked.
