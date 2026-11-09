# Signals: ephemeral live data between the members of a folder

- **Status:** Draft (round 4)
- **Scope:** *Signals*: presence, cursors, drags at 60 Hz, live unsigned edits and game input exchanged between the members of a folder or collection. A signal is never a version, never stored and never cached. This spec defines:
  - who may send and receive (the members record, through the gate of [data-layer.md](data-layer.md) §20);
  - run keys and run headers;
  - the packet: its body, its run signature and its seal;
  - the push into the namespaces' sync groups, and the local leg over shared memory;
  - what a receiver checks, in order, and what it delivers;
  - limits, errors, the wire format and threat notes.
- **Implementation:** the gate is `ndn_data::signal` (ndn-rs `crates/app/ndn-data`). Everything else is `ndn_surface::signal`, feature `signals` (ndn-ext `crates/surface/ndn-surface`). No forwarder, link or trust-context library treats signals specially.
- **Related specs:** [data-layer.md](data-layer.md) (members §6, §6.1, §6.3; seals §9; sync groups §12; the gate §20), [ndn-link.md](ndn-link.md) (relays and transit §15.7), [trust-context.md](trust-context.md) (revocations).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119], [RFC 8174]) when, and only when, they appear in all capitals, as shown here.

---

## 1. Terminology

| Term | Meaning |
|---|---|
| scope | A folder or a collection of the data layer. Its members record in force governs its signals. |
| member | For signals: a device whose key a writer prefix of the scope's record in force covers, or which the record's audience admits, and whose key no trust context it holds revokes ([data-layer.md](data-layer.md) §20). |
| sender | The device key that signed a run's header: `/<ns>/<…device>/KEY/<id>`. |
| run | One sender's signals in one scope under one ephemeral Ed25519 **run key**, from its header's `RunStart` until its `RunNotAfter`. |
| run header | A Data packet, signed by the device key, binding the run key, the run's start and end and its local ring (§3). |
| packet | One signal or a batch of signals, signed by the run key, sealed in a sealed scope (§4). It travels as the ApplicationParameters of a push Interest (§5) and as a frame on the run's ring (§6). |
| signal key | A sealed scope's key for signals: derived from the content key of the scope's epoch inside the data layer ([data-layer.md](data-layer.md) §20). |
| group | A namespace's sync group `<O>/32=sync` ([data-layer.md](data-layer.md) §12). |
| address | An application-defined label within a sender's signals, such as `cursor`, `presence` or `drag/<element>`. A newer signal for an address replaces the older one. |

## 2. Model

1. A signal is never a version. No signal, packet or run header is ever written into a device's store or log, counted into a collection's state, served, or answered for by anyone.
2. A signal is never cached. It never travels as Data (§5.4), so no content store can keep it.
3. Only members send and receive (§7). A receiver checks the sender's membership on every packet, against the record in force at that moment.
4. A signal is authenticated by its run key, and the run key by the sender's device key. A receiver MUST verify the run signature of every packet it delivers, including packets that came from this host (§6): local faces are not validated by a forwarder.
5. In a sealed scope every packet is sealed under the signal key. Only the readers of the epoch can open it.
6. Signals are lossy. Per sender, signals are ordered by sequence. A receiver delivers the newest signal per (sender, address) and refuses replays (§8).
7. A signal expires. One past its `Expires` is never delivered.
8. **Commit:** live work becomes versions only through the data layer's ordinary `put` / `put_op` (one version, or a group, signed by the writer's device key). Signals themselves never become versions, and nothing in this spec turns one into a version.

## 3. Runs

### 3.1 The run key

A sender opens a run with a fresh Ed25519 key pair drawn from the operating system's randomness. The secret key MUST NOT leave the process and MUST NOT be stored. The **RunId** is the first 16 octets of SHA-256 of the run's 32-octet public key. A RunId therefore names exactly one run key: nobody can claim another run's id.

### 3.2 The run header

The run header is a Data packet:
- **Name:** `<device>/32=signal/<scope>/32=run/<RunId>`: `<device>` the device name of the signing key, then the KeywordNameComponent `signal`, the scope's components, the KeywordNameComponent `run`, and a GenericNameComponent of the 16 RunId octets. Like every packet the data layer signs (a log entry is `<device>/32=log/<subject>/…`), it is named under its signer's device, since a validator picks the trust context, schema and anchors by the packet's name. For a self-certifying member adopted for the folder, the folder's scoped view judges it, as it judges that member's log entries about the folder ([data-layer.md](data-layer.md) §6.3);
- **Content:** a RunHeaderBody (§11);
- **Signature:** by the sender's device key, as the data layer signs its own packets. No FreshnessPeriod.

The body binds:
- `RunKey`: the run's public key;
- `RunStart`: the run's first sequence, the sender's clock in microseconds since the Unix epoch when the run opened;
- `RunNotAfter`: when the run ends, in ms since the Unix epoch, at most 24 h after the run opened;
- `LocalRing` (optional): the 32-octet secret of the run's local ring (§6).

The device key signs the header only while the device is a member of the scope ([data-layer.md](data-layer.md) §20). The header is never published under its name and never answered for. It travels only inside packets (§4).

### 3.3 Sequences

A run's first signal takes `RunStart`; each next signal takes the next integer. Sequences are **per sender**. A renewal (§3.4) starts the new run at the sequence after the old run's last. A new run that continues nothing (a restart, another scope's run) starts at the sender's clock in microseconds at its opening, so above every sequence of an earlier run, as long as a sender makes fewer than a million signals per second and its clock doesn't step back. A receiver orders a sender's signals by sequence across its runs (§8.3).

Two runs of one sender in one scope at once (two processes of one device, each with a run its device key signed) share the sender's sequence space: a receiver orders them as one sender's. They MUST use distinct addresses, or the later-opened run's signals hide the other's as stale.

### 3.4 Renewal and end

A sender SHOULD open a new run (a new run key, a new header) once 90 % of a run's lifetime has passed, and continue its sequences in it. A run ends at `RunNotAfter`, when its sender closes it (its ring tells local readers), or when the sender's process ends. Remote receivers forget a run at its `RunNotAfter` (plus the clock skew they allow), or sooner when a newer run of the same sender replaces it (§8.4).

## 4. Packets

### 4.1 The body

A **SignalBody** carries, in order:
1. the scope's Name;
2. the RunId;
3. optionally the run's header (`RunHeader`, the header's whole Data wire);
4. zero to 32 `Signal`s, each with its sequence, address, `Expires` and payload, in ascending sequence order with no repeated sequence; at least one unless the RunHeader rides;
5. the `RunSignature`: Ed25519 by the run key over the octets `"ndn-signal/1"` followed by every octet of the SignalBody's TLV-VALUE that precedes the RunSignature TLV.

The signature covers the scope's name, so a packet can't be replayed into another scope. The header rides in a run's first packet, and again in the first packet sent once 1 s has passed since it last rode. When the header is due and doesn't fit beside the signals within the packet limit (§4.3), the sender first pushes a **header-only** packet (the header and no signal, signed by the run key, counted against its rate) and then the signals. A receiver takes a header-only packet as the run's admission only and delivers nothing from it. A receiver that lost the header holds the run's packets as unknown until the next one (§8.1).

### 4.2 The seal

In a sealed scope the packet is a **SignalSealed** instead:
- `KeyId`: the 8-octet id of the signal key used ([data-layer.md](data-layer.md) §20);
- `SealNonce`: 24 random octets;
- `Ciphertext`: XChaCha20-Poly1305 under the signal key and the nonce, over the plaintext of the whole SignalBody TLV, with AAD `"ndn-signal/1"` followed by the KeyId octets, its 16-octet tag appended.

The body is signed first and then sealed. A sender seals under the first key `signal_scope` gives: the key of the epoch in force at the sender. A packet of a sealed scope MUST NOT be sent unsealed, and a receiver MUST refuse a SignalBody for a scope whose record in force is sealed.

### 4.3 Size

A packet's whole encoding is at most 1,024 octets. An address is at most 64 octets and a payload at most 768. A packet carries at most 32 signals.

## 5. The push

### 5.1 Groups

A sender pushes each packet into the group of every namespace the scope's record in force names: the scope's own namespace, the namespace of each writer prefix, of each reader (a group reader by its collection's namespace) and each self-certifying writer adopted for the folder. These are exactly the groups the data layer publishes a notice about the scope into ([data-layer.md](data-layer.md) §12), as `signal_scope().groups` lists them. Each member's devices hear the packet in the group of their own namespace, which every forwarder holding that namespace carries to its devices, and which every relay serving its devices carries with the multicast strategy while the namespace is in transit ([ndn-link.md](ndn-link.md) §15.7).

### 5.2 The push Interest

For each group `<O>/32=sync`, the sender expresses one Interest:
- **Name:** `<O>/32=sync/32=signal/<ParametersSha256Digest>`;
- **ApplicationParameters:** the packet;
- **InterestLifetime:** 1,000 ms; **HopLimit:** 8; no CanBePrefix, no MustBeFresh, no ForwardingHint; unsigned.

No one answers it. A sender ignores any Nack it receives for it. The name is unique per packet (its parameters digest), so a forwarder never aggregates two packets in one PIT entry. A copy that reaches a forwarder twice is suppressed by its nonce.

### 5.3 Receiving

A device that receives signals registers its own namespace's group `<ns>/32=sync` (`signal_scope().listen`) on a connection of its own. On a forwarder this is an ordinary prefix registration. On an in-process engine the host routes the group to that connection's face, as it routes the data layer's sync face. The group's multicast strategy then delivers every Interest under it to every local registration and over every link that carries the namespace, never back toward the face it came from.

The group's prefix is shared by two protocols: State Vector Sync takes `<group>/v=2` (`v=3` in the ndnd dialect), and signals take `<group>/32=signal`. Each ignores the other's Interests: SVS refuses a name whose next component isn't its version, and a signal receiver ignores every name that is not `<group>/32=signal/<ParametersSha256Digest>` with a matching digest.

### 5.4 Why Interests and no Data

A pushed Interest needs no forwarder change: no unsolicited Data, no new strategy, no new route. It crosses relays like a Sync Interest. It also keeps signals out of every content store, because only Data enters one. A pull would cost a round trip per signal; a pushed Interest costs one way. Data with NDNLPv2 `CachePolicy = NoCache` would remain the right carriage for any later signal answer ([§13.7](#137-carriage)), but this spec defines none.

## 6. The local leg

A run MAY open a **local ring**: an `ndn-surface` broadcast ring (one writer, any number of read-only readers, lossy: it never blocks the sender and laps a slow reader). Its surface name is `<scope>/32=signal/32=ring/<RunId>` and its attach secret is the header's `LocalRing`. Every packet the run pushes is also published on its ring, with the same octets.

A receiver that admits a run header carrying a `LocalRing` checks whether the ring's control socket (derived from the surface name, ndn-surface rendezvous) exists on this host. If it does, the receiver attaches with the secret and reads the run's packets off the ring from then on. The ring's packets go through the same checks as pushed ones (§8). They are verified, deduplicated and counted against the run alike; `Signal.local` tells which way a signal came. The forwarder's later copies of the same packets meet a full replay window and are dropped before verification.

So discovery rides the push: a host on which two members run learns of each other's rings from the first packet. In a sealed scope the secret travels inside the seal, so only the scope's readers can attach. A ring's mapping is read-only to readers, and each frame is copied out once before verification. A lossy ring can be overwritten during a read, so a borrowed view could change between the signature check and delivery.

## 7. Membership

A device sends and receives the signals of a scope only while it is a member by the record in force over the scope at the device ([data-layer.md](data-layer.md) §20):
- `subscribe` and `open` are refused `NotMember` otherwise (also when the device is a writer outside a sealed scope's audience: it may not hold the key), `NotReady` when no record over the scope is held yet, or (sealed) when no key of the epoch in force is held yet (its ask is started). Neither follows the scope: a device that doesn't follow it yet hears no record of it, and the refusal says to follow it (watch it, or get a collection under it) and ask again;
- every `send` checks again: from the moment the sender's device holds a record removing it (or revoking its key), `send` is refused `NotMember`;
- a receiver admits a run header only through `signal_admit`. The header must be named `<device>/32=signal/<scope>/32=run/<RunId>` for this scope, with `<device>` its signing key's device; its signature must verify by the device's validator (for a self-certifying member adopted for the folder, the folder's scoped view, [data-layer.md](data-layer.md) §6.3); and its key must be a member's;
- a receiver checks `signal_member(scope, sender)` for **every packet** before delivering it. The check is synchronous, under the device's lock, against the record in force at that call. It also fails for a key that the trust context governing it revokes.

## 8. What a receiver does

### 8.1 Order of checks

For each push Interest under its group, and each frame off a ring it attached, a receiver:
1. takes only `<group>/32=sync/32=signal/<digest>` whose digest is the SHA-256 of the ApplicationParameters (a ring frame is taken as is), at most 1,024 octets, else `malformed`;
2. if sealed: looks the KeyId up among the signal keys of the scopes it subscribes to (asking `signal_scope` of every subscribed scope again when the id is unknown, at most once a second), else `unknown_key`, dropped undecrypted; opens the seal and decodes the body, else `malformed`; refuses a body naming another scope than the key's (`malformed`);
3. decodes the SignalBody, else `malformed`. It drops one for a scope nobody here subscribes to (`unsubscribed`), and refuses an unsealed body for a sealed scope (`malformed`);
4. finds the run by RunId:
   - while the run's header is being admitted, the packet waits behind it, in arrival order, at most 32 packets per run (beyond: `unknown_run`). Once the run is held they are processed in that order from step 5; if the header is refused, each is counted with the header's refusal;
   - if no run is held and the body carries a header: checks that `RunId` is SHA-256 of `RunKey` truncated to 16 octets (else `bad_signature`), that the header's name is the run header of this RunId and scope (else `malformed`), that `RunNotAfter` plus the clock skew allowed is not past (else `expired`) and at most 24 h plus that skew ahead (else `malformed`), then admits it through `signal_admit`, at most 8 admissions at once per process (beyond: `flood`). A refusal is counted (`bad_signature`, `not_member`, `malformed`; `unknown_run` when the record isn't held yet) and the run is not held. Holding it obeys §8.4;
   - if no run is held and no header rides: `unknown_run`, dropped unverified;
   - a held run's packet naming another scope is `malformed`; a header-only packet of a held run is done; a packet past its run's `RunNotAfter` plus the skew is `expired`; a sequence below `RunStart` is `malformed`;
5. applies the replay window (§8.2, `replayed`) and the run's and the scope's receive rates (§10, `flood`). They come before any signature check, so a flood of copies costs no verification;
6. verifies the RunSignature, else `bad_signature`;
7. checks `signal_member(scope, sender)`, else `not_member`;
8. checks the window again (a copy may have been taken meanwhile, `replayed`) and marks the packet's sequences seen;
9. for each signal: drops it if `Expires` plus the clock skew allowed (30 s by default) is past (`expired`), or if `Expires` is more than 60 s plus that skew ahead (`malformed`); drops it if a newer signal of the same sender and address was delivered (`stale`); otherwise delivers it to every subscriber of the scope and notes its sequence as the newest for (sender, address).

A packet marks its sequences as seen in the run's window only once it passes step 7, so a forged copy can't burn an honest packet's sequences.

### 8.2 Replays

Each run keeps a window of the 1,024 highest sequences seen. A sequence already seen, or below the window, is a replay. A sequence below `RunStart` is malformed. The window lives as long as the run is held. A receiver that forgot a run (it restarted, or the run was replaced) bounds replays by `Expires` alone (§13.2).

### 8.3 The newest per address

A receiver delivers a signal only if its sequence is above the last one delivered for the same (sender, address), across the sender's runs. Under loss and reordering, a later arrival of an older signal is dropped as stale. A subscriber that reads slower than signals arrive gets the newest per (sender, address), never a backlog: a newer signal for a pair still unread replaces the unread one in place.

### 8.4 Runs held

A receiver holds at most 4 runs per sender key and 64 per scope, and lets go of a run once its `RunNotAfter` plus the skew is past. A newly admitted run of a sender at its cap replaces the sender's run with the lowest `RunStart`, if its own `RunStart` is higher; otherwise it is refused (`flood`). A scope at its cap refuses new runs (`flood`) until one ends.

## 9. Sending

`SignalRun::send` (and `send_batch`, `send_for`):
1. checks the device's membership and refreshes the scope from `signal_scope` (its groups, its keys), refusing as §7 says;
2. checks the limits (§10): `TooLarge`, `RateLimited { retry_after }`;
3. builds the SignalBody (the header if due), signs it, and seals it in a sealed scope;
4. pushes one Interest per group (§5.2), and publishes the packet on the run's ring.

A run's own signals are never delivered to its own process: the forwarder never returns an Interest to the face it came from. A sender that wants its own echo reads it from its own state.

## 10. Limits

| What | Limit | Over it |
|---|---|---|
| Address / payload / packet | 64 / 768 / 1,024 octets; 32 signals per packet | sender `TooLarge`; receiver `malformed` |
| Expires | at most 60 s after now | sender `TooLarge`; receiver `expired` |
| Run lifetime | at most 24 h (1 h by default), renewed at 90 % | receiver: a header past its `RunNotAfter`, `expired` |
| Sender rate | 120 packets/s per run, burst 30 | `RateLimited { retry_after }` |
| Receiver rate | 240 packets/s per run, 2,000 per scope | `flood`, before verification |
| Runs held | 4 per sender key, 64 per scope; 8 header admissions at once | `flood` |
| Replay window | 1,024 sequences per run | `replayed` |
| Newest per address | 1,024 (sender, address) pairs per scope; the least recently updated goes | n/a |
| Clock skew allowed | 30 s by default | n/a |

## 11. Wire format

TLV-TYPE numbers 0x0580–0x05AF ([README.md](README.md#tlv-type-numbers)). Every number is even: a decoder MUST skip an unknown even TLV inside these records and MUST refuse an unknown odd one, as in [data-layer.md](data-layer.md) §16.2. Numbers are NonNegativeInteger as in NDN.

| Type | Name | Value |
|---|---|---|
| 0x0580 | SignalBody | Name (scope), RunId, [RunHeader], Signal* (0–32; at least one unless RunHeader rides), RunSignature |
| 0x0582 | SignalSealed | KeyId, SealNonce, Ciphertext |
| 0x0584 | KeyId | 8 octets |
| 0x0586 | SealNonce | 24 octets |
| 0x0588 | Ciphertext | XChaCha20-Poly1305 ciphertext of the SignalBody TLV, with its 16-octet tag appended |
| 0x058A | RunId | 16 octets |
| 0x058C | RunHeader | the run header's whole Data wire |
| 0x058E | Signal | SignalSeq, Address, Expires, Payload |
| 0x0590 | SignalSeq | NonNegativeInteger |
| 0x0592 | Address | 0–64 octets |
| 0x0594 | Expires | NonNegativeInteger, ms since the Unix epoch |
| 0x0596 | Payload | 0–768 octets |
| 0x0598 | RunSignature | 64 octets, Ed25519 |
| 0x059A | RunHeaderBody | RunKey, RunStart, RunNotAfter, [LocalRing] |
| 0x059C | RunKey | 32 octets, Ed25519 public key |
| 0x059E | RunStart | NonNegativeInteger, µs since the Unix epoch |
| 0x05A0 | RunNotAfter | NonNegativeInteger, ms since the Unix epoch |
| 0x05A2 | LocalRing | 32 octets |

```
SignalPacket  = SignalBody / SignalSealed
SignalBody    = SIGNAL-BODY TLV-LENGTH Name RunId [RunHeader] *32Signal RunSignature
                ; at least one Signal unless RunHeader is present
SignalSealed  = SIGNAL-SEALED TLV-LENGTH KeyId SealNonce Ciphertext
Signal        = SIGNAL TLV-LENGTH SignalSeq Address Expires Payload
RunHeaderBody = RUN-HEADER-BODY TLV-LENGTH RunKey RunStart RunNotAfter [LocalRing]
```

Run header name: `<device>/32=signal/<scope>/32=run/<RunId>`. Local ring surface name: `<scope>/32=signal/32=ring/<RunId>`. Push Interest name: `<O>/32=sync/32=signal/<ParametersSha256Digest>`.

## 12. Errors

| Refusal | When | What to do |
|---|---|---|
| `NotMember { scope, why }` | this device is not a member by the record in force, or its key is revoked | ask the scope's owner to share it with this person or device |
| `NotReady { scope, why }` | no record over the scope held yet; or sealed and the key of the epoch in force not held yet (its ask is started) | ask again later (`NextStep::RetryLater`) |
| `TooLarge { what, size, max }` | an address, payload, batch or ttl over its limit | send less, or put a version |
| `RateLimited { retry_after }` | over the run's sending rate | send after `retry_after`, or batch |
| `Closed` | the run or the process's signals ended | open a new run |
| `Io(why)` | the forwarder connection or the local ring failed | reconnect |
| `Data(DataError)` | the data layer refused the scope for another reason (a bad name, a local fault) | what the data error's own next step says |

A receiver never answers a sender. It counts and logs (at `debug`, with the reason and what would admit the packet) every packet and signal it drops: `malformed`, `unknown_key`, `unknown_run`, `unsubscribed`, `bad_signature`, `not_member`, `replayed`, `stale`, `expired`, `flood`.

## 13. Threat notes

### 13.1 A forged sender

A member can't make signals that are delivered as another member's. A packet is delivered under the run whose RunId it carries. The RunId is the hash of exactly one run key, and the run key is bound to its sender only by a header that sender's device key signed. Forging therefore needs the other member's run secret key, or their device key. A sealed scope's signal key is shared by every reader, so any reader can make ciphertext that opens. It still can't make a RunSignature that verifies under another member's run key: the seal gives confidentiality, the run key gives authenticity. A non-member can't get a header admitted: `signal_admit` verifies the device key's chain to an anchor and checks membership. Its packets are dropped at step 4 (`unknown_run`) or refused there, without verifying their bodies. A local process gains nothing from local delivery: frames off a ring are verified exactly like pushed packets, and a ring's mapping is read-only to its readers.

### 13.2 Replay

Within a held run, the window refuses every sequence it has seen, and a sequence only counts as seen after its packet verified. So a copy, from a relay or the forwarder's second path, is delivered at most once. Across a receiver's restart (or a run it let go), a replayed packet of a run whose header still rides in the replayed traffic can be admitted again. Its signals are still dropped once their `Expires` (plus the clock skew allowed) is past. A replay can thus show a signal at most once more, and only within its own validity: by default 2 s plus 30 s of skew. An application whose signals must never be replayed, even this way, uses versions instead. A replay into another scope fails the signature, which covers the scope name.

### 13.3 A removed member

A removal is a members record. A receiver checks membership on every packet against the record in force, so the first packet it checks after it holds the removing record is refused. The same holds for the sender's own `send`. In a sealed scope, the removal starts a new epoch whose key the removed member never gets. Senders that hold the record seal under the new epoch's key, which the removed member can't open. Until a sender holds the removing record it may still seal under the old epoch. The removed member can read those packets, as it could read the old epoch's versions. Decisions come from the signed record, never from timing: a receiver that doesn't hold the record yet still admits the member, and admits no one else.

### 13.4 A stolen run key

A run key lives only in its sender's memory. A thief who takes it can sign packets of that run until `RunNotAfter` (1 h by default, at most 24 h). It can send sequences the honest sender hasn't used yet, and receivers keep whichever packet arrives first for a sequence. It can't open a new run or extend this one: that takes the device key. It can't move the run into another scope: the header names the scope, and the signature covers it. Removing the device, or revoking its key, ends the stolen run on every receiver that holds the record or revocation (§13.3, §7). Short runs bound the exposure: a sender that suspects its process memory SHOULD open a new run and let the old one lapse. A stolen **device** key is the data layer's revocation case: once a receiver holds the revocation, `signal_member` refuses the key's runs at once, and `signal_admit` admits no new header signed by it.

### 13.5 Flooding and denial of service

- **Before verification:** a receiver drops a packet that is oversized, malformed, sealed under an unknown key, of an unknown run without a header, over its run's or scope's rate, or a replay. A flood of such packets costs a decode and a table lookup each, never a signature check or a decryption under a guessed key.
- **Headers:** a header costs a certificate-chain walk once per run, at most 8 at once per process. A sender holds at most 4 runs, and a scope at most 64.
- **A member flooding:** a member can send up to the receive rate (240 packets/s per run, 2,000 per scope) before its packets are dropped. Its own device refuses beyond 120/s. Each delivered signal costs one Ed25519 verification per packet (about 50 µs) and replaces the sender's previous signal for that address, so a slow subscriber never queues a backlog. The owner removes a member who abuses this.
- **The network:** a push Interest lives 1 s in a PIT and has HopLimit 8. A forwarder's ordinary Interest limits apply to it as to any Interest.
- **The local ring:** its attach handshake refuses a process without the secret. ndn-surface's handoff stops serving new readers after 16 refused attaches. A local process can thus block later local attaches to a run, never its pushes. Readers that can't attach still get the pushed copies.

### 13.6 What relays and others see

A relay forwarding a push Interest sees:
- the group: the namespace of a member, as it already sees for sync notices;
- the packet's size and timing;
- in a sealed scope, the 8-octet KeyId (constant over an epoch, so packets of one scope and epoch can be linked to each other), the nonce and the ciphertext.

It does not see the scope's name, the sender, the run, the addresses or the payloads; the run header travels inside the seal. In an **unsealed** scope everything in the packet, the scope name and the sender's key name included, is plain to every forwarder on the path. An unsealed scope's signals are as public as its versions: seal the scope to keep them private. A relay can drop or delay packets, or replay them (§13.2), and can't forge or alter one (§13.1).

On the host, the forwarder's multicast delivers the push to every local face that registered the group, so any local process can register it. In a sealed scope it learns what a relay learns. In an unsealed scope it reads the packets, as a relay could.

### 13.7 Carriage

Signals never travel as Data. A future signal answer (for example a header asked for by name) MUST carry NDNLPv2 `CachePolicy = NoCache`, which the ndn-rs forwarder honours (`stages/cs.rs`). This spec defines none.

### 13.8 Clocks

`Expires` and `RunNotAfter` are read on the receiver's clock with the skew it allows. A receiver whose clock runs more than that skew ahead of a sender's drops the sender's signals as expired. One running behind admits them longer, and replays (§13.2) longer with them. Clocks decide only whether a signal is still live, never who may send. Membership, authenticity and replay decisions come from signed data and the window alone.

## 14. Conformance

Conformance cases (ndn-sim `ndn-data-conformance`, ids `e1`–`e10`) cover: a member's signals reaching the other members over the network; a non-member that can neither send nor receive; a member that can't forge another's signals; replays refused; a removed member stopped at once; a sealed scope whose relay sees only ciphertext; nothing in any content store; the newest per address under loss; a commit turning live work into one version; 60 Hz with several senders. ndn-surface's tests cover the local leg over shared memory and one link between two engines. The real-daemon end-to-end scenario `signals` (ndn-fwd `testbed/e2e`) carries cursors between two people through a relay that holds no context of theirs and has no route set by hand.

## 15. Decisions

- **Push into the sync groups, not a new prefix.** The groups already reach every member's devices through every relay with no configuration ([data-layer.md](data-layer.md) §12). A second per-namespace prefix would need the same routes, strategy choices and transit lifecycle added to the link and trust-context libraries. Sharing the group costs each SVS face a parse of the signal Interests it ignores, and each signal receiver a parse of the Sync Interests it ignores.
- **An asymmetric run key, not a shared one.** A symmetric key shared with the receivers would let any member forge any other's signals (ndf-rs, REPLY-to-ndn-workspace-1 §E). Signing every packet with the device key would make a chain walk per sender and expose the device key to a 60 Hz signing loop. A run key costs one Ed25519 signature per packet.
- **Sign, then seal.** A relay then sees no sender identity, and a member can't strip and re-sign another's packet without its run key.
- **XChaCha20-Poly1305 with random nonces.** One signal key serves every sender of an epoch, and an epoch can last months. A 24-octet random nonce keeps collisions negligible at any packet count.
- **The header rides inline, about once a second.** No pull path, so nothing about a signal is ever answered or cacheable. A receiver that lost the header waits at most a second, and packets it can't place cost nothing to drop.
- **Membership checked per packet, synchronously.** "A removed member stops at once" then means: at the first packet after the record is held, independent of any event delivery.

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
