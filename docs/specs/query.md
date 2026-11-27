# Query: asking the writers of a space, and what they answer

- **Status:** implemented for the **signed path**: `Heap::serve`, the query on `Heap::get` (`GetOptions::ask`), the signed Interest and the signed Data, sealing in sealed spaces, the server's judging, the asker's judging, targeting and counting, and the announce hint (`ANN_SERVES`). The **channel path is reserved**: `QueryPath::Channel` is refused at `get` with `HeapError::BadRequest` (the reason says the path is not built in this version of the layer and to ask `Signed` or `Auto`), `QueryPath::Auto` is therefore always the signed path, and `Via` is `#[non_exhaustive]` with the one variant `Signed`. Nothing in the channel path's design is normative until a section of this file or of [channel.md](channel.md) says so.
- **Implementation:** `ndn-heap`, module `query` (`ndn-rs/crates/app/ndn-heap/src/query/`): `types.rs` (the public types), `serving.rs` (`Heap::serve`, `Serving`), `table.rs` (the served prefixes and the announce hints), `serve.rs` (the server's judging), `ask.rs` (the asker), `answers.rs` (the answer queue of one `get`), `seal.rs` (sealing). The records are in `wire/query.rs`, the names in `wire/names.rs`, the announce field in `chan/wire.rs`, the stream in `chan/items.rs` and `chan/verbs.rs`, the dispatch in `serve.rs` and `chan/hub.rs`, the key agreement in `ndn-security` (`confidentiality.rs`: `pair_keys_to`, `RecipientKey::pair_keys_from`).
- **Scope:** a **query** is a question one member of a space puts to the **devices of the space's writers** and an **answer** is what a handler on such a device says back, by name, to that asker alone: `serve(prefix, handler)` on one side, `get` with an `ask` on the other. A query is **not a write**: nothing a handler answers is an entry, is stored, is cached or is anyone's current value. This file specifies the API, the invariant that keeps the feature from becoming a family of stored answers, the names and packets, the TLV block 0x06C0–0x06FF, sealing in a sealed space, how a server judges a query, how an asker judges an answer, targeting, counting and order, the announce hint, limits, security notes, test vectors and conformance cases.
- **Out of scope:** the channel path (reserved, §2); which writer may serve which prefix (every writer's device may serve any prefix, §12); merge rules and the heads of a path ([heap.md](heap.md) §10.3, [channel.md](channel.md) §17.9); what a handler computes.

The key words "MUST", "MUST NOT", "SHOULD" and "MAY" are as in BCP 14, in capitals only.

## 1. Terminology

| Term | Meaning |
|---|---|
| space, path | As [heap.md](heap.md) §2.1: a space `<O>/32=data/<c1…c4>` and a name relative to it. |
| asker | A **listed** member's device (a writer's or a reader's; a follower never asks) that calls `get` with an `ask`. |
| server | A **writer's** device that holds a `Serving` for a prefix of the space. |
| handler | The application's callback on a server: it runs once per query that reaches it and returns a `Reply`. |
| query | One question to one server: the signed Interest `<server>/32=query/<digest>` (§5). One `get` with an `ask` sends one query to each server it targets (§10.2); all carry the same query id. |
| answer | The signed Data of exactly that name (§5). One per query per server. |
| query id | Eight random octets the asker chooses per `get`, echoed in the answer (`Q_ID`) and given to the handler as `Query::id`. |
| plain, sealed | A query in a **public** space is *plain*: its path and octets are in the clear. In a **sealed** space it is *sealed*: the path and octets, and the whole status of the answer, are ciphertext under a pair key (§7). |
| pair key | `Kq` (seals queries) and `Ka` (seals answers), derived from one X25519 agreement between an asker device and a server device for one epoch (§7.2). |
| standing | As [channel.md](channel.md) §4.1: a key *stands* for a space when its person is listed in the role asked, its role is owner-capable, its context does not revoke it and this node does not suspect it. |
| silent | A server that said nothing by the query's deadline: a `Reply::Pass`, a handler past the deadline, a Data that never came, a down server. |

## 2. Status and what is reserved

The signed path is complete and is the only path. The following are **reserved** and MUST NOT be relied on:

- `QueryPath::Channel`: `get` refuses it with `BadRequest` before any I/O. An implementation that adds the path will add a second `Via` variant; `Via` is `#[non_exhaustive]` and a reader of it MUST use a wildcard arm.
- `QueryError` and `ServeError` are `#[non_exhaustive]`: the channel path adds setup refusals to the first.
- TLV 0x06D9 (`A_RETRY`) is reserved for a later answer that says how long to wait. It is not written and not read: a record that carries it is refused as an unknown critical type (§6).
- A value of `Query::via` or `Answered::via` other than `Signed`: none exists, and none is produced.

## 3. The API

### 3.1 `serve`

```rust
impl Heap {
    pub fn serve(&self, prefix: Name, handler: impl Handler) -> Result<Serving, ServeError>;
}

#[must_use] pub struct Serving;                 // prefix() -> &Name; Drop unregisters
pub trait Handler: Send + Sync + 'static {
    fn answer(&self, query: Query) -> HandlerFuture;   // BoxFuture<'static, Reply> (LocalBoxFuture on wasm32)
}
// any F: Fn(Query) -> Fut, Fut: Future<Output = Reply> + Send + 'static is a Handler

pub struct Query {
    pub id: QueryId,          // the asker's id (u64 of the 8 octets); the same to every server of one get
    pub path: Name,           // the asked name, relative to the space; a served prefix is a prefix of it
    pub bytes: Bytes,         // the query octets (opened, in a sealed space)
    pub asker: Asker,         // as the space judged it when the query arrived
    pub via: Via,             // Signed (non_exhaustive)
    /* private: the asker's deadline */
}
impl Query { pub fn remaining(&self) -> Duration; }   // how long the asker still waits
pub struct Asker { pub person: Name, pub device: Name }
pub enum Reply { Answer(Bytes), Refuse(AppRefusal), Pass }
pub struct AppRefusal { pub code: u16, pub text: String }   // AppRefusal::new cuts text to 256 octets
```

- `serve` registers `prefix` (a name relative to the space, empty allowed) with `handler` and returns a `Serving`; **dropping it unregisters the prefix at once**. A query that arrives after is answered `NotServed`. A handler already running is not told and its answer is still sent unless the asker's deadline has passed.
- A query is addressed to a path. A server answers when **one of its served prefixes of the space is a prefix of the path** (a name-component prefix: `/world` serves `/world/x` and not `/worldwide`); the handler of the **longest** such prefix runs, so one query runs one handler. Nested prefixes are allowed; the same prefix twice is `Overlap`.
- The handler runs **once per query that reaches it** (§8 step 9) and its `Reply` goes to that asker once:
  - `Answer(bytes)`: at most 4,096 octets. A longer answer is sent as the signed status `TooLarge` carrying 4,096 (§6). A larger result is the handler's `put` and an answer that names the path.
  - `Refuse(AppRefusal)`: the application's own refusal, a `u16` code it defines and a text of at most 256 octets (cut at a character boundary). It is an answer, not a system failure: the asker is told it as an `Answered` with a `refusal` and counts it `refused`.
  - `Pass`: nothing for this query. **Nothing is sent**: the Responder is dropped and no Nack is made, so the asker counts the server `silent` at its deadline. A handler that wants the asker to know says `Refuse`.
- The handler is run under the **asker's deadline** (`Q_DEADLINE` ms from the query's arrival). A handler that has not finished by then is dropped and **nothing is sent**: the asker counts the server `silent`. A handler with side effects keys them on `Query::id` and `Query::asker` (a retry is a new `get`, so a new id, and runs the handler again), and judges the asker itself where a removal matters: `Query::asker` is the judgement at arrival.
- `Query::asker.person` is the person the trust context vouched for the signing key as; `device` is the device the key belongs to.

`ServeError` (`#[non_exhaustive]`), each with a `next()`:

| Variant | When | NextStep |
|---|---|---|
| `NotWriter { space, why }` | this heap only follows the space, or this device is no writer of it by the entries held (a reader's device never serves), or its key does not stand | `AskOwner` |
| `NotReady { space, why }` | the space's creation record is not held yet | `RetryLater` |
| `Overlap { existing }` | this heap serves exactly this prefix already | `FixRequest` |
| `TooMany { max }` | the space serves 64 prefixes already | `FixRequest` |
| `BadPrefix { size, max }` | the sum of the octets of the prefix's component values is over 255 | `FixRequest` |

The first successful `serve` of a node also fixes the **replay floor** (§8.3) and makes the node announce the prefixes it serves (§11).

### 3.2 `get` with an `ask`

```rust
pub struct GetOptions { /* kept, heads, live, modes, trust, congestion as channel.md §17 */ pub ask: Option<Ask> }
                       // Clone, Debug, PartialEq, Eq: no longer Copy
pub struct Ask {
    pub query: Bytes,            // at most 2,048 octets
    pub targets: Targets,        // default Targets::Serving
    pub via: QueryPath,          // default QueryPath::Auto
    pub deadline: Duration,      // default 3 s; 1 ms to 10 s; setup, wait for a server and handler together
    pub answer_max: usize,       // default and most 4,096; 1 at least; a larger answer is a failure
    pub proof: bool,             // keep each answer's signed Data in Answered::proof; default false
}                                // Ask::new(query) gives the defaults
pub enum Targets { Serving, Devices(Vec<Name>), Person(Name) }   // at most 16 servers per query
pub enum QueryPath { Auto, Signed, Channel }                      // Channel is refused (§2)

// Kind gains (it is #[non_exhaustive]):
Kind::Answered(Answered)
pub struct Answered { pub query: QueryId, pub via: Via, pub refusal: Option<AppRefusal>, pub proof: Option<Bytes> }
// GetNotice gains (it is #[non_exhaustive]):
QueryFailed { server: Name, why: QueryError },
AnswersDone { asked: u32, answered: u32, refused: u32, failed: u32, silent: u32, not_asked: u32 },
```

- `get` stays synchronous and does no I/O in the caller's task: it judges the request, registers the answer queue and **spawns** the query on the node's tasks (the way [channel.md](channel.md) §17.1 registers both feeds). Nothing that happens after the call is lost for want of a first poll. **Dropping the `Items` cancels the query**: its Interests are dropped, its pending slots are released and a late answer is discarded; a handler already running is not told.
- **What an answer is.** A `Got` with `path` the asked path, `bytes` the answer octets (empty for a refusal), `writer` the **server's device**, `by` the **person of the key that signed the answer** as this node judged it (§10.1 step 4), and `kind` `Kind::Answered`. `Answered::query` is the query id, `via` the path it came by, `refusal` the handler's own refusal if it refused, `proof` the **whole signed Data** when `Ask::proof` was set (the server device's statement: anyone who holds the space's record can check it).
- **`Select`.** A query is addressed to the selector's name: `Select::Path(p)` and `Select::Prefix(p)` both ask path `p`.
- **A `get` that asks nothing else.** `kept: false` with `live: Live::Off` and `ask: Some(..)` is a **query-only stream** (§10.4). The same options with `ask: None` stay `BadRequest` ([channel.md](channel.md) §17.7).
- **Who may call.** `get` with an `ask` needs a **listed** reader or writer whose key stands. A follower is `NotAllowed`.

`get` refuses an `ask` at creation, with a reason and a `NextStep` ([heap.md](heap.md) §10.5), in this order:

| Refusal | When |
|---|---|
| `NotAllowed` | the device only follows the space (it takes no part in queries: open it as a member); or its key does not stand as a listed member (neither writer nor reader by the entries held, revoked, suspected, or its chain not shown clean) |
| `BadRequest` | `QueryPath::Channel` (reserved, §2); a query over 2,048 octets; a deadline of zero or over 10 s; `answer_max` of zero or over 4,096; an asked path whose name value is over 255 octets; `Targets::Devices` empty, naming more than 16, naming a name that is no device name (it holds a keyword or a digest component) or lies under `/localhost` or `/localhop`, or naming this device itself |
| `NotReady` | the space's creation record is not held yet |

That no server is known is **not** a refusal at creation: it is told later, as `NoServer` (§10.2).

### 3.3 `QueryError`

A query to one server that fails is a `GetNotice::QueryFailed { server, why }` and counts `failed`. `why.next()` says what to do.

| Variant | Told when | NextStep |
|---|---|---|
| `NoServer { path }` | no server is known for the path (§10.2); `server` is the **space's name** | `FixRequest` |
| `NotListed` | the server Nacked `NoRoute`: it does not list this device's person, the key has no standing there, the person is outside a sealed space's audience, the query's `SignatureTime` is more than 120 s from the server's clock or before the server began serving (§8), or no route reaches it. The text names each | `AskOwner` |
| `NotServed { path }` | the server's signed status `NotServed` (`A_STATUS` 3): no served prefix of the path | `FixRequest` |
| `Busy` | a `Congestion` or `Duplicate` Nack: the server is over a limit of its own, or had seen a copy of this query | `RetryLater` |
| `NotYet` | a `NotYet` Nack: the server does not hold this device's certificate chain or the sealed space's epoch | `RetryLater` |
| `Unreachable` | any other Nack, or the connection closed | `RetryLater` |
| `TooLarge { what, max }` | the server's signed status `TooLarge` (`A_STATUS` 4), `max` its limit | `FixRequest` |
| `AnswerTooLarge { size, max }` | an answer over `Ask::answer_max` | `FixRequest` |
| `BadAnswer { why }` | the answer failed the asker's judging (§10.1), or what the forwarder reported was not a Nack or a timeout, or the server's seal key could not be had or judged (§7.1) | `RetryLater` |
| `TooManyOutstanding` | this node has 64 queries outstanding, or 16 to this server (§10.5) | `RetryLater` |
| `NotWriter { device }` | `Targets::Devices` named a device that is no writer of the space by the record held here: nothing is sent to it | `FixRequest` |
| `NotReady { why }` | the query could not be made: a sealed space with no epoch in force yet, the record cannot be written, or the device key did not sign | `RetryLater` |

A handler's own `Refuse` is **not** a `QueryError`: it is an answer (`Answered::refusal`), counted `refused`.

## 4. The invariant: no answers family

An earlier data layer had a family of *answers*: results that evaluators computed, readers recomputed and resealed, and stores kept as if they were values. It was deleted. `serve` is a **producer callback** and nothing more. Five rules state what the code and this file keep, each guarded by a test that fails if it is broken (`ndn-heap`, `query/serve_tests.rs` and `query/ask_tests.rs`):

1. **A handler runs once per query that reaches it, and its result goes to that asker once.** No answer is stored, indexed, cached or served to a second asker by this layer: not by the server (no answer table, no store write, no memo), and a forwarder is asked not to (the Data is `FreshnessPeriod` 0 with `CachePolicy NoCache`, and the Interest is `MustBeFresh`: a conforming store neither keeps it nor satisfies another Interest with it; §12 says what a store that does not conform can do). *Guards:* `no_answer_is_stored_or_cached` (three queries run the handler three times, each Data is sent `NoCache`, the node's store holds nothing new); `a_replayed_signed_query_is_a_duplicate_and_the_handler_ran_once`; `no_answer_is_ever_an_entry` (a second `get` runs the handler again: no memo).
2. **An answer is never an entry and never the current value of a path.** `Kind::Answered` is not `Kind::Kept`; it is not in the register, not in the kept listing and not told again by a later `get`. *Guard:* `no_answer_is_ever_an_entry` (`kept` finds nothing at the asked path at the asker or the server; a `get` without an `ask` lists nothing of it).
3. **No reader recomputes, reseals or derives anything from an answer.** The asker is told exactly what the server signed (`proof` is that Data, byte for byte); there is no evaluator, no result cache keyed by query and no derived-value kind. *Guards:* `proof_keeps_the_signed_data_and_it_verifies_as_the_servers`; `a_listed_asker_gets_the_handlers_answer_signed_by_the_servers_device`.
4. **State is memory, bounded by outstanding queries and judged members, and nothing is persisted.** The asker's pending set (64, 16 per server), its seal keys and pair keys (64 each), the answer queue of one `get` (64 answers, 1 MiB); the server's handlers in flight (64, 8 per person), its replay set (240 s, capped), its pair keys (1,024) and its counters per person. A restart forgets all of it; the replay floor (§8.3) is what makes that safe. *Guards:* `the_pending_set_holds_sixteen_per_server_and_sixty_four_in_all_and_releases`, `outstanding_limits_hold`, `a_slow_reader_loses_the_oldest_answers_and_is_told_lagged`, `the_pair_cache_derives_once_per_epoch_and_drops_what_moved_and_is_bounded`, `concurrency_cap_is_busy_with_no_queue`, `per_person_inflight_and_rate_hold_across_her_devices`, `the_replay_set_forgets_after_240_s_and_refuses_over_its_cap`.
5. **One answer per query per server.** A server sends one Data per Interest (the PIT is satisfied once) and the asker tells at most one outcome per server: every server asked ends in exactly one of `answered`, `refused`, `failed`, `silent`. A handler that has a stream of results returns one value (the application frames it) or `put`s and answers with the path. *Guards:* `asked_is_always_answered_plus_refused_plus_failed_plus_silent`; `several_servers_answer_and_done_counts_add_up`.

## 5. Names and packets

- **The query and its answer** are named `<server>/32=query/<ParametersSha256Digest>`, where `<server>` is the **server's device name**: the components before the keyword, a device name (no keyword and no digest component). Exactly one component follows the keyword, a ParametersSha256DigestComponent (type 2) of 32 octets. Nothing else parses as a query name: no component after the keyword, two, a generic one, an ImplicitSha256Digest, a digest of 31 or 33 octets, a device with a keyword or a digest component, the empty device, or another keyword. `<server>/32=query` is **the prefix** a query is signed under, before its digest is appended.
- **`query` is a core keyword.** It joins the keywords of [heap.md](heap.md) §2.4 (`CORE_KEYWORDS`): the keyword router sends `<device>/32=query/…` to the query judging of §8; an extension is never given it and `extend` refuses a claim of it.
- **The query** is an Interest with `MustBeFresh`, InterestLifetime = the milliseconds the asker still waits (`Q_DEADLINE`), ApplicationParameters = one `QUERY_ASK` (§6), and an `InterestSignatureInfo` with the **asker's device key** as KeyLocator, a `SignatureNonce` and a `SignatureTime` (wall-clock milliseconds). The parameters are at most 8 KiB and hash to the name's digest.
- **A node signs no Interest but two.** `NodeHandle::sign_interest` signs `<device>/32=chan` (a `CHAN_ASK`, [channel.md](channel.md) §3.1) and `<device>/32=query` (a `QUERY_ASK`), only when the parameters decode as the record the name takes and only for a device that lies under neither `/localhost` nor `/localhop`: a signed Interest of a device's key is a command wherever that key is trusted. Any other name is `BadRequest`; nothing else is signed.
- **The answer** is the Data of exactly that name, signed by a key of the **server's device** (the signature covers the sealed octets in a sealed space), `FreshnessPeriod` 0, carried in an NDNLPv2 packet with `CachePolicy = NoCache` (a header of one hop: a forwarder that forwards it says it again to each face), Content = one `QUERY_ANSWER` (§6), at most 8,000 octets. It carries no `SideRoute` header. A server answers every query it judges: with this Data, with a Nack, or (for `Pass` and a late handler only) with nothing.
- **The seal key packet** an asker needs in a sealed space is fetched by the **keyless name** `<server>/32=seal` with `CanBePrefix` (§7.1); heap.md §2.2 lists both forms.

## 6. TLV types

The query's TLV-TYPEs are the block **0x06C0–0x06FF**, registered to this file in the [specification registry](README.md#tlv-type-numbers). Odd numbers are critical: an unknown odd type inside these records is a malformed record (`UnknownCritical`), also inside the sealed parts of §7.3. Even numbers are skippable and reserved for additive fields, as in [heap.md](heap.md) §3.4. Numbers are NonNegativeIntegers. `Name` values are a Name's components, as the value of the TLV. `ASKER_CERT` is heap's 0x063D and `S_CERT` is channel's 0x0697. A reader accepts fields in any order and refuses a field twice or a required field absent.

| Type | Name | Value |
|---|---|---|
| 0x06C1 | `QUERY_ASK` | the ApplicationParameters of a query: `Q_SPACE`, `Q_PATH`?, `Q_ID`, `Q_DEADLINE`, `Q_BYTES`, then `Q_SEAL`, `Q_EPOCH`, `Q_SEQ` (all three or none), `ASKER_CERT`* (0x063D) |
| 0x06C3 | `Q_SPACE` | Name: the space |
| 0x06C5 | `Q_PATH` | Name: the asked path, relative to the space; at most 255 octets of name value. **Present iff the query is plain** |
| 0x06C7 | `Q_ID` | 8 octets: the asker's query id (echoed in the answer) |
| 0x06C9 | `Q_DEADLINE` | milliseconds, 1 to 10,000 |
| 0x06CB | `Q_BYTES` | the query octets (plain: at most 2,048); in a sealed query the **ciphertext** (16 to 2,367 octets: 2,048 + 255 + 64) |
| 0x06CD | `Q_SEAL` | 32 octets: the asker's ephemeral X25519 public key (sealed query only) |
| 0x06CF | `QUERY_ANSWER` | the Data's Content: `Q_ID`, then a **plain** status (`A_STATUS` and the fields its status takes) **or** `Q_SEQ` and `A_SEALED`; then `S_CERT`* (0x0697) |
| 0x06D1 | `A_STATUS` | 1 `Answered`, 2 `Refused`, 3 `NotServed`, 4 `TooLarge` |
| 0x06D3 | `A_BYTES` | the answer octets (status 1): at most 4,096 |
| 0x06D5 | `A_CODE` | the application's code (status 2, at most 65,535) or the limit (status 4) |
| 0x06D7 | `A_TEXT` | UTF-8, at most 256 octets (status 2) |
| 0x06D9 | `A_RETRY` | **reserved**, not written, not read: refused as an unknown critical type |
| 0x06DB | `Q_EPOCH` | the **value** of an `EPOCH_ID` (heap.md 0x061B): `Name(creator)`, `SEQ` (0x060B): the epoch the pair key is bound to (sealed query only) |
| 0x06DD | `Q_SEQ` | NonNegativeInteger: the sealing counter of the packet's sender: the asker's in a `QUERY_ASK`, **the query's own, echoed**, in a sealed `QUERY_ANSWER` (§7.4) |
| 0x06DF | `A_SEALED` | the ciphertext of the status fields (sealed answer only): 16 to 4,416 octets (4,096 + 256 + 64) |

The statuses and the fields they take (each status carries its own fields and **no others**; a stray field, a missing one or an unknown status is malformed):

| `A_STATUS` | Fields | Meaning |
|---|---|---|
| 1 `Answered` | `A_BYTES` | the handler answered |
| 2 `Refused` | `A_CODE` (≤ 65,535), `A_TEXT` | the handler refused, in the application's words |
| 3 `NotServed` | none | no prefix of the path is served here |
| 4 `TooLarge` | `A_CODE` = the limit | the handler's answer is over what fits (4,096) |

**Plain or sealed, nothing between.** A plain `QUERY_ASK` has `Q_PATH` and none of `Q_SEAL`, `Q_EPOCH`, `Q_SEQ`. A sealed one has all three and **no `Q_PATH`**: the path travels inside the ciphertext. A plain `QUERY_ANSWER` has the status fields and neither `Q_SEQ` nor `A_SEALED`; a sealed one has both and **no status field beside them**. Any other mixture is malformed.

**Limits of the records.** The whole `QUERY_ASK` is at most 8 KiB (8,192 octets) and the whole `QUERY_ANSWER` at most 8,000 octets: larger is refused when written and when read. A query carries at most 4 `ASKER_CERT` and an answer at most 4 `S_CERT`, each a whole Data of at most 4,096 octets and 6,144 in all, so the judge fetches nothing (§8 step 5, §10.1 step 3). A server that cannot fit its certificates beside the status sends the answer **without** them. The deadline is 1 to 10,000 milliseconds; `Q_ID` is exactly 8 octets and `Q_SEAL` exactly 32.

## 7. Sealed spaces

In a **public** space the query and the answer are in the clear (§12 says what a relay sees). In a **sealed** space ([heap.md](heap.md) §6) a plain query would show its path and octets to every forwarder, so a plain query to a sealed space is refused (§8 step 7) and a sealed one to a public space is refused too. The asker seals to the server.

### 7.1 The server's key

The asker needs the server's X25519 **recipient key**, the key its seal key packet carries ([heap.md](heap.md) §6.2). It sends an Interest for the **keyless name** `<server>/32=seal` with `CanBePrefix` and InterestLifetime the time it has left. The server answers with its **seal key packet** `<server>/32=seal/<public key>`, the same signed Data it serves under the keyed name: only the device's own name is answered, with its own packet, and any other device or key is answered with nothing. The keyless Interest is unsigned and costs the server a lookup. The asker accepts the packet only if:

1. its name parses as `<device>/32=seal/<key>` with `<device>` the server and the Content's key equal to the key in the name;
2. it verifies as a key of the server's device by the durable rule of [heap.md](heap.md) §9 (signature and chain, no clock): the seal key packet carries no certificates, so a certificate of its chain that is not held may be fetched, as for any device's packet;
3. the signing key **stands as a writer now**.

Any other result is `QueryFailed { BadAnswer }` (a timeout is `silent`, a Nack maps as §10.3). The asker keeps the key until the trust generation moves.

### 7.2 The pair key

The asker derives, **once per (space, server device, epoch in force)**, one pair of keys from one X25519 agreement and reuses them for every later query of that epoch to that server:

```
ephemeral        = a fresh X25519 key pair of the asker (its public half goes in Q_SEAL)
shared           = X25519(ephemeral secret, the server's recipient key)         (all-zero: refused)
context          = Name TLV(space) ‖ Name TLV(asker device) ‖ Name TLV(server device) ‖ EPOCH_ID TLV(epoch in force)    (pair_context)
pair             = HKDF-SHA256(ikm = shared, no salt,
                               info = "ndn-query/pair/1" ‖ ephemeral (32) ‖ recipient (32) ‖ length of context (u32, big-endian) ‖ context,
                               L = 32)
Kq               = HKDF-Expand(pair, "ndn-query/pair/q/1", 32)    seals the asker's queries
Ka               = HKDF-Expand(pair, "ndn-query/pair/a/1", 32)    seals the server's answers
```

The three labels differ from each other and from the label of the key-wrap KEK (`ndn-security/confidentiality/x25519-kek/1`), so one agreement cannot give a wrap key, and `Kq` never opens an answer nor `Ka` a query. The server derives the same pair from its recipient secret and the asker's `Q_SEAL`, with the same context, **after** the signed Interest has verified (§8 step 8). Both ends name AES-256-GCM; nothing negotiates it.

- **Bound to** the space, both device names, the epoch, both X25519 public keys: a different value in any of them derives other keys. The context is canonical (names are TLVs, so `/a/b` + `/c` is not `/a` + `/b/c`).
- **What it proves.** The Interest is signed by the asker's device and carries `Q_SEAL`; the Data is signed by the server's device. A ciphertext that opens under `Kq` therefore comes from the party that signed the query and one that opens under `Ka` from the party that signed the answer. It is origin authentication between two parties and **no non-repudiation toward a third**: either holder of the pair could have made any ciphertext. The signed Data is the proof, and what it proves in a sealed space is that the server signed *those ciphertext octets*.
- **What it does not give:** forward secrecy against the server's recipient secret, and anonymity from the server.

### 7.3 Sealing

A sealed `QUERY_ASK` carries `Q_SPACE`, `Q_ID`, `Q_DEADLINE`, `Q_SEAL`, `Q_EPOCH`, `Q_SEQ`, `ASKER_CERT`* in the clear and `Q_BYTES` = the ciphertext of

```
plaintext of a query  = Q_PATH (the asked path) ‖ Q_BYTES (the query octets)           as TLVs, in this order  (seal_inner)
plaintext of an answer = the status fields (A_STATUS and the fields of its status)      as TLVs                  (encode_inner)
```

The cipher is AES-256-GCM, output = ciphertext ‖ 16-octet tag (an empty plaintext is a tag alone, so no ciphertext is under 16 octets). The key is `Kq` for a query and `Ka` for an answer.

**What is sealed:** the path and the query octets of the ask; the **whole status** of the answer, which includes `NotServed`, `Refused` and `TooLarge` (an eavesdropper cannot tell an answer from a refusal). **What is not:** the space, the query id, the deadline, `Q_SEAL`, `Q_EPOCH`, `Q_SEQ`, the certificates, the names, the signatures, and the length of the ciphertext (no padding: it shows the plaintext's length to within the 16-octet tag).

**Additional data** binds the ciphertext to its exchange (`query_aad` / `answer_aad`): one **direction octet** (1 for a query, 2 for an answer), then the **server** as a Name TLV, the **asker** as a Name TLV, the **space** as a Name TLV, the **epoch** as an EPOCH_ID TLV, the asker's **ephemeral key** (32 octets), the **counter** (8 octets, big-endian) and the **query id** (8 octets). A ciphertext opens only as the thing it was sealed as, between the parties it was sealed between, in the exchange it was sealed for; moving a field, swapping the asker and the server, or flipping the direction does not open.

Both signatures cover the ciphertext: the Interest signs the parameters (and so `Q_BYTES` and `Q_SEAL`), the Data signs its Content.

### 7.4 The nonce

The nonce of AES-256-GCM is **four zero octets followed by the counter, 8 octets big-endian**, with the **query's** counter `Q_SEQ` for the query **and for its answer**: the query is sealed under `Kq` with the asker's counter, the answer under `Ka` with the **same** counter, and the answer's `Q_SEQ` repeats it (an asker refuses an answer whose counter is not its query's).

- **The asker's counter** starts at 0 for a new pair, rises by one per query and is never reused under one pair; a new pair (a new epoch, a new server key, an evicted cache entry) has a new ephemeral key, hence new keys, so the counter may restart at 0.
- **Why the answer does not use a counter of the server's own.** A server's counter would live in its memory with the pair. A restarted server, or one that dropped the pair, derives **the same** `Ka` again from the asker's unchanged ephemeral key and its own recipient key, and its counter would start over at 0: the same nonce under the same `Ka` for a different plaintext, which breaks GCM. The query's counter is the asker's, strictly rising per pair, so no nonce repeats under `Ka` as long as the asker never repeats a counter. An asker that does (a buggy or hostile one) holds `Kq` and `Ka` itself and endangers only its own exchange.
- The server does not keep a counter or a window per pair: the replay set of §8.3 refuses a repeated signed query, and the counter only has to be the asker's.

### 7.5 Caches and when they drop

- **The asker** keeps at most **64** server seal keys and **64** pairs (the one used longest ago is dropped). A seal key is dropped when the trust generation moves. A pair is dropped when the trust generation moves, when the members fold of its space moves, when the epoch in force or the server's key is not the one it was made for, or when the server is no writer any more (the same happens to the server's seal key). A query of a new epoch derives a new pair.
- **The server** keeps at most **1,024** pairs, one per (space, asker device), replaced when the asker's ephemeral key or epoch differs. A query that arrives with the table full and no pair of its own is a `Congestion` Nack. A pair is dropped: when its asker no longer stands as a listed person; when its asker is outside the audience of the epoch in force or the pair's epoch is not the one in force; when this device is no writer of the space (all its pairs); when the space is no longer open here; and when a sealed query fails to open (the asker holds a key the server does not: the next query derives again). The server judges its pairs again on its maintenance tick (every 250 ms and when the node is woken), cheaply when neither the trust generation nor the members fold has moved.
- Nothing here is persisted.

## 8. How the server judges

The server judges a query **cheapest first**, so a stranger costs a lookup and no signature and a member costs one verification. The steps that decline without a word answer a Nack and sign nothing. A Nack that names a reason is the one in the table; the asker maps it as §10.3.

| Step | Check | Refusal |
|---|---|---|
| 1 | The name parses as `<this device>/32=query/<digest>`; the Interest carries ApplicationParameters of at most 8 KiB that hash to the digest and decode as a `QUERY_ASK` within its limits; the Interest is signed with a KeyLocator naming a key of a device, a `SignatureNonce` and a `SignatureTime`; `Q_SPACE` is a space name | `NoRoute` Nack, for each failure |
| 2 | One token of the **lookup budget**; then the space is **open here as a member** (not as a follower); then the key **stands as a listed person** (`Who::Listed`: a writer or a reader the record lists, owner-capable role, not revoked, not suspected), **by the entries held now**. A public space does not make a reader of an unlisted person: queries need a listed asker | `Congestion` over the budget; `NoRoute` otherwise |
| 3 | The **clock**: `SignatureTime` within **120 s** of this device's clock (`|now − signed| ≤ 120,000 ms`) **and not before the replay floor** (§8.3) | `NoRoute` |
| 4 | One token of the **verification budget** | `Congestion` |
| 5 | The **signature** verifies by the live rule from the certificates held and the at most four carried, **fetching nothing**; the carried certificates are held only as unverified copies for the one judging and dropped unless the walk reaches a trust anchor. The signer is judged by the context of **its own device**. This is the one expensive step | a chain not held and not carried: `NotYet`; a signature that does not verify: `NoRoute` |
| 6 | The **replay set** (§8.3) | a repeat of (key, nonce, time): `Duplicate`; a full set: `Congestion` |
| 7 | **Standing again** under the record's lock, as the key that signed the query; **this device is a writer** of the space; in a **sealed** space: an epoch in force exists, the query is sealed, its `Q_EPOCH` is the epoch in force, and the asker's person is in the audience of that epoch; in a **public** space: the query is plain. Then one token of the **person's rate** (§8.4) | standing lost, this device no writer, a plain query in a sealed space, a sealed one in a public space, the person outside the audience: `NoRoute`. No epoch in force here, or `Q_EPOCH` is not it: `NotYet`. Over the person's rate: `Congestion` |
| 8 | A **sealed** query is opened under the pair key (§7.2: derived once per (asker device, ephemeral key, epoch) and kept) and its plaintext decoded as `Q_PATH` and `Q_BYTES`; a **plain** one has its path already. Then the **served prefix**: the handler of the longest served prefix of the path | the pair table full: `Congestion`; a key no agreement can be made with, a ciphertext that does not open (the pair is dropped), a plaintext that is not a path and octets: `NoRoute`. **No prefix of the path is served: a signed `NotServed` answer** (no handler runs, no place is taken) |
| 9 | A **place** for the handler: this node runs fewer than **64** handlers, this person fewer than **8** (on all her devices together), and she has answer octets left (§8.4). **No wait queue.** Then the handler runs under the asker's deadline, and its result is signed and sent | no place: `Congestion` Nack. Handler `Pass`, or past the deadline: **nothing is sent** |

Notes on the steps:

- **A stranger costs no signature.** A key the record does not list is `NoRoute` at step 2: no signature is verified or made and nothing is fetched. A forged query that names a listed key costs one verification (step 5) charged to the **verification budget of the face it came over**, and charges **nobody's person rate**, since the rate is taken only after the signature verified and the replay set accepted it. An out-of-window time is refused at step 3, **before** any signature is checked (`a_hostile_query_with_a_forged_time_is_judged_by_the_window_before_a_signature`).
- **Budgets shared with channel asks.** The lookup budget (per ingress face 1,024 a second, burst 1,024; the node 8,192 a second, burst 8,192) and the verification budget (per ingress face 64 a second, burst 256; the node 1,024 a second, burst 1,024) are the **same** [channel.md](channel.md) §3.3 steps 2 and 3 take from: a flood of queries and a flood of channel asks draw on one allowance of each and cannot starve the node twice (`the_lookup_and_verification_budgets_are_shared_with_channel_asks`).
- **The status of an answer** (§6) is the handler's: `Answer` becomes `Answered` (or `TooLarge` when over 4,096 octets), `Refuse` becomes `Refused` with its text cut at 256 octets. The answer is signed by this device, sealed first in a sealed space, with this device's certificates beside it **as room allows** (without them if the Content would be over 8,000 octets). If it still cannot be written or signed the server Nacks `NoRoute`. `NotServed` and `TooLarge` are signed answers, not Nacks: the asker is told why.
- **A late handler.** The handler's future runs under a timeout of the asker's `Q_DEADLINE` counted from the query's arrival; at the timeout it is dropped and nothing is sent.

### 8.3 The replay set and the replay floor

- **The replay set** remembers a query by a 128-bit digest of (asker key, `SignatureNonce`, `SignatureTime`) for **240 s from its arrival**: a copy is acceptable only within 120 s of the signed time, and the signed time was within 120 s of the original's arrival, so 240 s is sound. It holds at most **262,144** queries; past that a new query is a `Congestion` Nack (a set that dropped entries would let a copy run again). A repeat is a `Duplicate` Nack and the handler does not run again; it is refused **before** the person's rate, so a copy costs the asker nothing.
- **The floor.** The set is in memory, so a restart empties it, and a signed query captured in the 240 s before could be replayed once after it, which for a handler with side effects is a double grant. The node therefore records the wall-clock moment its **first `serve` succeeded** and refuses (step 3) any query **signed before it**. The floor is fixed once per run of the node and never moves. Before the first `serve` the floor is 0 (no handler is registered, so a query is answered `NotServed` or refused at step 7).
- **The cost.** An asker whose clock is behind the server's by δ is refused for the first δ after the server started serving. Its `NotListed` text says the query may have been signed before the server began serving and to check the clock.

### 8.4 The person's counters

Counters are **per asker person** (her devices together), in memory; an idle person's counters are swept after 240 s when the node holds 4,096 of them.

- **Rate:** 64 queries a second, burst 128, one token per query that passed step 6 and step 7's standing checks (`Congestion` over it).
- **In flight:** 8 handlers running at once; the node 64 (`Congestion`, no queue).
- **Answer octets:** a budget of 4 MiB a second (burst 4 MiB), charged **after** an answer is signed with the octets of its Content; one answer may put the budget into debt, and while it is in debt (credit not above zero) no new handler is started for her (`Congestion`). `NotServed` answers are not charged.

## 9. Limits

| What | Limit | Over it |
|---|---|---|
| `QUERY_ASK` | 8 KiB (8,192 octets) | refused when written; `NoRoute` Nack when read |
| Query octets (plain; inside a sealed query) | 2,048 | `BadRequest` at `get`; the record is refused |
| Path | 255 octets of name value (components with their type and length octets) | `BadRequest` at `get`; the record is refused |
| Sealed query ciphertext | 16 to 2,367 (2,048 + 255 + 64) | the record is refused |
| `Q_DEADLINE` | 1 to 10,000 ms | the record is refused |
| `ASKER_CERT` / `S_CERT` | 4 each; 4,096 octets each; 6,144 in all | the record is refused |
| Answer octets (`A_BYTES`; inside a sealed status) | 4,096 | the server answers `TooLarge` (limit 4,096); the asker's `answer_max` (1 to 4,096, default 4,096) makes a larger one `AnswerTooLarge` |
| Refusal text | 256 octets | a handler's text is cut at a character boundary; a record with more is refused |
| Sealed answer ciphertext | 16 to 4,416 (4,096 + 256 + 64) | the record is refused |
| `QUERY_ANSWER` Content | 8,000 | certificates are left out; else `NoRoute` Nack |
| Served prefixes | 64 per space on a node; a prefix is at most 255 octets (the sum of its component values) | `ServeError::TooMany`, `BadPrefix` |
| Servers per query | 16 | the rest counted in `not_asked` (`Devices` more than 16: `BadRequest`) |
| Deadline | default 3 s; 1 ms to 10 s | `BadRequest` |
| Asker: outstanding queries | 64 per node, 16 per server | `QueryFailed { TooManyOutstanding }` |
| Asker: cached seal keys, pair keys | 64 each | the one used longest ago is dropped |
| Asker: answer queue of one `get` | 64 answers and 1 MiB charged (each answer's octets, its proof, its path and 64) | the oldest answers are dropped and `Lagged` is told (§10.4) |
| Server: handlers running | 64 on the node; 8 per asker person | `Congestion` Nack; no wait queue |
| Server: queries per second per asker person | 64, burst 128 | `Congestion` |
| Server: answer octets per second per asker person | 4 MiB, burst 4 MiB | `Congestion` |
| Server: replay set | 240 s from arrival; 262,144 queries | `Duplicate`; `Congestion` when full |
| Server: clock window | 120 s either way, and not before the replay floor | `NoRoute` |
| Server: pair keys | 1,024 (one per space and asker device) | `Congestion` for a query with no pair of its own |
| Lookup budget | 1,024 a second per face, burst 1,024; 8,192 a second per node | `Congestion` Nack |
| Verification budget | 64 a second per face, burst 256; 1,024 a second per node, burst 1,024 | `Congestion` Nack |
| Announce | 16 prefixes and 512 octets of name values in all; announce parameters at most 1 KiB | the rest left out; the decoder refuses more |
| Announce hints | 90 s each; 256 devices per space | lapse; the one heard longest ago is dropped |

No figure of speed or CPU cost of this path is recorded in this file; none has been measured.

## 10. The asker

### 10.1 Judging an answer

The asker judges an answer in this order and tells nothing the order has not passed. Any failure is `QueryFailed { BadAnswer }`:

1. The Data's name equals the Interest's name.
2. The Content decodes as a `QUERY_ANSWER` within its limits (a record that breaks one is `BadAnswer` before any signature is checked: the certificates are in it).
3. The Data verifies as a key of **the server's device** by the durable rule ([heap.md](heap.md) §9: signature and chain, no clock except for a key whose role needs a cut), from the certificates held and the at most four the answer carries, **fetching nothing**. A signer whose chain is neither held nor carried is not told as an answer.
4. **The signer stands as a writer now** (`Who::Writer`). Its person is `Got::by`.
5. `Q_ID` is the id of this query.
6. The body matches the space: a plain status in a public space; in a sealed space a sealed one whose `Q_SEQ` is the query's counter and which opens under `Ka` with the additional data of §7.3 and decodes as a status. A sealed answer in a public space, or a plain one in a sealed space, is refused.
7. By status: `Answered` with at most `answer_max` octets is told (`AnswerTooLarge` otherwise); `Refused` is told as an answer carrying its `AppRefusal`; `NotServed` is `QueryFailed { NotServed }`; `TooLarge` is `QueryFailed { TooLarge }`.

A signed Data that contradicts the space's record (a signer that is not a writer, a non-matching id) is a failure of that server only: the other servers of the query are unaffected.

### 10.2 Several servers: targets, and when none is known

| `Targets` | Who is asked |
|---|---|
| `Devices(d)` | exactly those, de-duplicated, in order (at most 16). A device that is no writer of the space, by the record held here and judged **now**, is **not asked**: it is `QueryFailed { NotWriter }` and counts `failed`. A name that is no device name, a reserved one, or this device is refused at `get` |
| `Person(p)` | the devices of person `p` that the record knows plus those whose announce (§11) was heard within 90 s, **that are writers** (and not this device), in name order, the first 16; the rest are counted in `not_asked`. A person who is no writer has none |
| `Serving` (default) | the devices whose announce lists a prefix of the asked path (heard within 90 s), judged offline as writers of the space and not this device, **the 16 heard last**; the rest are counted in `not_asked` |

A query is sent **to each server separately**, a signed Interest of its own to that server's name: the servers never see each other's. Every one is judged by the **asker** now, from the record held; the hint only suggests whom to ask.

**None known.** With `Targets::Serving` and no known server, the query **waits for the first announce, until its deadline**, and does not wait for nobody: `Person` with none known does not wait. When no server is known at the end of the wait, the stream tells `QueryFailed { server: <the space's name>, why: NoServer { path } }` and then `AnswersDone { asked: 0, answered: 0, refused: 0, failed: 0, silent: 0, not_asked }`. The `NoServer` notice names no server and is **not counted** as `failed`.

### 10.3 Counting

Each targeted server ends in **exactly one** bucket:

| Bucket | The server |
|---|---|
| `answered` | gave bytes: an `Answered` with the handler's answer |
| `refused` | its **handler** refused: an `Answered` with an `AppRefusal` and empty bytes |
| `failed` | a `QueryFailed` was told for it: a Nack, a signed `NotServed` or `TooLarge`, an answer that failed judging, an answer over `answer_max`, no writer, too many outstanding |
| `silent` | said nothing by the deadline: a `Pass`, a handler past the deadline, a Data that never came, a server that is down |

**`asked = answered + refused + failed + silent`, always** (`asked_is_always_answered_plus_refused_plus_failed_plus_silent`), over the servers addressed, and `not_asked` is the servers known beyond the 16, **not** in the sum. `AnswersDone` is told **once**, when the last server has resolved or the **deadline** passes (the servers not resolved by then are counted `silent`, and their Interests are dropped).

**The deadline is liveness, never correctness.** A late answer is dropped and cannot be told apart from silence by the asker (`the_deadline_ends_the_run_and_a_late_answer_is_never_told`). Nothing the application decides should depend on the deadline.

**The library never retries.** A lost query is `silent`; a retry is a new `get`, with a new id, and runs the handler again. The replay set refuses a repeated signed query, so a retransmission by a lower layer does not run a handler twice.

**The Nack of the server becomes a `QueryError`** (the rest of §3.3 is told as it is named there):

| What the asker got | `QueryError` |
|---|---|
| `NoRoute` Nack | `NotListed` |
| `Congestion` or `Duplicate` Nack | `Busy` |
| `NotYet` Nack | `NotYet` |
| any other Nack, or the connection closed | `Unreachable` |
| no Data by the deadline | the server is `silent` (not a failure) |
| any other error of the connection | `BadAnswer`, with its text |

### 10.4 Order, and when the stream ends

1. **The kept listing comes first, always** ([channel.md](channel.md) §17.3 item 1); **answers that arrive during the listing are held and come after it.**
2. **After the listing the three sources take turns** (kept, emitted, answered): the poll starts after the source taken last, so a source with something queued is never starved by another (`answers_alternate_fairly_with_kept_after_the_listing`, `answers_during_the_listing_come_after_it`). **No order is promised between an answer and a kept or emitted item**: an answer a handler made after a `put` can reach the asker before the `put` does.
3. **Within the answers:** the order they were told, which is the order the servers resolved; none between servers.
4. **Notices.** `QueryFailed` and `AnswersDone` come **after the answers queued before them**; they are never dropped (at most one per server and the one `AnswersDone`). `AnswersDone` is told once and is the last thing the query queues.
5. **A query-only stream** (`kept: false`, `live: Live::Off`, `ask: Some`) **ends after `AnswersDone`**: the stream yields `None` when it has been taken. With kept values or emissions on, the stream goes on and `AnswersDone` is a notice (`a_query_only_stream_ends_after_answersdone`, `a_stream_with_kept_goes_on_after_answersdone`). `caught_up()` is about the kept listing and is unaffected (at once when `kept` is `false`).
6. **A slow reader.** Answers queue in a queue of their own of **64 answers and 1 MiB charged**; when full, the **oldest** answers are dropped and `Lagged { missed }` is told in their place (adjacent drops are one notice). The server is never made to wait: its work ended when it sent. A slow reader of answers delays no kept item (`a_slow_reader_loses_the_oldest_answers_and_is_told_lagged`).
7. `Items::next_batch` moves the answers queued before the next notice and stops at a notice or a `Lagged`.

### 10.5 The pending set

The asker holds **64** queries outstanding in all and **16** to one server; a query over either is `QueryFailed { TooManyOutstanding }` at once, not at its deadline. A slot is released when its query resolves or when its `Items` is dropped (`dropping_items_cancels_the_pending_query`).

## 11. Discovery: `ANN_SERVES`

The announce of [channel.md](channel.md) §9 (`CHAN_ANNOUNCE`, 0x06A1) gains one field.

| Type | Name | Value |
|---|---|---|
| 0x06AC | `ANN_SERVES` | Name, repeatable: a prefix, relative to the space, the sender serves queries under. At most 16 per announce and 512 octets of name values in all. **Even**: a reader that predates it skips it |

- **What it lists.** The prefixes a device serves (§3.1), **shortest first** (by the octets of the name value, then by name), at most 16 names and 512 octets of name values in all; the ones that do not fit are left out (an asker names them with `Targets::Devices`). An empty prefix (the whole space) is a legal name.
- **When.** Whenever a `serve` registers a prefix, whenever a `Serving` is dropped (so the next announce lacks it), every 30 s while something is served, and with every announce [channel.md](channel.md) §9 sends. It is the **same** unsigned Interest `<sync group>/32=chan/<digest>` under the same rules: HopLimit 8, InterestLifetime 1 s, nobody answers it and nothing caches it.
- **Empty modes.** A device that holds **no channel** announces its prefixes **alone**: `CHAN_ANNOUNCE` with no `ASK_MODE` and at least one `ANN_SERVES`. An announce with **neither** a mode nor a prefix is malformed and is **never sent**: a device with no channel that stops serving sends nothing, and its hint lapses after 90 s. A hearer that finds no mode in an announce asks for no channel.
- **The hearer records a hint** when the announcing device passes the checks [channel.md](channel.md) §9 item 2 makes **offline**: its person is a **writer** of the space and its name is a device name under no reserved prefix (a device the record vouches for needs only the writer check). The hint is recorded **whatever is decided about asking for a channel**, and whether or not the hearer wants live data. An announce that lists no prefix **removes** the device's hint. A hint lives **90 s** (three announce periods); a space keeps at most **256** devices' hints, dropping the one heard longest ago.
- **It is only a hint.** The announce is unsigned: any name under a writer's namespace passes for one of her devices. The asker judges the device a writer itself before it asks, and the server's own judging of the query is the authority: a device that announced a prefix it does not serve answers a signed `NotServed`, and a device that is no writer is not asked (and, asked anyway, is refused at §8 step 7). See §12.

## 12. Security notes

**What a member can do to a server.**
- *Handler DoS.* One person holds at most 8 handlers and the node 64, a hung handler is dropped at the query's deadline (at most 10 s), and there is deliberately **no wait queue** (it would be an unbounded delay and memory). Eight persons can occupy all 64 for 10 s: that is the application's capacity decision (the limits are the layer's, not configurable here). A stranger takes none.
- *Signature DoS.* A member makes the server verify one signature and make one per query, bounded by her 64-a-second rate and by the budgets of §8. A forged query naming a member costs one verification charged to the face's budget, never to the named member's rate.
- *Pair-key exhaustion and X25519 work.* In a sealed space each (space, asker device) holds one pair on the server, replaced whenever the asker sends another ephemeral key; a member with many devices, or one that changes the ephemeral key on every query, makes the server do an X25519 agreement per query, bounded by her rate. Pairs are 1,024 for the node: a member that holds many devices can fill the table, after which a **new** pair is a `Congestion` Nack for everyone (`PAIRS_MAX` is not partitioned per person). The cost of an agreement is not measured here.
- *Amplification.* A query is at most 8 KiB and an answer's Content at most 8,000 octets, so a member can ask for several times her bytes; the answer goes back only on the **Interest's in-record** (a Data satisfies a PIT entry once), so there is **no reflection** to a third party. Her answer octets are budgeted (4 MiB a second).
- *Replay.* The replay set, the 120 s window and the floor (§8.3). A restart cannot be used to run a captured query. A query captured and replayed **within** the window of a server that did not restart is `Duplicate`.

**What a server can do to askers.** A writer's device is trusted with what it says, as far as the space's record trusts a writer.
- *Lie.* Any writer's device may serve any prefix and answer anything. Its answer is **signed**, so a false answer is the writer's own signed statement and `proof` keeps it for anyone who must hold the writer to it; the layer does not judge the content. An asker that gets two different answers chooses by `writer` and `by`. Which writer may serve which prefix is **not** specified: a members-record field that said so is a change to [heap.md](heap.md) not made here.
- *Refuse, delay, stay silent.* A server may `Refuse`, answer slowly or `Pass`; the asker's deadline bounds what it waits and `silent` records it.
- *Learn.* The server learns the asker's person and device (as it judged them), the path and the query octets, and the time. In a sealed space it opens them; the sealing keeps them from relays, not from the server.
- *An answer too large* is `TooLarge`; one over `answer_max` is `AnswerTooLarge`: the asker bounds what it reads.

**What a relay sees.**
- *Public space:* the whole query and answer (path, octets, status), the asker's and the server's names, the id and the deadline. `NoCache`, `FreshnessPeriod` 0 and `MustBeFresh` ask a store not to keep the answer or serve it to another Interest; they are requests, not enforcement. A relay that stores the answer anyway can give it again to an Interest of the same name (only a copy of the asker's signed Interest has that name), and that copy never reaches the server's replay set; the content is public to every relay on the path in any case. Only a sealed space keeps it from them.
- *Sealed space:* the space, both device names, the id, the deadline, the ephemeral key, the epoch, the counter, the certificate chains, the signatures, and the **length** of the ciphertexts; not the path, the octets or the status. It can tell an asker's queries to one server apart by the ephemeral key and the counter.

**Hints are forgeable and can crowd.** `ANN_SERVES` is unsigned. Any party that can reach the sync group can send an announce that names a writer's device as serving a path; the asker then spends **one signed query** on it and is told `NotServed` or gets nothing. A flood of such announces for many writer-namespace names can fill a space's 256-hint table and push the real servers out of the **16 heard last** that `Targets::Serving` asks. That does not make a wrong answer acceptable (each answer is judged, §10.1) but it can **hide a real server from `Serving`**: an application that must reach a particular server names it with `Targets::Devices`.

**Clocks.** The only wall-clock readings are the signed `SignatureTime` and the replay floor. No decision about who is a member, which key stands or whether an answer is genuine rests on a clock.

**An answer is evidence only as strong as its path.** A `Signed` answer is the server device's statement; in a sealed space it is the server's statement about ciphertext, and the plaintext is shown to be the server's only because only the server and the asker could have made it (§7.2: no proof to a third party).

## 13. Test vectors

Hex, one record each, as the implementation writes them (the same octets are asserted in `wire/query_tests.rs` and `chan/wire_tests.rs`). Space `/a/32=data/w`, path `/get`, query id `0102030405060708`, deadline 3000 ms, query octets `6869` (`hi`).

`QUERY_ASK`, plain, with one certificate `c0de01`:

```
fd06c138fd06c30c080161200464617461080177fd06c5050803676574fd06c7080102030405060708fd06c9020bb8fd06cb026869fd063d03c0de01
```

`QUERY_ASK`, sealed (no `Q_PATH`): 20 octets `cc` as the ciphertext, ephemeral key 32 × `11`, epoch (`/a/d`, seq 3), counter 5, no certificate:

```
fd06c174fd06c30c080161200464617461080177fd06c7080102030405060708fd06c9020bb8fd06cb14ccccccccccccccccccccccccccccccccccccccccfd06cd201111111111111111111111111111111111111111111111111111111111111111fd06db0d0706080161080164fd060b0103fd06dd0105
```

`QUERY_ANSWER`, plain, same id, no certificate:

```
Answered "ok":        fd06cf17fd06c7080102030405060708fd06d10101fd06d3026f6b
Refused 7 "no":       fd06cf1cfd06c7080102030405060708fd06d10102fd06d50107fd06d7026e6f
NotServed:            fd06cf11fd06c7080102030405060708fd06d10103
TooLarge, limit 4096: fd06cf17fd06c7080102030405060708fd06d10104fd06d5021000
```

`QUERY_ANSWER`, sealed: counter 9, 18 octets `dd` as the ciphertext, one certificate `c0de02` (`S_CERT`, 0x0697):

```
fd06cf2efd06c7080102030405060708fd06dd0109fd06df12ddddddddddddddddddddddddddddddddddddfd069703c0de02
```

The plaintext runs that are sealed (§7.3): the status `Answered "ok"` as `encode_inner`, and the path `/get` with the octets `hi` as `seal_inner`:

```
status:   fd06d10101fd06d3026f6b
query:    fd06c5050803676574fd06cb026869
```

`CHAN_ANNOUNCE` with `ANN_SERVES` ([channel.md](channel.md) §9): sender `/bob/phone`, mode `Latest`, serves `/world`; and the same sender with **no mode**, serving `/world` alone:

```
fd06a120fd06770c0803626f62080570686f6e65fd06670101fd06ac070805776f726c64
fd06a11bfd06770c0803626f62080570686f6e65fd06ac070805776f726c64
```

Names (asserted as parse results in `wire/names_tests.rs`; the keyword is the KeywordNameComponent `32=query`, the digest a ParametersSha256DigestComponent of 32 octets):

| Name | `parse_query_name` |
|---|---|
| `/alice/laptop/32=query/<32 octets>` | the device `/alice/laptop` and the digest; the node serves it as a query |
| `/alice/laptop/32=query` | none (it is the prefix; `parse_query_prefix` gives `/alice/laptop`) |
| `/alice/laptop/32=query/<32 octets>/more` | none |
| `/alice/laptop/32=query/<generic component>` | none |
| `/alice/laptop/32=query/<ImplicitSha256Digest of 32 octets>` | none |
| `/alice/laptop/32=query/<digest of 31 or of 33 octets>` | none |
| `/alice/32=held/laptop/32=query/<digest>` | none (a device holds no keyword) |
| `/32=query/<digest>` (the empty device) | none |
| `/alice/laptop/32=chan/<digest>` | none (a channel ask is not a query) |

The keyless seal name `<device>/32=seal` (`/alice/laptop/32=seal`) parses as the device `/alice/laptop` and nothing longer: the keyed name `/alice/laptop/32=seal/<key>` is **not** the keyless name (and has it as a prefix, so it answers a `CanBePrefix` Interest for it); `/32=seal`, `/alice/32=held/laptop/32=seal` and `/alice/laptop/32=chan` do not parse.

The key schedule and the AEAD have no fixed ciphertext vector here: the tests assert that the nonce is the four zero octets and the counter and that the output equals AES-256-GCM of a reference implementation under the pair's keys, that `Kq` and `Ka` differ, and that a change of any field of the additional data or the context does not open.

## 14. Conformance cases

The observable behaviours a conformance suite checks. Each names the test that guards it in `ndn-heap`.

**Names, packets and the wire**

- **q1** `<D>/32=query/<digest>` parses as §5 and nothing else does; `query` is a core keyword (an extension claiming it is refused); `<D>/32=seal` (keyless) is answered with the device's own seal key packet and no other device's. (`wire/names_tests.rs`: `a_query_name_is_one_digest_under_a_device_and_nothing_else_parses`, `the_keyless_seal_name_is_a_device_and_the_keyword_and_nothing_else`)
- **q2** The vectors of §13 encode and decode to the octets shown; a plain query has `Q_PATH` and no sealing fields, a sealed one all three sealing fields and no `Q_PATH`; an answer's status carries its own fields and none other; an unknown even type is skipped and an unknown odd type, `0x06D9` among them, is refused, in every record and in the sealed parts. (`wire/query_tests.rs`)
- **q3** The limits of §6 and §9 hold at both ends of the wire: a deadline of 0 or over 10,000, a query over 2,048, a path over 255, five certificates, a certificate over 4,096, 6,144 in all, a refusal text over 256, an answer over 4,096 and a Content over 8,000 are refused. (`wire/query_tests.rs`)
- **q4** A signed query is a signed Interest of the asker's device key with `MustBeFresh`; `sign_interest` signs `<device>/32=query` for a `QUERY_ASK` and `<device>/32=chan` for a `CHAN_ASK` and refuses every other name, a device under `/localhost` or `/localhop`, and parameters that are not the record the name takes. (`sign_interest_signs_a_query_and_refuses_anything_else_under_query`)
- **q5** The answer is a Data of exactly the query's name, signed by the server's device, `FreshnessPeriod` 0 and sent `NoCache`; three queries make three names and three handler runs and the store holds nothing new. (`a_listed_asker_gets_the_handlers_answer_signed_by_the_servers_device`, `no_answer_is_stored_or_cached`)

**The server**

- **q6** A stranger's query is a `NoRoute` Nack and costs no signature verification. A forged query naming a listed key costs one verification and a `NoRoute` Nack. (`a_strangers_query_is_nacked_and_costs_no_signature_verification`)
- **q7** A reader's device cannot `serve` (`ServeError::NotWriter`) and a reader may ask; a follower and an unlisted device may not ask. (`a_readers_device_cannot_serve_and_a_reader_may_ask`, `a_follower_and_an_unlisted_device_may_not_ask`, `a_reader_may_ask`)
- **q8** The handler sees the asker's person and device as judged; the handler of the longest served prefix runs; a path no prefix serves is a signed `NotServed` and no handler runs; dropping the `Serving` stops serving. (`the_handler_sees_the_askers_person_and_device_as_judged`, `the_longest_prefix_handler_runs_and_a_path_no_prefix_serves_is_a_signed_notserved`, `dropping_the_serving_stops_it`)
- **q9** A `Refuse` is answered with its code and its text cut at 256 octets; an `Answer` over 4,096 is a signed `TooLarge`. (`an_application_refusal_is_answered_with_its_code_and_text_and_cut_at_256`, `an_answer_over_4096_is_a_signed_toolarge_status`)
- **q10** `Pass` sends nothing at all (no Data, no Nack); a handler past the asker's deadline is dropped and its answer is not sent. (`pass_is_silent`, `a_handler_past_the_deadline_is_dropped_and_its_answer_not_sent`)
- **q11** A replayed signed query is a `Duplicate` Nack and the handler ran once; a replay is refused before the person's rate is charged; the replay set forgets after 240 s and refuses over its cap. (`a_replayed_signed_query_is_a_duplicate_and_the_handler_ran_once`, `the_replay_set_forgets_after_240_s_and_refuses_over_its_cap`)
- **q12** A query signed before the first `serve` is refused; the 120 s window holds, and a forged time is refused before any signature is checked. (`a_query_signed_before_serve_began_is_refused`, `the_clock_window_holds`, `a_hostile_query_with_a_forged_time_is_judged_by_the_window_before_a_signature`)
- **q13** Eight handlers per person across her devices and 64 on the node; over them a `Congestion` Nack and no queue; the person's rate and answer-octet budget hold. (`per_person_inflight_and_rate_hold_across_her_devices`, `concurrency_cap_is_busy_with_no_queue`, `the_answer_octets_of_a_person_are_a_budget_of_4_mib_a_second`)
- **q14** The lookup and verification budgets are shared with channel asks. (`the_lookup_and_verification_budgets_are_shared_with_channel_asks`)
- **q15** A query whose chain the server does not hold is a `NotYet` Nack; the same query carrying the chain is answered. (`a_query_whose_chain_the_server_does_not_hold_is_nacked_notyet_and_carrying_it_answers`)

**Sealed spaces**

- **q16** A sealed space's query and answer are ciphertext on the wire; one X25519 agreement serves two queries of one epoch; the pair of an old epoch and of a removed asker is dropped. (`a_sealed_space_query_and_answer_are_ciphertext_on_the_wire`, `a_sealed_space_query_end_to_end_one_agreement_for_two_queries`, `the_pair_cache_derives_once_per_epoch_and_drops_what_moved_and_is_bounded`)
- **q17** A query of a stale epoch is a `NotYet` Nack; an asker outside the audience is a `NoRoute` Nack; a plain query in a sealed space and a sealed one in a public space are `NoRoute` Nacks. (`a_query_with_a_stale_epoch_is_nacked_notyet`, `a_sealed_asker_not_in_the_audience_is_nacked`, `a_plain_query_in_a_sealed_space_and_a_sealed_one_in_a_public_space_are_nacked`)
- **q18** Sealing (`query/seal.rs`): the nonce is four zero octets and the counter and the suite AES-256-GCM; `Kq` does not open an answer nor `Ka` a query; a changed octet of the data or of the ciphertext, or of the context, does not open; two counters give two ciphertexts.

**The asker**

- **q19** `get` refuses each bad request with its reason, in the order of §3.2, including `QueryPath::Channel`. (`get_with_ask_refuses_each_bad_request_with_its_reason`)
- **q20** `asked = answered + refused + failed + silent` over every mixture of servers, and `Pass` counts `silent` while a handler's refusal counts `refused`. (`asked_is_always_answered_plus_refused_plus_failed_plus_silent`, `several_servers_answer_and_done_counts_add_up`, `pass_is_counted_silent_and_a_refusal_is_refused_not_failed`)
- **q21** A late answer is dropped and the deadline ends the query; `AnswersDone` is told once. (`the_deadline_ends_the_run_and_a_late_answer_is_never_told`, `a_late_answer_is_dropped_and_the_deadline_ends_the_query`)
- **q22** Order: answers during the kept listing come after it; the sources take turns after it; a query-only stream ends after `AnswersDone` and one with kept values goes on; a slow reader loses the oldest answers and is told `Lagged`. (`answers_during_the_listing_come_after_it`, `answers_alternate_fairly_with_kept_after_the_listing`, `a_query_only_stream_ends_after_answersdone`, `a_stream_with_kept_goes_on_after_answersdone`, `a_slow_reader_loses_the_oldest_answers_and_is_told_lagged`)
- **q23** The pending set holds 64, 16 per server, and releases on resolution and on dropping the `Items`. (`the_pending_set_holds_sixteen_per_server_and_sixty_four_in_all_and_releases`, `outstanding_limits_hold`, `dropping_items_cancels_the_pending_query`)
- **q24** Targets: `Serving` asks the hinted writers of a prefix of the path and no other, none known waits and then tells `NoServer`; `Person` and `Devices` de-duplicate and ask only writers; a named non-writer is `NotWriter`, not asked and counted `failed`. (`targets_serving_uses_the_announce_hint_and_none_known_is_noserver`, `targets_person_and_devices`, `a_named_non_writer_is_not_asked`, `a_named_writer_that_never_answers_is_silent_at_the_deadline`)
- **q25** An answer is judged: one signed by a non-writer, one with another query's id, and one over `answer_max` are failures (`BadAnswer`, `BadAnswer`, `AnswerTooLarge`); `proof` keeps the signed Data and it verifies as the server's. (`the_answer_signed_by_a_non_writer_is_badanswer`, `a_mismatched_query_id_is_badanswer`, `an_answer_over_answer_max_fails_answertoolarge`, `proof_keeps_the_signed_data_and_it_verifies_as_the_servers`)
- **q26** No answer is ever an entry, and a second `get` runs the handler again. (`no_answer_is_ever_an_entry`)

**The announce**

- **q27** An announce lists what is served and a hearer records a hint only for a writer's device; the announce is sent again when the set served changes, is due every 30 s while something is served, and lists at most 16 names and 512 octets, shortest first. A device that holds no channel announces its prefixes with no mode; an announce with neither is malformed. (`the_announce_lists_what_is_served_and_a_hearer_records_a_hint`, `the_announce_is_sent_again_when_the_set_served_changes`, `the_announce_is_due_every_30_s_while_something_is_served`, `the_announce_lists_at_most_16_names_and_512_octets_shortest_first`, `chan/wire_tests.rs`: `an_announce_carries_the_prefixes_it_serves_and_may_hold_no_channel`, `an_announce_names_at_most_16_prefixes_and_512_octets_and_something_to_do`)
