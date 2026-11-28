# Query: asking the writers of a space, and what they answer

- **Status:** implemented, **both paths**. The **signed path**: `Heap::serve`, the query on `Heap::get` (`GetOptions::ask`), the signed Interest and the signed Data, sealing in sealed spaces, the server's judging, the asker's judging, targeting and counting, and the announce hint (`ANN_SERVES`). The **channel path** (§15, built in REPLY-25 stage 4): one signed ask makes an `Ask` session (channel mode 4) and every query after it is a pair of sealed frames, a `QUERY` up and an `ANSWER` down, matched by a token in the forwarder's side PIT, with no signature after the first; `QueryPath::{Auto, Signed, Channel}` choose between the paths per server (§3.2), `Via` is `#[non_exhaustive]` with `Signed` and `Sealed`, and `QueryError` gains `NoSession` and `Congested`. What is **not built**: the conformance suite's cases for the channel path (stage 5, §15.15) and `A_RETRY` (§2).
- **Implementation:** `ndn-heap`, module `query` (`ndn-rs/crates/app/ndn-heap/src/query/`): `types.rs` (the public types), `serving.rs` (`Heap::serve`, `Serving`), `table.rs` (the served prefixes and the announce hints), `serve.rs` (the signed path's judging and the limits both paths share), `ask.rs` (the asker and its path choice), `answers.rs` (the answer queue of one `get`), `seal.rs` (sealing), and for the channel path `chan_serve.rs` (the server's half: a `QUERY` judged and answered) and `chan_ask.rs` (the asker's half: the pending entries, the `ANSWER`, silence). The records are in `wire/query.rs`, the names in `wire/names.rs`, the announce field and the `Ask` mode in `chan/wire.rs`, the frames and their plaintexts in `chan/qframe.rs`, the pairs and the nonce in `chan/pair.rs`, the setup of an `Ask` session in `chan/answer.rs` and `chan/ask.rs`, the stream in `chan/items.rs` and `chan/verbs.rs`, the dispatch in `serve.rs`, `chan/route.rs` and `chan/hub.rs`, the key agreement in `ndn-security` (`confidentiality.rs`: `pair_keys_to`, `RecipientKey::pair_keys_from` for the signed path; `wrap_ck_to_pair`, `RecipientKey::unwrap_ck_pair` for the channel path).
- **Scope:** a **query** is a question one member of a space puts to the **devices of the space's writers** and an **answer** is what a handler on such a device says back, to that asker alone: `serve(prefix, handler)` on one side, `get` with an `ask` on the other. A query is **not a write**: nothing a handler answers is an entry, is stored, is cached or is anyone's current value. This file specifies the API, the invariant that keeps the feature from becoming a family of stored answers, the names and packets of the signed path, the TLV block 0x06C0–0x06FF, sealing in a sealed space, how a server judges a query, how an asker judges an answer, targeting, counting and order, the announce hint, limits, security notes, test vectors and conformance cases of the signed path, and (§15) the channel path: the `Ask` session, the pair key, the two frames, the nonce argument, the server's and the asker's judging, limits, what ends a pair, threat notes, residuals, vectors and the test names.
- **Out of scope:** which writer may serve which prefix (every writer's device may serve any prefix, §12); merge rules and the heads of a path ([heap.md](heap.md) §10.3, [channel.md](channel.md) §17.9); what a handler computes; the conformance suite's cases for the channel path (stage 5, not built, §15.15).

The key words "MUST", "MUST NOT", "SHOULD" and "MAY" are as in BCP 14, in capitals only.

## 1. Terminology

| Term | Meaning |
|---|---|
| space, path | As [heap.md](heap.md) §2.1: a space `<O>/32=data/<c1…c4>` and a name relative to it. |
| asker | A **listed** member's device (a writer's or a reader's; a follower never asks) that calls `get` with an `ask`. |
| server | A **writer's** device that holds a `Serving` for a prefix of the space. |
| handler | The application's callback on a server: it runs once per query that reaches it and returns a `Reply`. |
| query | One question to one server: on the signed path the signed Interest `<server>/32=query/<digest>` (§5), on the channel path one sealed `QUERY` frame (§15.4). One `get` with an `ask` sends one query to each server it targets (§10.2); all carry the same query id. |
| answer | On the signed path the signed Data of exactly that name (§5), on the channel path one sealed `ANSWER` frame (§15.4). One per query per server. |
| query id | Eight random octets the asker chooses per `get`, echoed in the signed path's answer (`Q_ID`) and given to the handler as `Query::id` on both paths (on the channel path it is the first field of the sealed `QUERY` plaintext, §15.5; the frame's token is **not** the query id). |
| plain, sealed | A query in a **public** space is *plain*: its path and octets are in the clear. In a **sealed** space it is *sealed*: the path and octets, and the whole status of the answer, are ciphertext under a pair key (§7). |
| pair key | `Kq` (seals queries) and `Ka` (seals answers), derived from one X25519 agreement between an asker device and a server device. On the signed path for one epoch and by the asker's ephemeral key (§7.2); on the channel path by the server's ephemeral key of one session answer, with other labels (§15.3). |
| standing | As [channel.md](channel.md) §4.1: a key *stands* for a space when its person is listed in the role asked, its role is owner-capable, its context does not revoke it and this node does not suspect it. |
| silent | A server that said nothing by the query's deadline: a `Reply::Pass`, a handler past the deadline, a Data that never came, a down server. |
| `Ask` session | A channel of mode 4 (`ASK_MODE` 4) a server makes for askers: it carries no emission and no checkpoint and gives each asker device a **pair** (§15.2). |
| pair (channel path) | The two directional keys `Kq`, `Ka` and the 8-octet pair id one `Ask` session answer gives one asker device; the server keeps the pair's replay window, the asker its counter (§15.3, §15.6). |
| token | 64 random bits the asker draws per query per server, in the clear in both frames: the forwarder's side PIT matches an `ANSWER` to its `QUERY` by it ([channel.md](channel.md) §14.13). |
| `qseq` | The asker's counter of queries under one pair: the nonce of the query and of its answer, and the replay window's key (§15.6). |

## 2. Status and what is reserved

Both paths are complete. The following are **reserved** and MUST NOT be relied on:

- TLV 0x06D9 (`A_RETRY`) is reserved for a later answer that says how long to wait. It is not written and not read: a record that carries it is refused as an unknown critical type (§6). The channel path has no TLV and no such field: a sealed `Busy` says `retry_ms` (§15.5), which the asker does not pass on (§15.9).
- `QueryError`, `ServeError` and `Via` are `#[non_exhaustive]`: a reader MUST use a wildcard arm. `Via` has two values, `Signed` and `Sealed` (the channel path); a later path adds a third.
- **The channel path's conformance cases** (the q-cases of a suite that runs against any implementation) are **stage 5 and not built**. §15.15 lists the tests of `ndn-heap` that guard the path today; they are this implementation's, not a suite.

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
    pub via: Via,             // Signed or Sealed (non_exhaustive)
    /* private: the asker's deadline */
}
impl Query { pub fn remaining(&self) -> Duration; }   // how long the asker still waits
pub struct Asker { pub person: Name, pub device: Name }
pub enum Reply { Answer(Bytes), Refuse(AppRefusal), Pass }
pub struct AppRefusal { pub code: u16, pub text: String }   // AppRefusal::new cuts text to 256 octets
```

- `serve` registers `prefix` (a name relative to the space, empty allowed) with `handler` and returns a `Serving`; **dropping it unregisters the prefix at once**. A query that arrives after is answered `NotServed`. A handler already running is not told and its answer is still sent unless the asker's deadline has passed.
- A query is addressed to a path. A server answers when **one of its served prefixes of the space is a prefix of the path** (a name-component prefix: `/world` serves `/world/x` and not `/worldwide`); the handler of the **longest** such prefix runs, so one query runs one handler. Nested prefixes are allowed; the same prefix twice is `Overlap`.
- The handler runs **once per query that reaches it** (§8 step 9 on the signed path, §15.7 step 11 on the channel path) and its `Reply` goes to that asker once:
  - `Answer(bytes)`: at most **4,096** octets on the signed path. A longer answer is sent as the signed status `TooLarge` carrying 4,096 (§6). On the **channel path** at most **65,536**: a longer one is a sealed `TooLarge` carrying 65,536, and one that does not fit the frame the path carries is a sealed `TooLarge` carrying what does (§15.9). A larger result is the handler's `put` and an answer that names the path.
  - `Refuse(AppRefusal)`: the application's own refusal, a `u16` code it defines and a text of at most 256 octets (cut at a character boundary). It is an answer, not a system failure: the asker is told it as an `Answered` with a `refusal` and counts it `refused`.
  - `Pass`: nothing for this query. **Nothing is sent**: the Responder is dropped and no Nack is made, so the asker counts the server `silent` at its deadline. A handler that wants the asker to know says `Refuse`.
- The handler is run under the **asker's deadline** (`Q_DEADLINE` ms from the query's arrival on the signed path; the plaintext's `deadline_ms` from the frame's arrival on the channel path). A handler that has not finished by then is dropped and **nothing is sent**: the asker counts the server `silent`. A handler with side effects keys them on `Query::id` and `Query::asker` (a retry is a new `get`, so a new id, and runs the handler again), and judges the asker itself where a removal matters: `Query::asker` is the judgement at arrival. `Query::id` is the asker's id of its `get` on **both** paths (on the channel path it is the first field of the sealed plaintext, not the frame's token), and `Query::via` says the path: `Signed` or `Sealed`.
- `Query::asker.person` is the person the trust context vouched for the signing key as; `device` is the device the key belongs to.

`ServeError` (`#[non_exhaustive]`), each with a `next()`:

| Variant | When | NextStep |
|---|---|---|
| `NotWriter { space, why }` | this heap only follows the space, or this device is no writer of it by the entries held (a reader's device never serves), or its key does not stand | `AskOwner` |
| `NotReady { space, why }` | the space's creation record is not held yet | `RetryLater` |
| `Overlap { existing }` | this heap serves exactly this prefix already | `FixRequest` |
| `TooMany { max }` | the space serves 64 prefixes already | `FixRequest` |
| `BadPrefix { size, max }` | the sum of the octets of the prefix's component values is over 255 | `FixRequest` |

The first successful `serve` of a node also arms the **replay floor** (§8.3: that moment plus 120 s), **before** the prefix is in the table, so no handler is reachable without a floor, and makes the node announce the prefixes it serves (§11). A node that has not begun to serve answers no signed query (§8 step 3).

### 3.2 `get` with an `ask`

```rust
pub struct GetOptions { /* kept, heads, live, modes, trust, congestion as channel.md §17 */ pub ask: Option<Ask> }
                       // Clone, Debug, PartialEq, Eq: no longer Copy
pub struct Ask {
    pub query: Bytes,            // at most 2,048 octets (1,024 on QueryPath::Channel)
    pub targets: Targets,        // default Targets::Serving
    pub via: QueryPath,          // default QueryPath::Auto
    pub deadline: Duration,      // default 3 s; 1 ms to 10 s; setup, wait for a server and handler together
    pub answer_max: usize,       // default 4,096; 1 at least; at most 4,096 on Signed, 65,536 on Auto and Channel; a larger answer is a failure
    pub proof: bool,             // keep each answer's proof (the signed query and the signed answer) in Answered::proof; default false
}                                // Ask::new(query) gives the defaults
pub enum Targets { Serving, Devices(Vec<Name>), Person(Name) }   // at most 16 servers per query
pub enum QueryPath { Auto, Signed, Channel }                      // which path, per server (below, §15.8)

// Kind gains (it is #[non_exhaustive]):
Kind::Answered(Answered)
pub struct Answered { pub query: QueryId, pub via: Via, pub refusal: Option<AppRefusal>, pub proof: Option<Bytes> }
// GetNotice gains (it is #[non_exhaustive]):
QueryFailed { server: Name, why: QueryError },
AnswersDone { asked: u32, answered: u32, refused: u32, failed: u32, silent: u32, not_asked: u32 },

// A proof is checked from the space's record alone (§10.1):
impl Heap { pub async fn verify_answer_proof(&self, proof: &[u8]) -> Result<VerifiedAnswer, ProofError>; }
pub struct VerifiedAnswer {          // #[non_exhaustive]
    pub space: Name, pub query: QueryId, pub asker: Name, pub asker_device: Name,
    pub server_person: Name, pub server: Name,
    pub path: Option<Name>, pub query_bytes: Option<Bytes>,   // None in a sealed space
    pub signed_at: Timestamp,                                 // the asker's clock when it signed the query
    pub answer: ProvenAnswer,
}
pub enum ProvenAnswer { Answered(Bytes), Refused(AppRefusal), NotServed, TooLarge { max: u64 }, Sealed { ciphertext: Bytes } }   // #[non_exhaustive]
pub enum ProofError { Malformed, OtherSpace, NoRecord, Question, AskerNotListed, Unrelated, Answer, ServerNotWriter, NotJudged }   // #[non_exhaustive], each with next()
```

- `get` stays synchronous and does no I/O in the caller's task: it judges the request, registers the answer queue and **spawns** the query on the node's tasks (the way [channel.md](channel.md) §17.1 registers both feeds). Nothing that happens after the call is lost for want of a first poll. **Dropping the `Items` cancels the query**: its Interests are dropped, its pending slots are released and a late answer is discarded; a handler already running is not told.
- **What an answer is.** A `Got` with `path` the asked path, `bytes` the answer octets (empty for a refusal), `author.writer` the **server's device**, `author.by` the **person of the key that signed the answer** as this node judged it (§10.1 step 4; on the channel path, which signs no answer, the person of the key that signed the **session** the pair came with, as this node judges it now, §15.8), and `kind` `Kind::Answered`. (`Got::author` is one `Arc<Author>` holding `by` and `writer`; the fields were `Got::by` and `Got::writer` before the performance pass, channel.md §18.10.) `Answered::query` is the query id, `via` the path it came by, `refusal` the handler's own refusal if it refused, `proof` the **proof** when `Ask::proof` was set: a `QUERY_PROOF` bundle (§6) of the asker's whole signed Interest and the server's whole answer Data, opaque octets to the application. Any member that holds the space's record checks it with `Heap::verify_answer_proof` (§10.1), whether or not it took part.
- **Which path (`Ask::via`), per server asked** (§15.8 says how the asker runs each):
  - `Signed`: the signed Interest of §5, always. Query at most 2,048 octets, `answer_max` at most 4,096.
  - `Channel`: the channel path of §15, always. It uses the `Ask` session this device holds with the server and **makes one if it holds none** (one signed ask, inside the query's deadline). It **never falls back to signed**: a setup the server refuses is `QueryFailed { NoSession }` with the setup's own reason and next step, and a node with no forwarder attached is `NotReady`. Query at most **1,024** octets, `answer_max` at most **65,536**, no `proof`.
  - `Auto` (the default): the channel only for a server whose `Ask` session this device **already holds** (with its pair, not idle for 60 s; an earlier `Channel` query or `ask_channel_in(.., ChannelMode::Ask)` made it), a forwarder attached, a query that fits one frame (at most 1,024 octets of query and a frame of at most 1,150 octets) and no `proof` asked; otherwise the signed path. **`Auto` never creates a session**, so a node's first query to a server is signed and the app opens the session itself (a `Channel` query, or `ask_channel_in`) when it wants the channel. An `Auto` query that falls to the signed path gets the signed path's limits, and so the server's `TooLarge { 4096 }` for an answer over 4,096.
  - `Answered::via` and `Query::via` say which path an answer came by: `Signed`, or `Sealed` for the channel path. An `Answered` of the channel path has `proof` `None` (§15.3: a frame sealed to a pair proves nothing to a third party).
- **`Select`.** A query is addressed to the selector's name: `Select::Path(p)` and `Select::Prefix(p)` both ask path `p`.
- **A `get` that asks nothing else.** `kept: false` with `live: Live::Off` and `ask: Some(..)` is a **query-only stream** (§10.4). The same options with `ask: None` stay `BadRequest` ([channel.md](channel.md) §17.7).
- **Who may call.** `get` with an `ask` needs a **listed** reader or writer whose key stands. A follower is `NotAllowed`.

`get` refuses an `ask` at creation, with a reason and a `NextStep` ([heap.md](heap.md) §10.5), in this order:

| Refusal | When |
|---|---|
| `NotAllowed` | the device only follows the space (it takes no part in queries: open it as a member); or its key does not stand as a listed member (neither writer nor reader by the entries held, revoked, suspected, or its chain not shown clean) |
| `BadRequest` | `QueryPath::Channel` with `Ask::proof` (a frame sealed to a pair proves nothing to a third party: ask `Signed` or `Auto`, which goes signed when a proof is asked, or ask without a proof); a query over **1,024** octets on `Channel` (`Auto` goes signed for it); a query over 2,048 octets; a deadline of zero or over 10 s; `answer_max` of zero, or over 4,096 on `Signed`, or over 65,536 on `Auto` and `Channel`; an asked path whose name value is over 255 octets; on `Channel` a frame that would be over 1,150 octets (a path or a query too long for one datagram on every path); `Targets::Devices` empty, naming more than 16, naming a name that is no device name (it holds a keyword or a digest component) or lies under `/localhost` or `/localhop`, or naming this device itself; `Targets::Serving` in a **sealed** space (its announces list no prefix, §11: the reason says to name the servers with `Targets::Devices` or `Targets::Person`). Every reason says the limit and what to ask instead |
| `NotReady` | the space's creation record is not held yet |

That no server is known is **not** a refusal at creation: it is told later, as `NoServer` (§10.2).

### 3.3 `QueryError`

A query to one server that fails is a `GetNotice::QueryFailed { server, why }` and counts `failed`. `why.next()` says what to do.

| Variant | Told when | NextStep |
|---|---|---|
| `NoServer { path }` | no server is known for the path (§10.2); `server` is the **space's name** | `FixRequest` |
| `NotListed` | the server Nacked `NoRoute`: it does not list this device's person, the key has no standing there, the person is outside a sealed space's audience, the query's `SignatureTime` is more than 120 s from the server's clock or not after the server's replay floor (its first `serve` plus 120 s, §8.3), the server has not begun to serve, or no route reaches it. The text names each and says to ask again in a couple of minutes | `AskOwner` |
| `NotServed { path }` | the server's signed status `NotServed` (`A_STATUS` 3): no served prefix of the path | `FixRequest` |
| `Busy` | on the signed path a `Congestion` or `Duplicate` Nack: the server is over a limit of its own, or had seen a copy of this query; on the channel path the server's sealed `Busy` (over its person's rate or handler places, §15.9; its `retry_ms` is not told) | `RetryLater` |
| `NotYet` | a `NotYet` Nack: the server does not hold this device's certificate chain or the sealed space's epoch | `RetryLater` |
| `Unreachable` | any other Nack, or the connection closed (on the channel path: the connection to the forwarder closed, or the pending entry was dropped) | `RetryLater` |
| `TooLarge { what, max }` | the server's signed status `TooLarge` (`A_STATUS` 4) or, on the channel path, its sealed `TooLarge` (§15.5): `max` its limit; on the channel path also a query frame over what the connection to the forwarder carries (`max` that size) | `FixRequest` |
| `AnswerTooLarge { size, max }` | an answer over `Ask::answer_max` | `FixRequest` |
| `BadAnswer { why }` | the answer failed the asker's judging (§10.1; on the channel path §15.8: a frame that carries the token and does not open under the pair's `Ka`, an epoch octet that is not the pair's, a plaintext that is no status, or a session signer that is no writer now), or what the forwarder reported was not a Nack or a timeout, or the server's seal key could not be had or judged (§7.1) | `RetryLater` |
| `TooManyOutstanding` | this node has 64 queries outstanding, or 16 to this server (§10.5) | `RetryLater` |
| `NotWriter { device }` | `Targets::Devices` named a device that is no writer of the space by the record held here: nothing is sent to it | `FixRequest` |
| `NotReady { why }` | the query could not be made: a sealed space with no epoch in force yet, the record cannot be written, or the device key did not sign; on the channel path no forwarder attached to the node (`attach_forwarder`), the session was let go as soon as it was made, the pair's counter is used up (the session is let go and the next query asks again), no free token could be drawn, or the forwarder took no query frame; each says what to do | `RetryLater` |
| `NoSession { why }` | `QueryPath::Channel` could not make the `Ask` session the query goes over: `why` is the setup's own refusal ([channel.md](channel.md) §6, a `ChanError`: `NotAnswered`, `Busy`, `Refused { TooMany, NotAudience, NotReady, … }`, `Unreachable`, …), whose text says why and what to do. The query was **not** sent signed instead | the setup's `why.next()` |
| `Congested` | this device's queue to its forwarder is full: the query frame was not sent (its counter number is spent and never reused, §15.6); try again in a moment, with fewer queries at once | `RetryLater` |

A handler's own `Refuse` is **not** a `QueryError`: it is an answer (`Answered::refusal`), counted `refused`.

## 4. The invariant: no answers family

An earlier data layer had a family of *answers*: results that evaluators computed, readers recomputed and resealed, and stores kept as if they were values. It was deleted. `serve` is a **producer callback** and nothing more. Five rules state what the code and this file keep, each guarded by a test that fails if it is broken (`ndn-heap`, `query/serve_tests.rs` and `query/ask_tests.rs`):

1. **A handler runs once per query that reaches it, and its result goes to that asker once.** No answer is stored, indexed, cached or served to a second asker by this layer: not by the server (no answer table, no store write, no memo), and a forwarder is asked not to (the Data is `FreshnessPeriod` 0 with `CachePolicy NoCache`, and the Interest is `MustBeFresh`: a conforming store neither keeps it nor satisfies another Interest with it; §12 says what a store that does not conform can do). *Guards:* `no_answer_is_stored_or_cached` (three queries run the handler three times, each Data is sent `NoCache`, the node's store holds nothing new); `a_replayed_signed_query_is_a_duplicate_and_the_handler_ran_once`; `no_answer_is_ever_an_entry` (a second `get` runs the handler again: no memo).
2. **An answer is never an entry and never the current value of a path.** `Kind::Answered` is not `Kind::Kept`; it is not in the register, not in the kept listing and not told again by a later `get`. *Guard:* `no_answer_is_ever_an_entry` (`kept` finds nothing at the asked path at the asker or the server; a `get` without an `ask` lists nothing of it).
3. **No reader recomputes, reseals or derives anything from an answer.** The asker is told exactly what the server signed (`proof` holds the answer Data byte for byte beside the signed question it answers, §6); there is no evaluator, no result cache keyed by query and no derived-value kind. *Guards:* `a_third_party_verifies_the_proof_from_the_record_alone_and_learns_what_and_when`; `a_listed_asker_gets_the_handlers_answer_signed_by_the_servers_device`.
4. **State is memory, bounded by outstanding queries and judged members, and nothing is persisted.** The asker's pending set (64, 16 per server), its seal keys and pair keys (64 each), the answer queue of one `get` (64 answers, 1 MiB); the server's handlers in flight (64, 8 per person), its replay set (240 s, capped), its pair keys (1,024) and its counters per person. A restart forgets all of it; the replay floor (§8.3) is what makes that safe. *Guards:* `the_pending_set_holds_sixteen_per_server_and_sixty_four_in_all_and_releases`, `outstanding_limits_hold`, `a_slow_reader_loses_the_oldest_answers_and_is_told_lagged`, `the_pair_cache_derives_once_per_epoch_and_drops_what_moved_and_is_bounded`, `concurrency_cap_is_busy_with_no_queue`, `per_person_inflight_and_rate_hold_across_her_devices`, `the_replay_set_forgets_after_240_s_and_refuses_over_its_cap`.
5. **One answer per query per server.** A server sends one Data per Interest (the PIT is satisfied once) and the asker tells at most one outcome per server: every server asked ends in exactly one of `answered`, `refused`, `failed`, `silent`. A handler that has a stream of results returns one value (the application frames it) or `put`s and answers with the path. *Guards:* `asked_is_always_answered_plus_refused_plus_failed_plus_silent`; `several_servers_answer_and_done_counts_add_up`.

**The channel path keeps all five rules** (§15.11 says how, with its guards): the server's pair keeps a window of counters and never an answer, the asker's pending entry holds a one-shot sender and is gone with its answer, one answer is made per `qseq` (a copy of a query is dropped, never answered again), and every server asked ends in exactly one bucket. Its state is memory too: the server's pairs (16,384, each with a 4,096-counter replay window), the asker's pairs and pending entries (the pending set is the signed path's, 64 and 16 per server); a restart forgets all of it, and §15.13 says what that costs.

## 5. Names and packets

*§5 to §10.1, §11 and §12 describe the **signed path**, with the parts both paths share marked in their text; the channel path has no Interest, Data, Nack or TLV of §6, and is §15.*

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
| 0x06E1 | `QUERY_PROOF` | the **proof** of an answer, kept by the asker (`Answered::proof`) and checked by `Heap::verify_answer_proof` (§10.1): `P_QUERY`, `P_ANSWER`, each once, in any order |
| 0x06E3 | `P_QUERY` | the asker's whole signed query Interest, as it went on the wire: at most 16 KiB |
| 0x06E5 | `P_ANSWER` | the server's whole answer Data, as it came: at most 16 KiB |

The statuses and the fields they take (each status carries its own fields and **no others**; a stray field, a missing one or an unknown status is malformed):

| `A_STATUS` | Fields | Meaning |
|---|---|---|
| 1 `Answered` | `A_BYTES` | the handler answered |
| 2 `Refused` | `A_CODE` (≤ 65,535), `A_TEXT` | the handler refused, in the application's words |
| 3 `NotServed` | none | no prefix of the path is served here |
| 4 `TooLarge` | `A_CODE` = the limit | the handler's answer is over what fits (4,096) |

**Plain or sealed, nothing between.** A plain `QUERY_ASK` has `Q_PATH` and none of `Q_SEAL`, `Q_EPOCH`, `Q_SEQ`. A sealed one has all three and **no `Q_PATH`**: the path travels inside the ciphertext. A plain `QUERY_ANSWER` has the status fields and neither `Q_SEQ` nor `A_SEALED`; a sealed one has both and **no status field beside them**. Any other mixture is malformed.

**Limits of the records.** The whole `QUERY_ASK` is at most 8 KiB (8,192 octets) and the whole `QUERY_ANSWER` at most 8,000 octets: larger is refused when written and when read. A query carries at most 4 `ASKER_CERT` and an answer at most 4 `S_CERT`, each a whole Data of at most 4,096 octets and 6,144 in all, so the judge fetches nothing (§8 step 5, §10.1 step 3). A server that cannot fit its certificates beside the status sends the answer **without** them. The deadline is 1 to 10,000 milliseconds; `Q_ID` is exactly 8 octets and `Q_SEAL` exactly 32.

**The proof.** A `QUERY_PROOF` has both packets and no other critical field: a missing or doubled one, a packet over 16 KiB (`PROOF_PACKET_MAX`, 16,384 octets) or empty, and an unknown odd type are refused; an unknown even type is skipped. A proof is therefore at most about 32 KiB, which the asker's answer queue charges (§9). It is not a message of the protocol: nothing sends it to anyone; the asker keeps it and hands it on as it sees fit.

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
- **What it proves.** The Interest is signed by the asker's device and carries `Q_SEAL`; the Data is signed by the server's device. A ciphertext that opens under `Kq` therefore comes from the party that signed the query and one that opens under `Ka` from the party that signed the answer. It is origin authentication between two parties and **no non-repudiation toward a third**: either holder of the pair could have made any ciphertext. The proof is the signed query and the signed Data; in a sealed space `verify_answer_proof` returns `ProvenAnswer::Sealed` and shows that this writer signed an answer sealed to this member's signed query at `signed_at`. It does not show what was said, and no disclosure of the plaintext exists in this version (disclosing the pair key would open every query of that pair and epoch).
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
- **Before the first `serve`, and after a restart.** A node that has not begun to serve answers **no signed query at all**, not even a sealed `NotServed`: it answers a plain `NoRoute` Nack (§8 step 3), signing and sealing nothing, so no `(Ka, Q_SEQ)` is used for a second plaintext. After a restart over the same store a copy of a query the previous run answered is refused by the floor before any answer is built (§8.3).

### 7.5 Caches and when they drop

- **The asker** keeps at most **64** server seal keys and **64** pairs (the one used longest ago is dropped). A seal key is dropped when the trust generation moves. A pair is dropped when the trust generation moves, when the members fold of its space moves, when the epoch in force or the server's key is not the one it was made for, or when the server is no writer any more (the same happens to the server's seal key). A query of a new epoch derives a new pair.
- **The server** keeps at most **1,024** pairs, one per (space, asker device), replaced when the asker's ephemeral key or epoch differs. A query that arrives with the table full and no pair of its own **drops the least recently used pair of the person who holds the most pairs** (ties: the person whose idlest pair is oldest) and takes its place: nobody is refused a pair. A pair is a cache: the person who lost one derives it again at one X25519 agreement at her next query. A pair is dropped: when its asker no longer stands as a listed person; when its asker is outside the audience of the epoch in force or the pair's epoch is not the one in force; when this device is no writer of the space (all its pairs); when the space is no longer open here; and when a sealed query fails to open (the asker holds a key the server does not: the next query derives again). The server judges its pairs again on its maintenance tick (every 250 ms and when the node is woken), cheaply when neither the trust generation nor the members fold has moved.
- Nothing here is persisted.

## 8. How the server judges

*This is the **signed path's** judging. The channel path's server judges a `QUERY` frame in the order of §15.7.*

The server judges a query **cheapest first**, so a stranger costs a lookup and no signature and a member costs one verification. The steps that decline without a word answer a Nack and sign nothing. A Nack that names a reason is the one in the table; the asker maps it as §10.3.

| Step | Check | Refusal |
|---|---|---|
| 1 | The name parses as `<this device>/32=query/<digest>`; the Interest carries ApplicationParameters of at most 8 KiB that hash to the digest and decode as a `QUERY_ASK` within its limits; the Interest is signed with a KeyLocator naming a key of a device, a `SignatureNonce` and a `SignatureTime`; `Q_SPACE` is a space name | `NoRoute` Nack, for each failure |
| 2 | One token of the **lookup budget**; then the space is **open here as a member** (not as a follower); then the key **stands as a listed person** (`Who::Listed`: a writer or a reader the record lists, owner-capable role, not revoked, not suspected), **by the entries held now**. A public space does not make a reader of an unlisted person: queries need a listed asker | `Congestion` over the budget; `NoRoute` otherwise |
| 3 | The **clock and the replay floor** (§8.3): this node has begun to serve (it has a floor), and `SignatureTime` is within **120 s** of this device's clock (`|now − signed| ≤ 120,000 ms`) and **after the floor** | `NoRoute`, plain: nothing is signed or sealed. A node that has not begun to serve answers every signed query this way |
| 4 | The **replay set** (§8.3) is **read**: a copy of a query already answered. It costs no signature and no unit of the verification budget | `Duplicate` |
| 5 | The **signature** verifies by the live rule from the certificates held and the at most four carried, **fetching nothing**; the carried certificates are held only as unverified copies for the one judging and dropped unless the walk reaches a trust anchor. The signer is judged by the context of **its own device**. One unit of the **verification budget** is paid before **every signature walk**, the first included (a query makes at most `1 + 4`). This is the one expensive step | over the budget: `Congestion`; a chain not held and not carried: `NotYet`; a signature that does not verify: `NoRoute` |
| 6 | The query **enters the replay set** (§8.3), now that it has verified | a copy that raced past step 4: `Duplicate`; a full set: `Congestion` |
| 7 | **Standing again** under the record's lock, as the key that signed the query; **this device is a writer** of the space; in a **sealed** space: an epoch in force exists, the query is sealed, its `Q_EPOCH` is the epoch in force, and the asker's person is in the audience of that epoch; in a **public** space: the query is plain. Then one token of the **person's rate** (§8.4) | standing lost, this device no writer, a plain query in a sealed space, a sealed one in a public space, the person outside the audience: `NoRoute`. No epoch in force here, or `Q_EPOCH` is not it: `NotYet`. Over the person's rate: `Congestion` |
| 8 | A **sealed** query is opened under the pair key (§7.2: derived once per (asker device, ephemeral key, epoch) and kept; a full table drops the idlest pair of the person who holds most, §7.5) and its plaintext decoded as `Q_PATH` and `Q_BYTES`; a **plain** one has its path already. Then the **served prefix**: the handler of the longest served prefix of the path | a key no agreement can be made with, a ciphertext that does not open (the pair is dropped), a plaintext that is not a path and octets: `NoRoute`. **No prefix of the path is served: a signed `NotServed` answer** (no handler runs, no place is taken) |
| 9 | A **place** for the handler: this node runs fewer than **64** handlers, this person fewer than **8** (on all her devices together), and she has answer octets left (§8.4). **No wait queue.** Then the handler runs under the asker's deadline, and its result is signed and sent | no place: `Congestion` Nack. Handler `Pass`, or past the deadline: **nothing is sent** |

Notes on the steps:

- **A stranger costs no signature.** A key the record does not list is `NoRoute` at step 2: no signature is verified or made and nothing is fetched. A forged query that names a listed key costs **up to `1 + 4` signature walks** (the key's own and one per carried certificate that must be judged), each paid by one unit of the **verification budget of the face it came over** and of the node, so the node's 1,024 units a second is a real bound on signature walks; a walk cut short by the budget is `Congestion` (`one_verification_token_pays_for_one_signature_walk`, `a_forged_chain_is_walked_only_as_far_as_the_budget_pays`). It charges **nobody's person rate**, since the rate is taken only after the signature verified and the replay set accepted it. A copy of a query already answered is `Duplicate` at step 4 with no signature and no unit spent (`a_replayed_query_costs_no_signature_verification`). An out-of-window time is refused at step 3, **before** any signature is checked (`a_hostile_query_with_a_forged_time_is_judged_by_the_window_before_a_signature`).
- **Budgets shared with channel asks.** The lookup budget (per ingress face 1,024 a second, burst 1,024; the node 8,192 a second, burst 8,192) and the verification budget (per ingress face 64 a second, burst 256; the node 1,024 a second, burst 1,024) are the **same** [channel.md](channel.md) §3.3 steps 2 and 3 take from: a flood of queries and a flood of channel asks draw on one allowance of each and cannot starve the node twice (`the_lookup_and_verification_budgets_are_shared_with_channel_asks`). A channel ask pays the verification budget per signature walk too (`one_verification_token_pays_for_one_signature_walk_of_an_ask`).
- **The status of an answer** (§6) is the handler's: `Answer` becomes `Answered` (or `TooLarge` when over 4,096 octets), `Refuse` becomes `Refused` with its text cut at 256 octets. The answer is signed by this device, sealed first in a sealed space, with this device's certificates beside it **as room allows** (without them if the Content would be over 8,000 octets). If it still cannot be written or signed the server Nacks `NoRoute`. `NotServed` and `TooLarge` are signed answers, not Nacks: the asker is told why.
- **A late handler.** The handler's future runs under a timeout of the asker's `Q_DEADLINE` counted from the query's arrival; at the timeout it is dropped and nothing is sent.

### 8.3 The replay set and the replay floor

- **The replay set** remembers a query by a 128-bit digest of (asker key, `SignatureNonce`, `SignatureTime`) for **240 s from its arrival**: a copy is acceptable only within 120 s of the signed time, and the signed time was within 120 s of the original's arrival, so 240 s is sound. It holds at most **262,144** queries; past that a new query is a `Congestion` Nack (a set that dropped entries would let a copy run again). A repeat is a `Duplicate` Nack and the handler does not run again. The set is **read at step 4**, before the verification budget and the signature, and **written at step 6**, only after the signature verified (so a forged query never takes an entry); a copy is therefore refused **before** the person's rate, and costs the asker nothing and the server no signature.
- **The floor.** The set is in memory, so a restart empties it, and a signed query captured in the 240 s before could be replayed once after it, which for a handler with side effects is a double grant. What bounds a query the previous run accepted is the clock: it was signed at most 120 s after it arrived (step 3), and that run ended before this one's first `serve`. The node therefore records the wall-clock moment its **first `serve` succeeded**, and its **floor is that moment plus 120 s** (`ASK_CLOCK_WINDOW_MS`); a query whose `SignatureTime` is **at or before the floor** is refused at step 3 with a plain `NoRoute` Nack, before any signature check, **whatever the asker's clock** (a floor equal to the serve instant would let a captured query signed by an asker whose clock runs ahead by up to 120 s pass: `a_captured_query_cannot_run_again_after_a_restart_whatever_the_askers_clock`). The floor is armed **before** the prefix enters the table, so no handler is reachable without one (`the_floor_is_set_before_the_prefix_is_reachable`, `no_handler_is_reachable_while_the_floor_is_unset`), is fixed once per run of the node and never moves, and is the node's, not a space's. Before the first `serve` there is no floor and **no signed query is answered**: a plain `NoRoute`, with nothing signed or sealed (§7.4; `a_sealed_query_before_the_first_serve_is_a_plain_nack_so_no_nonce_is_used_twice`).
- **The cost: a quiet period after every start.** For the first 120 s after a node begins to serve, plus however far the asker's clock is behind the server's, a signed query is refused (an asker whose clock is ahead is served sooner by the same amount). The asker is told `NotListed`, whose text names the quiet period and says to ask again in a couple of minutes. The node logs once, at `info`, when it arms the floor, and at `debug` the refusal of a query at or before it.

### 8.4 The person's counters

Counters are **per asker person** (her devices together), in memory; an idle person's counters are swept after 240 s when the node holds 4,096 of them.

- **Rate:** 64 queries a second, burst 128, one token per query that passed step 6 and step 7's standing checks (`Congestion` over it).
- **In flight:** 8 handlers running at once; the node 64 (`Congestion`, no queue).
- **Answer octets:** a budget of 4 MiB a second (burst 4 MiB), charged **after** an answer is signed with the octets of its Content; one answer may put the budget into debt, and while it is in debt (credit not above zero) no new handler is started for her (`Congestion`). `NotServed` answers are not charged.

## 9. Limits

| What | Limit | Over it |
|---|---|---|
| `QUERY_ASK` | 8 KiB (8,192 octets) | refused when written; `NoRoute` Nack when read |
| Query octets (plain; inside a sealed query) | 2,048 on the signed path and `Auto`; **1,024** on `QueryPath::Channel` (and for what a server opens from a `QUERY`) | `BadRequest` at `get` (`Auto` goes signed for a query over 1,024); the record is refused; a `QUERY` whose plaintext is over it is dropped (§15.7 step 7) |
| Path | 255 octets of name value (components with their type and length octets) | `BadRequest` at `get`; the record is refused |
| Sealed query ciphertext | 16 to 2,367 (2,048 + 255 + 64) | the record is refused |
| `Q_DEADLINE` | 1 to 10,000 ms | the record is refused |
| `ASKER_CERT` / `S_CERT` | 4 each; 4,096 octets each; 6,144 in all | the record is refused |
| Answer octets (`A_BYTES`; inside a sealed status) | signed path **4,096**; channel path **65,536** | signed: the server answers `TooLarge` (limit 4,096); the asker's `answer_max` (1 to 4,096 on `Signed`, 1 to 65,536 on `Auto` and `Channel`; default 4,096) makes a larger one `AnswerTooLarge`; channel: a sealed `TooLarge` (limit 65,536, or what the path's frame carries, §15.9) |
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
| Server: clock window | 120 s either way, and after the replay floor (first `serve` + 120 s); none before the first `serve` | `NoRoute` |
| Server: pair keys | 1,024 (one per space and asker device) | the idlest pair of the person who holds most is dropped; nobody is refused |
| Channel path: `Ask` session receivers | 1,024 askers per channel (the other modes 256), 32 devices per person per channel | a signed `TooMany` refusal at the setup, retry in 30 s (§15.2) |
| Channel path: `QUERY` frame | 52 octets of header and tag plus the plaintext; at most 1,150 octets from the asker (the floor of every path's datagram), at most 2,048 accepted by the server; query octets at most 1,024 | `BadRequest` at `get` (`Channel`), dropped `malformed` or `bad_plain` at the server (§15.7) |
| Channel path: `ANSWER` frame | 35 octets of header and tag plus the plaintext, at least 46 octets in all (padded inside the seal); a datagram when it fits the carrier's datagram limit for the route, else a stream frame, else a sealed `TooLarge` | §15.9 |
| Channel path: server pairs / replay window / counters | 16,384 pairs on a node; 4,096 counters of window per pair; a counter more than 2^24 above the highest seen is not opened; a pair lives its session's lifetime (1 h by default, at most 24 h) plus 5 s; a replaced pair opens queries 5 s more | `TooMany` refusal when the table is full (retry in 30 s); `replayed` drop; §15.6, §15.10 |
| Channel path: queries per second per asker person | 256, burst 256 (a bucket of its own: the signed path's is 64, burst 128) | a sealed `Busy` (at most one a second per pair), else dropped |
| Channel path: `Busy` | at most one a second to one pair; `retry_ms` is a fixed 1,000 | the others are dropped and counted `busy_dropped` |
| Channel path: `Ask` session idle / silent queries | released after 60 s without a query; released after 3 queries in a row that nothing answered | the next `Channel` query asks again (§15.8) |
| Channel path: breadcrumbs, `QUERY` rates at a forwarder | [channel.md](channel.md) §14.13: 16,384 breadcrumbs per table, 256 per face, 1,024 per route; 512 a second per face, burst 128; 2,048 a second per route, burst 512; a breadcrumb lives the frame's ttl clamped to 100 ms–10 s | dropped at the relay and counted there; the asker sees silence |
| Lookup budget | 1,024 a second per face, burst 1,024; 8,192 a second per node | `Congestion` Nack |
| Verification budget | 64 a second per face, burst 256; 1,024 a second per node, burst 1,024; one unit per signature walk (up to `1 + 4` a query) | `Congestion` Nack |
| Announce | 16 prefixes and 512 octets of name values in all; announce parameters at most 1 KiB | the rest left out; the decoder refuses more |
| Announce hints | 90 s **per prefix**; devices per space: 256 vouched (32 per person) and 16 unvouched (4 per person); 64 devices marked as having answered; 64 prefixes per device | lapse; the oldest vouched is dropped; a new unvouched name is refused when its pool is full; a new prefix of a device that holds 64 is not taken |
| Proof (`QUERY_PROOF`) | two packets of at most 16 KiB each | the answer fails `TooLarge` when written; `ProofError::Malformed` when read |

No figure of speed or CPU cost of this path is recorded in this file; none has been measured.

## 10. The asker

*§10.1 is the signed path's judging of an answer; §10.2 to §10.5 (targets, counting, order, the pending set) are **both paths'**. The channel path's asker, its judging of an `ANSWER` and its silence rule are §15.8.*

### 10.1 Judging an answer

The asker judges an answer in this order and tells nothing the order has not passed. Any failure is `QueryFailed { BadAnswer }`:

1. The Data's name equals the Interest's name.
2. The Content decodes as a `QUERY_ANSWER` within its limits (a record that breaks one is `BadAnswer` before any signature is checked: the certificates are in it).
3. The Data verifies as a key of **the server's device** by the durable rule ([heap.md](heap.md) §9: signature and chain, no clock except for a key whose role needs a cut), from the certificates held and the at most four the answer carries, **fetching nothing**. A signer whose chain is neither held nor carried is not told as an answer.
4. **The signer stands as a writer now** (`Who::Writer`). Its person is `Got::author.by`.
5. `Q_ID` is the id of this query.
6. The body matches the space: a plain status in a public space; in a sealed space a sealed one whose `Q_SEQ` is the query's counter and which opens under `Ka` with the additional data of §7.3 and decodes as a status. A sealed answer in a public space, or a plain one in a sealed space, is refused.
7. By status: `Answered` with at most `answer_max` octets is told (`AnswerTooLarge` otherwise); `Refused` is told as an answer carrying its `AppRefusal`; `NotServed` is `QueryFailed { NotServed }`; `TooLarge` is `QueryFailed { TooLarge }`.

A signed Data that contradicts the space's record (a signer that is not a writer, a non-matching id) is a failure of that server only: the other servers of the query are unaffected.

**Verifying a proof.** `Heap::verify_answer_proof(&[u8])` (async; it fetches and sends nothing) takes the bytes of `Answered::proof` and judges them from the space's record held by that node, with the entry points the server and the asker already use. An `Ok(VerifiedAnswer)` says that, in this order:

1. the bytes are a `QUERY_PROOF` of an Interest and a Data (else `Malformed`); the Interest is `<device>/32=query/<digest>`, its parameters hash to the digest and decode as a `QUERY_ASK`, and it is signed by a device key with a `SignatureNonce` and a `SignatureTime` (else `Question`); the space is this heap's (else `OtherSpace`);
2. the Data is named **exactly** as the Interest, so it answers the digest of that question, its signature and its time (else `Unrelated`);
3. the record holds the space's creation (else `NoRecord`); the **asker's signature** on the Interest verifies by the live rule, from the chain the query carries and the certificates held (else `Question`; `NotJudged` when the chain cannot be judged yet); and the asker **stands as listed** (`Who::Listed`) by the record held (else `AskerNotListed`);
4. the answer's Content decodes as a `QUERY_ANSWER`; the **answer's signature** verifies as a key of the named server device, by the durable rule, from the chain it carries and the certificates held (else `Answer`; `NotJudged` when pending); and that key **stands as a writer** (else `ServerNotWriter`);
5. `Q_ID` is the query's, the answer is plain where the query is plain and sealed where it is sealed, and in a sealed space the answer's `Q_SEQ` is the query's counter (else `Unrelated`).

It then gives the space, the query id, the asker and the server (person and device), the path and query octets (public space only), what the server answered (`ProvenAnswer`) and `signed_at`. **The time is the asker's:** `signed_at` is the query's `SignatureTime` on the asker's clock. The answer Data has a KeyLocator and no time, so a proof shows that the answer came **after** the query (it names its digest) and not how long after; the server's own ±120 s check is not signed. In a sealed space the proof is signed ciphertext and the verifier says `Sealed` (§7.2). Standing is judged by the record the verifier holds **when it verifies**, so a later removal or revocation fails the proof closed (§12).

### 10.2 Several servers: targets, and when none is known

| `Targets` | Who is asked |
|---|---|
| `Devices(d)` | exactly those, de-duplicated, in order (at most 16). A device that is no writer of the space, by the record held here and judged **now**, is **not asked**: it is `QueryFailed { NotWriter }` and counts `failed`. A name that is no device name, a reserved one, or this device is refused at `get` |
| `Person(p)` | the devices of person `p` that the record knows plus those whose announce (§11) was heard within 90 s, **that are writers** (and not this device), in name order, the first 16; the rest are counted in `not_asked`. A person who is no writer has none |
| `Serving` (default) | the devices whose announce lists a prefix of the asked path (heard within 90 s), judged offline as writers of the space and not this device, **the 16 best**: devices that answered a signed query first, then those the record vouches for, then the rest, the newest first within each; the rest are counted in `not_asked`. In a **sealed** space `Serving` is refused at `get` (§3.2) |

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

- **What it lists.** The prefixes a device serves (§3.1), **shortest first** (by the octets of the name value, then by name), at most 16 names and 512 octets of name values in all; the ones that do not fit are left out (an asker names them with `Targets::Devices`). An empty prefix (the whole space) is a legal name. **In a sealed space the announce lists no prefix at all:** it is an Interest in the clear, and a prefix served would show the sync group what is asked of whom (the query is sealed for that very reason, §7); a sealed space that only serves sends no announce for it. Askers there name the servers (`Targets::Devices`, `Targets::Person`).
- **When.** Whenever a `serve` registers a prefix, whenever a `Serving` is dropped (so the next announce lacks it; the hint of the dropped prefix is not removed by that announce but lapses, below, and the server answers a signed `NotServed` meanwhile), every 30 s while something is served, and with every announce [channel.md](channel.md) §9 sends. It is the **same** unsigned Interest `<sync group>/32=chan/<digest>` under the same rules: HopLimit 8, InterestLifetime 1 s, nobody answers it and nothing caches it.
- **Empty modes.** A device that holds **no channel** announces its prefixes **alone**: `CHAN_ANNOUNCE` with no `ASK_MODE` and at least one `ANN_SERVES`. An announce with **neither** a mode nor a prefix is malformed and is **never sent**: a device with no channel that stops serving sends nothing, and its hints lapse after 90 s (as every hint does, below). A hearer that finds no mode in an announce asks for no channel.
- **The hearer records a hint** when the announcing device passes the checks [channel.md](channel.md) §9 item 2 makes **offline**: its person is a **writer** of the space and its name is a device name under no reserved prefix (a device the record vouches for needs only the writer check). The hint is recorded **whatever is decided about asking for a channel**, and whether or not the hearer wants live data; **in a sealed space no hint is recorded from an announce that lists a prefix** (a sealed space's own devices list none). **An announce never removes or replaces a hint:** it is unsigned, so anyone can name a device and list `/other` or nothing, and a replacement or a removal would be as forgeable as an addition (`an_unsigned_announce_naming_a_server_cannot_take_its_hint_away`). It adds prefixes to the device (at most 64 a device; once it holds 64 the first heard stay) and refreshes the ones it lists. **Each prefix lapses alone, 90 s** (three announce periods) after it was last heard; a prefix a device has dropped stays up to 90 s, and an ask on it is answered with a signed `NotServed` (the server is the authority).
- **Two pools.** A device the record **vouches for** (it holds an admitted entry) or that **answered a signed query** of this node (a `proven` mark, set when an answer validates or when an announce-driven ask finds the session good: 64 per space) is in the **vouched** pool: 256 devices per space, 32 per person, the oldest not proven going first. Every other device is in the **unvouched** pool: 16 per space, 4 per person, and a **new name is refused when its pool is full** (the first heard stay until they lapse; a device already held is always refreshed). A device a writer made up under her namespace therefore cannot push a vouched or proven device out. Order for `Serving` and for the announce-heard part of `Person`: answered, then vouched, then unvouched, then newest.
- **It is only a hint.** The announce is unsigned: any name under a writer's namespace passes for one of her devices. The asker judges the device a writer itself before it asks, and the server's own judging of the query is the authority: a device that announced a prefix it does not serve answers a signed `NotServed`, and a device that is no writer is not asked (and, asked anyway, is refused at §8 step 7). See §12.

## 12. Security notes

*The threat notes of the channel path (a relay's garbage `ANSWER`, a held `QUERY`, a flood naming a valid pair id, what a member can do, what a relay sees) are §15.12; its residuals are §15.13.*

**What a member can do to a server.**
- *Handler DoS.* One person holds at most 8 handlers and the node 64, a hung handler is dropped at the query's deadline (at most 10 s), and there is deliberately **no wait queue** (it would be an unbounded delay and memory). Eight persons can occupy all 64 for 10 s: that is the application's capacity decision (the limits are the layer's, not configurable here). A stranger takes none.
- *Signature DoS.* A member makes the server verify one signature and make one per query, bounded by her 64-a-second rate and by the budgets of §8. A forged query naming a member costs up to `1 + 4` signature walks, each paid by the face's and the node's verification budget, never by the named member's rate; a copy of a query already answered costs no signature.
- *Pair-key exhaustion and X25519 work.* In a sealed space each (space, asker device) holds one pair on the server, replaced whenever the asker sends another ephemeral key; a member with many devices, or one that changes the ephemeral key on every query, makes the server do an X25519 agreement per query, bounded by her rate. Pairs are 1,024 for the node: when the table is full a new pair drops the least recently used pair of the person who holds the most (§7.5), so one person that holds many devices cannot lock others out, and she loses her own pairs first; she derives them again at one agreement each, bounded by her query rate. A pair is a cache: another person loses one only when she holds more pairs than anyone else, and it costs her one agreement. The cost of an agreement is not measured here.
- *Amplification.* A query is at most 8 KiB and an answer's Content at most 8,000 octets, so a member can ask for several times her bytes; the answer goes back only on the **Interest's in-record** (a Data satisfies a PIT entry once), so there is **no reflection** to a third party. Her answer octets are budgeted (4 MiB a second).
- *Replay.* The replay set, the 120 s window and the floor (§8.3). A restart cannot be used to run a captured query, **whatever the asker's clock**: the floor is the first `serve` plus 120 s. The price is the quiet period after every start (below). A query captured and replayed **within** the window of a server that did not restart is `Duplicate`, before any signature. The replay entry is made once a query has verified, **before** standing, the person's rate and a place for the handler are checked (step 7 and 9): a query refused there (`Congestion`) is used up, and the same signed octets sent again are `Duplicate`; the asker signs a new query for a new try (a retry is a new `get`).

**What a server can do to askers.** A writer's device is trusted with what it says, as far as the space's record trusts a writer.
- *Lie.* Any writer's device may serve any prefix and answer anything. Its answer is **signed**, so a false answer is the writer's own signed statement and, **in a public space**, `proof` keeps it with the query it answers, as a bundle anyone who holds the space's record verifies (§10.1), for whoever must hold the writer to it; the layer does not judge the content. An asker that gets two different answers chooses by `writer` and `by`. Which writer may serve which prefix is **not** specified: a members-record field that said so is a change to [heap.md](heap.md) not made here.
- *Refuse, delay, stay silent.* A server may `Refuse`, answer slowly or `Pass`; the asker's deadline bounds what it waits and `silent` records it.
- *Learn.* The server learns the asker's person and device (as it judged them), the path and the query octets, and the time. In a sealed space it opens them; the sealing keeps them from relays, not from the server.
- *An answer too large* is `TooLarge`; one over `answer_max` is `AnswerTooLarge`: the asker bounds what it reads.

**What a relay sees.**
- *Public space:* the whole query and answer (path, octets, status), the asker's and the server's names, the id and the deadline. `NoCache`, `FreshnessPeriod` 0 and `MustBeFresh` ask a store not to keep the answer or serve it to another Interest; they are requests, not enforcement. A relay that stores the answer anyway can give it again to an Interest of the same name (only a copy of the asker's signed Interest has that name), and that copy never reaches the server's replay set; the content is public to every relay on the path in any case. Only a sealed space keeps it from them.
- *Sealed space:* the space, both device names, the id, the deadline, the ephemeral key, the epoch, the counter, the certificate chains, the signatures, and the **length** of the ciphertexts; not the path, the octets or the status. It can tell an asker's queries to one server apart by the ephemeral key and the counter.

**Hints are forgeable; they cannot be deleted, and made-up names cannot crowd out vouched ones.** `ANN_SERVES` is unsigned. Any party that can reach the sync group can send an announce that names a writer's device as serving a path; the asker then spends **one signed query** on it and is told `NotServed` or gets nothing. What that can and cannot do (§11):
- *Deletion is closed:* nothing removes or replaces a hint but its own 90 s lapse, so an announce that lists nothing, or `/other`, takes no hint from a real server.
- *Crowding is bounded:* names made up under a writer's namespace go to the small **unvouched** pool (16 per space, 4 per person, new names refused when it is full) and cannot push out a device the record vouches for or that answered a signed query (256 per space, 32 per person); order is answered, vouched, unvouched, then newest. A flood therefore cannot hide a **vouched** or **proven** server from the 16 that `Targets::Serving` asks. That does not make a wrong answer acceptable in any case (each answer is judged, §10.1).
- *Residual: a real server that is neither vouched nor proven.* A writer's device that has put nothing (so the record holds no entry of it) and has not yet answered a signed query shares the 16-slot unvouched pool, and names made up **before it announces** can keep it out of `Targets::Serving`. `Targets::Devices` and `Targets::Person` are unaffected, and one signed answer promotes a device out of the pool. Closing it needs a **signed announce**, a wire change to what is an unsigned Interest, which this version does not make.
- *Residual: junk prefixes.* An unsigned announce can still add prefixes (at most 64 a device) to a real device's hint; the cost is one signed ask answered `NotServed`, for up to 90 s.
- *Sealed space:* `ANN_SERVES` is never sent in a sealed space, a hearer records no hint from one that lists a prefix, and `Targets::Serving` there is refused at `get` with the reason; the way is `Targets::Devices` or `Targets::Person`, not the announce.

**Clocks.** The only wall-clock readings are the signed `SignatureTime` and the replay floor. No decision about who is a member, which key stands or whether an answer is genuine rests on a clock.

**After every start there is a quiet period.** For 120 s after a node first serves (plus the asker's clock lag), signed queries are refused with `NoRoute` and the asker is told `NotListed` with a text that says to ask again in a couple of minutes. The reason is that the floor is the only thing that stops a query captured before a restart from running a handler a second time, and a floor that is only a clock needs the 120 s the asker's clock may run ahead. A durable high-water mark would remove the quiet period but needs a write to disk on every accepted query, which this layer does not make (nothing here is persisted, §4 rule 4). The floor is per node, not per space; an asker whose clock is far behind waits longer.

**Replay of a channel ask still costs one verification.** The channel setup's replay guard (`ndn_security::ReplayGuard`, [channel.md](channel.md) §3.3) records an ask only after it verified and has no read-only `contains`, so a replayed channel ask (the ask of an `Ask` session included) is verified once before it is told `Duplicate`. The signed query reads its set first (§8 step 4) and does not. Closing it needs a read-only `contains` in `ndn-security`. A channel ask pays the verification budget per signature walk like a query.

**Whether a key is listed can be probed.** A query that names a key the record does not list is a `NoRoute` Nack at step 2; one that names a listed key whose chain the server does not hold is a `NotYet` Nack at step 5, and one that carries the chain costs a verification first. A prober who knows a device's key name can tell, from the reason and the timing, whether it stands as listed at that server; it learns nothing of the role or the person's other devices. The reasons are the asker's guidance (`NotListed` is `AskOwner`, `NotYet` is `RetryLater`, §3.3), so they are not merged. A walk charged to the verification budget may cost less than a signature check when the first certificate is missing; it is charged as one unit, which is conservative.

**What a sealed space does not give.** There is **no forward secrecy** toward the server's static recipient key: a later compromise of it opens the pairs and so the recorded queries and answers of that server (§7.2). The announce is in the clear (§11): a sealed space lists no prefix in it. The channel path's own position (the pair keys come from the asker's recipient key, and every query is sealed, in a public space too) is §15.12.

**An answer is evidence only as strong as its path.** In a **public** space `proof` is the asker's signed query and the server's signed answer: the writer's own statement, bound to the question and to the asker's time, checked from the record alone (§10.1). In a **sealed** space it is the server's statement about ciphertext and no more: it shows that this writer signed an answer sealed to this member's signed query at `signed_at`, and the verifier says `Sealed`; the plaintext is the server's only because only the server and the asker could have made it (§7.2: no proof of the plaintext to a third party), and no disclosure exists. What a proof leaves open, with the reason:
- *The query's signature is judged by the live rule* (the asker's certificates must be valid now). A proof whose asker certificate has since lapsed fails (`Question`) though the exchange was valid then; the only durable rule is for Data, in `ndn-security`, and a durable validator for Interests is a change to that crate. Verify when the proof is received and keep the verdict.
- *Standing is judged by the record held when verifying,* not as of `signed_at`: the members fold keeps no time per entry. A person removed, or a key revoked, since the exchange fails the proof closed.
- *`signed_at` is the asker's own claim.* It is signed by the asker; the server (if honest) refused anything more than 120 s from its clock, but that check is not signed, and the Data has no time field (adding one changes the answer's signed wire, §6). A proof shows that the asker said so and that the server answered after it.
- *A sealed proof is ciphertext only,* for the reason in §7.2.

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

`QUERY_PROOF` of the packets `0501aa` (the query) and `0602bbcc` (the answer), as `wire/query_tests.rs` asserts them (the codec does not read inside the packets; `verify_answer_proof` does):

```
fd06e10ffd06e3030501aafd06e5040602bbcc
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

The channel path's golden octets (both headers and every plaintext) are §15.14; it has no vector of its key derivation (§15.14 says why).

## 14. Conformance cases

The observable behaviours a conformance suite checks. Each names the test that guards it in `ndn-heap`. The cases below are the **signed path's** and the path-independent ones; the channel path's guards are listed in §15.15 (its q-cases, for a suite that runs against any implementation, are stage 5 and not built).

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
- **q11** A replayed signed query is a `Duplicate` Nack and the handler ran once; a replay is refused before the person's rate is charged, before the verification budget and without a signature; the replay set forgets after 240 s and refuses over its cap. (`a_replayed_signed_query_is_a_duplicate_and_the_handler_ran_once`, `a_replayed_query_costs_no_signature_verification`, `the_replay_set_forgets_after_240_s_and_refuses_over_its_cap`)
- **q12** A node that has not begun to serve answers no signed query and signs and seals nothing (a plain `NoRoute`); the floor is the first `serve` plus 120 s, armed before the prefix is reachable, and a query signed at or before it is refused whatever the asker's clock, also after a restart over the same store; after the floor the query is answered; the 120 s window holds, and a forged time is refused before any signature is checked. (`a_sealed_query_before_the_first_serve_is_a_plain_nack_so_no_nonce_is_used_twice`, `no_handler_is_reachable_while_the_floor_is_unset`, `the_floor_is_set_before_the_prefix_is_reachable`, `a_captured_query_cannot_run_again_after_a_restart_whatever_the_askers_clock`, `a_query_signed_up_to_the_floor_is_refused_and_one_after_it_is_answered`, `the_clock_window_holds`, `a_hostile_query_with_a_forged_time_is_judged_by_the_window_before_a_signature`)
- **q13** Eight handlers per person across her devices and 64 on the node; over them a `Congestion` Nack and no queue; the person's rate and answer-octet budget hold. (`per_person_inflight_and_rate_hold_across_her_devices`, `concurrency_cap_is_busy_with_no_queue`, `the_answer_octets_of_a_person_are_a_budget_of_4_mib_a_second`)
- **q14** The lookup and verification budgets are shared with channel asks, and one unit of the verification budget pays for one signature walk, in a query and in a channel ask. (`the_lookup_and_verification_budgets_are_shared_with_channel_asks`, `one_verification_token_pays_for_one_signature_walk`, `chan/setup_tests.rs`: `one_verification_token_pays_for_one_signature_walk_of_an_ask`, `a_forged_chain_is_walked_only_as_far_as_the_budget_pays`)
- **q15** A query whose chain the server does not hold is a `NotYet` Nack; the same query carrying the chain is answered. (`a_query_whose_chain_the_server_does_not_hold_is_nacked_notyet_and_carrying_it_answers`)

**Sealed spaces**

- **q16** A sealed space's query and answer are ciphertext on the wire; one X25519 agreement serves two queries of one epoch; the pair of an old epoch and of a removed asker is dropped; a full pair table drops the idlest pair of the person who holds most and refuses no one. (`a_sealed_space_query_and_answer_are_ciphertext_on_the_wire`, `a_sealed_space_query_end_to_end_one_agreement_for_two_queries`, `the_pair_cache_derives_once_per_epoch_and_drops_what_moved_and_is_bounded`, `a_full_pair_table_drops_the_idlest_pair_of_the_person_with_most_and_refuses_no_one`)
- **q17** A query of a stale epoch is a `NotYet` Nack; an asker outside the audience is a `NoRoute` Nack; a plain query in a sealed space and a sealed one in a public space are `NoRoute` Nacks. (`a_query_with_a_stale_epoch_is_nacked_notyet`, `a_sealed_asker_not_in_the_audience_is_nacked`, `a_plain_query_in_a_sealed_space_and_a_sealed_one_in_a_public_space_are_nacked`)
- **q18** Sealing (`query/seal.rs`): the nonce is four zero octets and the counter and the suite AES-256-GCM; `Kq` does not open an answer nor `Ka` a query; a changed octet of the data or of the ciphertext, or of the context, does not open; two counters give two ciphertexts.

**The asker**

- **q19** `get` refuses each bad request with its reason, in the order of §3.2, including `QueryPath::Channel` with a proof, a query over 1,024 octets on `Channel`, a frame over 1,150 octets, and the answer limits of each path. (`get_with_ask_refuses_each_bad_request_with_its_reason`; for the channel rules also `chan_ask_tests.rs`: `channel_with_proof_is_refused_and_auto_with_proof_goes_signed`, `a_query_over_1024_octets_is_refused_on_channel_and_goes_signed_on_auto`, `the_limits_of_answer_max_follow_the_path`)
- **q20** `asked = answered + refused + failed + silent` over every mixture of servers, and `Pass` counts `silent` while a handler's refusal counts `refused`. (`asked_is_always_answered_plus_refused_plus_failed_plus_silent`, `several_servers_answer_and_done_counts_add_up`, `pass_is_counted_silent_and_a_refusal_is_refused_not_failed`)
- **q21** A late answer is dropped and the deadline ends the query; `AnswersDone` is told once. (`the_deadline_ends_the_run_and_a_late_answer_is_never_told`, `a_late_answer_is_dropped_and_the_deadline_ends_the_query`)
- **q22** Order: answers during the kept listing come after it; the sources take turns after it; a query-only stream ends after `AnswersDone` and one with kept values goes on; a slow reader loses the oldest answers and is told `Lagged`. (`answers_during_the_listing_come_after_it`, `answers_alternate_fairly_with_kept_after_the_listing`, `a_query_only_stream_ends_after_answersdone`, `a_stream_with_kept_goes_on_after_answersdone`, `a_slow_reader_loses_the_oldest_answers_and_is_told_lagged`)
- **q23** The pending set holds 64, 16 per server, and releases on resolution and on dropping the `Items`. (`the_pending_set_holds_sixteen_per_server_and_sixty_four_in_all_and_releases`, `outstanding_limits_hold`, `dropping_items_cancels_the_pending_query`)
- **q24** Targets: `Serving` asks the hinted writers of a prefix of the path and no other, the best vouched first, none known waits and then tells `NoServer`, and in a sealed space is refused at `get`; `Person` and `Devices` de-duplicate and ask only writers; a named non-writer is `NotWriter`, not asked and counted `failed`. Made-up names do not crowd the real server out of the targets. (`targets_serving_uses_the_announce_hint_and_none_known_is_noserver`, `targets_serving_in_a_sealed_space_is_refused_with_what_to_do`, `spoofed_device_names_do_not_crowd_the_real_server_out_of_the_targets`, `query/table.rs`: `names_nothing_vouches_for_cannot_crowd_a_real_device_out`, `a_device_that_answered_outranks_newer_hints_that_did_not`, `the_devices_remembered_as_answered_are_bounded_and_the_oldest_goes`, `targets_person_and_devices`, `a_named_non_writer_is_not_asked`, `a_named_writer_that_never_answers_is_silent_at_the_deadline`)
- **q25** An answer is judged: one signed by a non-writer, one with another query's id, and one over `answer_max` are failures (`BadAnswer`, `BadAnswer`, `AnswerTooLarge`); `proof` is the signed query and the signed answer (see q28). (`the_answer_signed_by_a_non_writer_is_badanswer`, `a_mismatched_query_id_is_badanswer`, `an_answer_over_answer_max_fails_answertoolarge`)
- **q26** No answer is ever an entry, and a second `get` runs the handler again. (`no_answer_is_ever_an_entry`)

**The announce**

- **q27** An announce lists what is served and a hearer records a hint only for a writer's device; the announce is sent again when the set served changes, is due every 30 s while something is served, and lists at most 16 names and 512 octets, shortest first. A device that holds no channel announces its prefixes with no mode; an announce with neither is malformed. (`the_announce_lists_what_is_served_and_a_hearer_records_a_hint`, `the_announce_is_sent_again_when_the_set_served_changes`, `the_announce_is_due_every_30_s_while_something_is_served`, `the_announce_lists_at_most_16_names_and_512_octets_shortest_first`, `chan/wire_tests.rs`: `an_announce_carries_the_prefixes_it_serves_and_may_hold_no_channel`, `an_announce_names_at_most_16_prefixes_and_512_octets_and_something_to_do`)
  Added by the hint fixes: an announce never removes or replaces a hint, each prefix lapses alone after 90 s, a device holds at most 64 prefixes, the pools are bounded (256 vouched, 32 a person; 16 unvouched, 4 a person), and the announce of a sealed space lists no prefix. (`an_unsigned_announce_naming_a_server_cannot_take_its_hint_away`, `a_sealed_space_announce_names_no_served_prefix`, `query/table.rs`: `an_announce_takes_nothing_away_only_the_lapse_does`, `the_prefixes_of_a_device_are_bounded_and_the_first_stay`, `the_vouched_hints_per_space_are_bounded_and_the_oldest_goes`, `one_person_cannot_take_more_than_her_share_of_the_vouched_hints`)

**The proof**

- **q28** A third party that holds the space's record and took no part verifies a proof and learns the asker, the server, the path, the query octets, the answer and `signed_at` (the asker's clock); it refuses a changed answer (`Answer`), changed query octets (`Question`), a question swapped for another's (`Unrelated`), an answer signed by a non-writer (`ServerNotWriter`), a query of a person the record does not list (`AskerNotListed`) and a bare Data (`Malformed`); in a sealed space the proof is signed ciphertext, shown as `Sealed`, with neither path nor query octets, and neither appears in its octets. The record is two critical packets: a missing, doubled, oversize or unknown odd field is refused. Tests: `a_third_party_verifies_the_proof_from_the_record_alone_and_learns_what_and_when`, `a_proof_with_a_changed_answer_or_a_changed_question_is_refused`, `a_proof_whose_question_was_swapped_for_another_is_refused`, `a_proof_signed_by_a_non_writer_or_asked_by_a_non_member_is_refused`, `the_proof_of_a_sealed_answer_is_signed_ciphertext_and_the_verifier_says_so`, `wire/query_tests.rs`: `a_proof_is_two_packets_in_one_critical_record_with_golden_octets`, `a_proof_refuses_what_is_missing_doubled_over_the_limit_or_unknown_and_critical`.

## 15. The channel path

The signed path (§5 to §10) spends a signature at each end of every query. The **channel path** spends them once: the asker makes an **`Ask` session** with one signed ask ([channel.md](channel.md) §3, mode 4), the session answer gives the asker device and the server device a **pair** of keys, and every query after that is **one sealed `QUERY` frame up and one sealed `ANSWER` frame down** over the route the session installed ([channel.md](channel.md) §14.13). Nothing here is an NDN packet: no Interest, no Data, no Nack, no signature after the first, no replay set, no clock.

What the two paths **share** (and §15 does not repeat): `Heap::serve` and the handler (`Query`, `Reply`: `Answer`, `Refuse`, `Pass`); `get` with an `ask`, its targets (§10.2), its counting (§10.3), its order (§10.4) and its pending set (§10.5: 64 queries on a node, 16 to one server, taken before the path is chosen); the server's places for handlers (64 on the node, 8 per asker person) and the person's answer octets (4 MiB a second, burst 4 MiB), taken from one pool (`ServerState::slot`); and the asker's judging of who the server is (a writer now). What **differs**: the cost (no signature and no X25519 per query; one AEAD seal and one open at each end), the seal (every query is sealed, in a **public** space as well as a sealed one), the **absence of Nacks** (every drop is silence, §15.9), the absence of a proof (§15.3), and the limits (§15.9).

**What it costs, as measured.** The tests count signatures: after the one signed ask, the second and every later query of a session adds none at the asker or the server (`the_second_query_in_a_session_costs_no_signature`, `a_warm_session_carries_many_queries_to_a_real_server_with_no_signature`). No latency or throughput figure of the channel path is recorded in this file; none has been measured. [INFERENCE] that it is faster than the signed path follows from the missing signatures and agreement, and is not a measurement.

### 15.1 Which path, and what it needs

`Ask::via` ([§3.2](#32-get-with-an-ask)) chooses per server. Both `Channel` and `Auto` need a **forwarder attached to the node** (`NodeHandle::attach_forwarder`, or an embedded engine's app face): the asker sends its `QUERY` through the node's connection to its forwarder, the connection `Keep` uses, and the server answers through its own carrier. `Channel` without one is `NotReady` and `Auto` is signed (§15.8). The route the frames take is the one the session answer's `SideRoute` header laid ([channel.md](channel.md) §3.2, §14.3).

### 15.2 The `Ask` session

An `Ask` session is an ordinary channel session ([channel.md](channel.md) §3) of **mode 4**: `ASK_MODE` 4 in the ask and `S_MODE` 4 in the session ([channel.md](channel.md) §7; modes 1 to 3 are as before). The setup is judged **exactly as any ask is**: the name, the lookup and verification budgets, standing as a **listed** person, the clock, the replay guard, the asker's rate (4 a second, burst 8 per key), this device a writer, a sealed space's audience, the caps. It costs **one signature at each end** (the ask and the session Data). What is different:

- **One signed ask; no welcome.** The session carries `S_CKPT_MS` 0 (no checkpoints are sent and the receiver waits for none), an empty `S_TABLE` and no `S_WINDOW`. The sender queues **no `HELLO`, no bind, no standing value and no stream frame**, so the claim limiter that `ASK_NEW` feeds is not consulted. `S_WRAP` wraps the channel key `K` as it does for any session, but **`K` is used for nothing**: no frame of an `Ask` channel is sealed under it, a query sealed under it is not accepted (§15.7 step 5, `a_query_sealed_under_the_channel_key_is_not_accepted`), and a frame of a data layout that names the channel id is dropped at the receiver before any key is tried (`kind`, [channel.md](channel.md) §12.1; `an_ask_channel_carries_no_emission_and_emit_refuses_it`). From the **same** X25519 agreement as the wrap the server also derives the asker's **pair** (§15.3) and holds it **before the session Data leaves**, so the asker may query the moment it holds the Data.
- **Made by the first ask.** An `Ask` channel exists when the first ask for it is admitted: `serve` pre-opens none, and an announce lists **no** `Ask` mode ([channel.md](channel.md) §9: a decoder refuses `ASK_MODE` 4 inside a `CHAN_ANNOUNCE`; the prefixes a device serves, `ANN_SERVES`, say that it answers queries). The device has to be a writer of the space (as any sender) but **need not serve anything**: a query for a path it serves nothing under is answered with a sealed `NotServed` (§15.5). The channel counts among the sender's 64 channels.
- **Carriers.** The session offers the carriers the ask lists, the stream dropped when the first hop toward the asker has none ([channel.md](channel.md) §3.3 step 9, §14.9). An `Ask` ask is never refused `NoStream`: the mode needs none. Whether an answer too large for a datagram may go on a stream is what this leaves: the pair records whether the asker's path offers one (§15.9).
- **The caps.** An `Ask` channel keeps **1,024 askers** (the other modes 256: a receiver holds no queue and no frames are sent to it, only a pair of about 200 octets with its replay window) and **32 devices of one person**; the node keeps **16,384 pairs** in all. Over a cap the sender answers a signed `TooMany` refusal (retry in 30 s) whose text says which cap, why and what to do (`ask again later, or ask a device that serves fewer askers`).
- **No re-key on renewal or lapse.** A channel of another mode re-keys when a receiver renews after 5 minutes and when a lease lapsed ([channel.md](channel.md) §3.6). An `Ask` channel **never does either**: a re-key makes every receiver ask again, and here nothing is sent under the key. It re-keys (the key epoch moves) only when a receiver is **dropped** (removal, revocation, the person left the audience) and when a sealed space's audience epoch moves. **A re-key drops the pairs of the receivers it dropped and no other:** a standing member's pair keeps the key epoch it was made at (its frames name it in their last header octet) and nothing she holds is re-keyed, so dropping it would only silence her (`a_standing_members_pair_survives_another_members_removal`).
- **Renewal is a new pair.** The asker renews like any session, at 75 % of the lifetime (1 h asked; the sender clamps it to 1 minute to 24 hours). The renewal is a new signed ask and a new session answer, hence a **new ephemeral key, a new pair id and a counter from 0**. The pair it replaces opens queries for **5 s more** (`RETIRED_GRACE`): the asker installs the new pair one round trip after the server made it, and the queries it sent meanwhile name the old one. A pending query keeps the pair it was sealed under, so its answer opens.
- **A pair lives its session's lifetime plus 5 s** on the server's monotonic clock: after that the server opens no query of it, and the maintenance pass drops it (§15.10).
- **The route is kept by `Keep`.** The asker's node `Keep`s the route every 10 s while it holds the session ([channel.md](channel.md) §14.5), so every hop has a sink for the asker's face (what an `ANSWER` goes down to) and a source toward the server (what a `QUERY` goes up to). The route ends 30 s after the last `Keep`.
- **Idle: 60 s** (`ASK_IDLE`). A session no query used for a minute is let go by the maintenance pass, with an `Unsub`, and its pair with it. A query's `Items` being dropped does **not** end the session (the release rule of [channel.md](channel.md) §3.4, "a channel is let go when the last `Items` is dropped", would defeat the reuse that is the point); `the_ask_session_survives_items_drop_and_is_released_after_60_s_idle`.
- **One ask at a time.** The asks of one node for one server's `Ask` channel are made one after the other: each gives a new pair and replaces the one the server holds, so two in flight could leave the asker with a pair the server already replaced.

### 15.3 The pair key

The server derives, **once per session answer**, one pair of keys for the asker device from the X25519 agreement it already makes for the key wrap ([channel.md](channel.md) §3.2), and the asker derives the same at install:

```
ephemeral   = a fresh X25519 key pair of the SERVER, made for this one session answer (its public half is the first 32 octets of S_WRAP)
recipient   = the asker's ASK_RECIPIENT (32 octets)
shared      = X25519(ephemeral secret, recipient)                    (all-zero: refused)
context     = Name TLV(space) ‖ Name TLV(asker device) ‖ Name TLV(server device) ‖ channel id (8, big-endian) ‖ key epoch (u32, big-endian)     (pair_context)
pair        = HKDF-SHA256(ikm = shared, no salt,
                          info = "ndn-channel/pair/1" ‖ ephemeral (32) ‖ recipient (32) ‖ length of context (u32, big-endian) ‖ context, L = 32)
Kq          = HKDF-Expand(pair, "ndn-channel/pair/q/1", 32)          seals the asker's queries
Ka          = HKDF-Expand(pair, "ndn-channel/pair/a/1", 32)          seals the server's answers
pair id     = HKDF-Expand(pair, "ndn-channel/pair/id/1", 8)          public by design: the server finds the pair a frame names in one lookup
```

The wrap's key-encryption key comes from the **same** `shared` under its own label (`ndn-security/confidentiality/x25519-kek/1` ‖ ephemeral ‖ recipient), so one scalar multiplication gives both and the labels keep them apart. The four labels differ from each other, from the wrap's and from the **signed path's** (`ndn-query/pair/*`, §7.2): one agreement cannot give a key of another use. The names are Name TLVs, so the context is canonical. The cipher is the session's `S_AEAD` (AES-256-GCM or ChaCha20-Poly1305), for both keys. The wrapped key opens only with the asker's recipient secret and only under the session Data's name (the AAD), and the Data is signed by the server's device, so an asker that holds the pair holds one the **signed session** carried; nothing else authenticates the ephemeral key.

- **Bound to** the space, both device names, the channel id, the key epoch (the full `u32`) and both X25519 public keys: a different value in any of them gives other keys (`the_pair_context_binds_each_of_its_fields_and_is_canonical`; `ndn-security`: `the_channel_pair_differs_per_asker_per_context_and_per_ask`, `the_channel_pair_is_not_the_signed_paths_nor_the_wrap_key`). A second ask is a second agreement: new keys and a new pair id.
- **What it proves.** A frame that opens under `Kq` was made by a holder of the pair: the asker device the session was wrapped to (whose signed ask named the recipient key) or the server. One that opens under `Ka`, by the server or the asker. It is **origin authentication between those two devices and no non-repudiation toward anyone else**: either holder could have made any frame. That is why `Ask::proof` is signed-path only (`QueryPath::Channel` with a proof is a `BadRequest`) and why an `Answered` of this path has `proof` `None`.
- **What it does not give.** The channel key `K`, which every asker of the channel holds, opens nothing here: a member cannot read or forge another member's queries (§15.12). There is **no forward secrecy toward the asker's recipient secret**: whoever later holds it, and recorded session Data and frames, derives the pair again. The server's ephemeral secret is made and dropped inside the one call that answers the session, so a later compromise of the server's keys opens no pair. There is no anonymity from the server.
- **No test fixes an ephemeral key**, so there is **no vector** of this derivation (§15.14). The tests of `ndn-security` assert that both ends derive the same keys, that another context, ephemeral, recipient or AAD gives other keys, that a low-order key is refused and that the channel pair is neither the signed path's nor the wrap key; the derivation above is stated from the code, not from a vector.

### 15.4 The two frames

Both are **side frames** ([channel.md](channel.md) §11, §14.13): not NDN packets, marker `0x00`, never fragmented or retransmitted. A forwarder reads only the prefix (the first 19 octets of a `QUERY`, the first 18 of an `ANSWER`) and routes by it; everything after is the pair's and sealed. The 20-octet header of a `DATA` frame ([channel.md](channel.md) §11.1) is **not** theirs: `Header::new` and `Header::decode` refuse kinds 5 and 6 (`QueryLayer`, counted `kind`) before any AEAD and before the replay window is touched, and the query layer decodes them with its own codec (`chan/qframe.rs`).

**`QUERY`** (kind 5), datagram only, first octet `0x25`:

| Octets | Field |
|---|---|
| 0 | `0x00`, the marker |
| 1 | `0x25`: `ver` 1, `class` 0, `kind` 5 |
| 2–9 | the **route id** = the channel id of the `Ask` session, big-endian |
| 10–17 | the **token**: 8 random octets, per query per server |
| 18 | the **ttl** in units of 100 ms: how long a relay keeps the breadcrumb |
| 19–26 | the **pair id** |
| 27–34 | `qseq`, big-endian: the asker's counter under the pair |
| 35 | the key epoch's **low octet** |
| 36… | the AEAD ciphertext of the plaintext (§15.5), then the 16-octet tag |

The **additional data** is octets 0 to 35, **all 36 header octets**. The key is `Kq`. The nonce is §15.6's. The frame is at least 52 octets of header and tag plus the plaintext (at least 10 octets), so at least 62; the server refuses one over 2,048 octets and the asker never sends one over 1,150 (§15.9).

**`ANSWER`** (kind 6), either class, first octet `0x26` on a datagram or `0x36` on a stream:

| Octets | Field |
|---|---|
| 0 | `0x00` |
| 1 | `0x26` (class 0) or `0x36` (class 1), `kind` 6 |
| 2–9 | the route id, as the query's |
| 10–17 | the token **of the query it answers** |
| 18 | the key epoch's low octet, as the query's |
| 19… | the AEAD ciphertext of the status (§15.5), then the 16-octet tag |

The additional data is octets 0 to 18, **all 19 header octets**: the class is in octet 1, so an answer moved to the other class opens nowhere. The key is `Ka`, the nonce is the **query's** (§15.6): the frame carries no counter, the asker takes it from its pending entry. The frame is at least 35 octets of header and tag plus the status, and **at least 46 octets in all** on every carrier ([channel.md](channel.md) §11.3): a status shorter than 11 octets is padded inside the seal (§15.5).

**The side PIT** ([channel.md](channel.md) §14.13). A `QUERY` goes **up** the route, from a sink to the source, and leaves at each hop a one-shot **breadcrumb** `(route id, token) → (ingress face, expiry)`; the `ANSWER` comes **down** the breadcrumbs, one hop at a time, to the **one face that asked**, and removes each. **Neither is ever fanned out to the other sinks of the route**: a query is the asker's and an answer is for that one asker. The forwarder opens, verifies and judges nothing of either. The token is drawn by the asker **from the operating system's CSPRNG, per query per server** (never a counter or a hash of anything observable: a relay cannot check this, so the asker MUST); a token in flight at a relay is a duplicate for every face. The ttl the asker writes is its remaining deadline in 100 ms, rounded up, from 1 to 100; a relay clamps what it reads to 100 ms to 10 s. A relay that cannot take a frame, or has no route or breadcrumb for it, drops it and counts it; **no Nack is built**.

**What a frame carries that a relay can read:** the route id, the token, the ttl, the pair id, `qseq`, the epoch octet and the lengths, and for an answer its class.

### 15.5 The plaintexts

Varints are the QUIC variable-length integer ([channel.md](channel.md) §11.4: the two high bits of the first octet give the length 1, 2, 4 or 8, the rest is the value, big-endian, at most 2^62 − 1; a writer uses the shortest form, a reader accepts a longer one).

**The plaintext of a `QUERY`:**

```
id (8 octets, big-endian) | deadline_ms (varint, 1 to 10,000) | path length (varint, at most 255) | path (the value of the Name: its components, each as a TLV) | query octets (the rest, at most 1,024)
```

`id` is **the asker's query id** (`Query::id` at the handler: the same to every server of one `get`; §1). It is inside the seal because a relay needs only the token. It is the asker's claim: any member may choose any id, so a handler keys its side effects on the id **and the asker**. `deadline_ms` is what the asker still waits, **relative**: the server counts it from the frame's arrival. A deadline of 0 or over 10,000, a path over 255 octets or that is no run of name components, and a plaintext cut inside a field are refused (`bad_plain`).

**The plaintext of an `ANSWER`** is a status octet and its fields; a plaintext shorter than **11 octets** is padded to 11 with the octet `0x80` and zero octets, so the frame is at least 46 octets:

| Octet | Status | Fields | Meaning |
|---|---|---|---|
| 0 | `Answered` | length (varint), the answer octets | the handler answered |
| 1 | `Refused` | `code` (2 octets, big-endian), text length (varint, at most 256), the UTF-8 text | the handler's own refusal: the application's word, an answer and not a failure |
| 2 | `Busy` | `retry_ms` (varint) | the server cannot take the query now (§15.9) |
| 3 | `NotServed` | none | no prefix of the path is served here |
| 4 | `TooLarge` | `max` (varint) | the answer does not fit what the path carries: at most `max` octets |

The status numbers are **0 to 4 here** and are not the signed path's `A_STATUS` (1 to 4, §6). The fields' length is explicit, so the padding is unambiguous: after the fields a reader accepts **nothing, or `0x80` followed only by zero octets**; any other octet is refused, as are a status above 4, a refusal text over 256 octets or that is no UTF-8, and a plaintext cut inside a field. A refusal text a handler gives that is longer than 256 octets is **cut** at a character boundary, not refused.

### 15.6 The nonce

Both directions use the 12-octet nonce **the key epoch's low octet, three zero octets, `qseq` (8 octets, big-endian)**. `qseq` is the asker's counter under one pair, strictly rising from 0 and **never reused**, and the answer **repeats the query's `qseq` under the other key**. So a nonce is used once under each key, provided that:

1. **The asker never repeats a `qseq` under a pair.** The counter takes each number **once** (an atomic increment), whatever becomes of the send: a query that was refused `Congested`, never sent or never answered keeps its number spent. A retry is a **new query** with a new number, and two servers are two pairs with two counters. At 2^62 the pair is used up: the asker lets the session go and asks again.
2. **The server answers a `qseq` at most once.** It marks the number in the pair's replay window **after the AEAD opened and before it does anything else**, so a copy of the frame, a concurrent copy and a retransmission are dropped, and every answer the server ever makes (the handler's, `Busy`, `NotServed`, `TooLarge`) is made **only for a query it opened and marked**. A frame that did not authenticate marks nothing and gets nothing, not even a `Busy`. Exactly **one** frame is sealed per marked query: a handler's answer that does not fit the path is replaced by the `TooLarge` that goes instead of it, never sent in addition.
3. **A pair is never re-derived.** Its keys come from an ephemeral key the server made for one session answer and dropped; a server that restarted, evicted the pair or let it lapse has no `Ka` to use again, and the asker's next ask gives new keys, a new pair id and a counter from 0. A re-key of the channel does not matter either (a standing member's pair is not re-derived). Two servers never share a pair.

**The contrast with the signed path** (§7.4). There the **asker's** ephemeral key outlives the server's cache: a restarted server derives the same `Ka` again from the asker's unchanged key, so it cannot keep a counter of its own and the answer uses the query's counter, whose uniqueness rests on the asker alone and, for replays, on the replay set and the floor (§8.3). Here the **server's** ephemeral key is as short-lived as the pair, so the server cannot derive a key again, and the replay window of the pair (below) is the whole of the replay argument; there is no floor and no quiet period.

**The replay window.** Each server pair holds a window of the last **4,096 counters** (a bitmap beside the highest `qseq` marked), like the frame window of [channel.md](channel.md) §12.2: a `qseq` already marked, or 4,096 or more below the highest, is dropped **before any AEAD**; one more than 2^24 above the highest is dropped before any AEAD too, so a forger cannot push the window past the asker's real counter with one frame. The mark is made only after the AEAD opened. Guards: `a_replayed_qseq_is_dropped_and_marked_only_after_the_aead`, `a_second_answer_is_never_made_for_one_qseq_busy_included` (every ANSWER sent is captured: no `(route, qseq)` repeats per pair, with the `Busy` and `NotServed` paths and 100 concurrent copies of one frame), `two_servers_and_a_rekey_never_reuse_a_nonce` (frames captured across a renewal, a re-ask, an eviction and a restart: no `(key, nonce)` pair repeats).

### 15.7 How the server judges a query

`NodeInner::query_frame` runs in the receive loop and is **synchronous up to the handler**: it never waits, and each step costs more than the one before it, so a stranger costs a lookup and a forgery one AEAD. Each drop is counted in `chan.pairs.stats` and **sends nothing**.

| Step | Check | Refusal | Counter |
|---|---|---|---|
| 1 | the frame is 52 to 2,048 octets and its 36-octet header parses (marker, `0x25`, prefix) | dropped | `malformed` |
| 2 | the pair id names a **live** pair of this node on the route id the frame names (its lease not ended; not retired more than 5 s ago) | dropped, **no AEAD** | `unknown_pair` |
| 3 | the epoch octet is the low octet of the pair's key epoch, and `qseq` is **fresh** in the pair's window (§15.6) | dropped, no AEAD, nothing marked | `unknown_pair` (the octet), `replayed` |
| 4 | the asker **still stands**: the pair holds the `(trust generation, fold version)` she was judged by, and two atomic loads say whether either moved; if so the space's pairs are judged again offline (`chan_rejudge`: the standing are restamped, the rest dropped) and the pair is looked up again | gone: dropped **before any AEAD** | `rejudged_out` |
| 5 | **one AEAD open** under `Kq`, additional data the 36 header octets | dropped, **nothing marked: a forged frame burns no counter** | `opens` (attempts), `bad_seal` |
| 6 | `qseq` is **marked** in the window | already marked (a copy that raced past step 3): dropped | `replayed` |
| 7 | the plaintext decodes (§15.5) and its query is at most 1,024 octets | dropped, no answer (logged at `debug`) | `bad_plain` |
| 8 | one token of the asker **person's rate on this path**: 256 a second, burst 256, all her devices together | over: a sealed `Busy` if one is due (§15.9), else dropped | `busy`, `busy_dropped` |
| 9 | the **longest served prefix** of the path (§3.1) | none: a sealed `NotServed` (no handler, no place taken) | `not_served` |
| 10 | a **place** for the handler: fewer than 64 running on the node, fewer than 8 for the person (the signed path's places, shared), and she has answer octets left (§8.4) | none: a sealed `Busy` as in step 8 | `busy`, `busy_dropped` |
| 11 | the handler runs in a task of its own under the asker's deadline (`deadline_ms` from this frame's arrival). The `Query` it is given has `id` the plaintext's id, `path`, `bytes`, `asker` the pair's owner (person and device as judged when the ask was, and again by step 4) and `via` `Sealed`. Its reply is mapped to a status, sealed under `Ka` with the **query's `qseq`** and the `ANSWER` header as the additional data, and sent (§15.9 says on which class) | `Pass` and a handler past the deadline: **nothing is sent**; a carrier that cannot take the frame: counted | `handlers`, `answers`, `silent`, `not_sent` |

- **The rate is charged after the AEAD, and that is deliberate.** The person is known only from the pair, and a rate charged before the open would let a forger who names her pair id drain her bucket; charged after, only her own frames spend it. The price is that a flood naming a valid pair id costs one AEAD per frame (§15.12).
- **The generation check is per query and per tick.** Step 4 makes a removal or a revocation take effect at the **next query** even if the maintenance pass has not run: `a_removed_asker_is_dropped_at_the_generation_move_before_open` (the `opens` counter does not move and the handler does not run). Every move of the space's fold (any entry written to it) makes the next query of each pair run one offline rejudge of the space's pairs, once per move; its cost is not measured.
- `Query::asker` is as judged when the query arrived; a handler that must be sure judges the asker itself (§3.1).
- A `Reply::Answer` over 65,536 octets becomes a sealed `TooLarge { 65536 }`; a `Refuse` becomes `Refused` with its text cut at 256 octets. The answer octets sent are charged to the person's budget after the frame leaves.

### 15.8 The asker

Per server asked, in this order (a failure at any step is that server's outcome, and the other servers of the query are unaffected):

1. **The server is a writer now** (else `NotWriter`) and a **pending slot** is free (64 on the node, 16 to this server: `TooManyOutstanding`), as on the signed path.
2. **The path.** `Signed`: the signed path. `Auto`: the channel **only if** `Ask::proof` is not set, the query is at most 1,024 octets and its frame (52 + 8 + at most 2 + the path's length octets and value + the query) at most 1,150 octets, a forwarder is attached, **and** this device holds a **usable** `Ask` session with that server with a pair (not past its lifetime and grace; judged by the same record: a session whose `(trust generation, fold version)` moved is judged again offline, and a sender that no longer stands as a writer ends it); otherwise signed. `Auto` **never creates a session**. `Channel`: no forwarder is `NotReady`; a usable session is used; with none the asker makes one (`chan_ask(.., Ask)`, **inside the query's deadline**: a deadline that passes during the setup is `silent`, a refusal is `NoSession { why }`, a session let go at once is `NotReady`); it **never falls back to signed**.
3. **The query.** The next `qseq` of the pair (§15.6); a **token** from the operating system's CSPRNG (a `(route, token)` already pending is drawn again, four tries, then `NotReady`); the header (§15.4) with the ttl and the pair's epoch octet; the plaintext (§15.5) with the `get`'s query id and the remaining deadline in ms (1 to 10,000); the seal under `Kq`. The **pending entry** `(route, token) → { a one-shot sender, the pair, qseq }` is registered **before the frame is sent** (an answer can come back at once). The frame goes as a datagram through the node's connection to its forwarder, without waiting: a full queue is `Congested`, a frame over what the connection carries is `TooLarge { max }`, a closed connection is `Unreachable`, anything else `NotReady`.
4. **The wait** is for the entry's resolution or the deadline; the deadline is `silent`.
5. **An `ANSWER` frame** (`query_answer_frame`, synchronous in the receive loop): a header that does not parse is dropped (`bad_frame`); the pending entry of `(route, token)` is **taken**, none being `unmatched` (a copy of an answer already taken, a late answer after the deadline, a stranger's: dropped); the epoch octet must be the pair's; the sealed part at least a tag; it is opened under **`Ka`** with the entry's pair, epoch octet and `qseq` and the 19 header octets as the additional data; the plaintext must decode as a status (§15.5). **Any failure of these resolves the entry as `BadAnswer`**, one outcome for that query (§15.12 says why the token's being in the clear makes this the rule). A success resolves it once and tells the pair its server holds it (`answered`, which clears its silence count).
6. **Who the server is.** `author.by` is the person of the key that signed the **session**, standing **now** as a writer (`Who::Writer`); a signer that is no writer now is `BadAnswer` ("it is not the server"). `author.writer` is the server's device. An `Answered` or a `Refused` marks the server **proven** for `Targets::Serving` (§11). The status becomes the outcome as on the signed path (§10.1 step 7):

| Status | Outcome |
|---|---|
| `Answered`, at most `answer_max` octets | an `Answered` item with `via: Sealed`, `proof` `None` |
| `Answered`, over `answer_max` | `QueryFailed { AnswerTooLarge }` |
| `Refused` | an `Answered` item with the `AppRefusal` and empty bytes, counted `refused` |
| `Busy` | `QueryFailed { Busy }` |
| `NotServed` | `QueryFailed { NotServed { path } }` |
| `TooLarge { max }` | `QueryFailed { TooLarge { max } }` |

7. **Silence.** A query nothing answered by its deadline is one **silent query of its pair**. **Three in a row** mean the server has forgotten the pair (a restart, an eviction, a lapsed lease, a removal, or a route lost on the way: nothing else tells the asker, §15.9), so the asker **lets the session go** (an `Unsub`) and drops its pair; the next `Channel` query asks again, which is also where a removed asker is **told why** (`NoSession`). An answer that opens resets the count. **Cancelling** a query (dropping the `Items`) is not silence.
8. **The pending entry is removed** by whatever ends the wait: the answer, the deadline, or the `Items` being dropped; the pair is never touched by it.

`asked = answered + refused + failed + silent` holds on this path as on the other (`asked_equals_answered_refused_failed_silent_on_the_channel_path`).

### 15.9 Limits and refusals

**Every drop at the server is silent, and the asker's remedy is the same.** The forwarder cannot sign or seal a refusal, and a server that answered a frame it could not authenticate would be an oracle and a reflector, so a `QUERY` that is dropped is answered with nothing, and so is one whose pair the server no longer holds. The asker sees silence until its deadline (the query's outcome is `silent`), and after three in a row it asks again for a session (§15.8 step 7); **ask again, and if the asker was removed, the setup says so** (`NoSession`, with the setup's reason and `NextStep`). What the server **does** say, sealed under `Ka` and only for a query it opened and marked, is below.

| What | Limit | Over it, and what to do |
|---|---|---|
| Handlers running | 64 on the node, 8 per asker person (all her devices; shared with the signed path) | a sealed `Busy`, told as `QueryFailed { Busy }` (`RetryLater`): try again later with a new `get` (the server's `retry_ms`, a fixed 1,000, is not passed on). No wait queue |
| Queries per second per asker person | 256, burst 256, on this path only | a sealed `Busy`, as above |
| Answer octets per second per asker person | 4 MiB, burst 4 MiB, charged after an answer is sent; a person in debt starts no handler | a sealed `Busy`, as above |
| `Busy` itself | at most **one a second per pair** (a refusal is a seal that costs the server): `retry_ms` is a fixed 1,000 | the others are dropped and counted `busy_dropped`: the asker sees silence for them |
| Query octets | 1,024 | `BadRequest` at `get` on `Channel`; `Auto` goes signed; a `QUERY` that opens over it is dropped `bad_plain` |
| `QUERY` frame | at most 1,150 octets from the asker; 52 to 2,048 accepted | `BadRequest` at `get` on `Channel` (the reason says to ask a shorter path or send less, or `Auto`); `malformed` |
| Answer octets | 65,536 | a sealed `TooLarge { 65536 }` |
| The `ANSWER` frame | a **datagram** if the sealed frame fits `Carrier::datagram_max_for(route)` (the smallest limit of the sinks' faces, none counted below 1,150); else a **stream** frame (class 1, `0x36`) if the pair's owner path offers a stream (the ask's carriers kept `stream`, §15.2) and the carrier has one and it fits its stream frame limit, the send bounded by the asker's deadline; else a sealed `TooLarge { max }` where `max` is the longest answer that fits (1,362 octets on a datagram carrier of 1,400) | the asker is told `TooLarge { max }` and `FixRequest`: send less, have the handler `put` and answer the path |
| `NotServed` | no served prefix of the path | a sealed `NotServed`; ask a server that serves it (`Targets::Serving`) |
| `Pass`, a handler past the deadline | | nothing is sent: silent |
| `answer_max` | 1 to 65,536 on `Channel` and `Auto` (default 4,096) | `BadRequest` at `get`; an answer over it is `AnswerTooLarge` (raise `answer_max`, or have the handler `put`) |
| A pair | 16,384 on the node, 1,024 askers per `Ask` channel, 32 devices per person | a signed `TooMany` refusal at the setup, retry in 30 s |

**Counters.** The server's (`chan.pairs.stats`): `queries`, `malformed`, `unknown_pair`, `replayed`, `rejudged_out`, `opens`, `bad_seal`, `bad_plain`, `not_served`, `busy`, `busy_dropped`, `handlers`, `answers`, `silent`, `not_sent`. The asker's: `sent`, `unmatched`, `bad_frame`, `bad_answers`, `answers`, `silent`, `congested`. A test reads them; the cost claims above are asserted through them.

### 15.10 What ends a pair, and what the asker does

| Event | Server | Asker |
|---|---|---|
| A receiver is **removed or revoked**, her person **leaves the audience**, or the trust generation moves so that she no longer stands | the pair is dropped **at once**: by the first query that finds the generation or the fold moved (step 4, before any AEAD), by the maintenance pass (every 250 ms and when woken), whichever comes first. The channel is re-keyed and every **other** pair stays (`removal_revocation_and_a_sealed_space_audience_move_drop_the_pair_at_once`) | silence; after three, `NoSession` on the next `Channel` query |
| A sealed space's **audience epoch moves** | the channel is re-keyed; pairs of people still in the audience stay, the others are dropped as above | as above |
| The **sender** is no writer any more, or the space is **closed** or no longer open as a member here | every pair of the space is dropped and the channels of it end (`chan_close_space`) | the session ends (`NotMember`) at the next query's or tick's judgement; the pair goes with it; `Auto` goes signed, `Channel` asks again and is refused |
| The **lease** lapses (the lifetime plus 5 s) without a renewal | no query opens after the lease even before the maintenance pass drops the pair (and the receiver, without a re-key) | the session lapses; its pair goes (`retain_sessions`) |
| A **new ask** of the same asker device (a renewal, a second first ask) | the old pair opens queries for 5 s and is then swept; the new one is the device's | the new pair replaces the old for new queries; pending queries keep theirs |
| The **table is full** (16,384) | a new pair is refused with a signed `TooMany`; nothing is evicted for it | the ask is refused, `NoSession` |
| **Restart** or loss of memory | every pair is forgotten (nothing is persisted) | three silent queries, then a new session (§15.13) |
| **Node stop** | `drop_all`: every pair | every session ends and every pair is dropped |
| **Idle 60 s**, three silent queries, the counter at 2^62 | | the session is let go with an `Unsub` and the pair dropped; the next `Channel` query asks again |

The asker's own pairs follow its sessions: a session that ended or lapsed takes its pair with it at the next maintenance pass, and a query already sent under it keeps a reference, so its answer still opens.

### 15.11 No answers family on this path

§4's five rules hold. **What is kept**: at the server, per pair, the keys, the owner (space, device, person, key), the window of counters (a bitmap of which counters were opened: **never an answer**), when she was judged, the lease and when a `Busy` may next be sent; per handler a place until it ends. At the asker, per pair the keys, the counter, the last use and the silence count; per query a **pending entry** that holds a one-shot sender and is **removed by its answer**. At a relay, a breadcrumb that its answer removes (§14.13). **What is never kept**: any answer, any status, any query's octets after the handler took them, anything keyed by what was asked. An `ANSWER` is a side frame and never a Data, so no store sees it.

- **One answer per (query, server)**: the marking of §15.6 makes a copy of a query a dropped frame, never a second answer; the asker takes the pending entry once, so a second `ANSWER` for a token is dropped; `Kind::Answered` is never an entry (§4 rule 2 applies unchanged).
- *Guards* (`query/chan_serve_tests.rs`, `query/chan_ask_tests.rs`): `no_state_survives_an_answer` (55 queries, some answered, some `NotServed`, some copies: afterwards the counts of pairs, handler places, channels, receivers and served prefixes are as before, a copy of an answered query gets nothing, and the person has all her places back), `a_second_answer_is_never_made_for_one_qseq_busy_included`, `an_answer_goes_to_the_one_asker_and_the_handler_runs_once`, `a_second_answer_for_a_token_is_dropped`, `dropping_items_cancels_the_pending_entries`, `asked_equals_answered_refused_failed_silent_on_the_channel_path`.

### 15.12 Threat notes

- **A stranger's frame** (a pair id this node does not hold) costs a size test, a header parse and one table lookup (`unknown_pair`): no AEAD (`a_query_from_an_unknown_pair_id_costs_no_aead`).
- **A flood naming a valid pair id.** The pair id is in the clear, so any hop that saw one frame of a pair can name it. A frame with a fresh in-window `qseq` costs the server **one AEAD open**, which fails (`bad_seal`) and **marks nothing**; a frame with a marked, old or far counter costs none (`replayed`). It spends nobody's rate and no handler place, because the rate is charged after authentication (§15.7). A frame only reaches the server if a relay sends it up a route, and the relays bound the sinks' `QUERY` rates ([channel.md](channel.md) §14.13). The cost of one AEAD open is not measured here.
- **A forged frame burns no counter.** The window marks after the AEAD opened, so a forgery with a genuine `qseq` cannot make the genuine query `replayed` (`a_replayed_qseq_is_dropped_and_marked_only_after_the_aead`; `a_flipped_octet_in_any_header_field_or_body_fails_the_aead` flips each of the 36 header octets and the body).
- **No reflection.** The server answers only a query it opened and marked, and sends the one answer into its own carrier; the forwarder's breadcrumb routes it to the one face that asked, hop by hop, and a frame names no address. One query makes one frame (a `Busy` at most once a second per pair) of at most 65,536 + a few octets, within the person's 4 MiB a second. A forger without `Kq` gets nothing, not even a Nack.
- **A relay can end a query with a garbage frame.** The token is in the clear, so a relay can send an `ANSWER` carrying it: the asker takes the entry, the frame does not open under `Ka`, and the query is `BadAnswer`; the genuine answer after it is `unmatched` (`an_answer_that_fails_the_aead_is_a_bad_answer_and_one_outcome`). A relay could as well drop the query or the answer: this adds nothing it could not do, and the asker's remedy is a new query. A relay **cannot** forge an answer (it has no `Ka`), change a frame (the route, token, ttl, pair id, `qseq`, epoch octet and, for an answer, the class are additional data), steer a frame to another asker (the breadcrumb is the forwarder's), or make a server answer twice.
- **A relay can hold a `QUERY` and deliver it late.** The server reads **no clock** for a query: there is no signed time, no replay floor, no quiet period. The deadline in the plaintext counts from the frame's arrival, so a handler may run once **after the asker gave up** (its pending entry gone, the answer `unmatched`). A copy is never run again, and a query 4,096 counters behind the pair's highest is `replayed`. A handler with side effects keys them on `Query::id` and `Query::asker` and may read `Query::remaining()`.
- **What a member can do.** She holds her own pair and the channel key `K`; `K` opens nothing here (`a_query_sealed_under_the_channel_key_is_not_accepted`), so she cannot read or forge another member's frames (`Kq` and `Ka` of her pair are not theirs), and what she does moves no other pair's counter. She can ask as fast as her person's 256 a second, hold 8 handlers, draw 4 MiB a second of answers, and hold up to 32 devices' pairs on one channel, each made by a signed ask (4 a second per key, one verification and one signature at the server each). She can seal a frame of a data layout naming the channel id: it is dropped at every asker (`kind`). She can choose any query id.
- **What a relay sees.** Of every frame: the route id, the token, the ttl, the pair id, `qseq`, the epoch octet, the exact length (a `QUERY` is 52 octets over its plaintext, an `ANSWER` 35 over its status, padded to at least 46: **there is no padding to hide a length**), and for an answer its class. It can tie a query to its answer by the token, and link all the queries of one pair by the pair id. The session Data it carried named the space, the sender and the mode in the clear ([channel.md](channel.md) §3.2), so a relay that saw it can tie the route id to them. It sees **not** the path, the query octets or the status (all sealed), **in a public space as well as a sealed one**: on the signed path a public space's query is in the clear (§12).
- **A removed asker is told by silence.** The signed path says `NotListed` (a Nack); this path cannot, so the asker sees silent queries and the setup, at its next `Channel` query, says why (§15.9).
- **Clocks.** Nothing on this path is decided by a wall clock. The monotonic clock bounds a pair's lease, the retired grace (5 s), the idle time (60 s), the deadline and the ttl.
- **Forward secrecy and non-repudiation:** §15.3.

### 15.13 Residuals

1. **A restarted server costs the asker three silent queries.** A server that restarted, evicted or lapsed a pair never answers it (§15.6 item 3, the price of never re-deriving a pair), and nothing tells the asker but silence: each of the three queries waits for its deadline (3 s by default) before the session is let go and the fourth asks again (`a_restarted_server_is_found_out_by_silence_and_the_fourth_query_works`). The same recovery serves a route lost at a relay. No message from the server says "unknown pair": it would answer a frame it could not authenticate.
2. **A garbage `ANSWER` ends a query** and a relay can drop any frame (§15.12). The asker's remedy is a new query.
3. **A `QUERY` held by a relay runs its handler late, once** (§15.12). Closing it needs a time the server can check, which a sealed, clockless frame does not carry.
4. **A fold move costs one offline rejudge of the space's pairs** at the next query (§15.7). A space with a writer that puts often moves the fold often; the cost, O(pairs of the space), is not measured.
5. **`Busy` is rationed** to one a second per pair and its `retry_ms` is a fixed 1,000 that the asker does not tell the application: the other limited queries of that second are silent, and a limited asker retries after its own choice of delay.
6. **The asker's `answer_max` is not told to the server**: an answer over it but within the server's limit is sent in full and refused at the asker (`AnswerTooLarge`), as on the signed path.
7. **Two first `Channel` queries to one server at once** each run the setup (one after the other); the second is a renewal that gives a new pair. The first query's frame, sealed under the first pair, still opens within the old pair's 5 s grace, and its answer opens under the pair its pending entry holds.
8. **No proof and no non-repudiation** (§15.3); **no forward secrecy toward the asker's recipient secret** (§15.3).
9. **It needs a forwarder** on both nodes and a route kept by `Keep` through every hop (§15.1, §15.2); a hop that lost the route drops the `QUERY` and the asker sees silence.
10. **Nothing is measured** of this path's speed or CPU cost (§15 introduction).
11. **The conformance suite's cases for this path are not built** (stage 5).

### 15.14 Test vectors

Hex, as `chan/qframe_tests.rs` asserts them (written by hand from this section, not by the codec under test; run once against the code for this revision: 12 passed). **There is no vector of the pair derivation or of a sealed frame** (§15.3: no test fixes an ephemeral key, and the ciphertext depends on it), so the octets below are the headers and the plaintexts, which a reader can rebuild by hand. Route id `0102030405060708`, token `1112131415161718`, pair id `a1a2a3a4a5a6a7a8`, `qseq` `0x0102`, key epoch low octet `07`, ttl 5 (500 ms).

`QUERY` header (36 octets, also the AAD):

```
00250102030405060708111213141516171805a1a2a3a4a5a6a7a8000000000000010207
```

Octet by octet: marker `00`, `25`; route `0102030405060708`; token `1112131415161718`; ttl `05`; pair id `a1a2a3a4a5a6a7a8`; `qseq` `0000000000000102`; epoch `07`.

`ANSWER` header (19 octets, also the AAD), on a datagram and on a stream:

```
datagram: 00260102030405060708111213141516171807
stream:   00360102030405060708111213141516171807
```

`QUERY` plaintexts, query id `0x1122334455667788` (octets `1122334455667788`): deadline 3000 ms (varint `4bb8`), path `/a/b` (value `080161080162`, 6 octets), query octets `6869` (`hi`); and the least plaintext (deadline 1 ms, the empty path, no octets):

```
11223344556677884bb8060801610801626869
11223344556677880100
```

A deadline of 0 (`1122334455667788 00 00`), of 10,001 ms (`1122334455667788 6711 00`), a path claiming 6 octets with 2 present, a path of components that run past their end (`1122334455667788 01 02 0805`) and a plaintext cut inside the id are **refused**.

`ANSWER` plaintexts (each padded to 11 octets by `80` and zero octets):

```
Answered "hi":                0002 6869 80 000000000000          = 0002686980000000000000
Refused 0x0102 "no":          01 0102 02 6e6f 80 00000000        = 010102026e6f8000000000
Busy, retry 1000 ms:          02 43e8 80 00000000000000          = 0243e88000000000000000
NotServed:                    03 80 000000000000000000           = 0380000000000000000000
TooLarge, max 4096:           04 5000 80 00000000000000          = 0450008000000000000000
```

An `Answered` of 100 octets begins `00 4064` (a length of 100 is a two-octet varint) and is not padded (103 octets); an `Answered` of 9 octets is exactly 11 octets, with no pad. A refusal text of 400 octets is cut at 256 (its length is the varint `4100`). A plaintext with a status of 5, an `Answered` whose length runs past the end, a pad whose octets after `80` are not all zero, octets after the fields that are no pad, a refusal text over 256 octets or that is no UTF-8, and an empty plaintext are **refused**.

### 15.15 The tests that guard the channel path

The channel path's **q-cases** (observable behaviours a suite checks against any implementation, as §14 does for the signed path) are **stage 5 and not built**. Until then these tests of `ndn-heap` and `ndn-security` guard it; they are this implementation's, and each names what it asserts.

**The frames and plaintexts** (`chan/qframe_tests.rs`): `a_query_header_is_these_36_octets`, `a_relay_reads_the_same_route_token_and_ttl_from_a_query`, `an_answer_header_is_these_19_octets_on_either_class`, `the_overheads_are_52_and_35`, `a_header_of_another_kind_or_too_short_is_refused`, `a_query_plaintext_is_id_deadline_path_length_path_and_query`, `an_empty_path_and_empty_query_are_fine_a_zero_or_huge_deadline_is_not`, `a_query_plaintext_that_is_cut_or_names_a_bad_path_is_refused`, `every_answer_status_has_these_octets_and_is_padded_to_a_46_octet_frame`, `a_long_enough_answer_is_not_padded`, `an_answer_that_is_cut_unknown_or_badly_padded_is_refused`, `a_refusal_text_is_cut_at_256_octets_not_refused`. The channel codec refuses kinds 5 and 6: `chan/frame.rs` `a_header_refuses_the_counts_and_sequences_no_frame_has` (`Header::new` and `Header::decode`), `chan/rx_tests.rs` `a_query_or_an_answer_is_refused_before_the_aead_and_burns_no_sequence`. That an announce lists no `Ask` mode is `Announce::decode`'s rule (`chan/wire.rs`); no test names it.

**The pair and the nonce** (`chan/pair_tests.rs`): `the_nonce_is_the_epochs_low_octet_three_zeros_and_the_counter`, `the_pair_context_binds_each_of_its_fields_and_is_canonical`, `a_query_opens_under_the_asker_key_an_answer_under_the_servers_and_not_the_other_way`, `a_flipped_octet_in_any_header_field_the_counter_the_epoch_or_the_body_fails_the_aead`, `both_aeads_seal_and_open_the_same_way`, `a_server_pair_marks_a_counter_once_and_checks_before_it_marks`, `a_busy_is_due_once_a_second`, `a_pair_is_found_by_its_id_on_its_own_channel_until_its_lease_ends`, `a_replaced_pair_opens_for_the_grace_and_not_after`, `dropping_a_device_or_a_space_takes_every_pair_of_it_at_once`, `a_rejudging_drops_the_askers_that_do_not_stand_and_restamps_the_rest`, `the_server_table_is_bounded_and_refuses_when_full_of_live_pairs`, `a_pair_says_it_moved_when_the_trust_generation_or_the_fold_did`, `an_askers_counter_takes_each_number_once_even_across_threads`, `an_askers_counter_is_used_up_at_the_limit_and_never_wraps`, `three_silent_queries_in_a_row_say_the_server_forgot_the_pair_and_an_answer_resets_it`, `the_asker_keeps_a_pair_per_session_and_lets_idle_and_vanished_ones_go`. The derivation (`ndn-security`, `confidentiality.rs`): `the_channel_pair_is_the_same_on_both_ends_and_the_key_still_opens`, `the_channel_pair_differs_per_asker_per_context_and_per_ask`, `the_channel_pair_is_not_the_signed_paths_nor_the_wrap_key`, `a_low_order_ephemeral_or_recipient_is_refused_for_the_channel_pair_too`, `a_wrong_aad_opens_no_key_and_so_no_pair`.

**The server** (`query/chan_serve_tests.rs`): `a_query_from_an_unknown_pair_id_costs_no_aead`, `a_flipped_octet_in_any_header_field_or_body_fails_the_aead`, `a_query_sealed_under_the_channel_key_is_not_accepted`, `a_replayed_qseq_is_dropped_and_marked_only_after_the_aead`, `a_removed_asker_is_dropped_at_the_generation_move_before_open`, `removal_revocation_and_a_sealed_space_audience_move_drop_the_pair_at_once`, `a_standing_members_pair_survives_another_members_removal`, `a_second_answer_is_never_made_for_one_qseq_busy_included`, `two_servers_and_a_rekey_never_reuse_a_nonce`, `the_handler_sees_the_askers_query_id_not_the_token`, `an_answer_goes_to_the_one_asker_and_the_handler_runs_once`, `the_handler_limits_per_person_and_in_all_answer_busy_once_a_second_per_pair`, `the_rate_per_person_is_256_a_second`, `not_served_and_too_large_are_sealed_statuses`, `a_pass_and_a_late_handler_send_nothing`, `no_state_survives_an_answer`, `an_ask_channel_carries_no_emission_and_emit_refuses_it`, `a_stream_less_hop_limits_the_answer_to_a_datagram`, `a_large_answer_goes_on_the_stream_class`.

**The asker** (`query/chan_ask_tests.rs`): `auto_uses_a_warm_session_and_else_signed_and_via_says_which`, `auto_never_creates_a_session`, `channel_with_a_refused_setup_never_falls_back_to_signed`, `channel_creates_the_session_with_one_signed_ask`, `the_second_query_in_a_session_costs_no_signature`, `the_ask_session_survives_items_drop_and_is_released_after_60_s_idle`, `a_public_space_channel_query_is_sealed_to_the_pair`, `a_sealed_space_channel_query_round_trips`, `an_answer_for_a_token_not_pending_is_dropped`, `a_second_answer_for_a_token_is_dropped`, `an_answer_that_fails_the_aead_is_a_bad_answer_and_one_outcome`, `three_silent_queries_let_the_session_go_and_the_next_asks_again`, `an_answer_in_time_clears_the_silence`, `dropping_items_cancels_the_pending_entries`, `a_node_with_no_forwarder_says_so_and_auto_goes_signed`, `a_query_over_1024_octets_is_refused_on_channel_and_goes_signed_on_auto`, `channel_with_proof_is_refused_and_auto_with_proof_goes_signed`, `the_limits_of_answer_max_follow_the_path`, `an_answer_over_answer_max_is_answer_too_large`, `each_status_is_the_outcome_the_signed_path_gives`, `asked_equals_answered_refused_failed_silent_on_the_channel_path`, `two_servers_answer_with_different_pairs_and_tokens`, `the_handler_is_given_the_query_id_of_the_get_on_the_channel_path`; against a real server: `a_warm_session_carries_many_queries_to_a_real_server_with_no_signature`, `a_restarted_server_is_found_out_by_silence_and_the_fourth_query_works`, `two_real_servers_answer_one_query_each_over_their_own_pairs`, `a_refusal_a_not_served_path_and_a_pass_on_a_real_server`. And `query/ask_tests.rs`: `get_with_ask_refuses_each_bad_request_with_its_reason`.
