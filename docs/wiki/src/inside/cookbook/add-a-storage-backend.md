# Add a storage backend

"Storage" in ndn-rs is two distinct layers, and adding a backend means picking
the right one:

| Layer | Trait | Crate | What it is |
|---|---|---|---|
| **Content Store** | `ContentStore` | `ndn-store` | The forwarder's cache table: name → wire Data, freshness, admission, capacity |
| **KV engine** | `Backend` / `SyncBackend` | `ndn-storage` | A domain-agnostic ordered byte key→value store the repo/persistent tiers build on |

A `ContentStore` is a forwarding table (one of the three in
[the pipeline](../architecture/forwarding-pipeline.md)). A `Backend` is Layer 0
of the storage stack — no NDN names, just ordered bytes — reused by every data
model (the named CS/Repo store, content-addressed blob stores, embedded flash).
Choose the layer, then follow the matching recipe.

## Recipe A — a Content Store

`ContentStore` (`ndn-store/src/content_store.rs`) is `async` so a disk-backed
store is supported; in-memory ones complete synchronously. Only four methods are
required — the rest are defaulted:

```rust,ignore
use bytes::Bytes;
use std::sync::Arc;
use ndn_packet::{Interest, Name};
use ndn_store::{ContentStore, CsCapacity, CsEntry, CsMeta, InsertResult};

pub struct MyCs { /* ... */ }

impl ContentStore for MyCs {
    async fn get(&self, interest: &Interest) -> Option<CsEntry> {
        // Match by name; honour MustBeFresh, CanBePrefix, and a trailing
        // ImplicitSha256DigestComponent. Return None on a miss.
        todo!()
    }

    async fn insert(&self, data: Bytes, name: Arc<Name>, meta: CsMeta) -> InsertResult {
        // Store the *wire bytes* verbatim. Callers supply well-formed, signed
        // Data — the CS does NOT re-verify signatures.
        todo!()
    }

    async fn evict(&self, name: &Name) -> bool { todo!() }

    fn capacity(&self) -> CsCapacity { CsCapacity::bytes(0) }
}
```

Key contracts:

- **Store wire bytes, not decoded packets.** `CsEntry { data: Bytes, stale_at:
  u64, name: Arc<Name> }` holds the encoded Data so a cache hit re-emits the
  original bytes with no re-encoding. `CsEntry::is_fresh(now_ns)` implements the
  freshness predicate; `CsMeta::stale_at` is the nanosecond deadline derived from
  the Data's `FreshnessPeriod`.
- **`insert` returns `InsertResult`** — `Inserted`, `Replaced`, or `Skipped`.
- **The CS does not verify signatures.** Validation happens earlier on the return
  path (see the pipeline). A CS that re-verifies would double-pay.
- The defaulted admin methods matter for NFD parity: `admit_enabled` /
  `serve_enabled` back the `cs/config` Admit/Serve toggles (when serving is off,
  `get` returns `None`; when admission is off, `insert` is a no-op), and
  `variant_name` / `stats` back `cs/info`. Copy the real handling from `LruCs`.
- `ErasedContentStore` (the object-safe, boxed-future view) is auto-implemented
  for any `ContentStore` via a blanket impl — you get `Arc<dyn
  ErasedContentStore>` for free.

The smallest real implementor to copy is `NullCs` (same file); the production
one is `LruCs` (`ndn-store/src/lru_cs.rs`), a byte-bounded LRU with a name-trie
prefix index for `CanBePrefix`.

**The admission-policy hook.** Whether a Data packet is *worth* caching is a
separate decision from *how* to cache it, expressed by `CsAdmissionPolicy`:

```rust,ignore
pub trait CsAdmissionPolicy: Send + Sync + 'static {
    fn should_admit(&self, data: &ndn_packet::Data) -> bool;
}
```

`DefaultAdmissionPolicy` admits only Data with a positive `FreshnessPeriod` —
matching NFD, because caching `FreshnessPeriod=0` Data churns evictions without
ever satisfying a `MustBeFresh` Interest. `AdmitAllPolicy` admits everything.

**Register it** with the engine:

```rust,ignore
use std::sync::Arc;
use ndn_engine::EngineBuilder;

let engine = EngineBuilder::new(Default::default())
    .content_store(Arc::new(MyCs { /* ... */ }))
    .build().await?;
```

Built-in stores: `LruCs` (in-memory LRU), `ShardedCs<C>` (wraps another
`ContentStore`, sharding by name hash for concurrency), `FjallCs` (`fjall`
feature, on-disk), `SqliteCs` (`sqlite-cs` feature, the Android persistent
backend), and `NullCs`.

## Recipe B — a KV engine (`Backend` / `SyncBackend`)

`ndn-storage` is the pluggable ordered-byte engine (`ndn-storage/src/lib.rs`).
Keys sort lexicographically, so a parent byte-prefix precedes its descendants —
which is what makes prefix scans the primitive for `CanBePrefix` lookups and
"last-N under a name". There are two facets:

- `Backend` — **async**, object-safe (`Arc<dyn Backend>` via `async_trait`):
  `get` / `put` / `delete` / `scan_prefix` / `first_under` / `write_batch` /
  `name`.
- `SyncBackend` — the **synchronous** core, `no_std + alloc`, with borrowed
  `&[u8]` keys. Blocking engines implement this directly.

**The idiom for a blocking engine:** implement `SyncBackend` with direct calls,
then make the async `Backend` a thin `spawn_blocking` wrapper over it — one
source of truth, two surfaces. `FjallBackend` and `RedbBackend` are the worked
examples; here is the shape from `FjallBackend`:

```rust,ignore
impl SyncBackend for MyEngine {
    fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> { /* blocking */ }
    // put / delete / scan_prefix / write_batch ...
}

#[async_trait]
impl Backend for MyEngine {
    async fn get(&self, key: Vec<u8>) -> StorageResult<Option<Bytes>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || SyncBackend::get(&this, &key))
            .await.map_err(StorageError::backend)?
    }
    // ...
}
```

Notes:

- **A genuine miss is `Ok(None)`; only a real fault is `Err`.** Do not collapse
  an engine error into "miss" — `StorageError` surfaces it.
- **`write_batch` should be atomic** where the engine supports a transaction; the
  default applies ops sequentially (not atomic), so override it.
- A non-blocking sync engine (in-memory, embedded flash) needs no async impl at
  all: `SyncAsAsync` bridges any `SyncBackend` into `Backend` inline. Wrap any
  `Backend` in `Instrumented` for per-op `tracing` spans.

Built-in engines: `MemoryBackend` (async, in-memory), `SyncMemoryBackend`
(`sync` feature, `no_std` in-memory floor), `FjallBackend` (`fjall`, LSM),
`RedbBackend` (`redb`, ACID B-tree), and `FlashLogBackend` (`flash`, over
`embedded-storage::NorFlash`). To expose a KV engine as a name→wire store, wrap
it in `NamedStore<B>` — `name_key(name)` encodes an NDN `Name` to a storage key
whose byte-prefix ordering matches NDN component order.

## Testing

Both traits are exercised the same way: assert a `get` after an `insert`/`put`, a
prefix scan, eviction, and the freshness/admission predicates. The store
benches (`ndn-store/benches/{lru,sharded,fjall}.rs`) and the storage tests are
the models. Run with `cargo nextest run -p ndn-store -p ndn-storage` (see
[the testing guide](../testing.md)). An embedded `SyncBackend` must also compile
under `--no-default-features --features sync` for the `no_std` target.

## See also

- [The forwarding pipeline](../architecture/forwarding-pipeline.md) — the CS as one of the three tables.
- [The crate graph](../architecture/crate-graph.md) — where `ndn-store` and `ndn-storage` sit.
