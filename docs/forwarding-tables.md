# Forwarding Tables: FIB, PIT, and Content Store

## FIB — Name Trie

```rust
pub struct Fib(NameTrie<Arc<FibEntry>>);

pub struct FibEntry {
    pub nexthops: Vec<FibNexthop>,
}

pub struct FibNexthop {
    pub face_id: FaceId,
    pub cost:    u32,
}
```

### Trie Structure

Each trie node uses `HashMap<NameComponent, Arc<RwLock<TrieNode<V>>>>`. The `Arc` lets you hold a reference to a child while releasing the parent lock — essential for concurrent longest-prefix match.

```rust
fn lpm(&self, name: &Name) -> Option<Arc<FibEntry>> {
    let mut node = self.root.read();
    let mut best = node.entry.clone();
    for component in name.components() {
        match node.children.get(component) {
            None => break,
            Some(child) => {
                let child_guard = child.read();
                if child_guard.entry.is_some() { best = child_guard.entry.clone(); }
                // release parent lock, hold child lock only
                drop(node);
                node = child_guard;
            }
        }
    }
    best
}
```

Every `TrieNode` along a matching path can optionally hold a `FibEntry` — not just leaves. LPM walks to the deepest matching node and returns the last `FibEntry` seen on the way down.

**`RwLock` per node**: FIB updates (prefix registration) are rare compared to lookups. Many Tokio tasks can read-lock concurrently without blocking each other.

**`StrategyTable`** is a second `NameTrie<Arc<dyn Strategy>>` — same structure, mapping name prefixes to strategies. The FIB and strategy lookups share the same `Name` decomposition.

## PIT — Pending Interest Table

```rust
pub struct Pit(DashMap<PitToken, PitEntry>);

pub struct PitEntry {
    pub name:        Arc<Name>,
    pub selector:    Option<Selector>,
    pub in_records:  Vec<InRecord>,
    pub out_records: Vec<OutRecord>,
    pub nonces_seen: SmallVec<[u32; 4]>,
    pub expiry:      u64,
}

pub struct InRecord  { pub face_id: FaceId, pub nonce: u32, pub expiry: u64 }
pub struct OutRecord { pub face_id: FaceId, pub last_nonce: u32, pub expiry: u64 }
```

`DashMap` gives sharded concurrent access — no global lock on the hot path.

**PIT key**: `(Name, Option<Selector>)`. Two Interests for the same name but different `MustBeFresh` or `CanBePrefix` values are distinct PIT entries in NDN semantics.

**`InRecord` / `OutRecord`**: From the NDN spec. Each incoming face gets an `InRecord` with its nonce and expiry. Each face the Interest was forwarded on gets an `OutRecord`. Data fans back to all `InRecord` faces. A Nack on an `OutRecord` face may trigger re-forwarding on another FIB face.

**`nonces_seen: SmallVec<[u32; 4]>`**: Loop suppression. Four slots covers the vast majority of real topologies inline without heap allocation.

### `PitToken`

```rust
pub struct PitToken(u64);

impl PitToken {
    pub fn from_interest(name: &Name, selector: Option<&Selector>) -> Self {
        let mut h = FxHasher::default();
        name.hash(&mut h);
        selector.hash(&mut h);
        PitToken(h.finish())
    }
}
```

`FxHasher` rather than `SipHash` — PIT tokens are not user-controlled inputs, no DoS-resistant hashing needed. `u64` hash is safe to copy across tasks and `await` points. Collision probability at realistic PIT sizes (tens of thousands of entries) is negligible.

### Expiry

The PIT expiry background task runs every 1 ms and calls `pit.drain_expired(now_ns())`. This is more scalable than one `tokio::sleep` per entry — at 100k concurrent Interests, 100k timer futures would be too expensive. A hierarchical timing wheel or simple 1 ms drain loop handles the common case.

**Strategy state sidecar**: Per-Interest strategy state lives in a separate `DashMap<PitToken, StrategyState>` rather than inside `PitEntry`. Keeps the PIT a plain data structure; the strategy system manages its own scratch space.

## Content Store

### `ContentStore` Trait

```rust
pub trait ContentStore: Send + Sync + 'static {
    async fn get(&self, interest: &Interest) -> Option<CsEntry>;
    async fn insert(&self, data: &Data) -> InsertResult;
    async fn evict(&self, name: &Name) -> bool;
    fn capacity(&self) -> CsCapacity;
}

pub struct CsEntry {
    pub data:     Bytes,    // wire-format — CS hit → direct face.send(), no re-encoding
    pub stale_at: u64,      // FreshnessPeriod decoded once at insert time
}
```

### `NullCs`

```rust
pub struct NullCs;
impl ContentStore for NullCs {
    async fn get(&self, _: &Interest) -> Option<CsEntry> { None }
    async fn insert(&self, _: &Data) -> InsertResult { InsertResult::Skipped }
    async fn evict(&self, _: &Name) -> bool { false }
    fn capacity(&self) -> CsCapacity { CsCapacity::zero() }
}
```

Routers pushing caching to the application layer configure `NullCs` and pay nothing on the pipeline hot path.

### `LruCs`

Wraps `lru::LruCache` in a `Mutex`. Capacity bounded by **bytes** not entry count — NDN Data ranges from ~100 to 8800 bytes, so entry-count bounding leads to very uneven memory use.

Maintains a running `current_bytes: usize` and evicts LRU entries until `current_bytes <= capacity_bytes` after each insert.

**Freshness**: Passive check on `get()` — compare `stale_at` against current time. Stale entries remain for consumers that don't set `MustBeFresh`, getting evicted naturally by LRU pressure.

### `ShardedCs<C>`

Reduces lock contention by sharding any `ContentStore` implementation across N instances:

```rust
pub struct ShardedCs<C: ContentStore> {
    shards:      Vec<C>,
    shard_count: usize,
}
```

Shard by **first name component** (not full name hash) — related content (`/video/seg/1`, `/video/seg/2`) lands in the same shard, preserving locality for sequential access.

### `PersistentCs` (RocksDB or redb)

For warm cache across restarts. Key layout:

```
key:   [name TLV bytes]   // lexicographic order == name order
value: [wire Data bytes]
```

Storing name TLV bytes as the key enables range scans for prefix matching — `CanBePrefix` lookups become a RocksDB range scan from `/prefix/\x00` to `/prefix/\xFF`.

**redb** (pure Rust, MVCC, small footprint) is the better fit for a Rust-first stack unless you need RocksDB's compaction tuning for very large caches.

### Lookup Semantics

`get()` must honour three Interest selectors:

- **`CanBePrefix=true`**: Any cached Data whose name has the Interest name as a prefix is valid. Requires a name trie over CS entries for efficient prefix lookup. For exact-match (`CanBePrefix=false`) maintain a `HashMap` for O(1) lookup. Inserts go into both; evictions remove from both.
- **`MustBeFresh`**: Compare current time against `stale_at` on the returned entry.
- **Implicit SHA256 digest**: Exact byte match required.
