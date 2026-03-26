# Packet Types and PacketContext

## Name

```rust
pub struct Name {
    components: SmallVec<[NameComponent; 8]>,
}

pub struct NameComponent {
    typ:   u64,    // distinguishes generic, versioned, sequence-number, implicit-digest
    value: Bytes,  // zero-copy slice of original receive buffer
}
```

`SmallVec<[NameComponent; 8]>` keeps names with ≤8 components on the stack during decode before moving into `Arc<Name>`. The `Bytes` in each component slices into the original receive buffer — no component value is copied.

`Name` is always shared as `Arc<Name>` so PIT keys, FIB lookups, CS keys, and strategy contexts all refer to the same allocation without copying.

`NameComponent` hashing must match on both `typ` AND `value` — two components are equal only if their TLV type and byte value both match.

## Interest

```rust
pub struct Interest {
    raw:       Bytes,
    name:      Arc<Name>,                  // always decoded (FIB/PIT/CS need it)
    nonce:     OnceLock<Option<u32>>,
    lifetime:  OnceLock<Option<Duration>>,
    selectors: OnceLock<Selector>,         // CanBePrefix, MustBeFresh, etc.
}
```

`OnceLock` fields are lazily decoded — the first caller pays the decode cost; subsequent callers read the cached value. Fields that no stage reaches on a CS hit are never decoded.

## Data

```rust
pub struct Data {
    raw:              Bytes,
    name:             Arc<Name>,
    content:          Bytes,        // zero-copy slice of raw
    sig_info:         SignatureInfo,
    sig_value:        Bytes,        // zero-copy slice of raw
    // offsets into raw for verification:
    signed_start:     usize,
    signed_end:       usize,
    sig_value_start:  usize,
    sig_value_end:    usize,
}

impl Data {
    pub fn signed_region(&self) -> &[u8] {
        &self.raw[self.signed_start..self.signed_end]
    }
    pub fn sig_value(&self) -> &[u8] {
        &self.raw[self.sig_value_start..self.sig_value_end]
    }
}
```

The signed region (Name + MetaInfo + Content + SignatureInfo) is **contiguous** in the NDN wire encoding. Verification takes a `&[u8]` slice directly into the receive buffer — no intermediate allocation.

## PacketContext

`PacketContext` is passed **by value** through pipeline stages. `Action::Continue` returns the context back; short-circuit actions (`Satisfy`, `Drop`, `Nack`) consume it. This makes the pipeline ordering enforced at compile time — no stage can use a context after it has been consumed.

```rust
pub struct PacketContext {
    pub raw_bytes:  Bytes,
    pub face_id:    FaceId,
    pub name:       Option<Arc<Name>>,     // None until TlvDecodeStage
    pub packet:     DecodedPacket,
    pub pit_token:  Option<PitToken>,      // None until PitCheckStage
    pub out_faces:  SmallVec<[FaceId; 4]>, // populated by StrategyStage
    pub cs_hit:     bool,
    pub verified:   bool,
    pub arrival:    u64,                   // ns since Unix epoch, taken at face recv
    pub tags:       AnyMap,
}

pub enum DecodedPacket {
    Raw,                // before TlvDecodeStage
    Interest(Interest),
    Data(Data),
    Nack(Nack),
}
```

### Field Notes

**`name` at top-level**: Every stage touches the name — FIB lookup, PIT lookup, CS lookup. Hoisting it out of `DecodedPacket` means stages clone the `Arc` cheaply rather than pattern-matching into the enum every time.

**`DecodedPacket::Raw`**: Stages before decode (face check, rate limiting) operate on `Raw` and pass it through. A pure relay stage that moves packets between faces never pays the decode cost.

**`out_faces: SmallVec<[FaceId; 4]>`**: FIB lookup returns 1–2 faces in practice. `SmallVec` with inline capacity 4 keeps this on the stack for the common case. `FaceId` is a `u32` newtype — 32 bytes inline total.

**`pit_token: Option<PitToken>`**: Starts as `None`; the PIT stage writes it. A `debug_assert!` in the dispatch stage catches ordering violations in debug builds.

**`arrival: u64`**: Timestamp taken at face `recv()`, before the pipeline channel enqueue. Interest lifetime accounting starts when the packet arrives at the face, not when the pipeline processes it. `u64` ns rather than `Instant` because `Instant` is not `Send` on all platforms and cannot be serialized for pipeline traces.

**`tags: AnyMap`**: Via `HashMap<TypeId, Box<dyn Any + Send>>`. For fields stages need to communicate without coupling — congestion marks, resolved trust anchors, instrumentation timestamps. **Not** for anything the core forwarding logic depends on; those get explicit fields.

## AnyMap

```rust
pub struct AnyMap(HashMap<TypeId, Box<dyn Any + Send>>);

impl AnyMap {
    pub fn insert<T: Any + Send>(&mut self, val: T) { ... }
    pub fn get<T: Any + Send>(&self) -> Option<&T> { ... }
}
```

Rule of thumb: if removing a tag would break forwarding, make it an explicit field. If it enriches the packet for downstream consumers or researchers, it belongs in `tags`.
