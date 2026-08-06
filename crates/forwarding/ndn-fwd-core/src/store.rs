//! Storage abstraction for the sans-IO pipeline.
//!
//! The forwarding decisions in [`crate::pipeline`] need to *query* the
//! forwarding tables — longest-prefix-match against the FIB, loop detection
//! against the PIT — without knowing how those tables are stored. These traits
//! are that seam: the native engine implements them over its `DashMap`/trie
//! tables, the constrained forwarder over its `heapless` tables, and the core
//! orchestrates lookups against the trait surface alone.
//!
//! **PIT-key resolution.** A shared insert/satisfy needs a key both backends
//! accept. The decision: the key is the name's **component byte-slices**
//! (`&[&[u8]]`) — the same representation [`FibStore::lpm`] already takes — and
//! each impl derives its own internal key from them (the constrained PIT an FNV
//! hash, the native PIT a `Name`). This keeps `ndn-fwd-core` dependency-free
//! (no `ndn-packet`), and because `record_pending` and `satisfy` are handed the
//! same slice sequence for a given name, their keys agree by construction. See
//! `.claude/notes/embedded-ndn-modular-build-2026-05-22.md` § 5e.

/// FIB query surface: longest-prefix-match.
pub trait FibStore {
    /// The forwarder's face identifier (`u8` on constrained nodes, a wider id
    /// on the native engine).
    type Face: Copy + PartialEq;

    /// Longest-prefix-match nexthop for a name given as its per-component TLV
    /// value bytes. `None` when no prefix matches.
    fn lpm(&self, components: &[&[u8]]) -> Option<Self::Face>;
}

/// PIT query + mutation surface. All entry-keyed methods take the name's
/// component byte-slices; the impl derives its own internal key (see the
/// module-level PIT-key resolution).
pub trait PitStore {
    /// The forwarder's face identifier.
    type Face: Copy + PartialEq;

    /// Whether this nonce has already been seen — a forwarding loop. A nonce of
    /// 0 means "absent" and is never a duplicate; callers pass the decoded
    /// nonce and the decision applies that rule.
    fn has_nonce(&self, nonce: u32) -> bool;

    /// Record a pending Interest keyed by `components`. `created_ms` /
    /// `lifetime_ms` are supplied by the caller so the core stays clock-free.
    fn record_pending(
        &mut self,
        components: &[&[u8]],
        incoming_face: Self::Face,
        nonce: u32,
        lifetime_ms: u32,
        created_ms: u32,
    );

    /// Satisfy pending Interest(s) for a Data whose name is `components`:
    /// invoke `send_to` once per recorded downstream face, then drop the entry.
    /// Returns whether anything matched. Keyed identically to `record_pending`.
    fn satisfy(&mut self, components: &[&[u8]], send_to: impl FnMut(Self::Face)) -> bool;

    /// Drop any pending Interest for `components` without satisfying it (e.g. on
    /// a Nack). Returns whether an entry was removed.
    fn discard_pending(&mut self, components: &[&[u8]]) -> bool;
}

/// Content Store surface, keyed (like the PIT) by name component byte-slices.
pub trait CsStore {
    /// Fresh cached Data wire for `components` at `now_ms`, or `None` on a miss
    /// or a stale entry.
    fn lookup(&self, components: &[&[u8]], now_ms: u32) -> Option<&[u8]>;

    /// Admit a Data's wire bytes to the cache. `freshness_ms` is the Data's
    /// FreshnessPeriod (0 = immediately stale); `now_ms` stamps the insert.
    fn admit(&mut self, components: &[&[u8]], wire: &[u8], freshness_ms: u32, now_ms: u32);

    /// Number of entries currently cached (for status introspection). Defaults
    /// to 0 — a real store overrides it; [`NoCs`] keeps the default.
    fn len(&self) -> usize {
        0
    }

    /// Whether the cache is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A [`CsStore`] that caches nothing — the default for forwarders built without
/// a Content Store (the constrained no-`cs` floor, or any minimal build).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoCs;

impl CsStore for NoCs {
    fn lookup(&self, _components: &[&[u8]], _now_ms: u32) -> Option<&[u8]> {
        None
    }
    fn admit(&mut self, _components: &[&[u8]], _wire: &[u8], _freshness_ms: u32, _now_ms: u32) {}
}

// ── Name-table observation (ndn-ext #92: Tier-1 BF-PIT / BF-CS) ─────────────────────────────────

/// **Observe PIT and CS mutations**, so a downstream name filter can mirror the forwarder's tables.
///
/// A pre-parse name filter (`ndn-ext`'s Tier-1: BF-PIT / BF-CS) is only correct while its tables
/// agree with the forwarder's. If they drift, the failure is not lost efficiency — a stale BF-PIT
/// **drops Data the node is waiting for**, which looks like packet loss and a retransmission, not
/// like a bug. So the mirror has to be fed from the same events that mutate the real tables, and
/// this trait is that seam.
///
/// It lives here rather than in the filter's crate because `ndn-ext` depends on `ndn-rs`, so the
/// dependency can only point one way. The forwarding core defines the events; whoever cares
/// implements them.
///
/// **Ordering contract, and it is not optional.** Insertions must become visible to the filter
/// *before* the traffic they authorise can arrive — a recorded PIT entry can be answered
/// microseconds later. Removals may lag safely, since an over-large filter only over-accepts.
/// Implementations must therefore publish on insert and may batch on remove.
pub trait NameTableObserver {
    /// A pending Interest was recorded.
    fn on_pit_insert(&self, components: &[&[u8]]);
    /// A pending Interest was satisfied or discarded.
    fn on_pit_remove(&self, components: &[&[u8]]);
    /// Data was admitted to the Content Store.
    fn on_cs_admit(&self, components: &[&[u8]]);
}

/// A no-op observer, so wrapping is free when no filter is attached.
impl NameTableObserver for () {
    fn on_pit_insert(&self, _: &[&[u8]]) {}
    fn on_pit_remove(&self, _: &[&[u8]]) {}
    fn on_cs_admit(&self, _: &[&[u8]]) {}
}

/// A [`PitStore`] that reports its mutations to a [`NameTableObserver`].
///
/// A decorator rather than a change to the pipeline: the forwarding path is untouched, and a node
/// that wants a mirrored filter opts in by wrapping its store. Nothing else observes a difference.
pub struct ObservedPit<P, O> {
    pub inner: P,
    pub observer: O,
}

impl<P, O> ObservedPit<P, O> {
    pub fn new(inner: P, observer: O) -> Self {
        Self { inner, observer }
    }
}

impl<P: PitStore, O: NameTableObserver> PitStore for ObservedPit<P, O> {
    type Face = P::Face;

    fn has_nonce(&self, nonce: u32) -> bool {
        self.inner.has_nonce(nonce)
    }

    fn record_pending(
        &mut self,
        components: &[&[u8]],
        incoming_face: Self::Face,
        nonce: u32,
        lifetime_ms: u32,
        created_ms: u32,
    ) {
        // Notify FIRST: the filter must admit the reply, and the reply can be in flight before this
        // call even returns. Notifying after would leave a window in which the entry exists in the
        // PIT but the filter still rejects its Data.
        self.observer.on_pit_insert(components);
        self.inner.record_pending(components, incoming_face, nonce, lifetime_ms, created_ms);
    }

    fn satisfy(&mut self, components: &[&[u8]], send_to: impl FnMut(Self::Face)) -> bool {
        let hit = self.inner.satisfy(components, send_to);
        // Only report a removal that actually happened — telling the filter to decrement a counter
        // for an entry that was never there corrupts it, and a counting Bloom filter has no way to
        // detect or recover from that.
        if hit {
            self.observer.on_pit_remove(components);
        }
        hit
    }

    fn discard_pending(&mut self, components: &[&[u8]]) -> bool {
        let hit = self.inner.discard_pending(components);
        if hit {
            self.observer.on_pit_remove(components);
        }
        hit
    }
}

/// A [`CsStore`] that reports admissions to a [`NameTableObserver`].
pub struct ObservedCs<C, O> {
    pub inner: C,
    pub observer: O,
}

impl<C, O> ObservedCs<C, O> {
    pub fn new(inner: C, observer: O) -> Self {
        Self { inner, observer }
    }
}

impl<C: CsStore, O: NameTableObserver> CsStore for ObservedCs<C, O> {
    fn lookup(&self, components: &[&[u8]], now_ms: u32) -> Option<&[u8]> {
        self.inner.lookup(components, now_ms)
    }

    fn admit(&mut self, components: &[&[u8]], wire: &[u8], freshness_ms: u32, now_ms: u32) {
        self.observer.on_cs_admit(components);
        self.inner.admit(components, wire, freshness_ms, now_ms);
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}
