//! G4 — pluggable forwarding-plane QoS / egress scheduling.
//!
//! Today a face's egress is a single FIFO `mpsc` with only `CongestionPolicy::{Drop,
//! Backpressure}` — no classes, no priority. NDN QoS is research-active with no
//! agreed-optimal answer (DiffServ-by-name, LP traffic-class, WFQ/DRR, NDN-DPDK traffic
//! classes…), so this picks no winner: it defines the *seam* — a [`EgressScheduler`] that
//! decides transmit **order** (orthogonal to G1 congestion control, which decides
//! rate/path) and an [`EgressClassifier`] that maps a packet to a [`TrafficClass`] — and
//! ships one concrete scheduler (strict priority) plus a name-prefix classifier. WFQ/DRR
//! are future [`EgressScheduler`] impls behind the same trait.
//!
//! The FIFO default is the *absence* of a scheduler: a face with no scheduler configured
//! keeps its single mpsc, byte-for-byte today's behavior and zero added cost.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};

use ndn_packet::Name;
use tokio::sync::Notify;

use crate::engine::EgressItem;

/// A traffic class — the scheduling priority of a packet. **Lower is higher priority**
/// (class 0 is served before class 1). Within a class, order is FIFO.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrafficClass(pub u8);

impl TrafficClass {
    /// The default class for unclassified traffic (highest priority, so an unconfigured
    /// or fall-through packet is never starved behind classified bulk).
    pub const DEFAULT: TrafficClass = TrafficClass(0);
}

impl Default for TrafficClass {
    fn default() -> Self {
        TrafficClass::DEFAULT
    }
}

/// Maps an outbound packet to a [`TrafficClass`]. Cheap — it runs on the egress path.
pub trait EgressClassifier: Send + Sync {
    /// Classify a packet by its name (when known) and whether it is an Interest.
    fn classify(&self, name: Option<&Name>, is_interest: bool) -> TrafficClass;
}

/// Classify by **longest-matching name prefix** (DiffServ-by-name): the most specific
/// configured prefix that is a prefix of the packet name sets the class; names matching
/// nothing (and packets with no name) fall to `default`.
pub struct PrefixClassifier {
    /// `(prefix, class)` rules; longest matching prefix wins.
    rules: Vec<(Name, TrafficClass)>,
    default: TrafficClass,
}

impl PrefixClassifier {
    /// Build from `(prefix, class)` rules and the fall-through `default` class.
    pub fn new(rules: Vec<(Name, TrafficClass)>, default: TrafficClass) -> Self {
        Self { rules, default }
    }
}

impl EgressClassifier for PrefixClassifier {
    fn classify(&self, name: Option<&Name>, _is_interest: bool) -> TrafficClass {
        let Some(name) = name else {
            return self.default;
        };
        self.rules
            .iter()
            .filter(|(prefix, _)| name.has_prefix(prefix))
            .max_by_key(|(prefix, _)| prefix.components().len())
            .map(|(_, class)| *class)
            .unwrap_or(self.default)
    }
}

/// The egress queue for one face: the dispatcher [`enqueue`](Self::enqueue)s classified
/// packets; the face send loop drains them in scheduling order via
/// [`dequeue`](Self::dequeue). Used behind `Arc<dyn EgressScheduler>`, so it is
/// `async_trait` (dyn-compatible). The FIFO default is the absence of one (the raw mpsc).
#[async_trait::async_trait]
pub trait EgressScheduler: Send + Sync {
    /// Admit `item` of `class`. Returns `false` if it was dropped (queue full under the
    /// face's congestion policy).
    fn enqueue(&self, item: EgressItem, class: TrafficClass) -> bool;

    /// The next item to transmit, in scheduling order. Resolves when one is available;
    /// returns `None` once the scheduler is [`closed`](Self::close) and drained.
    async fn dequeue(&self) -> Option<EgressItem>;

    /// Mark the scheduler closed (face shutting down): pending items still drain, then
    /// [`dequeue`](Self::dequeue) returns `None`.
    fn close(&self);

    /// `(queued, capacity)` — the egress queue depth, for G1 congestion marking.
    fn depth(&self) -> (u64, u64);

    /// Total packets dropped on a full queue.
    fn dropped(&self) -> u64;
}

/// Builds a fresh [`EgressScheduler`] for a face. One per face (each face owns its own
/// queue), so the engine stores a factory rather than a shared scheduler.
pub type EgressSchedulerFactory =
    std::sync::Arc<dyn Fn() -> std::sync::Arc<dyn EgressScheduler> + Send + Sync>;

/// A queued packet, ordered by `(class, seq)` so the heap yields the highest-priority
/// class first and FIFO within a class.
struct Pending {
    class: u8,
    seq: u64,
    item: EgressItem,
}

impl PartialEq for Pending {
    fn eq(&self, other: &Self) -> bool {
        self.class == other.class && self.seq == other.seq
    }
}
impl Eq for Pending {}
impl Ord for Pending {
    fn cmp(&self, other: &Self) -> Ordering {
        // `BinaryHeap` is a max-heap; invert so the *smallest* (class, seq) — highest
        // priority, then earliest — is the maximum and pops first.
        other
            .class
            .cmp(&self.class)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}
impl PartialOrd for Pending {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// **Strict-priority** scheduler: always transmits the highest-priority (lowest-numbered)
/// non-empty class first, FIFO within a class. A single bounded heap (total `capacity`);
/// on overflow it **tail-drops** the arriving packet (a lower-priority flood cannot evict
/// already-queued higher-priority packets, and the bound caps memory). Backpressure-style
/// blocking is the FIFO default's job; strict priority is opt-in and drop-only.
pub struct PriorityScheduler {
    capacity: usize,
    inner: Mutex<Inner>,
    notify: Notify,
    closed: AtomicBool,
    dropped: AtomicU64,
}

struct Inner {
    heap: BinaryHeap<Pending>,
    seq: u64,
}

impl PriorityScheduler {
    /// A strict-priority scheduler holding at most `capacity` packets across all classes.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(Inner {
                heap: BinaryHeap::new(),
                seq: 0,
            }),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
        }
    }
}

#[async_trait::async_trait]
impl EgressScheduler for PriorityScheduler {
    fn enqueue(&self, item: EgressItem, class: TrafficClass) -> bool {
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.heap.len() >= self.capacity {
                drop(inner);
                self.dropped.fetch_add(1, AtomicOrdering::Relaxed);
                return false;
            }
            let seq = inner.seq;
            inner.seq += 1;
            inner.heap.push(Pending {
                class: class.0,
                seq,
                item,
            });
        }
        self.notify.notify_one();
        true
    }

    async fn dequeue(&self) -> Option<EgressItem> {
        loop {
            {
                let mut inner = self.inner.lock().unwrap();
                if let Some(p) = inner.heap.pop() {
                    return Some(p.item);
                }
            }
            if self.closed.load(AtomicOrdering::Acquire) {
                // Re-check under no lock: closed + empty ⇒ done. (A racing enqueue before
                // close is impossible — close is the last call.)
                let inner = self.inner.lock().unwrap();
                if inner.heap.is_empty() {
                    return None;
                }
                continue;
            }
            self.notify.notified().await;
        }
    }

    fn close(&self) {
        self.closed.store(true, AtomicOrdering::Release);
        self.notify.notify_one();
    }

    fn depth(&self) -> (u64, u64) {
        let inner = self.inner.lock().unwrap();
        (inner.heap.len() as u64, self.capacity as u64)
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(AtomicOrdering::Relaxed)
    }
}

/// Number of traffic classes a [`DeficitRoundRobinScheduler`] serves (0..=7); a higher
/// [`TrafficClass`] is clamped into this range. Eight covers DiffServ-style class sets.
pub const DRR_CLASSES: usize = 8;

/// **Deficit Round Robin** scheduler: starvation-free fairness across classes, the
/// counterpoint to [`PriorityScheduler`] (whose strict priority can starve low classes
/// under sustained high-class load). Each class accrues a byte `quantum` per round and is
/// served up to its accumulated deficit, so every backlogged class makes progress and the
/// long-run share is byte-fair. A single bounded total `capacity`; tail-drop on overflow.
///
/// `quantum` should be **≥ the largest expected packet** (e.g. one MTU): a quantum smaller
/// than a packet still works but makes a class wait extra rounds to accumulate enough
/// deficit, so a single `dequeue` may scan several rounds before it can release a packet.
pub struct DeficitRoundRobinScheduler {
    quantum: u64,
    capacity: usize,
    inner: Mutex<DrrInner>,
    notify: Notify,
    closed: AtomicBool,
    dropped: AtomicU64,
}

struct DrrInner {
    /// `(size, item)` FIFO per class.
    queues: Vec<std::collections::VecDeque<(u64, EgressItem)>>,
    /// Per-class accumulated byte credit.
    deficit: Vec<u64>,
    /// Round-robin cursor + whether this visit has been credited a quantum yet.
    current: usize,
    credited: bool,
    len: usize,
}

impl DeficitRoundRobinScheduler {
    /// A DRR scheduler with `quantum` bytes per class per round and at most `capacity`
    /// packets queued across all classes.
    pub fn new(quantum: u64, capacity: usize) -> Self {
        Self {
            quantum: quantum.max(1),
            capacity: capacity.max(1),
            inner: Mutex::new(DrrInner {
                queues: (0..DRR_CLASSES).map(|_| std::collections::VecDeque::new()).collect(),
                deficit: vec![0; DRR_CLASSES],
                current: 0,
                credited: false,
                len: 0,
            }),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
        }
    }
}

#[async_trait::async_trait]
impl EgressScheduler for DeficitRoundRobinScheduler {
    fn enqueue(&self, item: EgressItem, class: TrafficClass) -> bool {
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.len >= self.capacity {
                drop(inner);
                self.dropped.fetch_add(1, AtomicOrdering::Relaxed);
                return false;
            }
            let size = item.0.len() as u64;
            let c = (class.0 as usize).min(DRR_CLASSES - 1);
            inner.queues[c].push_back((size, item));
            inner.len += 1;
        }
        self.notify.notify_one();
        true
    }

    async fn dequeue(&self) -> Option<EgressItem> {
        loop {
            {
                let mut inner = self.inner.lock().unwrap();
                if inner.len > 0 {
                    // DRR: round-robin over classes, crediting `quantum` once per visit,
                    // releasing the head while the class's deficit covers it. Guaranteed
                    // to return since `len > 0` (some class is backlogged and accrues
                    // credit each round until its head fits).
                    loop {
                        let cur = inner.current;
                        if inner.queues[cur].is_empty() {
                            inner.deficit[cur] = 0; // left the active list
                            inner.current = (cur + 1) % DRR_CLASSES;
                            inner.credited = false;
                            continue;
                        }
                        if !inner.credited {
                            inner.deficit[cur] += self.quantum;
                            inner.credited = true;
                        }
                        let head = inner.queues[cur].front().unwrap().0;
                        if inner.deficit[cur] >= head {
                            inner.deficit[cur] -= head;
                            let (_, item) = inner.queues[cur].pop_front().unwrap();
                            inner.len -= 1;
                            return Some(item);
                        } else {
                            inner.current = (cur + 1) % DRR_CLASSES;
                            inner.credited = false;
                        }
                    }
                }
            }
            if self.closed.load(AtomicOrdering::Acquire) {
                let inner = self.inner.lock().unwrap();
                if inner.len == 0 {
                    return None;
                }
                continue;
            }
            self.notify.notified().await;
        }
    }

    fn close(&self) {
        self.closed.store(true, AtomicOrdering::Release);
        self.notify.notify_one();
    }

    fn depth(&self) -> (u64, u64) {
        let inner = self.inner.lock().unwrap();
        (inner.len as u64, self.capacity as u64)
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(AtomicOrdering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EgressIntent;
    use bytes::Bytes;
    use ndn_transport::FaceId;

    fn item(tag: &str) -> EgressItem {
        (Bytes::from(tag.to_owned()), FaceId::INVALID, EgressIntent::default())
    }
    fn tag(it: &EgressItem) -> String {
        String::from_utf8(it.0.to_vec()).unwrap()
    }

    #[test]
    fn prefix_classifier_longest_match_wins() {
        let c = PrefixClassifier::new(
            vec![
                ("/sensors".parse().unwrap(), TrafficClass(2)),
                ("/sensors/temp/critical".parse().unwrap(), TrafficClass(0)),
            ],
            TrafficClass(3),
        );
        // Most specific matching prefix sets the class.
        assert_eq!(
            c.classify(Some(&"/sensors/temp/critical/v=1".parse().unwrap()), true),
            TrafficClass(0)
        );
        // Falls to the broader rule.
        assert_eq!(
            c.classify(Some(&"/sensors/humidity".parse().unwrap()), true),
            TrafficClass(2)
        );
        // No match ⇒ default; no name ⇒ default.
        assert_eq!(c.classify(Some(&"/other".parse().unwrap()), true), TrafficClass(3));
        assert_eq!(c.classify(None, false), TrafficClass(3));
    }

    #[tokio::test]
    async fn strict_priority_serves_high_class_first_fifo_within() {
        let s = PriorityScheduler::new(16);
        // Enqueue out of priority order; within a class, insertion order must hold.
        assert!(s.enqueue(item("lo-1"), TrafficClass(2)));
        assert!(s.enqueue(item("hi-1"), TrafficClass(0)));
        assert!(s.enqueue(item("mid-1"), TrafficClass(1)));
        assert!(s.enqueue(item("hi-2"), TrafficClass(0)));
        assert!(s.enqueue(item("lo-2"), TrafficClass(2)));

        let mut out = Vec::new();
        for _ in 0..5 {
            out.push(tag(&s.dequeue().await.unwrap()));
        }
        assert_eq!(out, vec!["hi-1", "hi-2", "mid-1", "lo-1", "lo-2"]);
    }

    #[tokio::test]
    async fn full_queue_tail_drops_and_counts() {
        let s = PriorityScheduler::new(2);
        assert!(s.enqueue(item("a"), TrafficClass(0)));
        assert!(s.enqueue(item("b"), TrafficClass(0)));
        assert!(!s.enqueue(item("c"), TrafficClass(0)), "third is tail-dropped");
        assert_eq!(s.depth(), (2, 2));
        assert_eq!(s.dropped(), 1);
    }

    #[tokio::test]
    async fn drr_interleaves_classes_without_starvation() {
        // Equal-size packets, quantum == packet size ⇒ DRR releases one per class per
        // round: the low class (5) is interleaved with the high class (0), never starved
        // behind it (contrast strict priority, which drains class 0 fully first).
        let s = DeficitRoundRobinScheduler::new(4, 32);
        for i in 0..3 {
            assert!(s.enqueue(item(&format!("c0-{i}")), TrafficClass(0)));
            assert!(s.enqueue(item(&format!("c5-{i}")), TrafficClass(5)));
        }
        let mut out = Vec::new();
        for _ in 0..6 {
            out.push(tag(&s.dequeue().await.unwrap()));
        }
        assert_eq!(out, vec!["c0-0", "c5-0", "c0-1", "c5-1", "c0-2", "c5-2"]);
    }

    #[tokio::test]
    async fn drr_byte_fair_share_across_unequal_loads() {
        // One class floods; another sends a little. DRR still serves both each round, so
        // the light class's packets are not stuck at the tail behind the flood.
        let s = DeficitRoundRobinScheduler::new(4, 64);
        for i in 0..5 {
            assert!(s.enqueue(item(&format!("hi-{i}")), TrafficClass(0)));
        }
        assert!(s.enqueue(item("lo-0"), TrafficClass(3)));
        // First two dequeues: one from each active class (round-robin), proving the light
        // class isn't starved behind the flood.
        let first = tag(&s.dequeue().await.unwrap());
        let second = tag(&s.dequeue().await.unwrap());
        assert_eq!(first, "hi-0");
        assert_eq!(second, "lo-0", "the light class is served the same round, not last");
    }

    #[tokio::test]
    async fn dequeue_blocks_until_enqueue_then_drains_on_close() {
        use std::sync::Arc;
        let s = Arc::new(PriorityScheduler::new(4));
        let s2 = s.clone();
        let waiter = tokio::spawn(async move { s2.dequeue().await.map(|i| tag(&i)) });
        // Nothing queued yet; let the waiter park, then feed it.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(s.enqueue(item("woke"), TrafficClass(0)));
        assert_eq!(waiter.await.unwrap().as_deref(), Some("woke"));

        // Close with one item still queued: it drains, then None.
        assert!(s.enqueue(item("last"), TrafficClass(0)));
        s.close();
        assert_eq!(s.dequeue().await.map(|i| tag(&i)).as_deref(), Some("last"));
        assert!(s.dequeue().await.is_none(), "closed + drained ⇒ None");
    }
}
