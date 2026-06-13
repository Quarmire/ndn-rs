//! Layer 1 — `SvSync` data plane (gaps #4, #5, #8).
//!
//! Layer 0 ([`svs_sync`](crate::svs_sync)) is a notification bus: it tells
//! you *that* a publisher advanced, but every consumer then re-implements
//! naming, fetching, serving and storage (the crate's own
//! `svs_gossip`/`subscriber` are evidence). This layer owns that, keeping
//! the transport-agnostic `mpsc<Bytes>` boundary so it still runs in the
//! browser, a simulator, or against real faces.
//!
//! * [`DataStore`] — pluggable storage; [`MemoryStore`] is the default.
//! * [`svs_data_name`] — the canonical ndn-svs data name
//!   `<node>/<group>/<seq>` (`svsync.hpp` `getDataName`), so packets
//!   published here are fetchable by a C++/Go peer and vice-versa.
//! * [`SvSync::publish_data`] — name, sign, store, and advance the core
//!   in one call; the same task answers Interests for our own data prefix
//!   out of the store, so three nodes missing the same seq emit identical
//!   Interest names that NDN forwarders aggregate and serve from cache.
//! * [`SvSync::fetch`] / [`SvSync::fetch_range`] — a windowed, retrying
//!   pipeline (ndn-svs `Fetcher`, window 10) instead of one Interest at a
//!   time, so a rejoining node with a 500-seq gap recovers in parallel.
//!
//! Wiring: the caller hands [`SvSync::join`] one outbound `mpsc<Bytes>`
//! (everything this node sends) and one inbound `mpsc<Bytes>` (everything
//! it receives). An internal demux routes inbound packets — Sync
//! Interests to the core, data Interests under our prefix to the store,
//! Data to the matching pending fetch.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Mutex, Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, Name, NameComponent};

use crate::protocol::{SyncError, SyncHandle, SyncUpdate};
use crate::rt;
use crate::svs_sync::{RetryPolicy, SvsConfig, join_svs_group};
use crate::tlv::encode_nni;

/// Append a sequence number as a generic name component holding its
/// NonNegativeInteger encoding — ndn-cxx `Name::appendNumber`, the form
/// ndn-svs uses for the trailing seq of a data name.
fn append_seq(name: Name, seq: u64) -> Name {
    name.append_component(NameComponent::generic(Bytes::from(encode_nni(seq))))
}

/// Canonical SVS-PS data name `<node>/<group>/<seq>`
/// (`ndn-svs/ndn-svs/svsync.hpp` `getDataName`:
/// `Name(nid).append(syncPrefix).appendNumber(seqNo)`).
pub fn svs_data_name(node: &Name, group: &Name, seq: u64) -> Name {
    let mut name = node.clone();
    for c in group.components() {
        name = name.append_component(c.clone());
    }
    append_seq(name, seq)
}

/// Pluggable storage for published Data, keyed by full Data name.
pub trait DataStore: Send + Sync {
    /// Store the encoded Data `wire` under `name`.
    fn insert(&self, name: Name, wire: Bytes);
    /// Return the encoded Data previously stored under `name`.
    fn get(&self, name: &Name) -> Option<Bytes>;
    /// Return the lexicographically-smallest stored Data whose name has
    /// `prefix` as a prefix — the answer to a `CanBePrefix` Interest
    /// (e.g. a seq-name Interest matching that seq's segment 0). The
    /// default scans nothing; [`MemoryStore`] overrides it.
    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        let _ = prefix;
        None
    }
}

/// In-memory [`DataStore`]. The default; persistent stores (e.g. an
/// IndexedDB backend via `ndn-pib-idb` on wasm) implement the same trait.
#[derive(Default)]
pub struct MemoryStore {
    map: std::sync::RwLock<HashMap<Name, Bytes>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.read().expect("MemoryStore poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl DataStore for MemoryStore {
    fn insert(&self, name: Name, wire: Bytes) {
        self.map
            .write()
            .expect("MemoryStore poisoned")
            .insert(name, wire);
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        self.map.read().expect("MemoryStore poisoned").get(name).cloned()
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        let map = self.map.read().expect("MemoryStore poisoned");
        map.iter()
            .filter(|(name, _)| name.has_prefix(prefix))
            .min_by(|(a, _), (b, _)| a.cmp(b))
            .map(|(_, wire)| wire.clone())
    }
}

/// A pending fetch: whether the Interest was `CanBePrefix` (so the reply
/// name may extend the request name) and the delivery channel.
type PendingMap = Arc<Mutex<HashMap<Name, (bool, oneshot::Sender<Bytes>)>>>;

/// Tunables for the data plane on top of [`SvsConfig`].
#[derive(Clone, Debug)]
pub struct SvSyncConfig {
    pub svs: SvsConfig,
    /// Freshness stamped on published Data.
    pub data_freshness: Duration,
    /// Lifetime of each fetch Interest, and the per-attempt fetch timeout.
    pub fetch_timeout: Duration,
    /// Max in-flight fetch Interests in [`SvSync::fetch_range`]
    /// (ndn-svs `Fetcher` window = 10).
    pub fetch_window: usize,
    /// Max payload bytes per segment; a larger publication is split into
    /// `<node>/<group>/<seq>/v=0/seg=i` segments (ndn-svs
    /// `MAX_DATA_SIZE = 8000`).
    pub max_segment_size: usize,
}

impl Default for SvSyncConfig {
    fn default() -> Self {
        Self {
            svs: SvsConfig::default(),
            data_freshness: Duration::from_secs(4),
            fetch_timeout: Duration::from_secs(4),
            fetch_window: 10,
            max_segment_size: 8000,
        }
    }
}

/// Layer 1 sync: notification core + data store + fetch/serve.
pub struct SvSync {
    node: Name,
    group: Name,
    data_prefix: Name,
    store: Arc<dyn DataStore>,
    handle: SyncHandle,
    net_out: mpsc::Sender<Bytes>,
    pending: PendingMap,
    seq: AtomicU64,
    retry: RetryPolicy,
    fetch_timeout: Duration,
    fetch_window: usize,
    data_freshness: Duration,
    cancel: CancellationToken,
}

impl SvSync {
    /// Join `group` as `node`, serving and fetching Data through the
    /// `net_out`/`net_in` channel pair. `store` holds this node's
    /// published Data (and may be shared/persistent).
    pub fn join(
        group: Name,
        node: Name,
        store: Arc<dyn DataStore>,
        net_out: mpsc::Sender<Bytes>,
        net_in: mpsc::Receiver<Bytes>,
        config: SvSyncConfig,
    ) -> Self {
        let cancel = CancellationToken::new();

        // Core channels: the core's outbound Sync Interests, and the
        // inbound Sync Interests we demux to it.
        let (core_out_tx, mut core_out_rx) = mpsc::channel::<Bytes>(256);
        let (core_in_tx, core_in_rx) = mpsc::channel::<Bytes>(256);

        let handle = join_svs_group(
            group.clone(),
            node.clone(),
            core_out_tx,
            core_in_rx,
            config.svs.clone(),
        );

        // Forward the core's Sync Interests onto the shared outbound net.
        let net_out_fwd = net_out.clone();
        let cancel_fwd = cancel.clone();
        rt::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_fwd.cancelled() => break,
                    pkt = core_out_rx.recv() => match pkt {
                        Some(p) => { let _ = net_out_fwd.send(p).await; }
                        None => break,
                    }
                }
            }
        });

        let data_prefix = {
            let mut p = node.clone();
            for c in group.components() {
                p = p.append_component(c.clone());
            }
            p
        };
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

        // Demux loop: route inbound wire to the core / store / fetchers.
        spawn_demux(
            net_in,
            core_in_tx,
            net_out.clone(),
            Arc::clone(&store),
            Arc::clone(&pending),
            group.clone(),
            data_prefix.clone(),
            cancel.clone(),
        );

        Self {
            node,
            group,
            data_prefix,
            store,
            handle,
            net_out,
            pending,
            seq: AtomicU64::new(0),
            retry: config.svs.retry_policy.clone(),
            fetch_timeout: config.fetch_timeout,
            fetch_window: config.fetch_window,
            data_freshness: config.data_freshness,
            cancel,
        }
    }

    /// Name, sign (DigestSha256), store, and announce a new publication.
    /// Returns the assigned sequence number.
    pub async fn publish_data(&self, payload: &[u8]) -> Result<u64, SyncError> {
        self.publish_data_with_mapping(payload, |_| None).await
    }

    /// Like [`Self::publish_data`], but `make_mapping` receives the
    /// assigned sequence number and may return `MappingData` bytes to
    /// piggyback in the triggered Sync Interest (used by Layer 2 to ride
    /// the seq→name mapping; see [`crate::mapping`]).
    pub async fn publish_data_with_mapping(
        &self,
        payload: &[u8],
        make_mapping: impl FnOnce(u64) -> Option<Bytes>,
    ) -> Result<u64, SyncError> {
        let seq = self.seq.fetch_add(1, Ordering::AcqRel) + 1;
        let name = svs_data_name(&self.node, &self.group, seq);
        let wire = DataBuilder::new(name.clone(), payload)
            .freshness(self.data_freshness)
            .build();
        self.store.insert(name, wire);
        // Advance the core in lockstep (this node is the sole publisher
        // for its own id, so the core's counter tracks `self.seq`) and
        // multicast the new state vector.
        match make_mapping(seq) {
            Some(mapping) => self.handle.publish_with_mapping(self.node.clone(), mapping).await?,
            None => self.handle.publish(self.node.clone()).await?,
        }
        Ok(seq)
    }

    /// Publish a multi-segment object under one sequence number: each
    /// `segments[i]` becomes outer Data named
    /// `<node>/<group>/<seq>/v=0/seg=i` carrying a `FinalBlockId`
    /// (ndn-svs `insertDataSegment`). `make_mapping` receives the seq for
    /// the piggyback. Returns the assigned seq. A consumer fetches it with
    /// [`Self::fetch_publication`].
    pub async fn publish_segments_with_mapping(
        &self,
        segments: &[Vec<u8>],
        make_mapping: impl FnOnce(u64) -> Option<Bytes>,
    ) -> Result<u64, SyncError> {
        let seq = self.seq.fetch_add(1, Ordering::AcqRel) + 1;
        let base = svs_data_name(&self.node, &self.group, seq);
        let last = segments.len().saturating_sub(1) as u64;
        for (i, seg) in segments.iter().enumerate() {
            let name = base.clone().append_version(0).append_segment(i as u64);
            let wire = DataBuilder::new(name.clone(), seg)
                .freshness(self.data_freshness)
                .final_block_id_typed_seg(last)
                .build();
            self.store.insert(name, wire);
        }
        match make_mapping(seq) {
            Some(mapping) => self.handle.publish_with_mapping(self.node.clone(), mapping).await?,
            None => self.handle.publish(self.node.clone()).await?,
        }
        Ok(seq)
    }

    /// Fetch a publication's outer-segment contents in order. Fetches the
    /// seq name with `CanBePrefix` so segment 0 answers whether the
    /// publication is single (`<node>/<group>/<seq>`) or segmented
    /// (`…/v=0/seg=0`); a `FinalBlockId` then drives the remaining
    /// segment fetches (windowed). Returns one element for an unsegmented
    /// publication. `None` if segment 0 can't be retrieved.
    pub async fn fetch_publication(&self, node: &Name, seq: u64) -> Option<Vec<Bytes>> {
        let seq_name = svs_data_name(node, &self.group, seq);
        let first_wire = express_with_retry_cbp(
            seq_name.clone(),
            true,
            &self.net_out,
            &self.pending,
            &self.retry,
            self.fetch_timeout,
        )
        .await?;
        let first = Data::decode(first_wire).ok()?;
        let first_content = first.content().cloned().unwrap_or_default();

        // Unsegmented: the reply is the bare seq name itself.
        let seg_count = match first
            .meta_info()
            .and_then(|m| m.final_block_component())
            .and_then(|r| r.ok())
            .and_then(|c| c.as_segment())
        {
            Some(last) => last + 1,
            None => return Some(vec![first_content]),
        };
        if seg_count <= 1 {
            return Some(vec![first_content]);
        }

        // Segmented: collect seg 0 (in hand), fetch 1..last (windowed).
        let base = seq_name.append_version(0);
        let rest = self.fetch_segments(&base, 1, seg_count - 1).await;
        let mut out = Vec::with_capacity(seg_count as usize);
        out.push(first_content);
        for seg in rest {
            out.push(seg?);
        }
        Some(out)
    }

    /// Windowed fetch of explicit segments `base/seg=lo..=hi`.
    async fn fetch_segments(&self, base: &Name, lo: u64, hi: u64) -> Vec<Option<Bytes>> {
        let sem = Arc::new(Semaphore::new(self.fetch_window.max(1)));
        let (res_tx, mut res_rx) = mpsc::channel::<(u64, Option<Bytes>)>((hi - lo + 1) as usize);
        for s in lo..=hi {
            let permit = Arc::clone(&sem).acquire_owned().await.expect("semaphore");
            let name = base.clone().append_segment(s);
            let net_out = self.net_out.clone();
            let pending = Arc::clone(&self.pending);
            let retry = self.retry.clone();
            let timeout = self.fetch_timeout;
            let res_tx = res_tx.clone();
            rt::spawn(async move {
                let _permit = permit;
                let payload = express_with_retry(name, &net_out, &pending, &retry, timeout)
                    .await
                    .and_then(|wire| {
                        Data::decode(wire)
                            .ok()
                            .map(|d| d.content().cloned().unwrap_or_default())
                    });
                let _ = res_tx.send((s, payload)).await;
            });
        }
        drop(res_tx);
        let mut out: Vec<(u64, Option<Bytes>)> = Vec::new();
        while let Some(item) = res_rx.recv().await {
            out.push(item);
        }
        out.sort_by_key(|(s, _)| *s);
        out.into_iter().map(|(_, p)| p).collect()
    }

    /// Fetch one publication's payload, with windowed-equivalent retry.
    pub async fn fetch(&self, node: &Name, seq: u64) -> Option<Bytes> {
        self.fetch_name(&svs_data_name(node, &self.group, seq)).await
    }

    /// Fetch an arbitrary exact Data name through the correlated fetcher
    /// (retry/back-off, replies matched to Interests by name). Returns the
    /// Data's content. For callers that name their data by a convention
    /// other than [`svs_data_name`] but still want the data plane's
    /// race-free fetch instead of a hand-rolled "read the next packet".
    pub async fn fetch_name(&self, name: &Name) -> Option<Bytes> {
        let wire = express_with_retry(
            name.clone(),
            &self.net_out,
            &self.pending,
            &self.retry,
            self.fetch_timeout,
        )
        .await?;
        let data = Data::decode(wire).ok()?;
        Some(data.content().cloned().unwrap_or_default())
    }

    /// Fetch an inclusive `[low, high]` sequence range from `node`,
    /// pipelined with up to [`SvSyncConfig::fetch_window`] Interests in
    /// flight. Returns payloads in sequence order; a `None` entry is a
    /// publication that could not be retrieved within the retry budget.
    pub async fn fetch_range(&self, node: &Name, low: u64, high: u64) -> Vec<Option<Bytes>> {
        if high < low {
            return Vec::new();
        }
        let sem = Arc::new(Semaphore::new(self.fetch_window.max(1)));
        let (res_tx, mut res_rx) = mpsc::channel::<(u64, Option<Bytes>)>((high - low + 1) as usize);

        for seq in low..=high {
            // Acquire before spawning → at most `fetch_window` in flight.
            let permit = Arc::clone(&sem).acquire_owned().await.expect("semaphore");
            let name = svs_data_name(node, &self.group, seq);
            let net_out = self.net_out.clone();
            let pending = Arc::clone(&self.pending);
            let retry = self.retry.clone();
            let timeout = self.fetch_timeout;
            let res_tx = res_tx.clone();
            rt::spawn(async move {
                let _permit = permit;
                let payload = match express_with_retry(name, &net_out, &pending, &retry, timeout)
                    .await
                {
                    Some(wire) => Data::decode(wire)
                        .ok()
                        .map(|d| d.content().cloned().unwrap_or_default()),
                    None => None,
                };
                let _ = res_tx.send((seq, payload)).await;
            });
        }
        drop(res_tx);

        let mut out: Vec<(u64, Option<Bytes>)> = Vec::with_capacity((high - low + 1) as usize);
        while let Some(item) = res_rx.recv().await {
            out.push(item);
        }
        out.sort_by_key(|(s, _)| *s);
        out.into_iter().map(|(_, p)| p).collect()
    }

    /// Await the next [`SyncUpdate`] (a peer advanced).
    pub async fn recv_update(&mut self) -> Option<SyncUpdate> {
        self.handle.recv().await
    }

    /// Move the [`SyncUpdate`] stream out for an external dispatcher (e.g.
    /// [`crate::pubsub::SvsPubSub`]). After this, [`Self::recv_update`]
    /// yields nothing. Call before wrapping the `SvSync` in an `Arc`.
    pub fn take_updates(&mut self) -> mpsc::Receiver<SyncUpdate> {
        let (_dead_tx, dummy) = mpsc::channel(1);
        std::mem::replace(&mut self.handle.rx, dummy)
    }

    /// This node's data prefix `<node>/<group>` (what it serves).
    pub fn data_prefix(&self) -> &Name {
        &self.data_prefix
    }

    /// Borrow the underlying store.
    pub fn store(&self) -> &Arc<dyn DataStore> {
        &self.store
    }

    pub fn leave(self) {
        self.cancel.cancel();
    }
}

impl Drop for SvSync {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_demux(
    mut net_in: mpsc::Receiver<Bytes>,
    core_in_tx: mpsc::Sender<Bytes>,
    net_out: mpsc::Sender<Bytes>,
    store: Arc<dyn DataStore>,
    pending: PendingMap,
    group: Name,
    data_prefix: Name,
    cancel: CancellationToken,
) {
    let group_len = group.components().len();
    rt::spawn(async move {
        loop {
            let raw = tokio::select! {
                _ = cancel.cancelled() => break,
                pkt = net_in.recv() => match pkt {
                    Some(p) => p,
                    None => break,
                },
            };
            if raw.is_empty() {
                continue;
            }
            match raw[0] {
                // Data (0x06): deliver to the matching pending fetch.
                0x06 => {
                    if let Ok(data) = Data::decode(raw.clone()) {
                        let name = (*data.name).clone();
                        let waiter = {
                            let mut p = pending.lock().await;
                            // Exact match first; else a CanBePrefix waiter
                            // whose request name is a prefix of this Data
                            // name (a seq-name Interest answered by seg 0).
                            if let Some(slot) = p.remove(&name) {
                                Some(slot)
                            } else {
                                let key = p
                                    .iter()
                                    .find(|(k, (cbp, _))| *cbp && name.has_prefix(k))
                                    .map(|(k, _)| k.clone());
                                key.and_then(|k| p.remove(&k))
                            }
                        };
                        if let Some((_, tx)) = waiter {
                            let _ = tx.send(raw);
                        }
                    }
                }
                // Interest (0x05): Sync Interest → core; data Interest → serve.
                0x05 => {
                    let Ok(interest) = Interest::decode(raw.clone()) else {
                        continue;
                    };
                    let comps = interest.name.components();
                    let is_sync = interest.name.has_prefix(&group)
                        && comps.len() > group_len
                        && comps[group_len].as_version() == Some(2);
                    if is_sync {
                        let _ = core_in_tx.send(raw).await;
                    } else if interest.name.has_prefix(&data_prefix) {
                        // Exact name, else the CanBePrefix child (seg 0).
                        let served = store.get(&interest.name).or_else(|| {
                            interest
                                .selectors()
                                .can_be_prefix
                                .then(|| store.find_under(&interest.name))
                                .flatten()
                        });
                        if let Some(wire) = served {
                            let _ = net_out.send(wire).await;
                        }
                    }
                }
                _ => {}
            }
        }
    });
}

/// One fetch attempt: register a waiter, express the Interest, await the
/// Data (or time out). `can_be_prefix` lets the reply name extend `name`
/// (used to fetch a publication's segment 0 by its seq name).
async fn express_once(
    name: Name,
    can_be_prefix: bool,
    net_out: &mpsc::Sender<Bytes>,
    pending: &PendingMap,
    timeout: Duration,
) -> Option<Bytes> {
    let (tx, rx) = oneshot::channel();
    pending.lock().await.insert(name.clone(), (can_be_prefix, tx));

    let mut builder = InterestBuilder::new(name.clone())
        .must_be_fresh()
        .lifetime(timeout);
    if can_be_prefix {
        builder = builder.can_be_prefix();
    }
    if net_out.send(builder.build()).await.is_err() {
        pending.lock().await.remove(&name);
        return None;
    }

    let res = tokio::select! {
        r = rx => r.ok(),
        _ = rt::sleep(timeout) => None,
    };
    // Clear any leftover waiter on timeout.
    pending.lock().await.remove(&name);
    res
}

/// [`express_once`] wrapped in the [`RetryPolicy`] back-off.
async fn express_with_retry(
    name: Name,
    net_out: &mpsc::Sender<Bytes>,
    pending: &PendingMap,
    retry: &RetryPolicy,
    timeout: Duration,
) -> Option<Bytes> {
    express_with_retry_cbp(name, false, net_out, pending, retry, timeout).await
}

/// [`express_with_retry`] with an explicit `CanBePrefix` flag.
async fn express_with_retry_cbp(
    name: Name,
    can_be_prefix: bool,
    net_out: &mpsc::Sender<Bytes>,
    pending: &PendingMap,
    retry: &RetryPolicy,
    timeout: Duration,
) -> Option<Bytes> {
    let mut delay = retry.base_delay;
    for attempt in 0..=retry.max_retries {
        if let Some(wire) =
            express_once(name.clone(), can_be_prefix, net_out, pending, timeout).await
        {
            return Some(wire);
        }
        if attempt < retry.max_retries {
            rt::sleep(delay).await;
            delay = Duration::from_secs_f64((delay.as_secs_f64() * retry.backoff_factor).min(60.0));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn data_name_matches_ndn_svs_getdataname() {
        // getDataName(nid=/a/node, syncPrefix=/grp, seq=5)
        //   = /a/node + /grp + appendNumber(5)
        let dn = svs_data_name(&name("/a/node"), &name("/grp"), 5);
        let comps: Vec<String> = dn
            .components()
            .iter()
            .map(|c| String::from_utf8_lossy(&c.value).to_string())
            .collect();
        assert_eq!(comps, vec!["a", "node", "grp", "\u{5}"]);
        // The seq component is a generic component holding NNI(5) = [0x05].
        assert_eq!(dn.components().last().unwrap().value.as_ref(), &[0x05]);
    }

    #[test]
    fn memory_store_roundtrip() {
        let s = MemoryStore::new();
        assert!(s.is_empty());
        s.insert(name("/d/1"), Bytes::from_static(b"wire"));
        assert_eq!(s.get(&name("/d/1")).as_deref(), Some(&b"wire"[..]));
        assert_eq!(s.get(&name("/d/2")), None);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn find_under_returns_smallest_prefixed() {
        // CanBePrefix on the seq name must resolve to segment 0.
        let s = MemoryStore::new();
        let seq = name("/n/g/5");
        s.insert(seq.clone().append_version(0).append_segment(2), Bytes::from_static(b"s2"));
        s.insert(seq.clone().append_version(0).append_segment(0), Bytes::from_static(b"s0"));
        s.insert(seq.clone().append_version(0).append_segment(1), Bytes::from_static(b"s1"));
        assert_eq!(s.find_under(&seq).as_deref(), Some(&b"s0"[..]));
        // No prefixed entry → None.
        assert_eq!(s.find_under(&name("/n/g/6")), None);
    }

    #[tokio::test]
    async fn publish_segments_names_and_final_block() {
        // publish_segments stores one Data per segment under
        // <node>/<group>/<seq>/v=0/seg=i, each carrying FinalBlockId.
        let group = name("/app/seg");
        let node = name("/app/seg/n");
        let (out_tx, _out_rx) = mpsc::channel::<Bytes>(256);
        let (_in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let svs = SvSync::join(
            group.clone(),
            node.clone(),
            Arc::clone(&store),
            out_tx,
            in_rx,
            SvSyncConfig::default(),
        );

        let segs = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec()];
        let seq = svs
            .publish_segments_with_mapping(&segs, |_| None)
            .await
            .expect("publish_segments");
        assert_eq!(seq, 1);

        let base = svs_data_name(&node, &group, seq).append_version(0);
        for (i, expect) in segs.iter().enumerate() {
            let wire = store
                .get(&base.clone().append_segment(i as u64))
                .unwrap_or_else(|| panic!("segment {i} stored"));
            let data = Data::decode(wire).expect("decode segment");
            assert_eq!(data.content().map(|c| c.as_ref()), Some(expect.as_slice()));
            // FinalBlockId = seg=2 on every segment.
            let fb = data
                .meta_info()
                .and_then(|m| m.final_block_component())
                .and_then(|r| r.ok())
                .and_then(|c| c.as_segment());
            assert_eq!(fb, Some(2), "segment {i} FinalBlockId");
        }
    }

    /// Two SvSync nodes wired through an in-memory broker: A publishes,
    /// B learns via the SyncUpdate and fetches the payload back. Exercises
    /// publish → announce → core merge → fetch → serve end to end.
    #[tokio::test]
    async fn publish_announce_fetch_roundtrip() {
        let group = name("/app/sync");
        let na = name("/app/sync/a");
        let nb = name("/app/sync/b");

        let (a_out_tx, mut a_out_rx) = mpsc::channel::<Bytes>(256);
        let (a_in_tx, a_in_rx) = mpsc::channel::<Bytes>(256);
        let (b_out_tx, mut b_out_rx) = mpsc::channel::<Bytes>(256);
        let (b_in_tx, b_in_rx) = mpsc::channel::<Bytes>(256);

        // Broker: A's out → B's in, B's out → A's in.
        let a_in_for_b = a_in_tx.clone();
        tokio::spawn(async move {
            while let Some(p) = b_out_rx.recv().await {
                let _ = a_in_for_b.send(p).await;
            }
        });
        let b_in_for_a = b_in_tx.clone();
        tokio::spawn(async move {
            while let Some(p) = a_out_rx.recv().await {
                let _ = b_in_for_a.send(p).await;
            }
        });

        let cfg = SvSyncConfig {
            svs: SvsConfig {
                sync_interval: Duration::from_millis(50),
                jitter_ms: 0,
                ..Default::default()
            },
            fetch_timeout: Duration::from_secs(2),
            ..Default::default()
        };

        let store_a: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let svs_a = SvSync::join(
            group.clone(),
            na.clone(),
            store_a,
            a_out_tx,
            a_in_rx,
            cfg.clone(),
        );
        let store_b: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let mut svs_b = SvSync::join(group.clone(), nb.clone(), store_b, b_out_tx, b_in_rx, cfg);

        // A publishes two objects.
        let s1 = svs_a.publish_data(b"hello-1").await.expect("publish 1");
        let s2 = svs_a.publish_data(b"hello-2").await.expect("publish 2");
        assert_eq!((s1, s2), (1, 2));

        // B should learn about A via a SyncUpdate, then fetch the payloads.
        let update = tokio::time::timeout(Duration::from_secs(3), svs_b.recv_update())
            .await
            .expect("timed out waiting for update")
            .expect("update");
        assert_eq!(update.publisher, na.to_string());
        assert!(update.high_seq >= 1);

        let got1 = tokio::time::timeout(Duration::from_secs(3), svs_b.fetch(&na, 1))
            .await
            .expect("fetch 1 timed out");
        assert_eq!(got1.as_deref(), Some(&b"hello-1"[..]));

        // Range fetch covering both.
        let range = tokio::time::timeout(Duration::from_secs(3), svs_b.fetch_range(&na, 1, 2))
            .await
            .expect("fetch_range timed out");
        assert_eq!(range.len(), 2);
        assert_eq!(range[0].as_deref(), Some(&b"hello-1"[..]));
        assert_eq!(range[1].as_deref(), Some(&b"hello-2"[..]));
    }
}
