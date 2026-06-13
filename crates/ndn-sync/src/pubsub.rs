//! Layer 2 — `SvsPubSub` (gap #7): arbitrary-named publications and
//! prefix subscriptions on top of the [`SvSync`](crate::svsync::SvSync)
//! data plane, matching ndn-svs `SVSPubSub` so it composes with other
//! implementations.
//!
//! A producer [`publish`](SvsPubSub::publish)es under an application name
//! (`/sensors/temp/...`), unrelated to its node id; a consumer
//! [`subscribe`](SvsPubSub::subscribe)s to a *prefix* and receives only
//! matching publications. The bridge is the [`MappingProvider`]: each
//! publication records `seq → app_name`, ridden in the Sync Interest
//! (piggyback) and answered on demand via the
//! `/<node>/<group>/MAPPING/<low>/<high>` query — which is exactly the
//! late-join backfill (a node joining an hour in can resolve every
//! historical seq to its name and fetch only what it subscribed to).
//!
//! Encapsulation: a publication is an inner `Data` packet named with the
//! application name; that inner packet is the *content* of the outer
//! per-seq SvSync Data, which is marked `ContentType = Data`
//! (`Other(6)`, ndn-svs `tlv::Data`) so an ndn-svs SVS-PS peer recognises
//! the encapsulation. The consumer decapsulates by decoding the content
//! back into a `Data` (structural, so it also works for peers that omit
//! the marker).
//!
//! Segmentation: a blob larger than
//! [`SvSyncConfig::max_segment_size`](crate::svsync::SvSyncConfig) is
//! split into inner `Data` segments named `<app>/v=0/seg=i` (each with a
//! `FinalBlockId`), published as the outer segments of one seq via
//! [`SvSync::publish_segments_with_mapping`]. The subscriber fetches the
//! seq with `CanBePrefix` (so segment 0 answers whether it's a single or
//! segmented publication) and reassembles — see
//! [`SvSync::fetch_publication`].
//!
//! Wiring mirrors [`SvSync`]: hand [`SvsPubSub::join`] one outbound and
//! one inbound `mpsc<Bytes>`. It interposes a thin demux that answers
//! mapping queries and routes mapping-query replies, forwarding all other
//! traffic to the wrapped `SvSync`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::{Bytes, BytesMut};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, Name};

use crate::mapping::{MappingList, MappingProvider};
use crate::protocol::SyncError;
use crate::rt;
use crate::svsync::{DataStore, MemoryStore, SvSync, SvSyncConfig};

/// A delivered publication: its application name and decapsulated payload.
#[derive(Clone, Debug)]
pub struct Publication {
    pub name: Name,
    pub payload: Bytes,
}

type PendingMap = Arc<Mutex<HashMap<Name, oneshot::Sender<Bytes>>>>;
type SubList = Arc<Mutex<Vec<(Name, mpsc::Sender<Publication>)>>>;

/// Layer 2 pub/sub over [`SvSync`].
pub struct SvsPubSub {
    node: Name,
    group: Name,
    svsync: Arc<SvSync>,
    mappings: Arc<MappingProvider>,
    net_out: mpsc::Sender<Bytes>,
    query_pending: PendingMap,
    subs: SubList,
    seq: AtomicU64,
    fetch_timeout: std::time::Duration,
    max_segment_size: usize,
    cancel: CancellationToken,
}

impl SvsPubSub {
    /// Join `group` as `node`, publishing/subscribing through the
    /// `net_out`/`net_in` channel pair.
    pub fn join(
        group: Name,
        node: Name,
        net_out: mpsc::Sender<Bytes>,
        net_in: mpsc::Receiver<Bytes>,
        config: SvSyncConfig,
    ) -> Self {
        let cancel = CancellationToken::new();
        let mappings = Arc::new(MappingProvider::new());
        let query_pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let subs: SubList = Arc::new(Mutex::new(Vec::new()));

        // Channels between our interposing demux and the wrapped SvSync.
        let (svs_in_tx, svs_in_rx) = mpsc::channel::<Bytes>(256);

        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        // Every outer publication encapsulates an inner Data, so mark it
        // ContentType = Data (ndn-svs `tlv::Data` = 6) for SVS-PS interop.
        let mut svs_config = config.clone();
        svs_config.content_type = Some(ndn_packet::meta_info::ContentType::Other(6));
        let mut svsync_owned = SvSync::join(
            group.clone(),
            node.clone(),
            store,
            net_out.clone(),
            svs_in_rx,
            svs_config,
        );
        // Own the update stream before sharing the SvSync via Arc.
        let updates = svsync_owned.take_updates();
        let svsync = Arc::new(svsync_owned);

        let query_prefix = MappingProvider::query_prefix(&node, &group);

        // Interpose: answer mapping queries, route mapping-query replies,
        // forward everything else down to SvSync.
        spawn_interpose(
            net_in,
            svs_in_tx,
            net_out.clone(),
            Arc::clone(&mappings),
            Arc::clone(&query_pending),
            group.clone(),
            query_prefix,
            cancel.clone(),
        );

        let svs = Self {
            node,
            group,
            svsync: Arc::clone(&svsync),
            mappings: Arc::clone(&mappings),
            net_out,
            query_pending,
            subs: Arc::clone(&subs),
            seq: AtomicU64::new(0),
            fetch_timeout: config.fetch_timeout,
            max_segment_size: config.max_segment_size.max(1),
            cancel: cancel.clone(),
        };

        // Subscription dispatcher: drain SvSync updates, resolve names,
        // deliver matching publications.
        svs.spawn_dispatcher(svsync, updates, mappings, subs, cancel);
        svs
    }

    /// Publish `blob` under the application name `app_name`. Returns the
    /// assigned sequence number. A blob larger than
    /// [`SvSyncConfig::max_segment_size`](crate::svsync::SvSyncConfig) is
    /// split into `<app_name>/v=0/seg=i` segments (one seq); the consumer
    /// reassembles them transparently.
    pub async fn publish(&self, app_name: Name, blob: &[u8]) -> Result<u64, SyncError> {
        let node = self.node.clone();
        let mappings = Arc::clone(&self.mappings);
        let app_for_map = app_name.clone();
        let make_mapping = move |seq: u64| {
            // Record locally and piggyback this publication's mapping.
            mappings.insert(&node, seq, app_for_map.clone());
            let mut list = MappingList::new(node.clone());
            list.pairs.push((seq, app_for_map.clone()));
            Some(list.encode())
        };

        let seq = if blob.len() <= self.max_segment_size {
            // Single inner Data <app_name> → blob, encapsulated as the
            // content of the outer per-seq publication.
            let inner = DataBuilder::new(app_name.clone(), blob).build();
            self.svsync
                .publish_data_with_mapping(&inner, make_mapping)
                .await?
        } else {
            // Segment: each chunk is an inner Data <app_name>/v=0/seg=i,
            // and those inner wires are the outer segment contents.
            let n = blob.len().div_ceil(self.max_segment_size);
            let last = (n - 1) as u64;
            let segments: Vec<Vec<u8>> = blob
                .chunks(self.max_segment_size)
                .enumerate()
                .map(|(i, chunk)| {
                    let seg_name = app_name
                        .clone()
                        .append_version(0)
                        .append_segment(i as u64);
                    DataBuilder::new(seg_name, chunk)
                        .final_block_id_typed_seg(last)
                        .build()
                        .to_vec()
                })
                .collect();
            self.svsync
                .publish_segments_with_mapping(&segments, make_mapping)
                .await?
        };
        let _ = self.seq.fetch_add(1, Ordering::AcqRel);
        Ok(seq)
    }

    /// Subscribe to `prefix`; matching publications arrive on the returned
    /// channel. The subscription lives until the receiver is dropped.
    pub async fn subscribe(&self, prefix: Name) -> mpsc::Receiver<Publication> {
        let (tx, rx) = mpsc::channel(64);
        self.subs.lock().await.push((prefix, tx));
        rx
    }

    /// This node's data prefix `<node>/<group>`.
    pub fn data_prefix(&self) -> &Name {
        self.svsync.data_prefix()
    }

    pub fn leave(self) {
        self.cancel.cancel();
    }

    fn spawn_dispatcher(
        &self,
        svsync: Arc<SvSync>,
        mut updates: mpsc::Receiver<crate::SyncUpdate>,
        mappings: Arc<MappingProvider>,
        subs: SubList,
        cancel: CancellationToken,
    ) {
        let group = self.group.clone();
        let net_out = self.net_out.clone();
        let query_pending = Arc::clone(&self.query_pending);
        let fetch_timeout = self.fetch_timeout;

        rt::spawn(async move {
            loop {
                let update = tokio::select! {
                    _ = cancel.cancelled() => break,
                    u = updates.recv() => match u {
                        Some(u) => u,
                        None => break,
                    },
                };

                let Ok(publisher) = update.publisher.parse::<Name>() else {
                    continue;
                };

                // Ingest any piggybacked mapping list first.
                if let Some(mb) = &update.mapping
                    && let Some(list) = MappingList::decode(mb)
                {
                    mappings.ingest(&list);
                }

                for seq in update.low_seq..=update.high_seq {
                    // Resolve seq → application name (local, else query).
                    let app_name = match mappings.get(&publisher, seq) {
                        Some(n) => Some(n),
                        None => {
                            resolve_via_query(
                                &publisher,
                                &group,
                                seq,
                                &net_out,
                                &query_pending,
                                &mappings,
                                fetch_timeout,
                            )
                            .await
                        }
                    };
                    let Some(app_name) = app_name else { continue };

                    // Does anyone care about this name?
                    let interested: Vec<mpsc::Sender<Publication>> = {
                        let guard = subs.lock().await;
                        guard
                            .iter()
                            .filter(|(p, _)| app_name.has_prefix(p))
                            .map(|(_, tx)| tx.clone())
                            .collect()
                    };
                    if interested.is_empty() {
                        continue;
                    }

                    // Fetch the publication (1 segment for a small blob,
                    // N for a large one). Each outer-segment content is an
                    // inner Data packet; decapsulate and reassemble.
                    let Some(outer_contents) = svsync.fetch_publication(&publisher, seq).await
                    else {
                        continue;
                    };
                    let Some(payload) = reassemble(&outer_contents) else {
                        continue;
                    };
                    let pubn = Publication {
                        name: app_name.clone(),
                        payload,
                    };
                    for tx in interested {
                        let _ = tx.send(pubn.clone()).await;
                    }
                }
            }
        });
    }
}

impl Drop for SvsPubSub {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Decapsulate each outer-segment content (an inner `Data` packet) and
/// concatenate their contents into the full publication payload. Returns
/// `None` if any segment fails to decode as a `Data`.
fn reassemble(outer_contents: &[Bytes]) -> Option<Bytes> {
    if outer_contents.len() == 1 {
        let data = Data::decode(outer_contents[0].clone()).ok()?;
        return Some(data.content().cloned().unwrap_or_default());
    }
    let mut buf = BytesMut::new();
    for oc in outer_contents {
        let data = Data::decode(oc.clone()).ok()?;
        if let Some(c) = data.content() {
            buf.extend_from_slice(c);
        }
    }
    Some(buf.freeze())
}

/// Express a `MAPPING/<seq>/<seq>` query and ingest the reply.
async fn resolve_via_query(
    node: &Name,
    group: &Name,
    seq: u64,
    net_out: &mpsc::Sender<Bytes>,
    pending: &PendingMap,
    mappings: &Arc<MappingProvider>,
    timeout: std::time::Duration,
) -> Option<Name> {
    let qname = MappingProvider::query_name(node, group, seq, seq);
    let (tx, rx) = oneshot::channel();
    pending.lock().await.insert(qname.clone(), tx);

    let interest = InterestBuilder::new(qname.clone())
        .must_be_fresh()
        .lifetime(timeout)
        .build();
    if net_out.send(interest).await.is_err() {
        pending.lock().await.remove(&qname);
        return None;
    }

    let reply = tokio::select! {
        r = rx => r.ok(),
        _ = rt::sleep(timeout) => None,
    };
    pending.lock().await.remove(&qname);

    let data = Data::decode(reply?).ok()?;
    let list = MappingList::decode(data.content()?)?;
    mappings.ingest(&list);
    mappings.get(node, seq)
}

#[allow(clippy::too_many_arguments)]
fn spawn_interpose(
    mut net_in: mpsc::Receiver<Bytes>,
    svs_in_tx: mpsc::Sender<Bytes>,
    net_out: mpsc::Sender<Bytes>,
    mappings: Arc<MappingProvider>,
    query_pending: PendingMap,
    group: Name,
    query_prefix: Name,
    cancel: CancellationToken,
) {
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
                // Interest: a mapping query we answer, else down to SvSync.
                0x05 => {
                    let Ok(interest) = Interest::decode(raw.clone()) else {
                        continue;
                    };
                    if interest.name.has_prefix(&query_prefix) {
                        if let Some((node, low, high)) =
                            MappingProvider::parse_query(&interest.name, &group)
                        {
                            let list = mappings.list_range(&node, low, high);
                            let data = DataBuilder::new((*interest.name).clone(), &list.encode())
                                .build();
                            let _ = net_out.send(data).await;
                        }
                    } else {
                        let _ = svs_in_tx.send(raw).await;
                    }
                }
                // Data: a mapping-query reply we route, else down to SvSync.
                0x06 => {
                    if let Ok(data) = Data::decode(raw.clone()) {
                        let name = (*data.name).clone();
                        let waiter = query_pending.lock().await.remove(&name);
                        if let Some(tx) = waiter {
                            let _ = tx.send(raw);
                            continue;
                        }
                    }
                    let _ = svs_in_tx.send(raw).await;
                }
                _ => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn wire_broker(
        mut from: mpsc::Receiver<Bytes>,
        to: mpsc::Sender<Bytes>,
    ) {
        tokio::spawn(async move {
            while let Some(p) = from.recv().await {
                if to.send(p).await.is_err() {
                    break;
                }
            }
        });
    }

    fn cfg() -> SvSyncConfig {
        cfg_seg(8000)
    }

    fn cfg_seg(max_segment_size: usize) -> SvSyncConfig {
        SvSyncConfig {
            svs: crate::SvsConfig {
                sync_interval: Duration::from_millis(50),
                jitter_ms: 0,
                ..Default::default()
            },
            fetch_timeout: Duration::from_secs(2),
            max_segment_size,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn large_blob_segments_and_reassembles() {
        // A blob far bigger than max_segment_size must split into many
        // <app>/v=0/seg=i segments and reassemble byte-exact on the
        // subscriber side.
        let group = n("/app/big");
        let pa = n("/app/big/prod");
        let cb = n("/app/big/cons");

        let (a_out_tx, a_out_rx) = mpsc::channel::<Bytes>(256);
        let (a_in_tx, a_in_rx) = mpsc::channel::<Bytes>(256);
        let (b_out_tx, b_out_rx) = mpsc::channel::<Bytes>(256);
        let (b_in_tx, b_in_rx) = mpsc::channel::<Bytes>(256);
        wire_broker(a_out_rx, b_in_tx);
        wire_broker(b_out_rx, a_in_tx);

        // 16-byte segments → a 1000-byte blob is 63 segments.
        let producer = SvsPubSub::join(group.clone(), pa.clone(), a_out_tx, a_in_rx, cfg_seg(16));
        let consumer = SvsPubSub::join(group.clone(), cb.clone(), b_out_tx, b_in_rx, cfg_seg(16));
        let mut rx = consumer.subscribe(n("/files")).await;

        let blob: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        producer
            .publish(n("/files/big.bin"), &blob)
            .await
            .expect("publish large");

        let got = tokio::time::timeout(Duration::from_secs(8), rx.recv())
            .await
            .expect("timed out")
            .expect("publication");
        assert_eq!(got.name, n("/files/big.bin"));
        assert_eq!(got.payload.len(), blob.len(), "reassembled length");
        assert_eq!(got.payload.as_ref(), blob.as_slice(), "byte-exact reassembly");
    }

    #[tokio::test]
    async fn boundary_blob_exactly_one_segment() {
        // A blob == max_segment_size stays single-segment (<= boundary).
        let group = n("/app/edge");
        let pa = n("/app/edge/p");
        let cb = n("/app/edge/c");
        let (a_out_tx, a_out_rx) = mpsc::channel::<Bytes>(256);
        let (a_in_tx, a_in_rx) = mpsc::channel::<Bytes>(256);
        let (b_out_tx, b_out_rx) = mpsc::channel::<Bytes>(256);
        let (b_in_tx, b_in_rx) = mpsc::channel::<Bytes>(256);
        wire_broker(a_out_rx, b_in_tx);
        wire_broker(b_out_rx, a_in_tx);

        let producer = SvsPubSub::join(group.clone(), pa, a_out_tx, a_in_rx, cfg_seg(32));
        let consumer = SvsPubSub::join(group.clone(), cb, b_out_tx, b_in_rx, cfg_seg(32));
        let mut rx = consumer.subscribe(n("/d")).await;

        let blob = vec![7u8; 32];
        producer.publish(n("/d/exact"), &blob).await.expect("publish");
        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out")
            .expect("publication");
        assert_eq!(got.payload, Bytes::from(blob));
    }

    #[tokio::test]
    async fn subscribe_by_prefix_receives_matching_publications() {
        let group = n("/app/ps");
        let pa = n("/app/ps/prod");
        let cb = n("/app/ps/cons");

        let (a_out_tx, a_out_rx) = mpsc::channel::<Bytes>(256);
        let (a_in_tx, a_in_rx) = mpsc::channel::<Bytes>(256);
        let (b_out_tx, b_out_rx) = mpsc::channel::<Bytes>(256);
        let (b_in_tx, b_in_rx) = mpsc::channel::<Bytes>(256);

        // A.out → B.in, B.out → A.in.
        wire_broker(a_out_rx, b_in_tx);
        wire_broker(b_out_rx, a_in_tx);

        let producer = SvsPubSub::join(group.clone(), pa.clone(), a_out_tx, a_in_rx, cfg());
        let consumer = SvsPubSub::join(group.clone(), cb.clone(), b_out_tx, b_in_rx, cfg());

        // Consumer subscribes to /sensors/temp only.
        let mut rx = consumer.subscribe(n("/sensors/temp")).await;

        // Producer publishes one matching and one non-matching name.
        producer
            .publish(n("/sensors/temp/room1"), b"21.5C")
            .await
            .expect("publish temp");
        producer
            .publish(n("/sensors/humidity/room1"), b"40%")
            .await
            .expect("publish humidity");

        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out")
            .expect("publication");
        assert_eq!(got.name, n("/sensors/temp/room1"));
        assert_eq!(got.payload.as_ref(), b"21.5C");

        // The non-matching publication must not arrive.
        let none = tokio::time::timeout(Duration::from_millis(400), rx.recv()).await;
        assert!(none.is_err(), "humidity must not match /sensors/temp");
    }

    #[tokio::test]
    async fn late_joiner_resolves_history_via_mapping_query() {
        // Producer publishes before the consumer subscribes; the consumer
        // must still resolve and fetch the historical publication. Force
        // the query path by clearing the piggyback (simulated: consumer
        // joins late, so the only update it sees is a fresh one, but the
        // mapping for the *first* seq must be resolvable via query).
        let group = n("/app/hist");
        let pa = n("/app/hist/prod");
        let cb = n("/app/hist/cons");

        let (a_out_tx, a_out_rx) = mpsc::channel::<Bytes>(256);
        let (a_in_tx, a_in_rx) = mpsc::channel::<Bytes>(256);
        let (b_out_tx, b_out_rx) = mpsc::channel::<Bytes>(256);
        let (b_in_tx, b_in_rx) = mpsc::channel::<Bytes>(256);
        wire_broker(a_out_rx, b_in_tx);
        wire_broker(b_out_rx, a_in_tx);

        let producer = SvsPubSub::join(group.clone(), pa.clone(), a_out_tx, a_in_rx, cfg());

        // Publish two before the consumer exists.
        producer.publish(n("/doc/ch1"), b"chapter-1").await.unwrap();
        producer.publish(n("/doc/ch2"), b"chapter-2").await.unwrap();

        let consumer = SvsPubSub::join(group.clone(), cb.clone(), b_out_tx, b_in_rx, cfg());
        let mut rx = consumer.subscribe(n("/doc")).await;

        // The consumer learns producer reached seq 2 via periodic sync,
        // then resolves seq 1 and 2 (query for the ones not piggybacked)
        // and fetches both chapters.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2 {
            let got = tokio::time::timeout(Duration::from_secs(6), rx.recv())
                .await
                .expect("timed out")
                .expect("publication");
            seen.insert(got.name.to_string());
        }
        assert!(seen.contains("/doc/ch1"), "must backfill ch1");
        assert!(seen.contains("/doc/ch2"), "must backfill ch2");
    }
}
