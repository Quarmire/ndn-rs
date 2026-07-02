//! PSync **Partial Sync** — the asymmetric producer/subscriber variant of
//! PSync (`PSync/partial-producer.{hpp,cpp}` + the Bloom-filter consumer in
//! `PSync/consumer.cpp`). Unlike Full Sync (every node tracks the whole
//! set), here one `PartialProducer` owns the set and many consumers each
//! subscribe to a subset of producer prefixes; the producer returns only
//! updates whose prefix is in the consumer's [`BloomFilter`].
//!
//! Protocol (wire-compatible names):
//! * **Hello** — consumer expresses `/<sync>/hello`; producer replies Data
//!   named `/<sync>/hello/<IBF>` whose content is the full prefix→seq list,
//!   so the consumer learns the current IBF and what it may subscribe to.
//! * **Sync** — consumer expresses
//!   `/<sync>/sync/<BF-count>/<BF-fpp>/<BF-bits>/<IBF>` (its subscription
//!   Bloom filter + the last IBF it saw); the producer subtracts the IBFs,
//!   filters the positive difference through the Bloom filter, and replies
//!   Data named `…/<current-IBF>` with the matching `<prefix>/<seq>` names.
//!   No matching update ⇒ the Interest is held until a later `publish`
//!   satisfies it (long-lived sync Interest).
//!
//! Both replies are segmented through the shared [`crate::transfer`]
//! pipeline (so a large prefix list / update set spans `…/<v>/seg=i`), and
//! the producer's IBF/name set is the same bounded `ProducerBase` the
//! Full producer uses.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Name, NameComponent};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::protocol::{SyncHandle, SyncUpdate};
use crate::psync_bloom::BloomFilter;
use crate::psync_sync::{
    PSyncInbound, ProducerBase, build_psync_content, decode_ibf, encode_ibf, parse_prefix_seq,
    parse_psync_payload,
};
use crate::rt;
use crate::transfer;

const HELLO: &[u8] = b"hello";
const SYNC: &[u8] = b"sync";

/// Configuration for a Partial Sync producer/consumer pair.
#[derive(Clone, Debug)]
pub struct PSyncPartialConfig {
    /// IBF cell budget (must match between producer and consumer; the
    /// consumer inherits it by echoing the producer's IBF). Default 80.
    pub ibf_count: usize,
    /// Bloom filter `projected_element_count` — the expected number of
    /// subscriptions (C++ `bfCount`). Default 200.
    pub bf_count: u32,
    /// Bloom filter target false-positive rate (C++ `bfFalsePositive`).
    /// Default 0.001.
    pub bf_false_positive: f64,
    /// Max `PSyncContent` bytes per reply segment (see [`crate::transfer`]).
    pub max_segment_size: usize,
    /// Interest lifetime for hello/sync/segment fetches. Default 1 s.
    pub interest_lifetime: Duration,
    pub channel_capacity: usize,
}

impl Default for PSyncPartialConfig {
    fn default() -> Self {
        Self {
            ibf_count: 80,
            bf_count: 200,
            bf_false_positive: 0.001,
            max_segment_size: 7000,
            interest_lifetime: Duration::from_secs(1),
            channel_capacity: 256,
        }
    }
}

// ---------------------------------------------------------------------------
// Producer
// ---------------------------------------------------------------------------

/// Ceiling on held (unsatisfiable) sync Interests (audit PSYNC-2). The map is
/// otherwise purged only on a timed sweep, so a flood of distinct sync Interests
/// within the lifetime window grows it without bound — and each entry pins a
/// BloomFilter + IBF. Mirrors the existing `seg_store` 1024 cap.
const MAX_PENDING_SYNC_INTERESTS: usize = 1024;

struct PartialPending {
    bf: BloomFilter,
    consumer_ibf: crate::psync::Ibf,
    expires_at: rt::Instant,
}

/// Spawn a Partial Sync **producer**: serves hello + sync Interests under
/// `sync_prefix`, holds unsatisfiable sync Interests, and re-checks them on
/// every [`SyncHandle::publish`]. The returned handle's `recv()` never
/// yields (a producer learns nothing); use `publish` to advance the set.
pub fn join_psync_partial_producer(
    sync_prefix: Name,
    send: mpsc::Sender<Bytes>,
    recv: mpsc::Receiver<PSyncInbound>,
    config: PSyncPartialConfig,
) -> SyncHandle {
    let cancel = CancellationToken::new();
    let (update_tx, update_rx) = mpsc::channel(config.channel_capacity);
    let (publish_tx, publish_rx) = mpsc::channel(64);
    let _ = update_tx; // producer emits no updates; keep the channel alive.

    let task_cancel = cancel.clone();
    rt::spawn(async move {
        partial_producer_task(sync_prefix, send, recv, publish_rx, config, task_cancel).await;
    });

    SyncHandle::new(update_rx, publish_tx, cancel)
}

async fn partial_producer_task(
    sync_prefix: Name,
    send: mpsc::Sender<Bytes>,
    mut recv: mpsc::Receiver<PSyncInbound>,
    mut publish_rx: mpsc::Receiver<(Name, Option<Bytes>)>,
    config: PSyncPartialConfig,
    cancel: CancellationToken,
) {
    let mut pb = ProducerBase::new(config.ibf_count);
    let mut seg_store: HashMap<Name, Bytes> = HashMap::new();
    let mut pending: HashMap<Name, PartialPending> = HashMap::new();
    let hello_comp = NameComponent::generic(Bytes::from_static(HELLO));
    let sync_comp = NameComponent::generic(Bytes::from_static(SYNC));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,

            _ = rt::sleep(Duration::from_secs(1)) => {
                let now = rt::Instant::now();
                pending.retain(|_, e| e.expires_at > now);
            }

            Some(inbound) = recv.recv() => {
                let raw = inbound.bytes;
                if raw.first() != Some(&0x05) { continue; }
                let Ok(interest) = ndn_packet::Interest::decode(raw.clone()) else { continue };
                let name = interest.name.as_ref().clone();

                // Serve a stored segment verbatim.
                if let Some(wire) = seg_store.get(&name).cloned() {
                    match inbound.reply {
                        Some(tx) => { let _ = tx.send(wire); }
                        None => { let _ = send.send(wire).await; }
                    }
                    continue;
                }

                let Some(suffix) = strip_prefix(&name, &sync_prefix) else { continue };
                match suffix.first() {
                    Some(c) if *c == hello_comp =>
                        serve_hello(&sync_prefix, &pb, &config, &mut seg_store, &send).await,
                    Some(c) if *c == sync_comp =>
                        serve_sync(&name, &suffix, &pb, &config, &mut pending, &mut seg_store, &send).await,
                    _ => {}
                }
            }

            Some((pub_name, mapping)) = publish_rx.recv() => {
                if pb.apply(&pub_name, mapping).is_some() {
                    satisfy_partial_pending(&pb, &config, &mut pending, &mut seg_store, &send).await;
                }
            }
        }
    }
}

/// Reply to a hello Interest: the full `<prefix>/<seq>` list + current IBF.
async fn serve_hello(
    sync_prefix: &Name,
    pb: &ProducerBase,
    config: &PSyncPartialConfig,
    seg_store: &mut HashMap<Name, Bytes>,
    send: &mpsc::Sender<Bytes>,
) {
    let names = pb.state_names();
    let base = sync_prefix
        .clone()
        .append_component(NameComponent::generic(Bytes::from_static(HELLO)))
        .append_component(current_ibf_component(pb));
    publish_segments(&base, &names, config, seg_store, send).await;
}

/// Reply to (or hold) a sync Interest:
/// `/<sync>/sync/<BF-count>/<BF-fpp>/<BF-bits>/<IBF>`.
async fn serve_sync(
    interest_name: &Name,
    suffix: &[NameComponent],
    pb: &ProducerBase,
    config: &PSyncPartialConfig,
    pending: &mut HashMap<Name, PartialPending>,
    seg_store: &mut HashMap<Name, Bytes>,
    send: &mpsc::Sender<Bytes>,
) {
    // suffix = [sync, count, fpp, bits, ibf]
    if suffix.len() != 5 {
        return;
    }
    // suffix[1..4] = BF (count, fpp, bits); suffix[4] = consumer IBF.
    let bf = match BloomFilter::from_name_suffix(&suffix[1..4]) {
        Some(bf) => bf,
        None => return,
    };
    let consumer_ibf = match decode_ibf(&suffix[4].value, config.ibf_count) {
        Some(ibf) => ibf,
        None => return,
    };

    let names = filtered_difference(pb, &consumer_ibf, &bf);
    match names {
        Some(names) if !names.is_empty() => {
            let base = interest_name
                .clone()
                .append_component(current_ibf_component(pb));
            publish_segments(&base, &names, config, seg_store, send).await;
        }
        Some(_) => {
            // Decodable but nothing the consumer subscribed to changed —
            // hold the Interest (long-lived) until a publish satisfies it.
            // Cap the map (audit PSYNC-2): when full, evict the soonest-to-expire
            // held Interest so a flood of distinct sync Interests can't grow it.
            if pending.len() >= MAX_PENDING_SYNC_INTERESTS
                && !pending.contains_key(interest_name)
                && let Some(victim) = pending
                    .iter()
                    .min_by_key(|(_, e)| e.expires_at)
                    .map(|(k, _)| k.clone())
            {
                pending.remove(&victim);
            }
            pending.insert(
                interest_name.clone(),
                PartialPending {
                    bf,
                    consumer_ibf,
                    expires_at: rt::Instant::now() + config.interest_lifetime,
                },
            );
        }
        None => {
            // Can't decode the IBF difference: the consumer is too far
            // behind. Reply with the whole subscribed-to set + a fresh IBF
            // so it resynchronises (instead of a separate application Nack).
            let all = subscribed_state(pb, &bf);
            let base = interest_name
                .clone()
                .append_component(current_ibf_component(pb));
            publish_segments(&base, &all, config, seg_store, send).await;
        }
    }
}

/// Re-check held sync Interests after a publish (C++
/// `satisfyPendingSyncInterests`): reply to any whose Bloom-filtered
/// difference is now non-empty, then drop it.
async fn satisfy_partial_pending(
    pb: &ProducerBase,
    config: &PSyncPartialConfig,
    pending: &mut HashMap<Name, PartialPending>,
    seg_store: &mut HashMap<Name, Bytes>,
    send: &mpsc::Sender<Bytes>,
) {
    let mut satisfied: Vec<Name> = Vec::new();
    for (iname, entry) in pending.iter() {
        if let Some(names) = filtered_difference(pb, &entry.consumer_ibf, &entry.bf)
            && !names.is_empty()
        {
            let base = iname.clone().append_component(current_ibf_component(pb));
            publish_segments(&base, &names, config, seg_store, send).await;
            satisfied.push(iname.clone());
        }
    }
    for iname in satisfied {
        pending.remove(&iname);
    }
}

/// Positive IBF difference (names we have that the consumer lacks) filtered
/// to the prefixes the consumer subscribed to. `None` ⇒ undecodable diff.
fn filtered_difference(
    pb: &ProducerBase,
    consumer_ibf: &crate::psync::Ibf,
    bf: &BloomFilter,
) -> Option<Vec<Name>> {
    let (we_have, _they_have) = pb.reconcile(consumer_ibf)?;
    Some(
        pb.names_for_hashes(&we_have)
            .into_iter()
            .filter(|name| bf_contains_prefix(bf, name))
            .collect(),
    )
}

/// The whole set, filtered to subscribed prefixes (resync fallback).
fn subscribed_state(pb: &ProducerBase, bf: &BloomFilter) -> Vec<Name> {
    pb.state_names()
        .into_iter()
        .filter(|name| bf_contains_prefix(bf, name))
        .collect()
}

/// A name `<prefix>/<seq>` is wanted iff the consumer's BF contains its
/// prefix (the seq component is stripped, mirroring C++ `getPrefix(-1)`).
fn bf_contains_prefix(bf: &BloomFilter, name: &Name) -> bool {
    match parse_prefix_seq(name) {
        Some((prefix, _seq)) => bf.contains(&prefix),
        None => bf.contains(name),
    }
}

fn current_ibf_component(pb: &ProducerBase) -> NameComponent {
    NameComponent::generic(encode_ibf(&pb.build_ibf()))
}

// ---------------------------------------------------------------------------
// Consumer
// ---------------------------------------------------------------------------

/// Spawn a Partial Sync **consumer**: hello-bootstraps the producer IBF,
/// then runs a long-lived sync loop carrying its [`BloomFilter`]
/// subscription set. [`SyncHandle::subscribe`] adds a producer prefix to
/// that set; `recv()` yields a [`SyncUpdate`] per new `<prefix>/<seq>` the
/// consumer is subscribed to.
pub fn join_psync_partial_consumer(
    sync_prefix: Name,
    send: mpsc::Sender<Bytes>,
    recv: mpsc::Receiver<PSyncInbound>,
    config: PSyncPartialConfig,
) -> SyncHandle {
    let cancel = CancellationToken::new();
    let (update_tx, update_rx) = mpsc::channel(config.channel_capacity);
    let (publish_tx, _publish_rx) = mpsc::channel(1); // consumer doesn't publish
    let (subscribe_tx, subscribe_rx) = mpsc::channel(64);

    let task_cancel = cancel.clone();
    rt::spawn(async move {
        partial_consumer_task(
            sync_prefix,
            send,
            recv,
            subscribe_rx,
            update_tx,
            config,
            task_cancel,
        )
        .await;
    });

    SyncHandle::with_subscribe(update_rx, publish_tx, subscribe_tx, cancel)
}

async fn partial_consumer_task(
    sync_prefix: Name,
    send: mpsc::Sender<Bytes>,
    mut recv: mpsc::Receiver<PSyncInbound>,
    mut subscribe_rx: mpsc::Receiver<Name>,
    update_tx: mpsc::Sender<SyncUpdate>,
    config: PSyncPartialConfig,
    cancel: CancellationToken,
) {
    let mut bf = BloomFilter::new(config.bf_count, config.bf_false_positive);
    let mut subs: HashSet<Name> = HashSet::new();
    let mut prefixes: HashMap<Name, u64> = HashMap::new();
    let mut current_ibf: Option<Bytes> = None;

    let hello_name = sync_prefix
        .clone()
        .append_component(NameComponent::generic(Bytes::from_static(HELLO)));
    let sync_base = sync_prefix
        .clone()
        .append_component(NameComponent::generic(Bytes::from_static(SYNC)));

    loop {
        // Absorb any new subscriptions (rebuild BF: insert is monotonic).
        while let Ok(prefix) = subscribe_rx.try_recv() {
            if subs.insert(prefix.clone()) {
                bf.insert(&prefix);
                // A new subscription must be re-evaluated against a fresh
                // IBF/Bloom round, so force a hello bootstrap.
                current_ibf = None;
            }
        }

        if cancel.is_cancelled() {
            break;
        }

        if subs.is_empty() {
            // Idle until the first subscription (or cancellation).
            tokio::select! {
                _ = cancel.cancelled() => break,
                maybe = subscribe_rx.recv() => match maybe {
                    Some(prefix) => { if subs.insert(prefix.clone()) { bf.insert(&prefix); current_ibf = None; } }
                    None => break,
                }
            }
            continue;
        }

        if current_ibf.is_none() {
            // Hello bootstrap: learn the producer IBF and, since the hello
            // reply lists the whole set, immediately surface any already-
            // published updates for subscribed prefixes (C++ onHelloData).
            match fetch_reassemble(
                &hello_name,
                &send,
                &mut recv,
                &cancel,
                config.interest_lifetime,
            )
            .await
            {
                Some((producer_base, content)) => {
                    current_ibf = ibf_value(&producer_base);
                    apply_state(&content, &subs, &mut prefixes, &update_tx).await;
                }
                None => continue, // timeout / cancelled → retry hello
            }
            continue;
        }

        // Sync: /<sync>/<BF>/<IBF> — long-lived; learns future updates.
        let ibf_comp = NameComponent::generic(current_ibf.clone().unwrap());
        let sync_name = bf.append_to_name(&sync_base).append_component(ibf_comp);

        match fetch_reassemble(
            &sync_name,
            &send,
            &mut recv,
            &cancel,
            config.interest_lifetime,
        )
        .await
        {
            Some((producer_base, content)) => {
                current_ibf = ibf_value(&producer_base);
                apply_state(&content, &subs, &mut prefixes, &update_tx).await;
            }
            None => continue, // timeout → re-send sync next iteration
        }
    }
}

/// Emit a [`SyncUpdate`] for each `<prefix>/<seq>` in a reply `State` whose
/// prefix the consumer is subscribed to and whose seq advances our local
/// view. Shared by the hello and sync paths.
async fn apply_state(
    content: &Bytes,
    subs: &HashSet<Name>,
    prefixes: &mut HashMap<Name, u64>,
    update_tx: &mpsc::Sender<SyncUpdate>,
) {
    let Some(names) = parse_psync_payload(content) else {
        return;
    };
    for name in names {
        let Some((prefix, seq)) = parse_prefix_seq(&name) else {
            continue;
        };
        if !subs.contains(&prefix) {
            continue;
        }
        let old = prefixes.get(&prefix).copied().unwrap_or(0);
        if seq > old {
            prefixes.insert(prefix.clone(), seq);
            let _ = update_tx
                .send(SyncUpdate {
                    publisher: prefix.to_string(),
                    name: name.clone(),
                    low_seq: old + 1,
                    high_seq: seq,
                    mapping: None,
                })
                .await;
        }
    }
}

/// Express `first` (CanBePrefix, MustBeFresh), await the seg=0 reply, fetch
/// any remaining segments, and return `(producer_base, content)` where
/// `producer_base` is the reply name minus the trailing `<version>/seg=i`
/// (so its last component is the producer's IBF). `None` on timeout or
/// cancellation.
async fn fetch_reassemble(
    first: &Name,
    send: &mpsc::Sender<Bytes>,
    recv: &mut mpsc::Receiver<PSyncInbound>,
    cancel: &CancellationToken,
    lifetime: Duration,
) -> Option<(Name, Bytes)> {
    let interest = InterestBuilder::new(first.clone())
        .lifetime(lifetime)
        .can_be_prefix()
        .must_be_fresh()
        .build();
    send.send(interest).await.ok()?;

    let seg0 = recv_matching(recv, cancel, first, lifetime).await?;
    let data = Data::decode(seg0).ok()?;
    let last = transfer::final_block_segment_clamped(&data).unwrap_or(0);
    let base_with_version = drop_last(&data.name); // strip seg=0
    let mut full = data.content().cloned().unwrap_or_default().to_vec();

    for i in 1..=last {
        let segname = base_with_version.clone().append_segment(i);
        let interest = InterestBuilder::new(segname.clone())
            .lifetime(lifetime)
            .must_be_fresh()
            .build();
        send.send(interest).await.ok()?;
        let segwire = recv_matching(recv, cancel, &segname, lifetime).await?;
        let d = Data::decode(segwire).ok()?;
        full.extend_from_slice(&d.content().cloned().unwrap_or_default());
    }

    // base_with_version = <producer_base>/<version>; drop the version too.
    let producer_base = drop_last(&base_with_version);
    Some((producer_base, Bytes::from(full)))
}

/// Await an inbound Data whose name has `want` as a prefix, dropping
/// unrelated packets, until `timeout` elapses or `cancel` fires.
async fn recv_matching(
    recv: &mut mpsc::Receiver<PSyncInbound>,
    cancel: &CancellationToken,
    want: &Name,
    timeout: Duration,
) -> Option<Bytes> {
    let deadline = rt::sleep(timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return None,
            _ = &mut deadline => return None,
            maybe = recv.recv() => {
                let inbound = maybe?;
                let raw = inbound.bytes;
                if raw.first() != Some(&0x06) { continue; }
                if let Ok(data) = Data::decode(raw.clone())
                    && data.name.as_ref().has_prefix(want)
                {
                    return Some(raw);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Segment a `<prefix>/<seq>` list under `base` into
/// `<base>/<version>/seg=i` Data, send seg=0, and store every segment
/// (bounded) so a peer's later `seg>=1` re-fetch is served.
async fn publish_segments(
    base: &Name,
    names: &[Name],
    config: &PSyncPartialConfig,
    seg_store: &mut HashMap<Name, Bytes>,
    send: &mpsc::Sender<Bytes>,
) {
    let content = build_psync_content(names);
    let version = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;
    let vbase = base.clone().append_version(version);
    let segs = transfer::segment_blob(
        &vbase,
        &content,
        config.max_segment_size,
        |name, chunk, last| {
            DataBuilder::new(name.clone(), chunk)
                .freshness(Duration::from_secs(1))
                .final_block_id_typed_seg(last)
                .sign_digest_sha256()
        },
    );
    if let Some((_, seg0)) = segs.first() {
        let _ = send.send(seg0.clone()).await;
    }
    const CAP: usize = 1024;
    for (name, wire) in segs {
        if seg_store.len() >= CAP
            && !seg_store.contains_key(&name)
            && let Some(victim) = seg_store.keys().next().cloned()
        {
            seg_store.remove(&victim);
        }
        seg_store.insert(name, wire);
    }
}

/// `name` with its last component removed.
fn drop_last(name: &Name) -> Name {
    let comps = name.components();
    let end = comps.len().saturating_sub(1);
    Name::from_components(comps[..end].iter().cloned())
}

/// The trailing components of `name` after `prefix`, or `None` if `name`
/// isn't under `prefix`.
fn strip_prefix(name: &Name, prefix: &Name) -> Option<Vec<NameComponent>> {
    if !name.has_prefix(prefix) {
        return None;
    }
    Some(name.components()[prefix.components().len()..].to_vec())
}

/// The IBF component value (the last component of a producer base name).
fn ibf_value(producer_base: &Name) -> Option<Bytes> {
    producer_base.components().last().map(|c| c.value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psync_sync::append_seq;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn channels() -> (
        mpsc::Sender<Bytes>,
        mpsc::Receiver<Bytes>,
        mpsc::Sender<PSyncInbound>,
        mpsc::Receiver<PSyncInbound>,
    ) {
        let (out_tx, out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<PSyncInbound>(256);
        (out_tx, out_rx, in_tx, in_rx)
    }

    #[tokio::test]
    async fn consumer_learns_only_subscribed_prefix() {
        let sync_prefix = n("/example/partial");
        let cfg = PSyncPartialConfig {
            interest_lifetime: Duration::from_millis(300),
            ..Default::default()
        };

        let (p_out, mut p_out_rx, p_in, p_in_rx) = channels();
        let (c_out, mut c_out_rx, c_in, c_in_rx) = channels();

        // Broker: producer.out → consumer.in, consumer.out → producer.in.
        let c_in_for_p = c_in.clone();
        tokio::spawn(async move {
            while let Some(p) = p_out_rx.recv().await {
                let _ = c_in_for_p.send(p.into()).await;
            }
        });
        let p_in_for_c = p_in.clone();
        tokio::spawn(async move {
            while let Some(p) = c_out_rx.recv().await {
                let _ = p_in_for_c.send(p.into()).await;
            }
        });

        let producer =
            join_psync_partial_producer(sync_prefix.clone(), p_out, p_in_rx, cfg.clone());
        let mut consumer = join_psync_partial_consumer(sync_prefix.clone(), c_out, c_in_rx, cfg);

        // Producer has two prefixes; consumer subscribes to only one.
        producer
            .publish(append_seq(&n("/example/partial/alice"), 3))
            .await
            .unwrap();
        producer
            .publish(append_seq(&n("/example/partial/bob"), 7))
            .await
            .unwrap();

        consumer
            .subscribe(n("/example/partial/alice"))
            .await
            .unwrap();

        let update = tokio::time::timeout(Duration::from_secs(8), consumer.recv())
            .await
            .expect("timed out")
            .expect("update");
        assert!(
            update.name.has_prefix(&n("/example/partial/alice")),
            "expected an alice update, got {}",
            update.name
        );
        assert_eq!(update.high_seq, 3);

        // bob is not subscribed → never delivered.
        let bob = tokio::time::timeout(Duration::from_millis(600), consumer.recv()).await;
        assert!(
            bob.is_err(),
            "bob must not be delivered to an alice-only consumer"
        );
    }

    #[tokio::test]
    async fn consumer_learns_future_publish_via_long_lived_sync() {
        let sync_prefix = n("/example/live");
        let cfg = PSyncPartialConfig {
            interest_lifetime: Duration::from_millis(300),
            ..Default::default()
        };

        let (p_out, mut p_out_rx, p_in, p_in_rx) = channels();
        let (c_out, mut c_out_rx, c_in, c_in_rx) = channels();

        let c_in_for_p = c_in.clone();
        tokio::spawn(async move {
            while let Some(p) = p_out_rx.recv().await {
                let _ = c_in_for_p.send(p.into()).await;
            }
        });
        let p_in_for_c = p_in.clone();
        tokio::spawn(async move {
            while let Some(p) = c_out_rx.recv().await {
                let _ = p_in_for_c.send(p.into()).await;
            }
        });

        let producer =
            join_psync_partial_producer(sync_prefix.clone(), p_out, p_in_rx, cfg.clone());
        let mut consumer = join_psync_partial_consumer(sync_prefix.clone(), c_out, c_in_rx, cfg);

        // Subscribe before anything is published, then publish later — the
        // consumer must learn it through its held (long-lived) sync Interest.
        consumer.subscribe(n("/example/live/sensor")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        producer
            .publish(append_seq(&n("/example/live/sensor"), 42))
            .await
            .unwrap();

        let update = tokio::time::timeout(Duration::from_secs(8), consumer.recv())
            .await
            .expect("timed out")
            .expect("update");
        assert!(update.name.has_prefix(&n("/example/live/sensor")));
        assert_eq!(update.high_seq, 42);
    }

    #[tokio::test]
    async fn subscribe_unsupported_on_full_psync() {
        use crate::psync_sync::{PSyncConfig, join_psync_group};
        let (out_tx, _out_rx) = mpsc::channel::<Bytes>(8);
        let (_in_tx, in_rx) = mpsc::channel::<PSyncInbound>(8);
        let h = join_psync_group(n("/g"), out_tx, in_rx, PSyncConfig::default());
        assert!(matches!(
            h.subscribe(n("/g/x")).await,
            Err(crate::protocol::SyncError::Unsupported)
        ));
    }
}
