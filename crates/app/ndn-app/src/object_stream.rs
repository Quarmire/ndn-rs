//! Streaming an RDR object over a persistent subscription (one-Interest-many-Data)
//! instead of per-segment pull.
//!
//! This is the producer half of the "bulk off the seam" design (see
//! `.claude/notes/vpn/` + the substrate-extension PIT doctrine): a content source
//! (e.g. a keyless leaf app) serves its object's raw segments by **streaming**
//! them into a subscriber's persistent PIT entry — the same idle-cheap datapath
//! `ndn-mobile::tun` uses — rather than answering one Interest per segment across
//! a process boundary.
//!
//! The segments are emitted **raw** (`DigestSha256`, content only). Authenticity
//! is applied downstream by the relay that re-publishes them under a routable,
//! node-signed name ([`relay_object_stream`]): the key holder signs, the content
//! source does not. This keeps a leaf keyless while removing the per-segment
//! RemoteSigner round-trip.
//!
//! Two request shapes are served on the object's prefix:
//! - a **persistent subscription** (carries a `SubscriptionRequest`) grants
//!   streaming budget; a single in-order streamer publishes `…/seg=<n>` Data, one
//!   per budget unit, until the object is exhausted. Credit is replenished by
//!   re-subscription, so the subscriber bounds how far ahead of demand we run.
//! - a **plain** `…/seg=<n>` Interest (and the `…/32=metadata` discovery) is
//!   answered one-shot from the same [`PreparedObject`] — the fallback path a
//!   relay uses to re-fetch a segment that has aged out of its window.

use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use ndn_packet::SubscriptionRequest;

use crate::rdr::PreparedObject;
use crate::{AppError, Producer};

/// Serve `prepared` as a stream over `producer` (registered at the object's
/// logical prefix). Returns when the producer connection closes or `cancel`
/// fires; the in-order streamer task it spawns is bound to `cancel`.
///
/// `prepared` should be unsigned (built without a signer): segments go out raw
/// and are signed by the downstream relay. A subscriber drives the pace via the
/// `max_data_count` budget on its subscription Interest.
pub async fn serve_object_stream(
    producer: Producer,
    prepared: Arc<PreparedObject>,
    cancel: CancellationToken,
) -> Result<(), AppError> {
    let producer = Arc::new(producer);
    // One permit per Data the subscriber has budgeted for; the streamer consumes
    // one per published segment and blocks when the budget is spent, so we never
    // run further ahead of demand than the granted credit.
    let budget = Arc::new(Semaphore::new(0));
    let last = prepared.last_seg;

    // In-order streamer: publish seg 0..=last, one per budget permit. Forward-only
    // — a retransmit of an already-streamed segment arrives as a plain Interest on
    // the serve loop below, not through the stream.
    {
        let producer = Arc::clone(&producer);
        let budget = Arc::clone(&budget);
        let prepared = Arc::clone(&prepared);
        let cancel = cancel.child_token();
        crate::rt::spawn(async move {
            let mut seg: u64 = 0;
            while seg <= last {
                let permit = tokio::select! {
                    _ = cancel.cancelled() => return,
                    p = budget.acquire() => match p {
                        Ok(p) => p,
                        Err(_) => return, // semaphore closed
                    },
                };
                permit.forget(); // consume one budget unit
                // Build the raw segment Data through the prepared object (same
                // read+frame path the one-shot answer uses, so naming is identical).
                let seg_name = prepared.versioned_name.clone().append_segment(seg);
                match prepared.answer_interest(&seg_name, None).await {
                    Ok(Some(wire)) => {
                        if producer.publish(wire).await.is_err() {
                            return; // connection gone
                        }
                    }
                    _ => return, // out of range / source error
                }
                seg += 1;
            }
        });
    }

    // Serve loop: a subscription grants budget (the persistent PIT entry already
    // exists — the streamer fills it, so the responder is dropped); a plain
    // Interest is answered one-shot (metadata discovery + segment re-fetch).
    let prepared_for_serve = Arc::clone(&prepared);
    producer
        .serve(move |interest, responder| {
            let budget = Arc::clone(&budget);
            let prepared = Arc::clone(&prepared_for_serve);
            async move {
                if let Some(sr) = interest
                    .app_parameters()
                    .and_then(SubscriptionRequest::find_in)
                {
                    budget.add_permits(sr.max_data_count.max(1) as usize);
                } else if let Ok(Some(wire)) =
                    prepared.answer_interest(&interest.name, None).await
                {
                    responder.respond_bytes(wire).await.ok();
                }
            }
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Consumer, EngineAppExt, EngineBuilder, SubscribeOptions};
    use bytes::Bytes;
    use ndn_engine::EngineConfig;
    use ndn_packet::Name;
    use std::collections::HashMap;
    use std::time::Duration;

    /// The leaf streamer answers one persistent subscription with the whole
    /// object's segments (one-Interest-many-Data), in order, credit-gated — the
    /// "bulk over an NDN face without per-segment pull" half of the design.
    #[tokio::test]
    async fn streams_whole_object_over_one_subscription() {
        let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .expect("engine");
        let cancel = CancellationToken::new();

        let prefix: Name = "/localhost/leaf/content/f1".parse().unwrap();
        // 5 segments at 8 KiB.
        let payload: Vec<u8> = (0..34_000u32).map(|i| (i & 0xff) as u8).collect();
        let prepared = Arc::new(PreparedObject::build(
            prefix.clone(),
            Bytes::from(payload.clone()),
            8192,
        ));
        let last = prepared.last_seg;

        // Leaf: serve the object as a stream over an in-proc producer face.
        let producer = engine.register_producer(prefix.clone(), cancel.child_token());
        {
            let prepared = Arc::clone(&prepared);
            let cancel = cancel.child_token();
            tokio::spawn(async move {
                let _ = serve_object_stream(producer, prepared, cancel).await;
            });
        }

        // Subscriber: one persistent subscription; collect every streamed segment.
        let consumer: Consumer = engine.app_consumer(cancel.child_token());
        let mut sub = consumer
            .subscribe(
                prefix.clone(),
                SubscribeOptions {
                    max_data_count: (last + 1) as u32,
                    lifetime: Duration::from_secs(30),
                    ..SubscribeOptions::default()
                },
            )
            .await
            .expect("subscribe");

        let mut got: HashMap<u64, Bytes> = HashMap::new();
        while (got.len() as u64) <= last {
            let data = tokio::time::timeout(Duration::from_secs(5), sub.recv())
                .await
                .expect("no stall")
                .expect("recv");
            let seg = data
                .name
                .components()
                .last()
                .and_then(|c| c.as_segment())
                .expect("segment name");
            got.insert(seg, data.content().cloned().unwrap_or_default());
        }

        // Reassemble in segment order → must equal the source payload.
        let mut out = Vec::with_capacity(payload.len());
        for n in 0..=last {
            out.extend_from_slice(got.get(&n).expect("each segment streamed"));
        }
        assert_eq!(out, payload, "streamed segments reassemble to the source");
        cancel.cancel();
    }
}
