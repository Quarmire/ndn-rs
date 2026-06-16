//! Ergonomic producer/consumer FEC API (feature `endpoint`).
//!
//! [`CodedProducer`] turns a published payload into K source + (N−K)
//! parity Data segments and serves them by name; [`CodedFetcher`] pulls
//! K-of-N segments with a pipelined window, over-fetching parity when a
//! segment is slow or lost, and recovers the payload as soon as the
//! decoder reaches rank K.
//!
//! These wrap the [`segment_payload`] / [`CodedAssembler`] building
//! blocks with the `ndn-app` [`Producer`] / [`Consumer`]. The forwarder
//! is untouched: every coded segment is an ordinary named, signed Data
//! object, and the multipath/multi-cache benefit of FEC comes from the
//! forwarder's own strategy answering different segment Interests over
//! different next-hops. The fetcher's job is the *adaptive K-of-N
//! selection* — fetch sources first, substitute parity on loss — not
//! intra-path parallelism (a single [`Connection`](ndn_app::Connection)
//! cannot correlate concurrent Interests without PIT tokens, so the
//! window is correlated app-side by the FEC index in each segment's
//! metadata).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_app::{AppError, Consumer, Producer};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Interest, Name};

use crate::CodingError;
use crate::assembler::CodedAssembler;
use crate::metadata::split_metadata;
use crate::policy::FecPolicy;
use crate::segmenter::segment_payload;

/// Error from the endpoint API: an FEC/codec error, an `ndn-app`
/// transport error, or a fetch that ran out of time before the decoder
/// reached rank K.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// FEC parameter / codec failure.
    #[error(transparent)]
    Coding(#[from] CodingError),
    /// Underlying `ndn-app` Consumer/Producer error.
    #[error(transparent)]
    App(#[from] AppError),
    /// The total deadline elapsed with fewer than K independent
    /// segments recovered.
    #[error("fetch incomplete: recovered rank {have} of {needed} before deadline")]
    Incomplete {
        /// Independent segments absorbed so far.
        have: u16,
        /// Segments (K) required to decode.
        needed: u16,
    },
}

/// Parse the trailing component of `name` as an ASCII-decimal FEC
/// segment index, given that `name` is exactly `object` plus one
/// component. Returns `None` for any other shape.
fn segment_index(name: &Name, object: &Name) -> Option<u16> {
    if name.len() != object.len() + 1 || !name.has_prefix(object) {
        return None;
    }
    let comp = name.components().last()?;
    std::str::from_utf8(&comp.value).ok()?.parse::<u16>().ok()
}

/// Segment name for `object` and FEC `index`: `<object>/<index>`.
fn segment_name(object: &Name, index: u16) -> Name {
    object.clone().append(index.to_string())
}

/// Producer-side coded publish: encode one payload as a generation and
/// serve its N coded segments by name.
pub struct CodedProducer {
    producer: Producer,
    policy: FecPolicy,
}

impl CodedProducer {
    /// Wrap a [`Producer`] with the FEC `policy` applied to published
    /// objects. The producer's registered prefix must cover the objects
    /// passed to [`serve_object`](Self::serve_object).
    pub fn new(producer: Producer, policy: FecPolicy) -> Self {
        Self { producer, policy }
    }

    /// The FEC policy this producer encodes under.
    pub fn policy(&self) -> &FecPolicy {
        &self.policy
    }

    /// Encode `payload` as generation `generation_id` and serve the
    /// resulting N coded segments at `<object>/<index>` until the engine
    /// closes the producer's face. Interests for an unknown index are
    /// dropped (the consumer must fall back to another segment).
    ///
    /// `object` must lie under the producer's registered prefix.
    pub async fn serve_object(
        self,
        object: Name,
        payload: Bytes,
        generation_id: u64,
    ) -> Result<(), EndpointError> {
        let plan = segment_payload(&payload, &self.policy, generation_id)?;
        let table: Arc<std::collections::HashMap<u16, Bytes>> =
            Arc::new(plan.into_iter().map(|s| (s.index, s.content)).collect());
        let object = Arc::new(object);

        self.producer
            .serve(move |interest: Interest, responder| {
                let table = Arc::clone(&table);
                let object = Arc::clone(&object);
                async move {
                    let name = (*interest.name).clone();
                    let Some(idx) = segment_index(&name, &object) else {
                        return;
                    };
                    if let Some(content) = table.get(&idx) {
                        let wire = DataBuilder::new(name, content).build();
                        let _ = responder.respond_bytes(wire).await;
                    }
                }
            })
            .await?;
        Ok(())
    }
}

/// Tunables for the consumer K-of-N fetch loop.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Maximum simultaneously-outstanding segment Interests.
    pub window: usize,
    /// How long to wait for *any* segment before assuming one was lost
    /// and over-fetching the next index.
    pub segment_timeout: Duration,
    /// Overall deadline for recovering the object.
    pub total_timeout: Duration,
    /// Interest lifetime stamped on each segment Interest.
    pub lifetime: Duration,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            window: 8,
            segment_timeout: Duration::from_millis(600),
            total_timeout: Duration::from_secs(12),
            lifetime: Duration::from_millis(4000),
        }
    }
}

/// Consumer-side coded fetch: pull K-of-N segments and recover the
/// payload.
#[derive(Debug, Default, Clone)]
pub struct CodedFetcher {
    config: FetchConfig,
}

impl CodedFetcher {
    /// A fetcher with default tunables.
    pub fn new() -> Self {
        Self::default()
    }

    /// A fetcher with explicit tunables.
    pub fn with_config(config: FetchConfig) -> Self {
        Self { config }
    }

    async fn send_index(
        &self,
        consumer: &Consumer,
        object: &Name,
        index: u16,
    ) -> Result<(), AppError> {
        let wire = InterestBuilder::new(segment_name(object, index))
            .lifetime(self.config.lifetime)
            .must_be_fresh()
            .build();
        consumer.send_raw(wire).await
    }

    /// Fetch the coded segments of `object` under `policy` and recover
    /// the original payload once any K of the N segments decode.
    ///
    /// `consumer` should be dedicated to this fetch for the duration of
    /// the call: the loop sends segment Interests with [`send_raw`] and
    /// drains replies with [`recv_data`], correlating them by the FEC
    /// index carried in each segment's metadata.
    ///
    /// [`send_raw`]: ndn_app::Consumer::send_raw
    /// [`recv_data`]: ndn_app::Consumer::recv_data
    pub async fn fetch(
        &self,
        consumer: &Consumer,
        object: Name,
        policy: &FecPolicy,
    ) -> Result<Bytes, EndpointError> {
        let n = policy.n;
        let mut asm = CodedAssembler::new();
        let mut seen: HashSet<u16> = HashSet::new();
        let mut next: u16 = 0;
        let mut outstanding: usize = 0;
        let deadline = Instant::now() + self.config.total_timeout;

        // Prime the pipeline with up to `window` source-segment Interests.
        let prime = self.config.window.min(n as usize) as u16;
        while next < prime {
            self.send_index(consumer, &object, next).await?;
            next += 1;
            outstanding += 1;
        }

        loop {
            // Nothing left in flight and nothing left to request → done.
            if outstanding == 0 && next >= n {
                return Err(EndpointError::Incomplete {
                    have: asm.rank(),
                    needed: policy.k,
                });
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(EndpointError::Incomplete {
                    have: asm.rank(),
                    needed: policy.k,
                });
            }
            let wait = self.config.segment_timeout.min(deadline - now);

            match tokio::time::timeout(wait, consumer.recv_data()).await {
                Ok(Ok(data)) => {
                    outstanding = outstanding.saturating_sub(1);
                    if let Some(content) = data.content()
                        && let Ok((meta, _)) = split_metadata(content)
                        && seen.insert(meta.index)
                    {
                        // Ignore segments that disagree with the
                        // established generation (stray traffic on the
                        // connection); a real decode yields the payload.
                        if let Ok(Some(payload)) = asm.absorb_content(content) {
                            return Ok(payload);
                        }
                    }
                    if next < n {
                        self.send_index(consumer, &object, next).await?;
                        next += 1;
                        outstanding += 1;
                    }
                }
                // Connection closed underneath us.
                Ok(Err(e)) => return Err(e.into()),
                // No segment arrived in time: a source is probably lost,
                // so pull the next (parity) index to make up the rank.
                Err(_) => {
                    if next < n {
                        self.send_index(consumer, &object, next).await?;
                        next += 1;
                        outstanding += 1;
                    } else if outstanding == 0 {
                        return Err(EndpointError::Incomplete {
                            have: asm.rank(),
                            needed: policy.k,
                        });
                    }
                }
            }
        }
    }
}
