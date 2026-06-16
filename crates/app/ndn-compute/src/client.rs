//! [`ComputeClient`] — the consumer-side counterpart to
//! [`ComputeService`](crate::ComputeService).
//!
//! Wraps an [`ndn_app::Consumer`] and frames typed arguments into the
//! invocation name, then decodes the response Data content into the result
//! type. [`call`](ComputeClient::call) targets transparent functions;
//! [`call_opaque`](ComputeClient::call_opaque) appends an unpredictable nonce
//! component and requests a fresh result, so opaque calls never alias.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use ndn_app::{AppError, Consumer};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Name, NameComponent};

use crate::codec::{ComputeArgs, ComputeValue};
use crate::registry::ComputeError;
use crate::thunk::Thunk;

const CALL_LIFETIME: Duration = Duration::from_millis(4000);

/// Why a [`ComputeClient`] call failed.
#[derive(Debug)]
pub enum ComputeClientError {
    /// The underlying fetch failed (timeout, Nack, connection, …).
    App(AppError),
    /// The response Data carried no content.
    NoContent,
    /// The response content could not be decoded into the result type.
    Decode(ComputeError),
    /// A job did not complete within the caller's `max_wait`.
    JobTimeout,
}

impl std::fmt::Display for ComputeClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComputeClientError::App(e) => write!(f, "compute call failed: {e}"),
            ComputeClientError::NoContent => write!(f, "compute response had no content"),
            ComputeClientError::Decode(e) => write!(f, "compute response decode failed: {e}"),
            ComputeClientError::JobTimeout => write!(f, "job did not finish within max_wait"),
        }
    }
}

impl std::error::Error for ComputeClientError {}

/// Consumer-side handle for invoking compute functions.
pub struct ComputeClient {
    consumer: Consumer,
}

impl ComputeClient {
    /// Wrap a [`Consumer`].
    pub fn new(consumer: Consumer) -> Self {
        Self { consumer }
    }

    /// Recover the wrapped [`Consumer`].
    pub fn into_inner(self) -> Consumer {
        self.consumer
    }

    /// Invoke a transparent function: build `<prefix>/<args…>`, fetch, and
    /// decode the result.
    pub async fn call<A, O>(
        &mut self,
        prefix: impl Into<Name>,
        args: A,
    ) -> Result<O, ComputeClientError>
    where
        A: ComputeArgs,
        O: ComputeValue,
    {
        let name = append_args(prefix.into(), &args);
        let data = self
            .consumer
            .fetch(name)
            .await
            .map_err(ComputeClientError::App)?;
        decode_result::<O>(data.content())
    }

    /// Invoke an opaque function: build `<prefix>/<args…>/<nonce>`, request a
    /// fresh result, fetch, and decode. The nonce keeps distinct calls from
    /// coalescing in the PIT or aliasing in the Content Store.
    pub async fn call_opaque<A, O>(
        &mut self,
        prefix: impl Into<Name>,
        args: A,
    ) -> Result<O, ComputeClientError>
    where
        A: ComputeArgs,
        O: ComputeValue,
    {
        let name = append_args(prefix.into(), &args).append_component(nonce_component());
        let builder = InterestBuilder::new(name)
            .must_be_fresh()
            .lifetime(CALL_LIFETIME);
        let data = self
            .consumer
            .fetch_with(builder)
            .await
            .map_err(ComputeClientError::App)?;
        decode_result::<O>(data.content())
    }

    /// Invoke a long-running job and block until the result is ready or
    /// `max_wait` elapses. Performs the thunk handshake: fetch the invocation
    /// name to obtain a thunk, then poll the thunk name every `poll_interval`
    /// (the first wait honors the thunk's ETA) until a non-thunk result arrives.
    /// Pair with [`ComputeService::job`](crate::ComputeService::job).
    pub async fn call_job<A, O>(
        &mut self,
        prefix: impl Into<Name>,
        args: A,
        poll_interval: Duration,
        max_wait: Duration,
    ) -> Result<O, ComputeClientError>
    where
        A: ComputeArgs,
        O: ComputeValue,
    {
        let invocation = append_args(prefix.into(), &args);
        self.run_job::<O>(invocation, poll_interval, max_wait).await
    }

    /// Like [`Self::call_job`], but for an
    /// [`opaque_job`](crate::ComputeService::opaque_job): appends a nonce so
    /// each call runs as its own job.
    pub async fn call_opaque_job<A, O>(
        &mut self,
        prefix: impl Into<Name>,
        args: A,
        poll_interval: Duration,
        max_wait: Duration,
    ) -> Result<O, ComputeClientError>
    where
        A: ComputeArgs,
        O: ComputeValue,
    {
        let invocation = append_args(prefix.into(), &args).append_component(nonce_component());
        self.run_job::<O>(invocation, poll_interval, max_wait).await
    }

    async fn run_job<O>(
        &mut self,
        invocation: Name,
        poll_interval: Duration,
        max_wait: Duration,
    ) -> Result<O, ComputeClientError>
    where
        O: ComputeValue,
    {
        let data = self
            .consumer
            .fetch(invocation)
            .await
            .map_err(ComputeClientError::App)?;
        let content = data.content().ok_or(ComputeClientError::NoContent)?;
        let thunk = Thunk::from_content(content).ok_or_else(|| {
            ComputeClientError::Decode(ComputeError::ComputeFailed(
                "job invocation did not return a thunk".into(),
            ))
        })?;
        let thunk_name = thunk.thunk_name;

        let deadline = Instant::now() + max_wait;
        let mut wait = thunk.eta.min(poll_interval);
        loop {
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
            let builder = InterestBuilder::new(thunk_name.clone())
                .must_be_fresh()
                .lifetime(CALL_LIFETIME);
            let data = self
                .consumer
                .fetch_with(builder)
                .await
                .map_err(ComputeClientError::App)?;
            let content = data.content().ok_or(ComputeClientError::NoContent)?;
            if Thunk::content_is_thunk(content) {
                if Instant::now() >= deadline {
                    return Err(ComputeClientError::JobTimeout);
                }
                wait = poll_interval;
                continue;
            }
            return O::decode(content).map_err(ComputeClientError::Decode);
        }
    }
}

fn append_args<A: ComputeArgs>(mut name: Name, args: &A) -> Name {
    for comp in args.to_components() {
        name = name.append_component(comp);
    }
    name
}

fn decode_result<O: ComputeValue>(content: Option<&Bytes>) -> Result<O, ComputeClientError> {
    let content = content.ok_or(ComputeClientError::NoContent)?;
    O::decode(content).map_err(ComputeClientError::Decode)
}

/// A 64-bit nonce as a hex `GenericNameComponent`. Mixes the wall clock with a
/// process-local counter so concurrent calls differ; hardened deployments that
/// need unpredictability against an adversary should supply a CSPRNG-backed
/// component instead.
fn nonce_component() -> NameComponent {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = CTR.fetch_add(1, Ordering::Relaxed);
    let nonce = nanos ^ seq.rotate_left(32);
    NameComponent::generic(Bytes::from(format!("{nonce:016x}")))
}
