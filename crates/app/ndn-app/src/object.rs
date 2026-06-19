//! [`ObjectFetch`] — one fluent builder for RDR object fetches.
//!
//! Replaces the `fetch_object` / `_verified` / `_verified_hinted` /
//! `_verified_hinted_progress` / `_streaming` / `_into` /
//! `_to_file_hinted_progress` method explosion on [`Consumer`] with a single
//! composable chain that reads top-to-bottom:
//!
//! ```no_run
//! # use ndn_app::Node;
//! # use std::sync::Arc;
//! # async fn run(node: Node, validator: ndn_security::Validator) -> Result<(), Box<dyn std::error::Error>> {
//! // simple
//! let bytes = node.object("/alice/photo").fetch().await?;
//!
//! // verified + forwarding hint + a progress bar
//! let bytes = node.object("/alice/photo")
//!     .verify(validator)
//!     .hint(["/gateway"])
//!     .progress(|done, total| eprintln!("{done}/{total}"))
//!     .fetch().await?;
//! # let _ = bytes; Ok(()) }
//! ```
//!
//! Three terminal verbs pick the delivery shape: [`fetch`](ObjectFetch::fetch)
//! (whole object in memory), [`stream`](ObjectFetch::stream) (each segment to a
//! callback, flat memory), and [`to_file`](ObjectFetch::to_file) (positioned
//! writes to a file, flat memory; unix, requires `verify`).

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_security::Validator;

use crate::consumer::Consumer;
use crate::error::AppError;

type ProgressFn = Box<dyn FnMut(u64, u64) + Send>;

/// A configured-but-not-yet-run object fetch. Build it with
/// [`Node::object`](crate::Node::object) or [`Consumer::object`], chain the
/// optional modifiers, then call one terminal verb.
pub struct ObjectFetch {
    consumer: Consumer,
    name: Name,
    validator: Option<Arc<Validator>>,
    hint: Vec<Name>,
    progress: Option<ProgressFn>,
}

impl ObjectFetch {
    pub(crate) fn new(consumer: Consumer, name: Name) -> Self {
        Self {
            consumer,
            name,
            validator: None,
            hint: Vec::new(),
            progress: None,
        }
    }

    /// Verify the metadata Data and every segment against `validator` before
    /// accepting their bytes (the secure RDR path). Without this, segments are
    /// taken unverified.
    pub fn verify(mut self, validator: impl Into<Arc<Validator>>) -> Self {
        self.validator = Some(validator.into());
        self
    }

    /// Attach a `ForwardingHint` (one or more delegation names) to every
    /// Interest in the fetch — for fetching across a producer's mobility anchor.
    pub fn hint(mut self, hint: impl IntoIterator<Item = impl Into<Name>>) -> Self {
        self.hint = hint.into_iter().map(Into::into).collect();
        self
    }

    /// Report progress as `(bytes_received, bytes_total)` — drive a download bar.
    /// `total` is 0 until the producer's declared size is known.
    pub fn progress(mut self, f: impl FnMut(u64, u64) + Send + 'static) -> Self {
        self.progress = Some(Box::new(f));
        self
    }

    fn progress_or_noop(&mut self) -> ProgressFn {
        self.progress.take().unwrap_or_else(|| Box::new(|_, _| {}))
    }

    /// Fetch the whole object into memory, segments reassembled in order.
    pub async fn fetch(mut self) -> Result<Bytes, AppError> {
        let validator = self.validator.clone();
        let hint = std::mem::take(&mut self.hint);
        let progress = self.progress_or_noop();
        let mut chunks: Vec<(u64, Bytes)> = Vec::new();
        self.consumer
            .fetch_object_streaming(
                self.name,
                validator,
                &hint,
                |_| false,
                progress,
                |seg, bytes| {
                    chunks.push((seg, bytes));
                    Ok(())
                },
            )
            .await?;
        chunks.sort_by_key(|(seg, _)| *seg);
        let mut out = bytes::BytesMut::new();
        for (_, b) in chunks {
            out.extend_from_slice(&b);
        }
        Ok(out.freeze())
    }

    /// Stream each segment to `on_segment(seg_index, bytes)` as it arrives over
    /// the congestion-controlled pipeline, so memory stays flat regardless of
    /// object size. `already_have(seg) == true` skips a segment (resume). Returns
    /// the producer-declared object size in bytes (0 if unadvertised).
    pub async fn stream(
        mut self,
        already_have: impl Fn(u64) -> bool,
        on_segment: impl FnMut(u64, Bytes) -> Result<(), AppError>,
    ) -> Result<u64, AppError> {
        let validator = self.validator.clone();
        let hint = std::mem::take(&mut self.hint);
        let progress = self.progress_or_noop();
        self.consumer
            .fetch_object_streaming(self.name, validator, &hint, already_have, progress, on_segment)
            .await
    }

    /// Fetch the whole object and deserialize it from JSON into `T` — the typed
    /// counterpart to [`Node::serve_object_typed`](crate::Node::serve_object_typed).
    /// All modifiers (`verify` / `hint` / `progress`) apply.
    #[cfg(feature = "serde")]
    pub async fn fetch_as<T: serde::de::DeserializeOwned>(self) -> Result<T, AppError> {
        let bytes = self.fetch().await?;
        serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Protocol(format!("object JSON decode: {e}")))
    }

    /// Stream verified segments straight to `file` at their byte offsets
    /// (positioned writes), so an arbitrarily large object lands on disk without
    /// ever being held in memory. Returns total bytes written.
    ///
    /// Requires [`verify`](Self::verify) — a large download should authenticate;
    /// without it this returns [`AppError::Unsupported`]. Unix only.
    #[cfg(unix)]
    pub async fn to_file(mut self, file: &std::fs::File) -> Result<u64, AppError> {
        let validator = self.validator.clone().ok_or_else(|| {
            AppError::Unsupported("object(..).to_file(..) requires .verify(validator)".into())
        })?;
        let hint = std::mem::take(&mut self.hint);
        let progress = self.progress_or_noop();
        #[allow(deprecated)] // this builder IS the replacement; it owns the impl path
        self.consumer
            .fetch_object_to_file_hinted_progress(self.name, validator, &hint, file, progress)
            .await
    }
}
