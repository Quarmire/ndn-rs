//! Reflexive-forwarding endpoint helpers (RICE §8 /
//! `draft-oran-icnrg-reflexive-forwarding`).
//!
//! Reflexive forwarding lets a *producer* send an Interest back to the
//! *consumer* of an in-flight exchange, along the reverse path, without the
//! consumer's name being routable. The consumer attaches a single-use
//! `REFLEXIVE_NAME` (`R`) to its forward Interest; each on-path forwarder
//! installs a temporary reverse route `R -> incoming face`; the producer then
//! Interests `R/<suffix>` and the engine routes it back along that path.
//!
//! Two roles, two helpers — both on `Consumer` (a producer pulls with a
//! side consumer face, mirroring `ndn-compute`'s `function_reflexive`):
//!
//! - [`Consumer::fetch_reflexive`] — the **advertiser**: send a forward
//!   Interest carrying `R`, serve the producer's reverse pull(s) under `R`,
//!   and return the forward Data.
//! - [`Consumer::pull_reflexive`] / [`Consumer::pull_reflexive_verified`] —
//!   the **puller**: from a received forward Interest, Interest `R/<suffix>`
//!   back along the reverse path and return the (optionally signature-checked)
//!   Data.
//!
//! ## Deployment note
//!
//! Reflexive forwarding has the *all-hops property*: every on-path forwarder
//! between the two endpoints must implement it (the reverse Interest is a new,
//! FIB-unroutable Interest that only resolves where a reverse route was
//! installed). Homogeneous `ndn-rs` meshes and first-hop-attached advertisers
//! satisfy this; heterogeneous paths do not.

use std::future::Future;
use std::time::Duration;

use crate::rt::Instant;

use bytes::Bytes;

use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp::is_lp_packet;
use ndn_packet::{Data, Interest};
use ndn_security::{SafeData, ValidationResult, Validator};

use crate::AppError;
use crate::consumer::{Consumer, decode_data_lp};

/// Re-exported for ergonomics: an unpredictable, single-use reflexive name.
pub use ndn_packet::encode::random_reflexive_name;

impl Consumer {
    /// Advertiser side. Send `forward` (a builder for the forward Interest)
    /// carrying the reflexive name `reflexive` (`R`), then serve the
    /// producer's reverse pulls — every Interest whose name falls under `R` is
    /// passed to `serve_reverse`, which returns the **Data wire** to answer it
    /// with (name it after the reverse Interest, and sign it if the puller
    /// will verify). Returns the forward Data once it arrives, or
    /// [`AppError::Timeout`].
    ///
    /// The forward Interest and the reverse pulls share this one face, so the
    /// reverse Data is multiplexed here rather than via a separate producer.
    pub async fn fetch_reflexive<F, Fut>(
        &mut self,
        forward: InterestBuilder,
        reflexive: ndn_packet::Name,
        timeout: Duration,
        serve_reverse: F,
    ) -> Result<Data, AppError>
    where
        F: FnMut(Interest) -> Fut,
        Fut: Future<Output = Result<Bytes, AppError>>,
    {
        let wire = forward.reflexive_name(reflexive.clone()).build();
        self.fetch_reflexive_wire(wire, reflexive, timeout, serve_reverse)
            .await
    }

    /// As [`fetch_reflexive`](Self::fetch_reflexive), but the caller supplies the
    /// fully-encoded forward Interest `wire` (which MUST already carry the
    /// reflexive name `reflexive`). Use this when the forward Interest is a
    /// *signed* command — e.g. a `/localhop/nfd/rib/register` whose signature
    /// must cover a builder-built body — so the reflexive name still rides along
    /// (in the unsigned body section) and the producer can pull back.
    pub async fn fetch_reflexive_wire<F, Fut>(
        &mut self,
        wire: Bytes,
        reflexive: ndn_packet::Name,
        timeout: Duration,
        mut serve_reverse: F,
    ) -> Result<Data, AppError>
    where
        F: FnMut(Interest) -> Fut,
        Fut: Future<Output = Result<Bytes, AppError>>,
    {
        self.send_raw(wire).await?;

        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(AppError::Timeout)?;
            let pkt = crate::rt::timeout(remaining, self.recv_raw())
                .await
                .map_err(|_| AppError::Timeout)?
                .ok_or(AppError::Closed)?;

            // A bare Interest under R is a reverse pull; anything else is the
            // forward Data (possibly LP-wrapped: Nack or fragment).
            if !is_lp_packet(&pkt)
                && let Ok(interest) = Interest::decode(pkt.clone())
                && interest.name.has_prefix(&reflexive)
            {
                let answer = serve_reverse(interest).await?;
                self.send_raw(answer).await?;
                continue;
            }
            return decode_data_lp(pkt);
        }
    }

    /// Puller side. From a received `forward` Interest (which must carry a
    /// reflexive name `R`), Interest `R/<suffix>` back along the reverse path
    /// and return the Data. Typically called from a `Producer`(crate::Producer)
    /// serve handler using a *side* `Consumer` on the same connection (the
    /// serve face is busy receiving the forward Interest).
    pub async fn pull_reflexive(
        &mut self,
        forward: &Interest,
        suffix: &str,
        timeout: Duration,
    ) -> Result<Data, AppError> {
        let reflexive = forward.reflexive_name().ok_or_else(|| {
            AppError::Protocol("forward Interest carries no reflexive name".into())
        })?;
        let name = (**reflexive).clone().append(suffix);
        let wire = InterestBuilder::new(name).lifetime(timeout).build();
        self.fetch_wire(wire, timeout + Duration::from_millis(500))
            .await
    }

    /// As [`pull_reflexive`](Self::pull_reflexive), but validate the pulled
    /// Data against `validator` and return [`SafeData`]. This is the
    /// authenticated reverse pull — e.g. a CA pulling a *signed* device
    /// approval, where the validated signer identity is the evidence.
    pub async fn pull_reflexive_verified(
        &mut self,
        forward: &Interest,
        suffix: &str,
        validator: &Validator,
        timeout: Duration,
    ) -> Result<SafeData, AppError> {
        let data = self.pull_reflexive(forward, suffix, timeout).await?;
        match validator.validate(&data).await {
            ValidationResult::Valid(safe) => Ok(*safe),
            ValidationResult::Invalid(e) => Err(AppError::Protocol(e.to_string())),
            ValidationResult::Pending => {
                Err(AppError::Protocol("certificate chain not resolved".into()))
            }
        }
    }
}
