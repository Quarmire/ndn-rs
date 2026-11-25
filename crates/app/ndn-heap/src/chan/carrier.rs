//! What a node's channel frames are handed to: the **carrier**, a link's way to send a frame as a
//! datagram or on its stream (docs/specs/channel.md, The carrier a face must provide).
//!
//! `ndn-heap` cannot depend on the faces (`ndn-face-quic`, `ndn-transport`'s `Face::send_side`), so
//! the host gives the node a [`Carrier`] and the node never sees a link. Until the forwarder's side
//! table routes frames (stage 4) a node has **one fixed route**: [`NodeHandle::attach_carrier`]
//! installs the carrier every channel frame of every channel goes to.
//!
//! # What a carrier MUST do
//!
//! * [`Carrier::datagram_max`] is the largest datagram frame the path takes **now** (it follows path
//!   MTU discovery: the sender reads it for every frame). `0` says the carrier has no datagram class.
//! * [`Carrier::try_send_datagram`] never blocks and never waits for room. It takes the frame, or
//!   refuses it: [`CarrierRefused::Full`] when the carrier's headroom rule says the link has enough
//!   queued ahead (docs/specs/ndn-link.md: the rate-aware headroom, `QUEUE_FLOOR` to `QUEUE_CAP`);
//!   [`CarrierRefused::TooLarge`] when the path no longer takes a frame of this size (it names the
//!   size that fits); [`CarrierRefused::Closed`] when the link is gone.
//! * [`Carrier::send_stream`] takes a whole frame onto the ordered, reliable stream, in the order it
//!   is called, and completes when the stream accepted it: it waits for flow control. The sender
//!   never calls it again before the previous call completed, and it **does not drop the future**
//!   of a call in progress (a frame is written whole or not at all, so the future needs no cancel
//!   safety). [`Carrier::has_stream`] says whether the class exists.
//! * [`Carrier::on_ready`] is how a datagram that was refused with `Full` is sent later with no timer
//!   and no task of the node's: the sender gives the carrier a closure, and the carrier **calls it
//!   once, from its own writer task, when `try_send_datagram` would take a frame again** (at once
//!   if it already would). The closure sends what waits, never blocks, and may call
//!   `try_send_datagram` and `on_ready` itself. A carrier that never calls it leaves the messages
//!   that were refused waiting until the next emission finds the link ready; a carrier that is
//!   dropped may drop the closures unrun. The closure may be called from any thread.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use parking_lot::RwLock;

use crate::host::NodeHandle;

/// The future of a [`Carrier::send_stream`].
#[cfg(not(target_arch = "wasm32"))]
pub type CarrierFuture<'a, T> = futures::future::BoxFuture<'a, T>;
/// The future of a [`Carrier::send_stream`].
#[cfg(target_arch = "wasm32")]
pub type CarrierFuture<'a, T> = futures::future::LocalBoxFuture<'a, T>;

/// Why a carrier did not take a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierRefused {
    /// The link has enough queued ahead (the headroom rule): try again when [`Carrier::on_ready`]
    /// calls back.
    Full,
    /// The path does not take a frame this size now; a frame of at most `max` octets does.
    TooLarge {
        /// The largest frame the path takes.
        max: usize,
    },
    /// The link is gone: nothing more will be taken.
    Closed,
}

/// A link's way to send a channel frame.
pub trait Carrier: Send + Sync {
    /// The largest datagram frame the path takes now; 0 if the carrier has no datagram class.
    fn datagram_max(&self) -> usize;

    /// Whether the carrier has an ordered, reliable stream.
    fn has_stream(&self) -> bool;

    /// Send `frame` as a datagram now, or say why not. Never blocks.
    fn try_send_datagram(&self, frame: Bytes) -> Result<(), CarrierRefused>;

    /// Send `frame` on the stream; completes when the stream took it.
    fn send_stream(&self, frame: Bytes) -> CarrierFuture<'_, Result<(), CarrierRefused>>;

    /// Call `drain` once, from the carrier's writer task, when a datagram would be taken again.
    fn on_ready(&self, drain: Box<dyn FnOnce() + Send>);
}

/// The node's fixed route: the carrier frames go to, if one was attached.
#[derive(Default)]
pub(crate) struct CarrierSlot {
    carrier: RwLock<Option<Arc<dyn Carrier>>>,
    /// Counts the carriers attached (0: none yet): a drain asked of an earlier carrier is not one
    /// asked of this.
    generation: AtomicU64,
}

impl CarrierSlot {
    /// The carrier, if one is attached.
    pub(crate) fn get(&self) -> Option<Arc<dyn Carrier>> {
        self.carrier.read().clone()
    }

    /// Which carrier is attached: 0 for none, then 1, 2, … for each one attached.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) fn set(&self, carrier: Arc<dyn Carrier>) {
        *self.carrier.write() = Some(carrier);
        self.generation.fetch_add(1, Ordering::AcqRel);
    }
}

impl NodeHandle {
    /// Install the carrier every channel frame of every channel is sent to: the node's fixed route
    /// until the forwarder's side table routes frames. A second call replaces the first.
    pub fn attach_carrier(&self, carrier: Arc<dyn Carrier>) {
        self.inner.chan.tx.carrier.set(carrier);
    }
}
