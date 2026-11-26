//! What a node does when a frame it took proves that the face it came over delivered a forgery
//! (docs/specs/channel.md): it asks its forwarder to **bar** that face from carrying channel frames.
//!
//! `ndn-heap` cannot reach a forwarder's side table, so the host gives the node an [`IngressBar`]
//! ([`NodeHandle::attach_bar`]); [`NodeHandle::attach_forwarder`](crate::host::NodeHandle) attaches
//! one over the node's own connection. The `ingress` a frame is delivered with
//! ([`NodeHandle::deliver_frame`](crate::host::NodeHandle::deliver_frame)) is the forwarder's face
//! id, and it is the number [`IngressBar::bar`] takes back.

use std::sync::Arc;

use parking_lot::RwLock;

use crate::host::NodeHandle;

/// Bars a face from carrying channel frames.
pub trait IngressBar: Send + Sync {
    /// Bar the face `ingress` (the number frames were delivered with) from channel frames, for as
    /// long as the forwarder says. Never blocks; a bar that cannot be applied is the host's to
    /// report.
    fn bar(&self, ingress: u64);
}

/// The node's bar, if the host attached one.
#[derive(Default)]
pub(crate) struct BarSlot {
    bar: RwLock<Option<Arc<dyn IngressBar>>>,
}

impl BarSlot {
    /// The bar, if one is attached.
    pub(crate) fn get(&self) -> Option<Arc<dyn IngressBar>> {
        self.bar.read().clone()
    }

    fn set(&self, bar: Arc<dyn IngressBar>) {
        *self.bar.write() = Some(bar);
    }
}

impl NodeHandle {
    /// Install what bars a face from channel frames when a frame that came over it is shown to
    /// be a forgery. A second call replaces the first. Without one the node still alerts, and
    /// bars nothing.
    pub fn attach_bar(&self, bar: Arc<dyn IngressBar>) {
        self.inner.chan.bar.set(bar);
    }
}
