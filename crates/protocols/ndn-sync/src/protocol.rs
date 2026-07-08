//! Sync-protocol abstraction over SVS, PSync, etc. Consumers subscribe
//! to a group prefix and the runtime picks the protocol.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use ndn_packet::Name;

/// Read-only, observational per-**name** high-water: the highest `(boot, seq)`
/// any peer has advertised for a name, recorded from inbound Sync Interests.
///
/// Under two-phase commit (`auto_ack: false`) a peer's state vector advances a
/// name only once it has *verified and stored* that publication, so this is the
/// honest "carried" signal — "this named data has been verified+stored to seq X
/// somewhere in the group." Because it is recorded WITHOUT the merge's
/// authoritative-for-self guard, a publisher can read the group's carriage of
/// its OWN name (which [`crate::svs::SvsNode::merge`] deliberately drops).
///
/// It is keyed by **name (data), never by peer/device.** An SVS Sync Interest
/// carries no sender identity, and the substrate deliberately mints no
/// who-has-what device roster (ndf-apps AD-9) — so this is a **depth on the
/// data, not a count of hosts.** It is STRICTLY observational: never consulted
/// in the validity or fetch path (mirrors `SyncUpdate::serving_party` / N-3).
#[derive(Debug, Default)]
pub struct ObservedState {
    map: RwLock<HashMap<Name, (u64, u64)>>,
}

impl ObservedState {
    /// Record one advertised `(name, boot, seq)`, keeping the highest
    /// `(boot, seq)` seen (boot-major, matching the SVS ordering). Called by the
    /// SVS task for every entry of every *authenticated* inbound Sync Interest —
    /// including entries naming the local node.
    pub(crate) fn record(&self, name: &Name, boot: u64, seq: u64) {
        let mut map = self.map.write().expect("ObservedState poisoned");
        let slot = map.entry(name.clone()).or_insert((0, 0));
        if (boot, seq) > *slot {
            *slot = (boot, seq);
        }
    }

    /// Highest observed seq for `name` (boot ignored), or `None` if never
    /// advertised — the "carried to seq X" depth for that named data.
    pub fn seq_for(&self, name: &Name) -> Option<u64> {
        self.map
            .read()
            .expect("ObservedState poisoned")
            .get(name)
            .map(|&(_, s)| s)
    }

    /// Highest observed `(boot, seq)` for `name`, or `None`.
    pub fn get(&self, name: &Name) -> Option<(u64, u64)> {
        self.map
            .read()
            .expect("ObservedState poisoned")
            .get(name)
            .copied()
    }

    /// Snapshot of every observed `(name, boot, seq)`, ordered by name for
    /// stable output — the group's advertised high-water per name.
    pub fn snapshot(&self) -> Vec<(Name, u64, u64)> {
        let map = self.map.read().expect("ObservedState poisoned");
        let mut out: Vec<_> = map.iter().map(|(n, &(b, s))| (n.clone(), b, s)).collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

#[derive(Clone, Debug)]
pub struct SyncUpdate {
    pub publisher: String,
    /// Prefix under which the new data can be fetched.
    pub name: Name,
    /// `[low, high]` inclusive sequence range of new publications.
    pub low_seq: u64,
    pub high_seq: u64,
    /// ndnSVS `MappingData`. Application-defined; convention is a
    /// `Name` TLV (type 7) so the consumer can fast-path the fetch.
    pub mapping: Option<Bytes>,
    /// Who is *serving* this data, when distinct from `publisher` (the author) — e.g. a relayer under
    /// D-40 A.2 multi-relayer. **Advisory / provenance only; never consulted in validity** (a serving
    /// party is not a data-identity dimension). `None` when the serving party is the publisher itself
    /// or is unknown at the sync layer (the consumer fills it from the fetch face when it matters).
    pub serving_party: Option<String>,
}

impl fmt::Display for SyncUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.low_seq == self.high_seq {
            write!(f, "{}#{}", self.name, self.low_seq)
        } else {
            write!(f, "{}#{}..{}", self.name, self.low_seq, self.high_seq)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sync I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connection lost")]
    Disconnected,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("operation not supported by this sync protocol")]
    Unsupported,
}

pub struct SyncHandle {
    /// Updates from peers.
    pub rx: tokio::sync::mpsc::Receiver<SyncUpdate>,
    /// `(publication_name, optional_mapping_bytes)` into the group.
    pub tx: tokio::sync::mpsc::Sender<(Name, Option<Bytes>)>,
    /// Prefix subscriptions — only wired in asymmetric protocols (PSync
    /// Partial). `None` for symmetric protocols (SVS, PSync Full) where
    /// every node tracks the whole set; [`SyncHandle::subscribe`] then
    /// returns [`SyncError::Unsupported`].
    subscribe_tx: Option<tokio::sync::mpsc::Sender<Name>>,
    /// Two-phase-commit acks — `(publisher_key, seq)` the app has validated + stored (D-44 / N-3).
    /// `None` under `auto_ack` (the SVS default) or for protocols without deferred merge; then
    /// [`SyncHandle::ack`] is a no-op the caller can safely make unconditionally.
    ack_tx: Option<tokio::sync::mpsc::Sender<(String, u64)>>,
    /// Observed per-name high-water (N-9), shared read-only with the SVS task
    /// that records it. `None` for protocols that don't observe peer vectors
    /// (PSync). Strictly observational — never on the validity/fetch path.
    observed: Option<Arc<ObservedState>>,
    cancel: tokio_util::sync::CancellationToken,
}

impl SyncHandle {
    pub fn new(
        rx: tokio::sync::mpsc::Receiver<SyncUpdate>,
        tx: tokio::sync::mpsc::Sender<(Name, Option<Bytes>)>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self {
            rx,
            tx,
            subscribe_tx: None,
            ack_tx: None,
            observed: None,
            cancel,
        }
    }

    /// Attach a two-phase-commit ack channel (used by the SVS driver when `auto_ack` is off).
    pub fn with_ack_channel(mut self, ack_tx: tokio::sync::mpsc::Sender<(String, u64)>) -> Self {
        self.ack_tx = Some(ack_tx);
        self
    }

    /// Attach the observed per-name high-water store (N-9; the SVS driver shares
    /// the handle it records into). See [`ObservedState`] and [`Self::observed`].
    pub fn with_observed(mut self, observed: Arc<ObservedState>) -> Self {
        self.observed = Some(observed);
        self
    }

    /// The read-only observed per-name high-water — the honest "carried" depth
    /// ("this named data has been verified+stored to seq X somewhere in the
    /// group", under `auto_ack: false`). `None` for protocols that don't record
    /// it (PSync). A depth keyed by name, never a per-device roster (AD-9); see
    /// [`ObservedState`].
    pub fn observed(&self) -> Option<&ObservedState> {
        self.observed.as_deref()
    }

    /// Like [`SyncHandle::new`], but with a subscription channel — used by
    /// the PSync Partial consumer so [`SyncHandle::subscribe`] is honored.
    pub fn with_subscribe(
        rx: tokio::sync::mpsc::Receiver<SyncUpdate>,
        tx: tokio::sync::mpsc::Sender<(Name, Option<Bytes>)>,
        subscribe_tx: tokio::sync::mpsc::Sender<Name>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self {
            rx,
            tx,
            subscribe_tx: Some(subscribe_tx),
            ack_tx: None,
            observed: None,
            cancel,
        }
    }

    /// Subscribe to a producer prefix. Honored only by the PSync Partial
    /// consumer (it adds the prefix to the Bloom-filter subscription set);
    /// returns [`SyncError::Unsupported`] for symmetric protocols.
    pub async fn subscribe(&self, prefix: Name) -> Result<(), SyncError> {
        match &self.subscribe_tx {
            Some(tx) => tx.send(prefix).await.map_err(|_| SyncError::Disconnected),
            None => Err(SyncError::Unsupported),
        }
    }

    /// Returns `None` when the group is closed.
    pub async fn recv(&mut self) -> Option<SyncUpdate> {
        self.rx.recv().await
    }

    pub async fn publish(&self, name: Name) -> Result<(), SyncError> {
        self.tx
            .send((name, None))
            .await
            .map_err(|_| SyncError::Disconnected)
    }

    /// `mapping` is forwarded to peers via the `MappingData` TLV in
    /// the next Sync Interest. A common convention is to pass a Name
    /// TLV so the consumer can fast-path the fetch.
    pub async fn publish_with_mapping(&self, name: Name, mapping: Bytes) -> Result<(), SyncError> {
        self.tx
            .send((name, Some(mapping)))
            .await
            .map_err(|_| SyncError::Disconnected)
    }

    /// Two-phase commit (D-44 / N-3): tell the sync layer that publication `(publisher, seq)` has been
    /// validated and stored, so it may now advance its state vector for it. Under `auto_ack` (the
    /// default) merges advance eagerly and this is a no-op — so a consumer can call it unconditionally.
    /// A rejected/held item is simply *not* acked, and its gap stays visible (no poison).
    pub async fn ack(&self, publisher: &str, seq: u64) -> Result<(), SyncError> {
        match &self.ack_tx {
            Some(tx) => tx.send((publisher.to_string(), seq)).await.map_err(|_| SyncError::Disconnected),
            None => Ok(()),
        }
    }

    pub fn leave(self) {
        self.cancel.cancel();
    }
}

impl Drop for SyncHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
