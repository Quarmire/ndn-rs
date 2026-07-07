//! Sync-protocol abstraction over SVS, PSync, etc. Consumers subscribe
//! to a group prefix and the runtime picks the protocol.

use std::fmt;

use bytes::Bytes;
use ndn_packet::Name;

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
            cancel,
        }
    }

    /// Attach a two-phase-commit ack channel (used by the SVS driver when `auto_ack` is off).
    pub fn with_ack_channel(mut self, ack_tx: tokio::sync::mpsc::Sender<(String, u64)>) -> Self {
        self.ack_tx = Some(ack_tx);
        self
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
