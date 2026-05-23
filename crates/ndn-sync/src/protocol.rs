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
}

pub struct SyncHandle {
    /// Updates from peers.
    pub rx: tokio::sync::mpsc::Receiver<SyncUpdate>,
    /// `(publication_name, optional_mapping_bytes)` into the group.
    pub tx: tokio::sync::mpsc::Sender<(Name, Option<Bytes>)>,
    cancel: tokio_util::sync::CancellationToken,
}

impl SyncHandle {
    pub fn new(
        rx: tokio::sync::mpsc::Receiver<SyncUpdate>,
        tx: tokio::sync::mpsc::Sender<(Name, Option<Bytes>)>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self { rx, tx, cancel }
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

    pub fn leave(self) {
        self.cancel.cancel();
    }
}

impl Drop for SyncHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
