//! Sync protocol trait — abstraction over SVS, PSync, etc.
//!
//! Consumers don't choose a sync protocol directly; they subscribe to a
//! group prefix and the runtime picks the appropriate protocol.

use std::fmt;

use ndn_packet::Name;

/// A notification that new data is available from a peer.
#[derive(Clone, Debug)]
pub struct SyncUpdate {
    /// The peer that published new data.
    pub publisher: String,
    /// Name prefix under which the new data can be fetched.
    pub name: Name,
    /// Sequence range of new publications: [low, high] inclusive.
    pub low_seq: u64,
    pub high_seq: u64,
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

/// Error type for sync protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sync I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connection lost")]
    Disconnected,
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Handle to a running sync group.
///
/// Returned by [`SyncProtocol::join`].  Provides a channel for receiving
/// updates and a method for announcing local publications.
pub struct SyncHandle {
    /// Receive sync updates (new data available from peers).
    pub rx: tokio::sync::mpsc::Receiver<SyncUpdate>,
    /// Send local publications into the sync group.
    pub tx: tokio::sync::mpsc::Sender<Name>,
    /// Cancel the sync background task.
    cancel: tokio_util::sync::CancellationToken,
}

impl SyncHandle {
    pub fn new(
        rx: tokio::sync::mpsc::Receiver<SyncUpdate>,
        tx: tokio::sync::mpsc::Sender<Name>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self { rx, tx, cancel }
    }

    /// Receive the next sync update. Returns `None` when the group is closed.
    pub async fn recv(&mut self) -> Option<SyncUpdate> {
        self.rx.recv().await
    }

    /// Announce that we published new data under `name`.
    pub async fn publish(&self, name: Name) -> Result<(), SyncError> {
        self.tx.send(name).await.map_err(|_| SyncError::Disconnected)
    }

    /// Leave the sync group.
    pub fn leave(self) {
        self.cancel.cancel();
    }
}

impl Drop for SyncHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
