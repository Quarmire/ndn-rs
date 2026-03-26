use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use ndn_packet::{Data, Interest, Name};
use ndn_transport::FaceId;

use crate::AppError;

/// An in-process face connecting application code to the forwarding engine.
///
/// `express()` sends an Interest and waits for the matching Data.
/// `produce()` registers a handler for a name prefix.
///
/// Internally uses `tokio::sync::mpsc` channels — zero-copy `Arc<>` passing
/// for same-process use.
pub struct AppFace {
    face_id: FaceId,
    /// Channel to send outbound Interests to the pipeline runner.
    tx: mpsc::Sender<OutboundRequest>,
}

enum OutboundRequest {
    Interest {
        interest: Interest,
        reply:    oneshot::Sender<Result<Data, AppError>>,
    },
    RegisterPrefix {
        prefix:  Arc<Name>,
        handler: Box<dyn Fn(Interest) + Send + Sync + 'static>,
    },
}

impl AppFace {
    pub fn face_id(&self) -> FaceId {
        self.face_id
    }

    /// Express an Interest and wait for the matching Data.
    pub async fn express(&self, interest: Interest) -> Result<Data, AppError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(OutboundRequest::Interest { interest, reply: tx })
            .await
            .map_err(|_| AppError::Engine(anyhow::anyhow!("engine shut down")))?;
        rx.await
            .map_err(|_| AppError::Engine(anyhow::anyhow!("engine dropped reply channel")))?
    }

    /// Register a handler for Interests matching `prefix`.
    pub async fn register_prefix<F>(&self, prefix: Name, handler: F) -> Result<(), AppError>
    where
        F: Fn(Interest) + Send + Sync + 'static,
    {
        self.tx
            .send(OutboundRequest::RegisterPrefix {
                prefix:  Arc::new(prefix),
                handler: Box::new(handler),
            })
            .await
            .map_err(|_| AppError::Engine(anyhow::anyhow!("engine shut down")))?;
        Ok(())
    }
}
