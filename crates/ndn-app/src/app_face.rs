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

pub enum OutboundRequest {
    Interest {
        interest: Box<Interest>,
        reply: oneshot::Sender<Result<Data, AppError>>,
    },
    RegisterPrefix {
        prefix: Arc<Name>,
        handler: Box<dyn Fn(Interest) + Send + Sync + 'static>,
    },
}

impl AppFace {
    /// Create a new `AppFace` and the matching request receiver.
    ///
    /// The caller (typically the engine) holds the `Receiver` and dispatches
    /// `OutboundRequest` messages as they arrive.
    pub fn new(face_id: FaceId, capacity: usize) -> (AppFace, mpsc::Receiver<OutboundRequest>) {
        let (tx, rx) = mpsc::channel(capacity);
        (AppFace { face_id, tx }, rx)
    }

    pub fn face_id(&self) -> FaceId {
        self.face_id
    }

    /// Express an Interest and wait for the matching Data.
    pub async fn express(&self, interest: Interest) -> Result<Data, AppError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(OutboundRequest::Interest {
                interest: Box::new(interest),
                reply: tx,
            })
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
                prefix: Arc::new(prefix),
                handler: Box::new(handler),
            })
            .await
            .map_err(|_| AppError::Engine(anyhow::anyhow!("engine shut down")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;

    fn make_interest(comp: &'static str) -> Interest {
        let name =
            Name::from_components([NameComponent::generic(Bytes::from_static(comp.as_bytes()))]);
        Interest::new(name)
    }

    fn make_data() -> Data {
        use ndn_tlv::TlvWriter;
        let nc = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x08, b"test");
            w.finish()
        };
        let name = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x07, &nc);
            w.finish()
        };
        let pkt = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x06, &name);
            w.finish()
        };
        Data::decode(pkt).unwrap()
    }

    #[test]
    fn face_id_accessor() {
        let (face, _rx) = AppFace::new(FaceId(42), 8);
        assert_eq!(face.face_id(), FaceId(42));
    }

    #[tokio::test]
    async fn express_sends_interest_to_receiver() {
        let (face, mut rx) = AppFace::new(FaceId(1), 8);
        let interest = make_interest("hello");
        let task = tokio::spawn(async move { face.express(interest).await });
        // Engine side: receive the request and reply.
        if let Some(OutboundRequest::Interest { reply, .. }) = rx.recv().await {
            reply.send(Ok(make_data())).unwrap();
        } else {
            panic!("expected Interest request");
        }
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn express_returns_error_when_channel_closed() {
        let (face, rx) = AppFace::new(FaceId(1), 8);
        drop(rx); // engine side dropped
        let result = face.express(make_interest("x")).await;
        assert!(matches!(result, Err(AppError::Engine(_))));
    }

    #[tokio::test]
    async fn express_propagates_nack() {
        use ndn_packet::NackReason;
        let (face, mut rx) = AppFace::new(FaceId(1), 8);
        let task = tokio::spawn(async move { face.express(make_interest("x")).await });
        if let Some(OutboundRequest::Interest { reply, .. }) = rx.recv().await {
            reply
                .send(Err(AppError::Nacked {
                    reason: NackReason::NoRoute,
                }))
                .unwrap();
        }
        let result = task.await.unwrap();
        assert!(matches!(
            result,
            Err(AppError::Nacked {
                reason: NackReason::NoRoute
            })
        ));
    }

    #[tokio::test]
    async fn register_prefix_sends_request() {
        let (face, mut rx) = AppFace::new(FaceId(1), 8);
        let prefix =
            Name::from_components([NameComponent::generic(Bytes::from_static(b"myprefix"))]);
        face.register_prefix(prefix.clone(), |_| {}).await.unwrap();
        if let Some(OutboundRequest::RegisterPrefix { prefix: p, .. }) = rx.recv().await {
            assert_eq!(*p, prefix);
        } else {
            panic!("expected RegisterPrefix request");
        }
    }

    #[tokio::test]
    async fn register_prefix_returns_error_when_channel_closed() {
        let (face, rx) = AppFace::new(FaceId(1), 8);
        drop(rx);
        let result = face.register_prefix(Name::root(), |_| {}).await;
        assert!(result.is_err());
    }
}
