//! Virtual face backed by an async callback (`CallbackFace`).
//!
//! Routes Interests to an application-provided async function and returns the
//! resulting `Data` (or a `NoRoute` Nack) through the standard face surface,
//! so the engine pipeline sees the callback as a normal FIB next-hop.

use std::sync::Arc;

use bytes::Bytes;
use futures::future::BoxFuture;
use tokio::sync::{Mutex, mpsc};

use ndn_packet::{Data, Interest, NackReason, lp::encode_lp_nack};
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

const RESP_QUEUE_CAP: usize = 64;

/// A virtual NDN face that satisfies Interests via an async callback.
///
/// Use [`InProcFace`](crate::local::InProcFace) when the application drives
/// its own event loop; use `CallbackFace` when a function can directly produce
/// `Data` for any `Interest`. The callback runs inside `send_bytes`, so a slow
/// callback blocks that task — return `None` quickly for unknown names if
/// throughput matters.
#[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
pub struct CallbackFace {
    id: FaceId,
    callback: Arc<dyn Fn(Interest) -> BoxFuture<'static, Option<Data>> + Send + Sync>,
    resp_tx: mpsc::Sender<Bytes>,
    resp_rx: Mutex<mpsc::Receiver<Bytes>>,
}

impl CallbackFace {
    /// `callback` returns `Some(data)` to satisfy the Interest or `None` to
    /// emit a `NoRoute` Nack.
    pub fn new<F>(id: FaceId, callback: F) -> Self
    where
        F: Fn(Interest) -> BoxFuture<'static, Option<Data>> + Send + Sync + 'static,
    {
        let (resp_tx, resp_rx) = mpsc::channel(RESP_QUEUE_CAP);
        Self {
            id,
            callback: Arc::new(callback),
            resp_tx,
            resp_rx: Mutex::new(resp_rx),
        }
    }

    /// Synchronous variant of [`new`](Self::new); prefer `new` when the
    /// lookup is itself async.
    pub fn from_fn<F>(id: FaceId, f: F) -> Self
    where
        F: Fn(Interest) -> Option<Data> + Send + Sync + 'static,
    {
        Self::new(id, move |interest| {
            let result = f(interest);
            Box::pin(async move { result })
        })
    }
}

impl Transport for CallbackFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::App
    }

    /// Non-Interest packets are silently dropped (no response queued).
    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        let Ok(interest) = Interest::decode(pkt.clone()) else {
            return Ok(());
        };
        let response = match (self.callback)(interest).await {
            Some(data) => data.raw().clone(),
            None => encode_lp_nack(NackReason::NoRoute, &pkt),
        };
        self.resp_tx
            .send(response)
            .await
            .map_err(|_| FaceError::Closed)
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.resp_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(FaceError::Closed)
    }
}

/// Wire-trace face: records every packet the engine sends to it and emits a
/// `NoRoute` Nack so the pipeline does not wait for Data. Register alongside
/// a real producer face and read [`TapFace::captured`] after a workload.
#[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
pub struct TapFace {
    id: FaceId,
    captured: Arc<Mutex<Vec<Bytes>>>,
    resp_tx: mpsc::Sender<Bytes>,
    resp_rx: Mutex<mpsc::Receiver<Bytes>>,
}

#[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
impl TapFace {
    pub fn new(id: FaceId) -> Self {
        let (resp_tx, resp_rx) = mpsc::channel(RESP_QUEUE_CAP);
        Self {
            id,
            captured: Arc::new(Mutex::new(Vec::new())),
            resp_tx,
            resp_rx: Mutex::new(resp_rx),
        }
    }

    /// Drain every wire packet captured since the last call.
    pub async fn captured(&self) -> Vec<Bytes> {
        let mut buf = self.captured.lock().await;
        std::mem::take(&mut *buf)
    }

    /// Shared handle for live observation; prefer [`Self::captured`] for
    /// one-shot collection.
    pub fn capture_handle(&self) -> Arc<Mutex<Vec<Bytes>>> {
        Arc::clone(&self.captured)
    }
}

impl Transport for TapFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::App
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.captured.lock().await.push(pkt.clone());
        if Interest::decode(pkt.clone()).is_ok() {
            let nack = encode_lp_nack(NackReason::NoRoute, &pkt);
            self.resp_tx
                .send(nack)
                .await
                .map_err(|_| FaceError::Closed)?;
        }
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.resp_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(FaceError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ndn_packet::Name;
    use ndn_packet::encode::{DataBuilder, encode_interest};
    use ndn_packet::lp::LpPacket;

    fn make_name(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn interest_wire(name: &Name) -> Bytes {
        encode_interest(name, None)
    }

    fn data_for(name: Name, content: &[u8]) -> Data {
        let wire = DataBuilder::new(name, content).build();
        Data::decode(wire).unwrap()
    }

    #[tokio::test]
    async fn callback_face_round_trip() {
        let face = CallbackFace::from_fn(FaceId(10), |interest| {
            let name = (*interest.name).clone();
            let data = data_for(name, b"hello");
            Some(data)
        });

        let name = make_name("/test/a");
        let interest = interest_wire(&name);
        face.send_bytes(interest).await.unwrap();

        let resp = face.recv_bytes().await.unwrap();
        let data = Data::decode(resp).unwrap();
        assert_eq!(*data.name, name);
        assert_eq!(data.content().map(|c| c.to_vec()), Some(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn callback_face_nack_on_miss() {
        let face = CallbackFace::from_fn(FaceId(11), |_| None);

        let name = make_name("/test/b");
        let wire = interest_wire(&name);
        face.send_bytes(wire).await.unwrap();

        let resp = face.recv_bytes().await.unwrap();
        let lp = LpPacket::decode(resp).unwrap();
        assert_eq!(
            lp.nack.and_then(|header| header.reason),
            Some(NackReason::NoRoute)
        );
    }

    #[tokio::test]
    async fn callback_face_async() {
        let face = CallbackFace::new(FaceId(12), |interest| {
            let name = (*interest.name).clone();
            Box::pin(async move {
                tokio::task::yield_now().await;
                let data = data_for(name, b"async-content");
                Some(data)
            })
        });

        let name = make_name("/test/async");
        face.send_bytes(interest_wire(&name)).await.unwrap();

        let resp = face.recv_bytes().await.unwrap();
        let data = Data::decode(resp).unwrap();
        assert_eq!(*data.name, name);
        assert_eq!(
            data.content().map(|c| c.to_vec()),
            Some(b"async-content".to_vec())
        );
    }

    #[tokio::test]
    async fn callback_face_concurrent() {
        let face = Arc::new(CallbackFace::from_fn(FaceId(13), |interest| {
            let name = (*interest.name).clone();
            let data = data_for(name, b"concurrent");
            Some(data)
        }));

        let name_a = make_name("/concurrent/a");
        let name_b = make_name("/concurrent/b");

        let fa = Arc::clone(&face);
        let wire_a = interest_wire(&name_a);
        let h_a = tokio::spawn(async move { fa.send_bytes(wire_a).await });

        let fb = Arc::clone(&face);
        let wire_b = interest_wire(&name_b);
        let h_b = tokio::spawn(async move { fb.send_bytes(wire_b).await });

        h_a.await.unwrap().unwrap();
        h_b.await.unwrap().unwrap();

        let resp_a = face.recv_bytes().await.unwrap();
        let resp_b = face.recv_bytes().await.unwrap();

        let da = Data::decode(resp_a).unwrap();
        let db = Data::decode(resp_b).unwrap();

        let names: std::collections::HashSet<_> = [(*da.name).clone(), (*db.name).clone()]
            .into_iter()
            .collect();
        assert!(names.contains(&name_a));
        assert!(names.contains(&name_b));
    }
}
