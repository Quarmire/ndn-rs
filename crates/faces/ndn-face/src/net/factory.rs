//! [`UdpFaceFactory`] — the reference [`FaceFactory`] impl.
//!
//! Proves the data-driven face-construction seam end to end: a connectivity
//! resolver holding `(FaceKind::Udp, FaceParams { remote, .. })` can build a
//! live [`UdpFace`] via `ForwarderEngine::add_face_of_kind` with no per-kind
//! code. Also directly useful: register it and UDP faces become buildable from
//! config rows / discovered-neighbor records.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use ndn_transport::{ErasedTransport, FaceError, FaceFactory, FaceId, FaceKind, FaceParams};

use super::udp::UdpFace;

/// Default local bind for a UDP face when `params.opt("local")` is absent:
/// ephemeral port on all interfaces.
const DEFAULT_LOCAL_BIND: &str = "0.0.0.0:0";

/// Reference [`FaceFactory`] for [`FaceKind::Udp`].
///
/// Reads the peer from [`FaceParams::remote`] (a `SocketAddr` string, e.g.
/// `192.0.2.1:6363`) and an optional `local` bind address from
/// `params.opt("local")` (default [`DEFAULT_LOCAL_BIND`]), then binds a
/// [`UdpFace`]. Malformed params surface as
/// `FaceError::Io(ErrorKind::InvalidInput)`; a bind failure surfaces as the
/// underlying `FaceError::Io`.
#[derive(Clone, Copy, Debug, Default)]
pub struct UdpFaceFactory;

fn invalid(msg: impl Into<String>) -> FaceError {
    FaceError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        msg.into(),
    ))
}

impl FaceFactory for UdpFaceFactory {
    fn kind(&self) -> FaceKind {
        FaceKind::Udp
    }

    fn create<'a>(
        &'a self,
        id: FaceId,
        params: &'a FaceParams,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn ErasedTransport>, FaceError>> + Send + 'a>> {
        Box::pin(async move {
            let remote = params
                .remote
                .as_deref()
                .ok_or_else(|| invalid("UdpFaceFactory: params.remote (peer addr) is required"))?;
            let peer: SocketAddr = remote
                .parse()
                .map_err(|e| invalid(format!("UdpFaceFactory: bad remote {remote:?}: {e}")))?;
            let local_str = params.opt("local").unwrap_or(DEFAULT_LOCAL_BIND);
            let local: SocketAddr = local_str
                .parse()
                .map_err(|e| invalid(format!("UdpFaceFactory: bad local {local_str:?}: {e}")))?;
            // `UdpFace::bind` returns io::Result; `?` maps io::Error → FaceError.
            let face = UdpFace::bind(local, peer, id).await?;
            Ok(Box::new(face) as Box<dyn ErasedTransport>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_reports_udp_kind() {
        assert_eq!(UdpFaceFactory.kind(), FaceKind::Udp);
    }

    #[tokio::test]
    async fn create_requires_remote() {
        // `Box<dyn ErasedTransport>` is not Debug, so match rather than unwrap_err.
        match UdpFaceFactory.create(FaceId(0), &FaceParams::default()).await {
            Err(FaceError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
            Err(other) => panic!("expected InvalidInput, got {other:?}"),
            Ok(_) => panic!("expected an error when remote is absent"),
        }
    }

    #[tokio::test]
    async fn create_binds_a_live_udp_face() {
        let params = FaceParams::remote("127.0.0.1:6363");
        let transport = UdpFaceFactory
            .create(FaceId(7), &params)
            .await
            .expect("bind should succeed on loopback");
        assert_eq!(transport.id(), FaceId(7));
        assert_eq!(transport.kind(), FaceKind::Udp);
    }
}
