use ndn_transport::{FaceId, FaceKind};

#[cfg(feature = "serial")]
use crate::serial::cobs::CobsCodec;

/// NDN face over a serial port with COBS framing. `0x00` never appears in the
/// encoded payload, so resync is at most one frame away after line noise.
#[cfg(feature = "serial")]
pub type SerialFace = ndn_transport::StreamFace<
    tokio::io::ReadHalf<tokio_serial::SerialStream>,
    tokio::io::WriteHalf<tokio_serial::SerialStream>,
    CobsCodec,
>;

#[cfg(feature = "serial")]
pub fn serial_face_open(
    id: FaceId,
    port: impl Into<String>,
    baud: u32,
) -> std::io::Result<SerialFace> {
    let port = port.into();
    let builder = tokio_serial::new(&port, baud);
    let stream = tokio_serial::SerialStream::open(&builder)?;
    let (r, w) = tokio::io::split(stream);
    let uri = format!("serial://{}", port);
    Ok(ndn_transport::StreamFace::new(
        id,
        FaceKind::Serial,
        Some(uri.clone()),
        Some(uri),
        r,
        w,
        CobsCodec::new(),
    ))
}

#[cfg(not(feature = "serial"))]
use bytes::Bytes;
#[cfg(not(feature = "serial"))]
use ndn_transport::{FaceError, Transport};

#[cfg(not(feature = "serial"))]
pub struct SerialFace {
    id: FaceId,
}

#[cfg(not(feature = "serial"))]
impl SerialFace {
    pub fn new(id: FaceId, _port: impl Into<String>, _baud: u32) -> Self {
        Self { id }
    }
}

#[cfg(not(feature = "serial"))]
impl Transport for SerialFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::Serial
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        Err(FaceError::Closed)
    }

    async fn send_bytes(&self, _pkt: Bytes) -> Result<(), FaceError> {
        Err(FaceError::Closed)
    }
}
