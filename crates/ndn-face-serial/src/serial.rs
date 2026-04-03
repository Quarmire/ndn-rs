use ndn_transport::{FaceId, FaceKind};

#[cfg(feature = "serial")]
use crate::cobs::CobsCodec;

/// NDN face over a serial port with COBS framing.
///
/// COBS (Consistent Overhead Byte Stuffing) provides reliable frame
/// resynchronisation after line noise — a `0x00` byte never appears in the
/// encoded payload, so re-sync is just a matter of waiting for the next `0x00`.
///
/// Suitable for: UART sensor nodes, LoRa radio modems, RS-485 industrial buses.
///
/// Uses [`StreamFace`](ndn_transport::StreamFace) with serial read/write halves
/// and [`CobsCodec`].  LP-encoding is enabled for network transport.
#[cfg(feature = "serial")]
pub type SerialFace = ndn_transport::StreamFace<
    tokio::io::ReadHalf<tokio_serial::SerialStream>,
    tokio::io::WriteHalf<tokio_serial::SerialStream>,
    CobsCodec,
>;

/// Open a serial port and wrap it as an NDN [`SerialFace`].
#[cfg(feature = "serial")]
pub fn serial_face_open(id: FaceId, port: impl Into<String>, baud: u32) -> std::io::Result<SerialFace> {
    let port = port.into();
    let builder = tokio_serial::new(&port, baud);
    let stream = tokio_serial::SerialStream::open(&builder)?;
    let (r, w) = tokio::io::split(stream);
    let uri = format!("serial://{}", port);
    Ok(ndn_transport::StreamFace::new(
        id,
        FaceKind::Serial,
        true,
        Some(uri.clone()),
        Some(uri),
        r,
        w,
        CobsCodec::new(),
    ))
}

// ─── Fallback when `serial` feature is disabled ────────────────────────────

#[cfg(not(feature = "serial"))]
use bytes::Bytes;
#[cfg(not(feature = "serial"))]
use ndn_transport::{Face, FaceError};

#[cfg(not(feature = "serial"))]
pub struct SerialFace {
    id:   FaceId,
    port: String,
    baud: u32,
}

#[cfg(not(feature = "serial"))]
impl SerialFace {
    pub fn new(id: FaceId, port: impl Into<String>, baud: u32) -> Self {
        Self { id, port: port.into(), baud }
    }
}

#[cfg(not(feature = "serial"))]
impl Face for SerialFace {
    fn id(&self) -> FaceId { self.id }
    fn kind(&self) -> FaceKind { FaceKind::Serial }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        Err(FaceError::Closed)
    }

    async fn send(&self, _pkt: Bytes) -> Result<(), FaceError> {
        Err(FaceError::Closed)
    }
}
