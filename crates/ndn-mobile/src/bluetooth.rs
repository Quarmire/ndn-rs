//! Bluetooth NDN face — generic over any async byte-stream.
//!
//! [`BluetoothFace`] uses COBS (Consistent Overhead Byte Stuffing) framing,
//! the same codec as [`SerialFace`](ndn_face_serial::SerialFace).  COBS is
//! the right choice for Bluetooth because:
//!
//! - RFCOMM and L2CAP are both stream-oriented — they carry bytes, not packets
//! - `0x00` never appears in a COBS-encoded payload, making it a reliable
//!   frame boundary: the decoder simply waits for the next `0x00` to resync
//! - After a dropped connection and reconnect, at most one frame is lost
//!
//! This type does **not** open the Bluetooth connection itself — that requires
//! platform-specific native code.  See the platform sections below for how to
//! bridge from Android or iOS into a `BluetoothFace`.
//!
//! # Android (Kotlin/Java → JNI)
//!
//! 1. Open a `BluetoothSocket` with `createRfcommSocketToServiceRecord()` and
//!    call `connect()`.
//! 2. Get the socket's file descriptor via `getFileDescriptor()` on the
//!    underlying `ParcelFileDescriptor`.
//! 3. Pass the raw fd to Rust via JNI (`jint` → `RawFd`) and wrap it:
//!
//! ```rust,ignore
//! use std::os::unix::io::FromRawFd;
//! use tokio::net::UnixStream;
//!
//! // SAFETY: fd is a valid, owned RFCOMM socket fd transferred from the JVM.
//! let stream = unsafe { UnixStream::from_raw_fd(raw_fd) };
//! let (r, w) = tokio::io::split(stream);
//! let face = bluetooth_face_from_parts(id, "bt://AA:BB:CC:DD:EE:FF", r, w);
//! ```
//!
//! 4. Add to the engine: `engine.engine().add_face(face, cancel_token)`.
//!
//! # iOS / iPadOS (Swift → C FFI)
//!
//! 1. Use `CoreBluetooth` to open an L2CAP channel
//!    (`CBPeripheral.openL2CAPChannel`) and retrieve the `CBL2CAPChannel`.
//! 2. The channel exposes `inputStream: InputStream` and
//!    `outputStream: OutputStream` — bridge these to Rust as a pair of pipe
//!    file descriptors via `socketpair(2)` or a custom Swift ↔ Rust bridge.
//! 3. Wrap in `tokio::io::split` and pass to `bluetooth_face_from_parts`.
//!
//! # Reconnection
//!
//! When the remote device disconnects, `face.recv()` returns
//! `FaceError::Closed`.  The engine removes the face automatically (OnDemand
//! persistency).  To reconnect, open a new native socket, create a new
//! `BluetoothFace`, and call `engine.engine().add_face(new_face, new_cancel)`.
//!
//! A simple exponential-backoff reconnect loop in the app layer is sufficient
//! for most use cases.

use tokio::io::{AsyncRead, AsyncWrite};

use ndn_face_serial::cobs::CobsCodec;
use ndn_transport::{FaceId, FaceKind, StreamFace};

/// NDN face over a Bluetooth byte stream.
///
/// Generic over the async read (`R`) and write (`W`) halves of the connection.
/// Use [`bluetooth_face_from_parts`] to construct.
///
/// LP-encoding is enabled so the engine can fragment large NDN packets across
/// the Bluetooth link (max NDN packet ~8.8 KiB; RFCOMM MTU typically 672 B).
pub type BluetoothFace<R, W> = StreamFace<R, W, CobsCodec>;

/// Wrap pre-split async I/O halves as a Bluetooth NDN face.
///
/// `peer` is a human-readable URI for logging (e.g. `"bt://AA:BB:CC:DD:EE:FF"`).
///
/// # Example
///
/// ```rust,ignore
/// // After obtaining (r, w) from platform Bluetooth API:
/// let face = bluetooth_face_from_parts(face_id, "bt://AA:BB:CC:DD:EE:FF", r, w);
/// engine.engine().add_face(face, cancel_token);
/// ```
pub fn bluetooth_face_from_parts<R, W>(
    id: FaceId,
    peer: impl Into<String>,
    reader: R,
    writer: W,
) -> BluetoothFace<R, W>
where
    R: AsyncRead + Send + Sync + Unpin,
    W: AsyncWrite + Send + Sync + Unpin,
{
    let uri = peer.into();
    StreamFace::new(
        id,
        FaceKind::Bluetooth,
        true, // LP-encode: enable fragmentation for Bluetooth MTU constraints
        Some(uri),
        None,
        reader,
        writer,
        CobsCodec::new(),
    )
}
