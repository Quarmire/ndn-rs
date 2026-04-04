//! Non-blocking face abstraction for embedded NDN nodes.
//!
//! The [`Face`] trait uses [`nb::Result`] for non-blocking I/O — the same
//! idiom used throughout `embedded-hal`. A face implementation returns
//! `Err(nb::Error::WouldBlock)` when no data is immediately available,
//! letting the forwarder poll all faces in a round-robin loop without
//! blocking.
//!
//! Embassy users can wrap an async peripheral in a thin adapter that calls
//! `nb::block!` inside a spawned task, or implement `Face` directly using
//! embassy's synchronous API.

/// A numeric face identifier (0–254). 255 is reserved.
pub type FaceId = u8;

/// Non-blocking NDN face.
///
/// Each face corresponds to one communication channel: a UART port, a UDP
/// socket (when the MCU has a network stack), a LoRa transceiver, etc.
///
/// # Contract
///
/// - `recv` **must not block**. Return `Err(nb::Error::WouldBlock)` if no
///   data is ready. The forwarder polls all faces in a tight loop.
/// - `send` **should not block** for longer than one COBS frame transmission.
///   If back-pressure is needed, return `Err(nb::Error::WouldBlock)` and the
///   forwarder will drop the packet (NDN Interest-suppression handles
///   retry logic at a higher level).
/// - `face_id` must be stable for the lifetime of the face.
pub trait Face {
    /// Error type for I/O failures.
    type Error: core::fmt::Debug;

    /// Non-blocking receive.
    ///
    /// Writes up to `buf.len()` bytes into `buf` and returns the number
    /// of bytes written, or `Err(nb::Error::WouldBlock)` if no data is ready.
    fn recv(&mut self, buf: &mut [u8]) -> nb::Result<usize, Self::Error>;

    /// Non-blocking send.
    ///
    /// Transmits `buf` as a single packet. Returns `Ok(())` on success or
    /// `Err(nb::Error::WouldBlock)` if the transmitter is busy.
    fn send(&mut self, buf: &[u8]) -> nb::Result<(), Self::Error>;

    /// Returns the stable numeric identifier for this face.
    fn face_id(&self) -> FaceId;
}

/// Object-safe wrapper used by the forwarder when iterating over a face slice.
///
/// This trait is implemented automatically for any `F: Face`. You don't
/// need to implement it manually.
pub trait ErasedFace {
    fn recv(&mut self, buf: &mut [u8]) -> nb::Result<usize, ()>;
    fn send(&mut self, buf: &[u8]) -> nb::Result<(), ()>;
    fn face_id(&self) -> FaceId;
}

impl<F: Face> ErasedFace for F {
    fn recv(&mut self, buf: &mut [u8]) -> nb::Result<usize, ()> {
        Face::recv(self, buf).map_err(|e| match e {
            nb::Error::WouldBlock => nb::Error::WouldBlock,
            nb::Error::Other(_) => nb::Error::Other(()),
        })
    }

    fn send(&mut self, buf: &[u8]) -> nb::Result<(), ()> {
        Face::send(self, buf).map_err(|e| match e {
            nb::Error::WouldBlock => nb::Error::WouldBlock,
            nb::Error::Other(_) => nb::Error::Other(()),
        })
    }

    fn face_id(&self) -> FaceId {
        Face::face_id(self)
    }
}
