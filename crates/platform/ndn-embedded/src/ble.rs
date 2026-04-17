//! Bluetooth LE face for embedded targets.
//!
//! Implements the NDNts `@ndn/web-bluetooth-transport` GATT framing — the same
//! wire protocol used by the Linux (`bluer`) and macOS (CoreBluetooth)
//! implementations — on top of a platform-neutral [`BlePlatform`] trait.
//!
//! # Interoperability
//!
//! - ndn-rs forwarder on Linux / macOS
//! - NDNts `@ndn/web-bluetooth-transport` (Web Bluetooth)
//! - `esp8266ndn` `BleServerTransport` (ESP32/Arduino)
//!
//! # Usage
//!
//! Implement [`BlePlatform`] for your MCU's BLE driver, then wrap it in an
//! [`EmbeddedBleFace`] and hand it to the [`Forwarder`]:
//!
//! ```rust,ignore
//! struct MyBle { /* nRF52840 SoftDevice handle */ }
//!
//! impl BlePlatform for MyBle {
//!     type Error = core::convert::Infallible;
//!     fn max_payload(&self) -> usize { 244 }
//!     fn is_subscribed(&self) -> bool { /* ... */ true }
//!     fn try_recv_fragment(&mut self, buf: &mut [u8]) -> nb::Result<usize, Self::Error> {
//!         /* pull from interrupt-driven ring buffer */
//!         Err(nb::Error::WouldBlock)
//!     }
//!     fn try_send_fragment(&mut self, frag: &[u8]) -> nb::Result<(), Self::Error> {
//!         /* push to SoftDevice notify queue */
//!         Ok(())
//!     }
//! }
//!
//! let face = EmbeddedBleFace::<_, 1024, 512>::new(1, MyBle { /* ... */ });
//! ```
//!
//! [`Forwarder`]: crate::Forwarder

use heapless::Vec;

use crate::face::{Face, FaceId};

// ── Protocol UUIDs ────────────────────────────────────────────────────────────

/// GATT service UUID for the NDN BLE transport (NDNts interop).
pub const BLE_SERVICE_UUID: &str = "099577e3-0788-412a-8824-395084d97391";
/// TX characteristic UUID — forwarder notifies client of outgoing NDN packets.
/// This is the SC (server → client) characteristic in NDNts terminology.
pub const BLE_TX_CHAR_UUID: &str = "972f9527-0d83-4261-b95d-b1b2fc73bde4";
/// RX characteristic UUID — client writes incoming NDN packets to the forwarder.
/// This is the CS (client → server) characteristic in NDNts terminology.
pub const BLE_RX_CHAR_UUID: &str = "cc5abb89-a541-46d8-a351-2f95a6a81f49";

// ── BlePlatform ───────────────────────────────────────────────────────────────

/// Hardware abstraction for a BLE GATT peripheral.
///
/// Implement this trait for your MCU's BLE driver to get an NDN
/// [`EmbeddedBleFace`] without writing any framing code.
///
/// # Contract
///
/// - All methods are non-blocking.
/// - `try_recv_fragment` and `try_send_fragment` use interrupt-driven ring
///   buffers internally; they never spin-wait.
/// - The implementation is **not** required to be `Send` or `Sync`.
pub trait BlePlatform {
    /// Error type for I/O failures.
    type Error: core::fmt::Debug;

    /// Maximum ATT payload bytes per write/notify (= `att_mtu − 3`).
    ///
    /// Typical values:
    /// - 20 bytes — default BLE 4.x MTU (23 − 3)
    /// - 244 bytes — nRF52 extended MTU (247 − 3)
    /// - 509 bytes — BLE 5.x maximum (512 − 3)
    fn max_payload(&self) -> usize;

    /// Returns `true` if at least one central is subscribed to TX notifications.
    ///
    /// When `false`, [`EmbeddedBleFace::send`] silently discards the packet
    /// rather than blocking on a TX queue with no consumer.
    fn is_subscribed(&self) -> bool;

    /// Try to read one ATT write payload (one BLE fragment) into `buf`.
    ///
    /// Returns `Ok(n)` with the number of bytes written to `buf[..n]`, or
    /// `Err(nb::Error::WouldBlock)` if the receive buffer is empty.
    fn try_recv_fragment(&mut self, buf: &mut [u8]) -> nb::Result<usize, Self::Error>;

    /// Try to send one ATT notify payload (one BLE fragment).
    ///
    /// Returns `Ok(())` on success or `Err(nb::Error::WouldBlock)` if the
    /// notification channel is busy (e.g., previous notification pending).
    fn try_send_fragment(&mut self, fragment: &[u8]) -> nb::Result<(), Self::Error>;
}

// ── EmbeddedBleFace ───────────────────────────────────────────────────────────

/// NDN face over BLE for embedded targets.
///
/// Implements NDNts BLE fragmentation / reassembly on top of a
/// [`BlePlatform`].  Each call to [`recv`] / [`send`] is non-blocking.
///
/// # Type parameters
///
/// - `B` — BLE platform driver (implement [`BlePlatform`]).
/// - `PKT` — maximum reassembled NDN packet size in bytes (default 1 KiB).
/// - `FRAG` — maximum BLE fragment size in bytes (default 512, covering max ATT MTU).
///
/// # Stack usage
///
/// `recv` and `send` each allocate a `[u8; FRAG]` scratch buffer on the stack.
/// With the default `FRAG = 512`, ensure your task/ISR stack is ≥ 1 KiB.
///
/// [`recv`]: Face::recv
/// [`send`]: Face::send
pub struct EmbeddedBleFace<B: BlePlatform, const PKT: usize = 1024, const FRAG: usize = 512> {
    id: FaceId,
    platform: B,
    /// Accumulation buffer for fragmented in-progress packets.
    asm_buf: Vec<u8, PKT>,
    /// True while collecting continuation fragments.
    asm_active: bool,
}

impl<B: BlePlatform, const PKT: usize, const FRAG: usize> EmbeddedBleFace<B, PKT, FRAG> {
    /// Create a new face with `id` and the given BLE platform implementation.
    pub fn new(id: FaceId, platform: B) -> Self {
        Self {
            id,
            platform,
            asm_buf: Vec::new(),
            asm_active: false,
        }
    }

    /// Access the underlying [`BlePlatform`] (e.g., to query connection state).
    pub fn platform(&self) -> &B {
        &self.platform
    }

    /// Mutably access the underlying [`BlePlatform`].
    pub fn platform_mut(&mut self) -> &mut B {
        &mut self.platform
    }

    /// Check if the accumulation buffer holds a complete NDN TLV packet.
    fn check_complete(&self) -> Option<usize> {
        tlv_packet_end(&self.asm_buf)
    }
}

impl<B: BlePlatform, const PKT: usize, const FRAG: usize> Face for EmbeddedBleFace<B, PKT, FRAG> {
    type Error = B::Error;

    /// Receive one NDN packet.
    ///
    /// Reads **one** ATT fragment per call; returns the complete reassembled
    /// packet once all fragments have been received.  Returns
    /// `WouldBlock` if no fragment was available or the packet is incomplete.
    fn recv(&mut self, buf: &mut [u8]) -> nb::Result<usize, Self::Error> {
        // Read one ATT fragment from the hardware.
        let mut tmp = [0u8; FRAG];
        let n = self.platform.try_recv_fragment(&mut tmp)?;
        if n == 0 {
            return Err(nb::Error::WouldBlock);
        }
        let frag = &tmp[..n];

        // Process according to NDNts BLE framing.
        let first_byte = frag[0];
        if first_byte & 0x80 != 0 {
            // First fragment — start fresh.
            self.asm_buf.clear();
            self.asm_active = true;
            if self.asm_buf.extend_from_slice(&frag[1..]).is_err() {
                // Packet exceeds PKT bytes — discard.
                self.asm_active = false;
                return Err(nb::Error::WouldBlock);
            }
        } else if self.asm_active {
            // Continuation fragment.
            if self.asm_buf.extend_from_slice(&frag[1..]).is_err() {
                self.asm_active = false;
                return Err(nb::Error::WouldBlock);
            }
        } else {
            // No header byte → complete unfragmented packet.
            if frag.len() > buf.len() {
                // Output buffer too small — caller should retry with larger buf.
                return Err(nb::Error::WouldBlock);
            }
            buf[..frag.len()].copy_from_slice(frag);
            return Ok(frag.len());
        }

        // Return the packet if the TLV is now complete.
        match self.check_complete() {
            Some(len) if len <= buf.len() => {
                buf[..len].copy_from_slice(&self.asm_buf[..len]);
                // Consume the completed packet from the buffer.
                let remaining = self.asm_buf.len() - len;
                self.asm_buf.copy_within(len.., 0);
                self.asm_buf.truncate(remaining);
                if remaining == 0 {
                    self.asm_active = false;
                }
                Ok(len)
            }
            _ => Err(nb::Error::WouldBlock),
        }
    }

    /// Send one NDN packet.
    ///
    /// Fragments the packet if it exceeds [`BlePlatform::max_payload`] bytes.
    /// Returns `WouldBlock` if no central is subscribed or the radio is busy.
    fn send(&mut self, buf: &[u8]) -> nb::Result<(), Self::Error> {
        if !self.platform.is_subscribed() {
            // No subscriber — silently discard (NDN suppression handles retry).
            return Ok(());
        }
        let max_payload = self.platform.max_payload();
        if max_payload == 0 {
            return Err(nb::Error::WouldBlock);
        }

        if buf.len() <= max_payload {
            // Unfragmented — send as-is.
            return self.platform.try_send_fragment(buf);
        }

        // Fragmented send.
        let frag_payload = max_payload.saturating_sub(1); // 1-byte header
        let mut seq: u8 = 0;
        let mut is_first = true;
        let mut offset = 0;
        let mut frag_buf = [0u8; FRAG];

        while offset < buf.len() {
            let end = (offset + frag_payload).min(buf.len());
            let chunk = &buf[offset..end];
            let header = if is_first {
                is_first = false;
                0x80 | (seq & 0x7F)
            } else {
                seq & 0x7F
            };
            seq = seq.wrapping_add(1);
            let frag_len = 1 + chunk.len();
            frag_buf[0] = header;
            frag_buf[1..frag_len].copy_from_slice(chunk);
            self.platform.try_send_fragment(&frag_buf[..frag_len])?;
            offset = end;
        }
        Ok(())
    }

    fn face_id(&self) -> FaceId {
        self.id
    }
}

// ── TLV completeness check ────────────────────────────────────────────────────

fn parse_varlength(buf: &[u8]) -> Option<(u64, usize)> {
    match buf.first().copied()? {
        b if b <= 252 => Some((b as u64, 1)),
        253 if buf.len() >= 3 => {
            Some((u16::from_be_bytes(buf[1..3].try_into().unwrap()) as u64, 3))
        }
        254 if buf.len() >= 5 => {
            Some((u32::from_be_bytes(buf[1..5].try_into().unwrap()) as u64, 5))
        }
        255 if buf.len() >= 9 => Some((u64::from_be_bytes(buf[1..9].try_into().unwrap()), 9)),
        _ => None,
    }
}

fn tlv_packet_end(buf: &[u8]) -> Option<usize> {
    let (_, type_len) = parse_varlength(buf)?;
    let (length, length_len) = parse_varlength(&buf[type_len..])?;
    let total = type_len + length_len + length as usize;
    if buf.len() >= total {
        Some(total)
    } else {
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock BlePlatform ────────────────────────────────────────────────────
    // Each `push_fragment` enqueues one complete ATT payload.
    // Each `try_recv_fragment` dequeues exactly one ATT payload.
    // `tx_log` records the raw bytes of each sent fragment (concatenated).

    type Frag = heapless::Vec<u8, 512>;

    struct MockBle {
        rx_frags: heapless::Deque<Frag, 32>,
        tx_log: heapless::Vec<u8, 4096>,
        subscribed: bool,
        max_payload: usize,
    }

    impl MockBle {
        fn new(max_payload: usize) -> Self {
            Self {
                rx_frags: heapless::Deque::new(),
                tx_log: heapless::Vec::new(),
                subscribed: true,
                max_payload,
            }
        }

        fn push_fragment(&mut self, data: &[u8]) {
            let mut v: Frag = heapless::Vec::new();
            v.extend_from_slice(data).unwrap();
            self.rx_frags.push_back(v).unwrap();
        }
    }

    impl BlePlatform for MockBle {
        type Error = core::convert::Infallible;
        fn max_payload(&self) -> usize {
            self.max_payload
        }
        fn is_subscribed(&self) -> bool {
            self.subscribed
        }
        fn try_recv_fragment(&mut self, buf: &mut [u8]) -> nb::Result<usize, Self::Error> {
            let frag = self.rx_frags.pop_front().ok_or(nb::Error::WouldBlock)?;
            let n = frag.len().min(buf.len());
            buf[..n].copy_from_slice(&frag[..n]);
            Ok(n)
        }
        fn try_send_fragment(&mut self, frag: &[u8]) -> nb::Result<(), Self::Error> {
            self.tx_log.extend_from_slice(frag).unwrap();
            Ok(())
        }
    }

    fn make_pkt(type_byte: u8, payload: &[u8]) -> heapless::Vec<u8, 256> {
        let mut v = heapless::Vec::new();
        v.push(type_byte).unwrap();
        v.push(payload.len() as u8).unwrap();
        v.extend_from_slice(payload).unwrap();
        v
    }

    // ── Unfragmented receive ───────────────────────────────────────────────

    #[test]
    fn recv_unfragmented() {
        let pkt = make_pkt(0x05, b"hello");
        let mut ble = MockBle::new(64);
        ble.push_fragment(&pkt);

        let mut face = EmbeddedBleFace::<_, 1024, 512>::new(0, ble);
        let mut buf = [0u8; 256];
        let n = nb::block!(face.recv(&mut buf)).unwrap();
        assert_eq!(&buf[..n], &pkt[..]);
    }

    // ── Fragmented receive ─────────────────────────────────────────────────

    #[test]
    fn recv_two_fragments() {
        let mut ble = MockBle::new(64);
        // Full packet: type=6, length=4, value=[1,2,3,4]
        let f1 = [0x80u8, 0x06, 0x04, 0x01, 0x02]; // first frag (5 bytes → 4 of packet)
        let f2 = [0x01u8, 0x03, 0x04]; // continuation (3 bytes → 2 of packet)
        ble.push_fragment(&f1);
        ble.push_fragment(&f2);

        let mut face = EmbeddedBleFace::<_, 1024, 512>::new(0, ble);
        let mut buf = [0u8; 256];

        // First call: receives f1, WouldBlock (incomplete).
        assert!(face.recv(&mut buf).is_err());
        // Second call: receives f2, returns complete packet.
        let n = nb::block!(face.recv(&mut buf)).unwrap();
        assert_eq!(&buf[..n], &[0x06, 0x04, 0x01, 0x02, 0x03, 0x04]);
    }

    // ── Fragmented send ────────────────────────────────────────────────────

    #[test]
    fn send_unfragmented() {
        let pkt = make_pkt(0x05, &[1, 2, 3]);
        let ble = MockBle::new(64);
        let mut face = EmbeddedBleFace::<_, 1024, 512>::new(0, ble);
        face.send(&pkt).unwrap();
        assert_eq!(&face.platform().tx_log[..], &pkt[..]);
    }

    #[test]
    fn send_fragmented_roundtrip() {
        // 10-byte packet, max_payload = 4 → frag_payload = 3 → ceil(12/3) = 4 frags.
        let payload = [0xAAu8; 10];
        let pkt = make_pkt(0x06, &payload);
        let ble = MockBle::new(4);
        let mut face = EmbeddedBleFace::<_, 1024, 512>::new(0, ble);
        face.send(&pkt).unwrap();

        // Reassemble: the tx_log holds concatenated sent fragments; re-split
        // into individual 4-byte fragments (the max_payload) for the receiver.
        let wire = face.platform().tx_log.clone();
        let ble2 = MockBle::new(4);
        let mut recv_face = EmbeddedBleFace::<_, 1024, 512>::new(0, ble2);

        let mut cursor = &wire[..];
        while !cursor.is_empty() {
            let n = 4.min(cursor.len());
            recv_face.platform_mut().push_fragment(&cursor[..n]);
            cursor = &cursor[n..];
        }

        let mut buf = [0u8; 256];
        let mut result = None;
        for _ in 0..10 {
            match recv_face.recv(&mut buf) {
                Ok(n) => {
                    result = Some(n);
                    break;
                }
                Err(nb::Error::WouldBlock) => {}
                Err(e) => panic!("unexpected error: {:?}", e),
            }
        }
        let n = result.expect("should have received complete packet");
        assert_eq!(&buf[..n], &pkt[..]);
    }

    // ── UUID interop guard ────────────────────────────────────────────────

    /// Regression guard: embedded UUIDs must match the desktop `ndn-faces`
    /// values, which are verified against NDNts and esp8266ndn upstream.
    #[test]
    fn gatt_uuids_match_ndnts_and_desktop() {
        assert_eq!(BLE_SERVICE_UUID, "099577e3-0788-412a-8824-395084d97391");
        // TX = SC (server→client, Notify) — matches ndn-faces BLE_SC_CHAR_UUID
        assert_eq!(BLE_TX_CHAR_UUID, "972f9527-0d83-4261-b95d-b1b2fc73bde4");
        // RX = CS (client→server, Write Without Response) — matches ndn-faces BLE_CS_CHAR_UUID
        assert_eq!(BLE_RX_CHAR_UUID, "cc5abb89-a541-46d8-a351-2f95a6a81f49");
    }
}
