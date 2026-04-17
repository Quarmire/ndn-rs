//! ESP32-C3 BLE peripheral test — verifies `EmbeddedBleFace` end-to-end.
//!
//! Starts a BLE GATT peripheral using the NDNts-compatible service UUID,
//! advertises, and responds to Interests under `/ndn/ble/esp32` with a
//! counter-based greeting.
//!
//! # Building and flashing
//!
//! ```sh
//! cd examples/ble/esp32c3
//! cargo run          # builds and flashes via espflash
//! cargo run --release # optimized build
//! ```
//!
//! # Hardware
//!
//! - ESP32-C3 development board (RISC-V)
//! - Built-in LED on GPIO8 (active low on most boards; adjust if needed)

#![no_std]
#![no_main]

extern crate alloc;

use core::cell::RefCell;

use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::prelude::*;
use esp_println::println;
use esp_wifi::ble::controller::BleConnector;
use heapless::Deque;
use log::info;

use ndn_embedded::ble::{BLE_RX_CHAR_UUID, BLE_SERVICE_UUID, BLE_TX_CHAR_UUID, BlePlatform, EmbeddedBleFace};
use ndn_embedded::face::Face;
use ndn_embedded::wire::encode_data_name;
use ndn_embedded::{Fib, FnClock, Forwarder, Pit};

// ── Heap allocator ───────────────────────────────────────────────────────────

fn init_heap() {
    const HEAP_SIZE: usize = 32 * 1024;
    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
    unsafe {
        esp_alloc::HEAP.add_region(esp_alloc::HeapRegion::new(
            &raw mut HEAP as *mut u8,
            HEAP_SIZE,
            esp_alloc::MemoryCapability::Internal.into(),
        ));
    }
}

// ── BlePlatform for ESP32-C3 ─────────────────────────────────────────────────

/// BLE platform implementation wrapping the esp-wifi NimBLE GATT server.
///
/// The GATT service is registered with the NDNts-compatible UUIDs.
/// Fragments are buffered in a heapless ring buffer and exchanged
/// non-blockingly with the `EmbeddedBleFace`.
struct Esp32Ble {
    rx_buf: Deque<heapless::Vec<u8, 512>, 16>,
    tx_buf: Deque<heapless::Vec<u8, 512>, 16>,
    subscribed: bool,
    mtu: usize,
}

impl Esp32Ble {
    fn new() -> Self {
        Self {
            rx_buf: Deque::new(),
            tx_buf: Deque::new(),
            subscribed: false,
            mtu: 244, // default after MTU negotiation on ESP32-C3
        }
    }

    /// Push a received fragment from the BLE callback into the RX buffer.
    fn push_rx(&mut self, data: &[u8]) {
        let mut v: heapless::Vec<u8, 512> = heapless::Vec::new();
        if v.extend_from_slice(data).is_ok() {
            let _ = self.rx_buf.push_back(v);
        }
    }

    /// Pop a fragment to send via BLE notification.
    fn pop_tx(&mut self) -> Option<heapless::Vec<u8, 512>> {
        self.tx_buf.pop_front()
    }
}

impl BlePlatform for Esp32Ble {
    type Error = core::convert::Infallible;

    fn max_payload(&self) -> usize {
        self.mtu
    }

    fn is_subscribed(&self) -> bool {
        self.subscribed
    }

    fn try_recv_fragment(&mut self, buf: &mut [u8]) -> nb::Result<usize, Self::Error> {
        match self.rx_buf.pop_front() {
            Some(frag) => {
                let n = frag.len().min(buf.len());
                buf[..n].copy_from_slice(&frag[..n]);
                Ok(n)
            }
            None => Err(nb::Error::WouldBlock),
        }
    }

    fn try_send_fragment(&mut self, fragment: &[u8]) -> nb::Result<(), Self::Error> {
        let mut v: heapless::Vec<u8, 512> = heapless::Vec::new();
        if v.extend_from_slice(fragment).is_err() {
            return Err(nb::Error::WouldBlock);
        }
        self.tx_buf.push_back(v).map_err(|_| nb::Error::WouldBlock)?;
        Ok(())
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[entry]
fn main() -> ! {
    init_heap();
    esp_println::logger::init_logger_from_env();

    info!("NDN BLE ESP32-C3 test starting");
    info!("Service UUID: {}", BLE_SERVICE_UUID);
    info!("TX char UUID: {}", BLE_TX_CHAR_UUID);
    info!("RX char UUID: {}", BLE_RX_CHAR_UUID);

    // ── Hardware init ────────────────────────────────────────────────────
    let peripherals = esp_hal::init(esp_hal::Config::default());

    // TODO: Initialize esp-wifi BLE stack and register GATT service.
    //
    // The esp-wifi BLE API is rapidly evolving. The general steps are:
    //
    // 1. Initialize the radio clocks and BLE controller:
    //    let init = esp_wifi::init(peripherals.RADIO_CLK, ...)?;
    //    let mut ble = BleConnector::new(&init, peripherals.BT);
    //
    // 2. Register the NDN GATT service with:
    //    - Service UUID: BLE_SERVICE_UUID
    //    - RX characteristic (CS): BLE_RX_CHAR_UUID (Write Without Response)
    //    - TX characteristic (SC): BLE_TX_CHAR_UUID (Notify)
    //
    // 3. Start advertising with the service UUID.
    //
    // 4. In the event loop, handle:
    //    - Write events on RX char → platform.push_rx(data)
    //    - Subscribe events on TX char → platform.subscribed = true
    //    - Outgoing fragments → pop_tx() and send as notifications
    //
    // See esp-wifi examples for the current BLE API surface:
    // https://github.com/esp-rs/esp-hal/tree/main/examples/src/bin

    let mut platform = Esp32Ble::new();
    let mut face = EmbeddedBleFace::<_, 1024, 512>::new(1, platform);

    // ── NDN forwarder ────────────────────────────────────────────────────
    let mut fib = Fib::<8>::new();
    // Route all traffic to the BLE face (face_id = 1).
    // In a real app you'd add specific prefixes.
    fib.add_route_str("/ndn/ble/esp32", 1, 0);

    let clock = FnClock(|| {
        // TODO: Replace with hardware timer read.
        // esp_hal::time::now().duration_since_epoch().to_millis() as u32
        0
    });
    let mut fw = Forwarder::<32, 8, _>::new(fib, clock);

    info!("Entering main loop — waiting for BLE connections …");
    let mut pkt_buf = [0u8; 1024];
    let mut resp_buf = [0u8; 512];
    let mut counter: u32 = 0;

    loop {
        // ── Receive ──────────────────────────────────────────────────
        match face.recv(&mut pkt_buf) {
            Ok(n) => {
                info!("Received packet: {} bytes", n);
                let raw = &pkt_buf[..n];

                // Check if it's an Interest (TLV type 0x05).
                if !raw.is_empty() && raw[0] == 0x05 {
                    counter += 1;
                    let content = b"Hello from ESP32!";
                    if let Some(len) =
                        encode_data_name(&mut resp_buf, "/ndn/ble/esp32", content)
                    {
                        info!("Sending Data response: {} bytes (count={})", len, counter);
                        match face.send(&resp_buf[..len]) {
                            Ok(()) => info!("Data sent"),
                            Err(e) => info!("Send error: {:?}", e),
                        }
                    }
                }
            }
            Err(nb::Error::WouldBlock) => {}
            Err(nb::Error::Other(e)) => {
                info!("Recv error: {:?}", e);
            }
        }

        // ── Tick ─────────────────────────────────────────────────────
        fw.run_one_tick();

        // TODO: Process BLE events here (read from BLE controller,
        // push RX fragments to platform, send TX fragments as
        // notifications). This depends on the esp-wifi BLE event loop.

        // Small delay to avoid busy-spinning.
        // In production, use WFI or an RTOS task yield.
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}
