//! App-to-forwarder IPC using lock-free SPSC queues.
//!
//! On an MCU the application and forwarder share the same address space.
//! `heapless::spsc::Queue` provides a lock-free, ISR-safe single-producer /
//! single-consumer ring buffer — the correct primitive for passing packets
//! between an interrupt handler (or RTOS task) and the main forwarder loop.
//!
//! # Usage
//!
//! ```rust,ignore
//! use ndn_embedded::ipc::{AppQueue, ForwarderQueue};
//! use heapless::spsc::Queue;
//!
//! static mut APP_TO_FWD: Queue<AppRequest, 8> = Queue::new();
//! static mut FWD_TO_APP: Queue<AppResponse, 8> = Queue::new();
//!
//! // In main():
//! let (mut app_tx, fwd_rx) = unsafe { APP_TO_FWD.split() };
//! let (mut fwd_tx, app_rx) = unsafe { FWD_TO_APP.split() };
//! ```

/// A request from an application to the forwarder.
#[derive(Clone, Debug)]
pub enum AppRequest {
    /// Express an Interest.
    ///
    /// The forwarder will look up the FIB, insert a PIT entry, and forward
    /// the Interest on the appropriate face.
    SendInterest {
        /// Raw wire bytes of the Interest packet (stack buffer).
        wire: [u8; 256],
        /// Number of valid bytes in `wire`.
        len: usize,
    },
    /// Produce a Data packet.
    ///
    /// The forwarder will check the PIT for matching pending Interests,
    /// satisfy them, and optionally cache the Data.
    SendData {
        /// Raw wire bytes of the Data packet.
        wire: [u8; 512],
        /// Number of valid bytes in `wire`.
        len: usize,
    },
}

/// A response from the forwarder to an application.
#[derive(Clone, Debug)]
pub enum AppResponse {
    /// A Data packet satisfying a previously expressed Interest.
    Data {
        /// Raw wire bytes of the Data packet.
        wire: [u8; 512],
        /// Number of valid bytes in `wire`.
        len: usize,
    },
    /// The Interest timed out (PIT entry expired before Data arrived).
    Timeout {
        /// FNV-1a hash of the Interest Name (to correlate with the original request).
        name_hash: u64,
    },
    /// The Interest was Nacked.
    Nack {
        /// FNV-1a hash of the Interest Name.
        name_hash: u64,
        /// NDN Nack reason code.
        reason: u64,
    },
}
