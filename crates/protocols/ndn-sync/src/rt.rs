//! Runtime-portable `spawn` / `sleep` / `Instant` for the sync driver loops.
//!
//! The SVS and PSync background tasks spawn a future and drive a periodic
//! timer. Native uses tokio; `wasm32-unknown-unknown` can't (tokio's timer
//! wheel panics, and there's no ambient tokio runtime to `spawn` onto), so the
//! wasm path uses `wasm_bindgen_futures::spawn_local` + `gloo_timers`. This
//! mirrors `ndn_runtime` and `ndn_app::rt`; the protocol code stays
//! cfg-free.

use std::future::Future;
use std::time::Duration;

/// Monotonic clock in the SAME domain as [`sleep`]: tokio's clock natively,
/// `performance.now()` on wasm.
///
/// The driver loops sleep until a deadline and then check `deadline <= now()`
/// before sending. With `std::time::Instant` here and `tokio::time::sleep` for
/// the wait, the two clocks diverge whenever tokio's is not the wall clock --
/// a paused/virtual runtime finishes the sleep in near-zero wall time, the
/// check stays false, and the periodic Sync Interest is not sent until real
/// time catches up. In ndn-sim that starved every re-advertisement on a lossy
/// link, so a consumer holding at a gap never learned of it again and the
/// replica stalled (stall_matrix `drop/pair`), with the outcome depending on
/// host speed. On a normal runtime tokio's clock tracks the monotonic clock,
/// so production timing is unchanged.
#[cfg(not(target_arch = "wasm32"))]
pub use tokio::time::Instant;
#[cfg(target_arch = "wasm32")]
pub use web_time::Instant;

/// Spawn a background task on the ambient executor. The future must be `Send`
/// on native (tokio is multi-threaded); wasm32 is single-threaded so it isn't.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn<F: Future<Output = ()> + Send + 'static>(fut: F) {
    tokio::spawn(fut);
}

#[cfg(target_arch = "wasm32")]
pub fn spawn<F: Future<Output = ()> + 'static>(fut: F) {
    wasm_bindgen_futures::spawn_local(fut);
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(dur: Duration) {
    tokio::time::sleep(dur).await;
}

#[cfg(target_arch = "wasm32")]
pub async fn sleep(dur: Duration) {
    gloo_timers::future::sleep(dur).await;
}
