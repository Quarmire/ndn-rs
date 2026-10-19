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

/// Monotonic clock, always the SAME clock [`sleep`] runs on: `tokio::time::Instant` natively,
/// `performance.now()` on wasm. Natively this must not be `std::time::Instant` — the driver
/// loops compute a deadline, `sleep` until it, then compare against `Instant::now()`. Under a
/// paused/virtual tokio clock (simulation, `start_paused` tests) `tokio::time::sleep` elapses in
/// virtual time while a std deadline only passes in wall time, so the periodic timer would
/// re-arm in a hot loop until the WALL clock caught up — sync cadence (and every outcome that
/// rides it) would depend on host speed. Unpaused, tokio's clock is the std monotonic clock.
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
