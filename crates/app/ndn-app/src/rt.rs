//! Runtime-portable `sleep` / `timeout` and a monotonic `Instant`, so the
//! consumer fetch path compiles and runs on both native (tokio) and wasm32
//! (gloo-timers) without threading a `Runtime` handle through every
//! `Consumer`(crate::Consumer).
//!
//! `tokio::time` panics on `wasm32-unknown-unknown` (it needs a timer wheel
//! the browser can't provide), so the wasm path races the future against a
//! `gloo_timers` sleep instead. Native keeps the thin tokio wrappers.

use std::future::Future;
use std::time::Duration;

/// Monotonic clock that works on both targets: `web_time::Instant` delegates to
/// `std::time::Instant` natively and to `performance.now()` on wasm32.
pub use web_time::Instant;

/// The future did not complete within the deadline.
#[derive(Debug)]
pub struct Elapsed;

/// Spawn a background task on the ambient executor. `Send` is required natively
/// (tokio is multi-threaded); wasm32 is single-threaded so it isn't. Used by the
/// [`Subscriber`](crate::Subscriber) pump tasks.
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

#[cfg(not(target_arch = "wasm32"))]
pub async fn timeout<F: Future>(dur: Duration, fut: F) -> Result<F::Output, Elapsed> {
    tokio::time::timeout(dur, fut).await.map_err(|_| Elapsed)
}

#[cfg(target_arch = "wasm32")]
pub async fn sleep(dur: Duration) {
    gloo_timers::future::sleep(dur).await;
}

#[cfg(target_arch = "wasm32")]
pub async fn timeout<F: Future>(dur: Duration, fut: F) -> Result<F::Output, Elapsed> {
    use futures::future::{Either, select};

    let timer = gloo_timers::future::sleep(dur);
    futures::pin_mut!(fut);
    futures::pin_mut!(timer);
    match select(fut, timer).await {
        Either::Left((out, _)) => Ok(out),
        Either::Right(((), _)) => Err(Elapsed),
    }
}
