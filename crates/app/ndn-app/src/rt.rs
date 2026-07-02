//! Runtime-portable `sleep` / `timeout` / `spawn` and a monotonic `Instant`, so the consumer
//! fetch path runs on native (tokio), wasm32 (gloo-timers), **and** an injected
//! [`Runtime`](ndn_runtime::Runtime) — the
//! virtual / discrete-event kernels — without threading a handle through every
//! [`Consumer`](crate::Consumer).
//!
//! Native default is the thin tokio wrappers. But when an **ambient runtime** is installed for the
//! current thread (via [`set_current_runtime`] — the sim's discrete-event executor does this while
//! it drives), `sleep`/`timeout`/`spawn` route through *that* runtime's clock + executor instead of
//! tokio's. That's what lets an app-driven fabric run deterministically on the event queue. wasm
//! keeps the `gloo_timers` race (`tokio::time` panics there).

use std::future::Future;
use std::time::Duration;

/// Monotonic clock that works on both targets: `web_time::Instant` delegates to
/// `std::time::Instant` natively and to `performance.now()` on wasm32.
pub use web_time::Instant;

/// The future did not complete within the deadline.
#[derive(Debug)]
pub struct Elapsed;

// ---- Ambient runtime (native): a "current executor" so rt::* can ride an injected Runtime -----

#[cfg(not(target_arch = "wasm32"))]
mod ambient {
    use std::cell::RefCell;
    use std::sync::Arc;

    use ndn_runtime::Runtime;

    thread_local! {
        static CURRENT: RefCell<Option<Arc<dyn Runtime>>> = const { RefCell::new(None) };
    }

    /// Restores the previous ambient runtime when dropped.
    pub struct RuntimeGuard(Option<Arc<dyn Runtime>>);
    impl Drop for RuntimeGuard {
        fn drop(&mut self) {
            CURRENT.with(|c| *c.borrow_mut() = self.0.take());
        }
    }

    /// Install `rt` as the ambient runtime for this thread; `rt::sleep`/`timeout`/`spawn` route
    /// through it until the returned guard drops. The sim's single-threaded discrete-event executor
    /// uses this so app code (fetch/serve) runs on the event queue instead of tokio.
    pub fn set_current_runtime(rt: Arc<dyn Runtime>) -> RuntimeGuard {
        CURRENT.with(|c| RuntimeGuard(c.borrow_mut().replace(rt)))
    }

    pub(super) fn current() -> Option<Arc<dyn Runtime>> {
        CURRENT.with(|c| c.borrow().clone())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use ambient::{RuntimeGuard, set_current_runtime};

/// Spawn a background task on the ambient executor. `Send` is required natively
/// (tokio is multi-threaded); wasm32 is single-threaded so it isn't. Used by the
/// [`Subscriber`](crate::Subscriber) pump tasks.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn<F: Future<Output = ()> + Send + 'static>(fut: F) {
    match ambient::current() {
        Some(rt) => rt.spawn(Box::pin(fut)),
        None => {
            tokio::spawn(fut);
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub fn spawn<F: Future<Output = ()> + 'static>(fut: F) {
    wasm_bindgen_futures::spawn_local(fut);
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(dur: Duration) {
    match ambient::current() {
        Some(rt) => rt.sleep(dur).await,
        None => tokio::time::sleep(dur).await,
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn timeout<F: Future>(dur: Duration, fut: F) -> Result<F::Output, Elapsed> {
    match ambient::current() {
        Some(rt) => ndn_runtime::timeout(&*rt, dur, fut)
            .await
            .map_err(|_| Elapsed),
        None => tokio::time::timeout(dur, fut).await.map_err(|_| Elapsed),
    }
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
