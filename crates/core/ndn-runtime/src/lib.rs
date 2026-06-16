//! `Spawn + Sleep + Now` runtime traits: one abstraction over Tokio (native)
//! and `wasm-bindgen-futures` + `gloo-timers` (browser) so engine and face
//! code never needs `cfg(target_arch = "wasm32")` for time/spawn.

use std::future::Future;
use std::task::{Context, Poll};
use std::{pin::Pin, sync::Arc, time::Duration};

pub use web_time::Instant;

// tokio::spawn requires Send; spawn_local on wasm32 doesn't, but Send is a
// strict superset, so a single Send-bound BoxFuture is forbidden only on wasm.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

#[cfg(target_arch = "wasm32")]
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + 'static>>;

/// A runtime-agnostic handle to a spawned task that resolves when the task
/// completes. Awaiting it is used for **ordered teardown** (e.g. waiting for a
/// protocol's task to release its `Arc`s before a downstream flush); dropping it
/// does **not** cancel the task. Replaces leaking a `tokio::task::JoinHandle`
/// through portable trait surfaces. Wraps the platform's own (Send + Sync)
/// completion handle so it can sit in shared engine state.
#[cfg(not(target_arch = "wasm32"))]
pub struct TaskHandle(tokio::task::JoinHandle<()>);

#[cfg(target_arch = "wasm32")]
pub struct TaskHandle(futures::channel::oneshot::Receiver<()>);

impl Future for TaskHandle {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Pin::new(&mut self.0).poll(cx).map(|_| ())
    }
}

/// Spawn `fut` on the ambient default runtime, returning an awaitable
/// [`TaskHandle`]. Native: a `tokio` task (must run inside a Tokio runtime).
/// wasm: `spawn_local` + a oneshot completion signal.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn_task(fut: BoxFuture) -> TaskHandle {
    TaskHandle(tokio::spawn(fut))
}

/// Wrap an existing native `tokio` task handle — lets impl crates that already
/// `tokio::spawn` internally hand back a runtime-agnostic [`TaskHandle`].
#[cfg(not(target_arch = "wasm32"))]
impl From<tokio::task::JoinHandle<()>> for TaskHandle {
    fn from(jh: tokio::task::JoinHandle<()>) -> Self {
        TaskHandle(jh)
    }
}

#[cfg(target_arch = "wasm32")]
pub fn spawn_task(fut: BoxFuture) -> TaskHandle {
    let (tx, rx) = futures::channel::oneshot::channel::<()>();
    wasm_bindgen_futures::spawn_local(async move {
        fut.await;
        let _ = tx.send(());
    });
    TaskHandle(rx)
}

pub trait Spawn: Send + Sync + 'static {
    fn spawn(&self, fut: BoxFuture);
}

pub trait Sleep: Send + Sync + 'static {
    fn sleep(&self, dur: Duration) -> BoxFuture;
}

pub trait Now: Send + Sync + 'static {
    fn now(&self) -> Instant;
}

pub trait Runtime: Spawn + Sleep + Now {}

#[cfg(not(target_arch = "wasm32"))]
pub struct TokioRuntime;

#[cfg(not(target_arch = "wasm32"))]
impl Spawn for TokioRuntime {
    fn spawn(&self, fut: BoxFuture) {
        tokio::spawn(fut);
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Sleep for TokioRuntime {
    fn sleep(&self, dur: Duration) -> BoxFuture {
        Box::pin(tokio::time::sleep(dur))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Now for TokioRuntime {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Runtime for TokioRuntime {}

#[cfg(target_arch = "wasm32")]
pub struct WasmRuntime;

#[cfg(target_arch = "wasm32")]
impl Spawn for WasmRuntime {
    fn spawn(&self, fut: BoxFuture) {
        wasm_bindgen_futures::spawn_local(fut);
    }
}

#[cfg(target_arch = "wasm32")]
impl Sleep for WasmRuntime {
    fn sleep(&self, dur: Duration) -> BoxFuture {
        Box::pin(gloo_timers::future::sleep(dur))
    }
}

#[cfg(target_arch = "wasm32")]
impl Now for WasmRuntime {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[cfg(target_arch = "wasm32")]
impl Runtime for WasmRuntime {}

pub fn default_runtime() -> Arc<dyn Runtime> {
    #[cfg(not(target_arch = "wasm32"))]
    return Arc::new(TokioRuntime);
    #[cfg(target_arch = "wasm32")]
    return Arc::new(WasmRuntime);
}
