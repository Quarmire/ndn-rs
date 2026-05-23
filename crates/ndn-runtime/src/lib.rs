//! `Spawn + Sleep + Now` runtime traits: one abstraction over Tokio (native)
//! and `wasm-bindgen-futures` + `gloo-timers` (browser) so engine and face
//! code never needs `cfg(target_arch = "wasm32")` for time/spawn.

use std::future::Future;
use std::{pin::Pin, sync::Arc, time::Duration};

pub use web_time::Instant;

// tokio::spawn requires Send; spawn_local on wasm32 doesn't, but Send is a
// strict superset, so a single Send-bound BoxFuture is forbidden only on wasm.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

#[cfg(target_arch = "wasm32")]
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + 'static>>;

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
