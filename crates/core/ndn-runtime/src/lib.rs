//! `Spawn + Sleep + Now` runtime traits: one abstraction over Tokio (native)
//! and `wasm-bindgen-futures` + `gloo-timers` (browser) so engine and face
//! code never needs `cfg(target_arch = "wasm32")` for time/spawn.

#![cfg_attr(docsrs, feature(doc_cfg))]

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
    /// Monotonic instant (durations, timeouts, interval timing). Never goes backwards;
    /// not comparable across processes.
    fn now(&self) -> Instant;

    /// **Wall-clock** time as nanoseconds since the Unix epoch — the basis for absolute,
    /// cross-node timestamps (PIT/Interest-lifetime deadlines, Data freshness, certificate
    /// validity). Distinct from [`now`](Self::now), which is monotonic and process-local.
    ///
    /// The default reads the system clock, so production runtimes need not implement it. A
    /// **virtual/simulation** runtime overrides this (and `now`/`sleep`) to return *logical*
    /// time, which is what makes a simulated run deterministic and reproducible — every
    /// engine time read flows through this one seam.
    fn unix_nanos(&self) -> u64 {
        use web_time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

pub trait Runtime: Spawn + Sleep + Now {}

/// The deadline elapsed before the future completed (returned by [`timeout`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

impl core::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "operation timed out")
    }
}
impl std::error::Error for Elapsed {}

/// Run `fut` with a deadline measured on **the runtime's own clock** — so under a virtual /
/// simulation runtime it's virtual time, not wall-clock. The executor-agnostic replacement for
/// `tokio::time::timeout`: a race between `fut` and `rt.sleep(dur)`, so it runs on any executor
/// (Tokio, the sim's discrete-event executor, wasm). Returns `Err(`[`Elapsed`]`)` if the deadline
/// wins.
pub async fn timeout<S, T, F>(rt: &S, dur: Duration, fut: F) -> Result<T, Elapsed>
where
    S: Sleep + ?Sized,
    F: Future<Output = T>,
{
    use futures::future::{Either, select};
    let sleep = rt.sleep(dur);
    futures::pin_mut!(fut);
    match select(fut, sleep).await {
        Either::Left((value, _)) => Ok(value),
        Either::Right(((), _)) => Err(Elapsed),
    }
}

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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The default `unix_nanos()` reads the system clock — production runtimes get it free.
    #[test]
    fn default_unix_nanos_reads_system_clock() {
        let rt = TokioRuntime;
        let a = rt.unix_nanos();
        assert!(
            a > 1_600_000_000_000_000_000,
            "plausible epoch ns (post-2020)"
        );
    }

    /// The seam a virtual/simulation runtime uses: override `unix_nanos`/`now`/`sleep` to
    /// return *logical* time so every engine time read is deterministic. (Slice 0 lays this
    /// seam; later slices supply a full virtual runtime + scheduler.) The clock state is a
    /// shared `Arc<AtomicU64>` so the test can advance logical time the way a scheduler will.
    #[test]
    fn virtual_runtime_can_drive_logical_epoch_time() {
        struct VirtualClock {
            epoch_ns: Arc<AtomicU64>,
        }
        impl Spawn for VirtualClock {
            fn spawn(&self, _fut: BoxFuture) {}
        }
        impl Sleep for VirtualClock {
            fn sleep(&self, _dur: Duration) -> BoxFuture {
                Box::pin(async {})
            }
        }
        impl Now for VirtualClock {
            fn now(&self) -> Instant {
                Instant::now()
            }
            fn unix_nanos(&self) -> u64 {
                self.epoch_ns.load(Ordering::Relaxed)
            }
        }
        impl Runtime for VirtualClock {}

        let clock = Arc::new(AtomicU64::new(1_000));
        let rt: Arc<dyn Runtime> = Arc::new(VirtualClock {
            epoch_ns: clock.clone(),
        });
        assert_eq!(
            rt.unix_nanos(),
            1_000,
            "logical epoch is whatever the sim sets"
        );
        // Advance logical time the way a scheduler will; the engine, reading only through
        // this seam, follows deterministically.
        clock.store(5_000, Ordering::Relaxed);
        assert_eq!(rt.unix_nanos(), 5_000);
    }
}
