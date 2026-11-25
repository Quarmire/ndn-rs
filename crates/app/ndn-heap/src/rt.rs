//! Runtime glue: the same spawn/sleep/timeout `ndn-app` uses, and a monotonic
//! clock in the same domain as its timers (tokio's natively, so a paused or
//! virtual runtime measures ages in its own time; `performance.now()` on
//! wasm32); and [`Tasks`], the tasks of one part of a node, which end when it
//! stops and which it can wait for.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use tokio::time::Instant;
#[cfg(target_arch = "wasm32")]
pub(crate) use web_time::Instant;

pub(crate) use ndn_app::rt::{sleep, spawn, timeout};

/// The tasks one part of a node runs (the network half, the judge, the flusher, the node's
/// own). [`Self::stop`] ends every one of them at its next poll, and drops what it held;
/// [`Self::ended`] returns once each has been dropped, so whatever they held (the node, the
/// store) is released by then. A task is counted when it is spawned, not when it first runs.
pub(crate) struct Tasks {
    live: AtomicUsize,
    gone: Notify,
    stop: CancellationToken,
}

/// One running task: counted until it is dropped.
struct Live(Arc<Tasks>);

impl Live {
    fn enter(tasks: &Arc<Tasks>) -> Live {
        tasks.live.fetch_add(1, Ordering::AcqRel);
        Live(Arc::clone(tasks))
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if self.0.live.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.gone.notify_waiters();
        }
    }
}

/// A task and its count. The future is dropped before the count is, whichever way the task
/// ends (finished, stopped, or dropped without being polled).
struct Counted<F> {
    task: Pin<Box<F>>,
    _live: Live,
}

impl<F: Future<Output = ()>> Future for Counted<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.get_mut().task.as_mut().poll(cx)
    }
}

impl Tasks {
    pub(crate) fn new() -> Arc<Tasks> {
        Arc::new(Tasks {
            live: AtomicUsize::new(0),
            gone: Notify::new(),
            stop: CancellationToken::new(),
        })
    }

    /// `task` as one of these tasks, counted from now: it runs until it ends or
    /// [`Self::stop`]. Spawn the result, or run it where a runtime of another crate runs it.
    pub(crate) fn track<F: Future<Output = ()>>(
        self: &Arc<Self>,
        task: F,
    ) -> impl Future<Output = ()> + use<F> {
        let (live, stop) = (Live::enter(self), self.stop.clone());
        Counted {
            task: Box::pin(async move {
                let _ = stop.run_until_cancelled(task).await;
            }),
            _live: live,
        }
    }

    /// Spawn `task` as one of these tasks.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn spawn<F: Future<Output = ()> + Send + 'static>(self: &Arc<Self>, task: F) {
        spawn(self.track(task));
    }

    /// Spawn `task` as one of these tasks.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn spawn<F: Future<Output = ()> + 'static>(self: &Arc<Self>, task: F) {
        spawn(self.track(task));
    }

    /// End every task, now and at the next poll of each.
    pub(crate) fn stop(&self) {
        self.stop.cancel();
    }

    /// Wait until no task is left: each ended and was dropped. Call it after [`Self::stop`]
    /// (or when every task ends of itself).
    pub(crate) async fn ended(&self) {
        loop {
            let gone = self.gone.notified();
            if self.live.load(Ordering::Acquire) == 0 {
                return;
            }
            gone.await;
        }
    }
}
