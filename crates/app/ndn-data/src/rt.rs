//! Runtime glue: the same spawn/sleep/timeout `ndn-app` uses, and a monotonic
//! clock in the same domain as its timers (tokio's natively, so a paused or
//! virtual runtime measures ages in its own time; `performance.now()` on
//! wasm32).

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use tokio::time::Instant;
#[cfg(target_arch = "wasm32")]
pub(crate) use web_time::Instant;

pub(crate) use ndn_app::rt::{sleep, spawn, timeout};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Cooperative cancellation of work run by [`blocking`]: raised at the deadline. Work that
/// cannot finish before it checks [`Cancel::cancelled`] between its steps and stops; what it
/// returns after the deadline is discarded.
#[derive(Clone)]
pub(crate) struct Cancel {
    raised: Arc<AtomicBool>,
    /// The wall clock at which the work is over time: never when the limit does not fit.
    deadline: Option<web_time::Instant>,
}

impl Cancel {
    /// A cancellation that is raised `limit` of wall-clock time from now.
    pub(crate) fn within(limit: Duration) -> Self {
        Cancel {
            raised: Arc::new(AtomicBool::new(false)),
            deadline: web_time::Instant::now().checked_add(limit),
        }
    }

    /// Whether the work is over its time: it should stop, and its result is not used.
    pub(crate) fn cancelled(&self) -> bool {
        self.raised.load(Ordering::Relaxed)
            || self.deadline.is_some_and(|d| web_time::Instant::now() >= d)
    }
}

/// Why [`blocking`] gave no result.
#[derive(Debug)]
pub(crate) enum Stopped {
    /// The work was not done within its time.
    Deadline,
    /// No thread could be started for it.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    NoThread,
}

/// Run `work`, CPU-bound and synchronous, within `limit` of wall-clock time, without holding
/// up the executor: on its own thread, with a watchdog that raises [`Cancel`] at the deadline
/// and ends the wait (the work is abandoned: it stops at its next [`Cancel::cancelled`] check,
/// and what it returns is dropped). On wasm32, which has no threads, it runs inline and only
/// its own checks of [`Cancel::cancelled`] bound it.
///
/// The wall clock only ever makes this return [`Stopped`], which the callers turn into a
/// refusal: it never decides what is true or trusted. It is the wall clock and not the
/// runtime's clock (a paused or virtual runtime would run it out while the thread works).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn blocking<T: Send + 'static>(
    limit: Duration,
    work: impl FnOnce(&Cancel) -> T + Send + 'static,
) -> Result<T, Stopped> {
    use futures::channel::oneshot;
    use futures::future::{Either, select};
    use parking_lot::{Condvar, Mutex};
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

    let cancel = Cancel::within(limit);
    let (done_tx, done_rx) = oneshot::channel();
    let (late_tx, late_rx) = oneshot::channel::<()>();
    let finished = Arc::new((Mutex::new(false), Condvar::new()));
    {
        let (cancel, finished) = (cancel.clone(), Arc::clone(&finished));
        std::thread::Builder::new()
            .name("ndn-data-work".into())
            .spawn(move || {
                let out = catch_unwind(AssertUnwindSafe(|| work(&cancel)));
                *finished.0.lock() = true;
                finished.1.notify_all();
                let _ = done_tx.send(out);
            })
            .map_err(|_| Stopped::NoThread)?;
    }
    {
        let (watched, finished) = (cancel.clone(), Arc::clone(&finished));
        let watchdog = std::thread::Builder::new()
            .name("ndn-data-watchdog".into())
            .spawn(move || {
                let mut done = finished.0.lock();
                if !finished
                    .1
                    .wait_while_for(&mut done, |d| !*d, limit)
                    .timed_out()
                {
                    return;
                }
                watched.raised.store(true, Ordering::Relaxed);
                let _ = late_tx.send(());
            });
        if watchdog.is_err() {
            // The work stops at its next check: nothing else is left to bound it.
            cancel.raised.store(true, Ordering::Relaxed);
            return Err(Stopped::NoThread);
        }
    }
    let out = match select(done_rx, late_rx).await {
        Either::Left((out, _)) => out,
        // The deadline came first, or the watchdog ended because the work did: then the
        // result is there.
        Either::Right((Err(_), done_rx)) => done_rx.await,
        Either::Right((Ok(()), _)) => return Err(Stopped::Deadline),
    };
    match out {
        Ok(Ok(out)) if cancel.cancelled() => {
            drop(out);
            Err(Stopped::Deadline)
        }
        Ok(Ok(out)) => Ok(out),
        Ok(Err(panic)) => resume_unwind(panic),
        // The thread ended without a result: it is gone with its panic reported there.
        Err(_) => Err(Stopped::NoThread),
    }
}

/// [`blocking`] on wasm32: no threads, so inline; the work stops at its own checks of the
/// deadline, and a result produced after it is discarded.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn blocking<T>(
    limit: Duration,
    work: impl FnOnce(&Cancel) -> T,
) -> Result<T, Stopped> {
    let cancel = Cancel::within(limit);
    let out = work(&cancel);
    match cancel.cancelled() {
        true => Err(Stopped::Deadline),
        false => Ok(out),
    }
}
