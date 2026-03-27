use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use ndn_store::Pit;

/// Background task that drains expired PIT entries every millisecond.
///
/// Runs until the cancellation token is cancelled.
pub async fn run_expiry_task(pit: Arc<Pit>, cancel: CancellationToken) {
    let interval = Duration::from_millis(1);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(interval) => {
                let now = now_ns();
                let expired = pit.drain_expired(now);
                if !expired.is_empty() {
                    tracing::trace!(count = expired.len(), "PIT entries expired");
                }
            }
        }
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expiry_task_cancels_promptly() {
        let pit    = Arc::new(Pit::new());
        let cancel = CancellationToken::new();
        let task   = tokio::spawn(run_expiry_task(pit, cancel.clone()));
        cancel.cancel();
        tokio::time::timeout(Duration::from_millis(200), task)
            .await
            .expect("expiry task did not stop after cancellation")
            .expect("task panicked");
    }

    #[tokio::test]
    async fn expiry_task_runs_without_panic() {
        let pit    = Arc::new(Pit::new());
        let cancel = CancellationToken::new();
        let task   = tokio::spawn(run_expiry_task(pit, cancel.clone()));
        // Let a few ticks pass to ensure the loop body executes at least once.
        tokio::time::sleep(Duration::from_millis(5)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_millis(200), task)
            .await
            .expect("expiry task did not stop after cancellation")
            .expect("task panicked");
    }
}
