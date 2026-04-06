use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use ndn_discovery::DiscoveryProtocol;
use tokio_util::sync::CancellationToken;

use ndn_store::Pit;
use ndn_transport::{FaceId, FaceKind, FacePersistency, FaceTable};

use crate::Fib;
use crate::discovery_context::EngineDiscoveryContext;
use crate::engine::FaceState;

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

/// Default idle timeout for on-demand faces (5 minutes).
const IDLE_TIMEOUT_NS: u64 = 5 * 60 * 1_000_000_000;

/// Sweep interval for idle face detection.
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Background task that removes on-demand faces that have been idle for too
/// long (no packets sent or received within `IDLE_TIMEOUT_NS`).
///
/// Runs every 30 seconds until the cancellation token is cancelled.
pub async fn run_idle_face_task(
    face_states: Arc<DashMap<FaceId, FaceState>>,
    face_table: Arc<FaceTable>,
    fib: Arc<Fib>,
    cancel: CancellationToken,
    discovery: Arc<dyn DiscoveryProtocol>,
    discovery_ctx: Arc<EngineDiscoveryContext>,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(IDLE_SWEEP_INTERVAL) => {
                let now = now_ns();
                let mut expired = Vec::new();

                for entry in face_states.iter() {
                    if entry.persistency != FacePersistency::OnDemand {
                        continue;
                    }
                    // Local faces (App, SHM, Internal) use cancel-token lifecycle,
                    // not idle timeout.  Their last_activity is never updated in
                    // run_face_reader, so they would be falsely reaped here.
                    let face_id = *entry.key();
                    if let Some(face) = face_table.get(face_id)
                        && matches!(face.kind(), FaceKind::App | FaceKind::Shm | FaceKind::Internal)
                    {
                        continue;
                    }
                    let last = entry.last_activity.load(std::sync::atomic::Ordering::Relaxed);
                    if now.saturating_sub(last) > IDLE_TIMEOUT_NS {
                        expired.push(face_id);
                    }
                }

                for face_id in expired {
                    discovery.on_face_down(face_id, &*discovery_ctx);
                    if let Some((_, state)) = face_states.remove(&face_id) {
                        state.cancel.cancel();
                    }
                    fib.remove_face(face_id);
                    face_table.remove(face_id);
                    tracing::debug!(face=%face_id, "idle on-demand face removed");
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
        let pit = Arc::new(Pit::new());
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run_expiry_task(pit, cancel.clone()));
        cancel.cancel();
        tokio::time::timeout(Duration::from_millis(200), task)
            .await
            .expect("expiry task did not stop after cancellation")
            .expect("task panicked");
    }

    #[tokio::test]
    async fn expiry_task_runs_without_panic() {
        let pit = Arc::new(Pit::new());
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run_expiry_task(pit, cancel.clone()));
        // Let a few ticks pass to ensure the loop body executes at least once.
        tokio::time::sleep(Duration::from_millis(5)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_millis(200), task)
            .await
            .expect("expiry task did not stop after cancellation")
            .expect("task panicked");
    }
}
