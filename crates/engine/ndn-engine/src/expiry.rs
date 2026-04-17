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
use crate::rib::Rib;

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

pub async fn run_rib_expiry_task(rib: Arc<Rib>, fib: Arc<Fib>, cancel: CancellationToken) {
    let interval = Duration::from_secs(1);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(interval) => {
                let affected = rib.drain_expired();
                if !affected.is_empty() {
                    tracing::debug!(count = affected.len(), "RIB entries expired");
                    for prefix in &affected {
                        rib.apply_to_fib(prefix, &fib);
                    }
                }
            }
        }
    }
}

const IDLE_TIMEOUT_NS: u64 = 5 * 60 * 1_000_000_000;
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
pub async fn run_idle_face_task(
    face_states: Arc<DashMap<FaceId, FaceState>>,
    face_table: Arc<FaceTable>,
    fib: Arc<Fib>,
    rib: Arc<Rib>,
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
                    // Idle timeout only applies to connectionless (UDP) faces.
                    // Local faces use cancel-token lifecycle; connection-oriented
                    // faces clean up when the socket closes.
                    let face_id = *entry.key();
                    if let Some(face) = face_table.get(face_id)
                        && matches!(
                            face.kind(),
                            FaceKind::App
                                | FaceKind::Shm
                                | FaceKind::Internal
                                | FaceKind::Unix
                                | FaceKind::Tcp
                                | FaceKind::WebSocket
                                | FaceKind::Management,
                        )
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
                    rib.handle_face_down(face_id, &fib);
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
