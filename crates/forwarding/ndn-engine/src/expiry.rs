use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use ndn_discovery_core::DiscoveryProtocol;
use ndn_runtime::Runtime;
use tokio_util::sync::CancellationToken;

use ndn_store::{DeadNonceList, Pit};
use ndn_transport::{FaceId, FaceKind, FacePersistency, FaceTable};

use crate::Fib;
use crate::discovery_context::EngineDiscoveryContext;
use crate::engine::FaceState;
use crate::observability::targets as t;
use crate::rib::Rib;
use std::sync::atomic::Ordering;

/// The dead nonce list's purge and the orphaned subscription budgets' reap need no precision:
/// the list treats expired entries as absent anyway (and bounds itself on insert), and the
/// budgets carry minute-scale deadlines. They run at most this far apart, and the PIT task never
/// sleeps longer, which also bounds how long a wall-clock step can delay it.
const HOUSEKEEPING: Duration = Duration::from_secs(1);

/// Expires PIT entries at their deadlines: the task sleeps until the soonest one the PIT may
/// hold ([`Pit::next_expiry`]), woken earlier when an entry expiring sooner comes in, and wakes
/// at most every housekeeping second otherwise. An idle forwarder does not spin.
#[tracing::instrument(
    level = "info",
    target = "engine",
    name = "expiry",
    skip_all,
    fields(kind = "pit")
)]
pub async fn run_expiry_task(
    pit: Arc<Pit>,
    dead_nonce_list: Option<Arc<DeadNonceList>>,
    face_states: Arc<DashMap<FaceId, FaceState>>,
    cancel: CancellationToken,
    runtime: Arc<dyn Runtime>,
) {
    // Housekeeping goes by the monotonic clock, PIT deadlines by the wall clock they are set in
    // (epoch ns via the runtime seam, so a virtual runtime drives PIT expiry deterministically).
    let mut housekeeping_at = runtime.now() + HOUSEKEEPING;
    loop {
        let to_expiry =
            Duration::from_nanos(pit.next_expiry().saturating_sub(runtime.unix_nanos()));
        let to_housekeeping = housekeeping_at.saturating_duration_since(runtime.now());
        let sleep = runtime.sleep(to_expiry.min(to_housekeeping));
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            // An entry expiring sooner came in: sleep until it instead.
            _ = pit.expiry_moved() => continue,
            _ = sleep => {}
        }
        let now = runtime.unix_nanos();
        if pit.next_expiry() <= now {
            let expired = pit.drain_expired_entries(now);
            if !expired.is_empty() {
                tracing::trace!(target: t::FWD_PIT, count = expired.len(), "PIT entries expired");
            }
            for (_token, entry) in &expired {
                crate::stages::pit::insert_dead_nonces(&dead_nonce_list, entry, now);
                // Credit `NUnsatisfiedInterests` on every in-face whose PIT entry timed out
                // without matching Data.
                for record in &entry.in_records {
                    if let Some(state) = face_states.get(&FaceId(record.face_id)) {
                        state
                            .counters
                            .in_unsatisfied_interests
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        if runtime.now() >= housekeeping_at {
            pit.reap_orphans(now);
            if let Some(dnl) = dead_nonce_list.as_ref() {
                dnl.purge_expired(now);
            }
            housekeeping_at = runtime.now() + HOUSEKEEPING;
        }
    }
}

#[tracing::instrument(
    level = "info",
    target = "engine",
    name = "expiry",
    skip_all,
    fields(kind = "rib")
)]
pub async fn run_rib_expiry_task(
    rib: Arc<Rib>,
    fib: Arc<Fib>,
    reflexive: Arc<crate::reflexive::ReflexiveTable>,
    cancel: CancellationToken,
    runtime: Arc<dyn Runtime>,
) {
    let interval = Duration::from_secs(1);
    loop {
        let sleep = runtime.sleep(interval);
        tokio::select! {
            biased;            _ = cancel.cancelled() => break,
            _ = sleep => {
                let affected = rib.drain_expired(runtime.now());
                if !affected.is_empty() {
                    tracing::debug!(target: t::ENGINE, count = affected.len(), "RIB entries expired");
                    for prefix in &affected {
                        rib.apply_to_fib(prefix, &fib);
                    }
                }
                // GC expired reflexive reverse-routes (W-RF-3). Lookup already
                // treats expired routes as absent; this just frees memory.
                let swept = reflexive.sweep(runtime.unix_nanos());
                if swept > 0 {
                    tracing::debug!(target: t::ENGINE, count = swept, "reflexive routes expired");
                }
            }
        }
    }
}

const IDLE_TIMEOUT_NS: u64 = 5 * 60 * 1_000_000_000;
const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
#[tracing::instrument(
    level = "info",
    target = "engine",
    name = "expiry",
    skip_all,
    fields(kind = "idle_face")
)]
#[allow(clippy::too_many_arguments)]
pub async fn run_idle_face_task(
    face_states: Arc<DashMap<FaceId, FaceState>>,
    face_table: Arc<FaceTable>,
    fib: Arc<Fib>,
    rib: Arc<Rib>,
    cancel: CancellationToken,
    discovery: Arc<dyn DiscoveryProtocol>,
    discovery_ctx: Arc<EngineDiscoveryContext>,
    runtime: Arc<dyn Runtime>,
) {
    loop {
        let sleep = runtime.sleep(IDLE_SWEEP_INTERVAL);
        tokio::select! {
            biased;            _ = cancel.cancelled() => break,
            _ = sleep => {
                let now = runtime.unix_nanos();
                let mut expired = Vec::new();

                for entry in face_states.iter() {
                    if entry.persistency != FacePersistency::OnDemand {
                        continue;
                    }
                    // Idle timeout only applies to connectionless (UDP) faces.
                    // Local faces use the cancel token; connection-oriented
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
                    tracing::debug!(target: t::FACE_SYSTEM, face=%face_id, "idle on-demand face removed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expiry_task_cancels_promptly() {
        let pit = Arc::new(Pit::new());
        let cancel = CancellationToken::new();
        let runtime = ndn_runtime::default_runtime();
        let face_states = Arc::new(DashMap::<FaceId, FaceState>::new());
        let task = tokio::spawn(run_expiry_task(
            pit,
            None,
            face_states,
            cancel.clone(),
            runtime,
        ));
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
        let runtime = ndn_runtime::default_runtime();
        let face_states = Arc::new(DashMap::<FaceId, FaceState>::new());
        let task = tokio::spawn(run_expiry_task(
            pit,
            None,
            face_states,
            cancel.clone(),
            runtime,
        ));
        tokio::time::sleep(Duration::from_millis(5)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_millis(200), task)
            .await
            .expect("expiry task did not stop after cancellation")
            .expect("task panicked");
    }

    /// The task sleeps until the soonest deadline the PIT holds: an entry inserted while it
    /// sleeps toward a later one (here the housekeeping second) must still expire on time.
    #[tokio::test]
    async fn entry_inserted_while_sleeping_expires_on_time() {
        use ndn_packet::Name;
        use ndn_store::{PitEntry, PitToken};

        let pit = Arc::new(Pit::new());
        let cancel = CancellationToken::new();
        let runtime = ndn_runtime::default_runtime();
        let face_states = Arc::new(DashMap::<FaceId, FaceState>::new());
        let task = tokio::spawn(run_expiry_task(
            Arc::clone(&pit),
            None,
            face_states,
            cancel.clone(),
            Arc::clone(&runtime),
        ));
        tokio::time::sleep(Duration::from_millis(20)).await;
        let later: Name = "/expiry/later".parse().unwrap();
        let soon: Name = "/expiry/soon".parse().unwrap();
        let (later_token, soon_token) = (
            PitToken::from_interest(&later),
            PitToken::from_interest(&soon),
        );
        pit.insert(
            later_token,
            PitEntry::new(Arc::new(later), runtime.unix_nanos(), 4_000),
        );
        pit.insert(
            soon_token,
            PitEntry::new(Arc::new(soon), runtime.unix_nanos(), 30),
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            !pit.contains(&soon_token),
            "an entry 30 ms from expiry must be gone 250 ms later"
        );
        assert!(
            pit.contains(&later_token),
            "an entry 4 s from expiry must still be there"
        );
        cancel.cancel();
        tokio::time::timeout(Duration::from_millis(200), task)
            .await
            .expect("expiry task did not stop after cancellation")
            .expect("task panicked");
    }
}
