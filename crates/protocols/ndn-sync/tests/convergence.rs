//! Multi-node SVS convergence harness.
//!
//! Wires N [`join_svs_group`] cores through a shared in-memory "network"
//! task with a configurable lossy/delaying shim, then asserts every node
//! eventually learns every publisher's latest sequence number. This is
//! the randomized-convergence (not literal-loom) check the suppression
//! timer needs: that logic looks right and races wrong, and the
//! channel-based driver makes an N-node harness cheap.
//!
//! Two scenarios: steady loss+delay, and a partition that heals.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_sync::{SvsConfig, join_svs_group};
use tokio::sync::{Mutex, mpsc};

/// Per-node view of "highest seq learned for each publisher", accumulated
/// from the [`SyncUpdate`] stream.
type Learned = Arc<Mutex<HashMap<String, HashMap<String, u64>>>>;

struct Shim {
    /// Drop probability in `[0.0, 1.0]`.
    loss: f64,
    /// Max added per-packet delay; actual delay is uniform `[0, max]`.
    max_delay_ms: u64,
}

/// Build N nodes joined to `group`, all reachable through one broker
/// task. Returns the publish handles (kept alive by the caller), the
/// node names, and the shared learned-state map.
async fn spawn_group(
    group: &Name,
    n: usize,
    config: SvsConfig,
    shim: Arc<Mutex<Shim>>,
    partitioned: Arc<Mutex<Vec<bool>>>,
) -> (Vec<ndn_sync::SyncHandle>, Vec<Name>, Learned) {
    let learned: Learned = Arc::new(Mutex::new(HashMap::new()));
    let names: Vec<Name> = (0..n)
        .map(|i| format!("/test/c/node-{i}").parse().unwrap())
        .collect();

    // Per-node inbound senders, so the broker can deliver to any node.
    let mut inbound_tx: Vec<mpsc::Sender<Bytes>> = Vec::new();
    // Central bus the broker reads: (origin_index, wire).
    let (bus_tx, mut bus_rx) = mpsc::channel::<(usize, Bytes)>(1024);
    let mut handles = Vec::new();

    for (i, name) in names.iter().enumerate() {
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        inbound_tx.push(in_tx);

        let mut handle = join_svs_group(group.clone(), name.clone(), out_tx, in_rx, config.clone());

        // Forward this node's outgoing Interests onto the shared bus.
        let bus = bus_tx.clone();
        tokio::spawn(async move {
            while let Some(pkt) = out_rx.recv().await {
                if bus.send((i, pkt)).await.is_err() {
                    break;
                }
            }
        });

        // Take ownership of the update receiver (SyncHandle.rx is public
        // but not Option, and the handle has a Drop impl, so swap in a
        // dummy receiver rather than moving out of the struct).
        let (_dummy_tx, dummy_rx) = mpsc::channel::<ndn_sync::SyncUpdate>(1);
        let mut rx = std::mem::replace(&mut handle.rx, dummy_rx);
        let learned_c = Arc::clone(&learned);
        let self_name = name.to_string();
        tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                let mut g = learned_c.lock().await;
                let per = g.entry(self_name.clone()).or_default();
                let slot = per.entry(update.publisher.clone()).or_insert(0);
                if update.high_seq > *slot {
                    *slot = update.high_seq;
                }
            }
        });

        handles.push(handle);
    }

    // Broker: fan each bussed packet out to every *other* node, applying
    // loss, delay, and the current partition mask.
    let inbound = inbound_tx.clone();
    tokio::spawn(async move {
        while let Some((origin, pkt)) = bus_rx.recv().await {
            let (loss, max_delay) = {
                let s = shim.lock().await;
                (s.loss, s.max_delay_ms)
            };
            for (j, tx) in inbound.iter().enumerate() {
                if j == origin {
                    continue;
                }
                {
                    let part = partitioned.lock().await;
                    // A packet crosses only if both endpoints are on the
                    // same side of the partition.
                    if part[origin] != part[j] {
                        continue;
                    }
                }
                if fastrand::f64() < loss {
                    continue;
                }
                let delay = if max_delay > 0 {
                    fastrand::u64(0..=max_delay)
                } else {
                    0
                };
                let tx = tx.clone();
                let pkt = pkt.clone();
                tokio::spawn(async move {
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    let _ = tx.send(pkt).await;
                });
            }
        }
    });

    (handles, names, learned)
}

/// Poll the learned map until every node knows every *other* node's final
/// sequence number, or `timeout` elapses.
async fn await_convergence(
    learned: &Learned,
    names: &[Name],
    final_seq: u64,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        {
            let g = learned.lock().await;
            let mut all = true;
            for (i, ni) in names.iter().enumerate() {
                let self_key = ni.to_string();
                let per = g.get(&self_key);
                for (j, nj) in names.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    let seen = per
                        .and_then(|m| m.get(&nj.to_string()))
                        .copied()
                        .unwrap_or(0);
                    if seen < final_seq {
                        all = false;
                    }
                }
            }
            if all {
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn fast_config() -> SvsConfig {
    SvsConfig {
        sync_interval: Duration::from_millis(40),
        jitter_ms: 10,
        suppression_period: Duration::from_millis(15),
        ..Default::default()
    }
}

#[tokio::test]
async fn converges_under_loss_and_delay() {
    fastrand::seed(0xC0FFEE);
    let group: Name = "/test/c".parse().unwrap();
    let n = 4;
    let final_seq = 3;

    let shim = Arc::new(Mutex::new(Shim {
        loss: 0.25,
        max_delay_ms: 12,
    }));
    let partitioned = Arc::new(Mutex::new(vec![false; n]));

    let (handles, names, learned) = spawn_group(
        &group,
        n,
        fast_config(),
        Arc::clone(&shim),
        Arc::clone(&partitioned),
    )
    .await;

    // Each node publishes `final_seq` times.
    for _ in 0..final_seq {
        for (h, name) in handles.iter().zip(names.iter()) {
            h.publish(name.clone()).await.expect("publish");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    let ok = await_convergence(&learned, &names, final_seq, Duration::from_secs(20)).await;
    assert!(ok, "group failed to converge under 25% loss + 12ms delay");
    drop(handles);
}

#[tokio::test]
async fn converges_after_partition_heals() {
    fastrand::seed(0x1234_5678);
    let group: Name = "/test/c".parse().unwrap();
    let n = 4;
    let final_seq = 2;

    let shim = Arc::new(Mutex::new(Shim {
        loss: 0.1,
        max_delay_ms: 8,
    }));
    // Split {0,1} | {2,3}.
    let partitioned = Arc::new(Mutex::new(vec![false, false, true, true]));

    let (handles, names, learned) = spawn_group(
        &group,
        n,
        fast_config(),
        Arc::clone(&shim),
        Arc::clone(&partitioned),
    )
    .await;

    // Publish while partitioned — cross-partition updates cannot flow.
    for _ in 0..final_seq {
        for (h, name) in handles.iter().zip(names.iter()) {
            h.publish(name.clone()).await.expect("publish");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    // Should NOT be globally converged yet (0/1 cannot see 2/3).
    let early = await_convergence(&learned, &names, final_seq, Duration::from_millis(600)).await;
    assert!(!early, "partition should prevent global convergence");

    // Heal the partition.
    {
        let mut p = partitioned.lock().await;
        for x in p.iter_mut() {
            *x = false;
        }
    }

    // Periodic re-advertisement must now carry the missing state across.
    let ok = await_convergence(&learned, &names, final_seq, Duration::from_secs(20)).await;
    assert!(ok, "group failed to converge after partition healed");
    drop(handles);
}
