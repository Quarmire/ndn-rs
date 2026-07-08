//! NS-8 restart recovery: a publisher resumes its sequence space from a durable
//! `DataStore` across a process restart, instead of restarting at seq 1 (which
//! would collide with the pre-restart names a peer already holds). Exercises the
//! seq-recovery path AND the Layer-0 lockstep — the core's advertised state
//! vector must resume too, or peers fetch a seq the data plane never named.
#![cfg(feature = "persistent-store")]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::Data;
use ndn_sync::store::BackendStore;
use ndn_sync::svsync::{DataStore, SvSync, SvSyncConfig, svs_data_name};
use ndn_sync::{SvsConfig, WireDialect};
use tokio::sync::mpsc;

fn cfg() -> SvSyncConfig {
    SvSyncConfig {
        svs: SvsConfig {
            sync_interval: Duration::from_millis(20),
            jitter_ms: 0,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// The local node's seq in the first Sync Interest the freshly-joined node emits.
async fn advertised_local_seq(out_rx: &mut mpsc::Receiver<Bytes>, node: &str) -> u64 {
    let raw = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("no Sync Interest emitted")
        .expect("channel closed");
    let interest = ndn_packet::Interest::decode(raw).expect("decode interest");
    let ap = interest.app_parameters().expect("app params");
    let sv = WireDialect::V2
        .decode_state_vector(&Bytes::copy_from_slice(ap))
        .expect("decode state vector");
    sv.iter()
        .find(|e| e.name.to_string() == node)
        .map(|e| e.seq)
        .unwrap_or(0)
}

#[tokio::test]
async fn restart_resumes_seq_from_durable_store() {
    let group = "/repo/grp".parse().unwrap();
    let node: ndn_packet::Name = "/repo/grp/a".parse().unwrap();

    // One durable store shared across both "boots" (a SyncMemoryBackend stands
    // in for on-disk fjall/redb — same SyncBackend path, no tempdir).
    let store: Arc<dyn DataStore> = Arc::new(BackendStore::memory());

    // Boot 1: publish three, then "crash" (drop the SvSync; the store survives).
    {
        let (out, _out_rx) = mpsc::channel(256);
        let (_in_tx, in_rx) = mpsc::channel(256);
        let svs = SvSync::join(
            group,
            node.clone(),
            Arc::clone(&store),
            out,
            in_rx,
            cfg(),
        );
        for i in 1..=3 {
            let seq = svs
                .publish_data(format!("v{i}").as_bytes())
                .await
                .expect("publish");
            assert_eq!(seq, i, "fresh boot counts 1,2,3");
        }
    }
    // The durable store holds seq 1..=3.
    assert!(store.get(&svs_data_name(&node, &"/repo/grp".parse().unwrap(), 3)).is_some());

    // Boot 2 over the SAME store.
    let group2: ndn_packet::Name = "/repo/grp".parse().unwrap();
    let (out2, mut out2_rx) = mpsc::channel(256);
    let (_in_tx2, in_rx2) = mpsc::channel(256);
    let svs2 = SvSync::join(
        group2.clone(),
        node.clone(),
        Arc::clone(&store),
        out2,
        in_rx2,
        cfg(),
    );

    // Lockstep: the very first Sync Interest must advertise seq 3 (recovered),
    // not 0 — proving the Layer-0 core resumed, not just SvSync's data counter.
    let advertised = advertised_local_seq(&mut out2_rx, "/repo/grp/a").await;
    assert_eq!(advertised, 3, "core must advertise the recovered seq");

    // The next publication is seq 4, and it does not clobber the seq-1 data.
    let next = svs2
        .publish_data(b"v4-after-restart")
        .await
        .expect("publish after restart");
    assert_eq!(next, 4, "restart resumed the seq space from the durable store");

    let old = store
        .get(&svs_data_name(&node, &group2, 1))
        .expect("seq-1 data still present");
    assert_eq!(
        Data::decode(old).unwrap().content().unwrap().as_ref(),
        b"v1",
        "restart must not overwrite pre-restart publications",
    );
}

/// The same recovery over a real on-disk fjall backend across two independent
/// backend instances (a true process-restart analogue).
#[cfg(feature = "store-fjall")]
#[tokio::test]
async fn restart_resumes_seq_over_fjall_disk() {
    let dir = std::env::temp_dir().join(format!("ndn-sync-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let group: ndn_packet::Name = "/repo/disk".parse().unwrap();
    let node: ndn_packet::Name = "/repo/disk/a".parse().unwrap();

    // Boot 1: open the store, publish two, then leave (cancels the node).
    {
        let store: Arc<dyn DataStore> =
            Arc::new(BackendStore::open_fjall(&dir).expect("open fjall"));
        let (out, _out_rx) = mpsc::channel(256);
        let (_in_tx, in_rx) = mpsc::channel(256);
        let svs = SvSync::join(group.clone(), node.clone(), store, out, in_rx, cfg());
        assert_eq!(svs.publish_data(b"a").await.unwrap(), 1);
        assert_eq!(svs.publish_data(b"b").await.unwrap(), 2);
        svs.leave();
    }

    // Boot 2: a brand-new backend instance over the same path recovers seq 2.
    // fjall holds a single-process file lock, so the reopen has to wait out the
    // cancelled boot-1 background tasks releasing their store handle — a
    // sequential restart in the field, a brief teardown race in-test.
    let store: Arc<dyn DataStore> = {
        let mut opened = None;
        for _ in 0..40 {
            match BackendStore::open_fjall(&dir) {
                Ok(s) => {
                    opened = Some(s);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        Arc::new(opened.expect("reopen fjall after retry"))
    };
    let (out, mut out_rx) = mpsc::channel(256);
    let (_in_tx, in_rx) = mpsc::channel(256);
    let svs = SvSync::join(group.clone(), node.clone(), store, out, in_rx, cfg());

    assert_eq!(advertised_local_seq(&mut out_rx, "/repo/disk/a").await, 2);
    assert_eq!(
        svs.publish_data(b"c").await.unwrap(),
        3,
        "fjall-persisted history resumes the seq space"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
