//! What a closed node leaves behind: no task, and no hold on the store.

use std::sync::Arc;

use ndn_sync::DataStore;
use ndn_sync::store::BackendStore;

use super::tests::{boot, bytes, cfg, public, solo, space};
use crate::space::PutOptions;
use crate::test_kit::{Engine, n};

/// A directory store the device's node runs on, and the directory.
fn on_disk() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let live = Engine::Fjall.live(dir.path());
    (dir, live)
}

/// The store's lock is released: the directory opens again at once, with no retry.
fn reopens(live: &std::path::Path, after: &str) -> impl DataStore {
    BackendStore::open_fjall(live).unwrap_or_else(|e| {
        panic!("{after}, the directory does not open again: {e}");
    })
}

/// A node that holds a space is closed: `close` returns when the store is released, and a
/// task the node started (the recovery of the space's own entries waits for a first vector
/// up to `Config.settle`) does not keep the store until it ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_returns_with_the_store_released() {
    let (_dir, live) = on_disk();
    let mut dev = solo().await;
    dev.store = Arc::new(BackendStore::open_fjall(&live).unwrap());
    let mut config = cfg();
    config.settle = std::time::Duration::from_secs(30);
    let (node, _) = boot(&dev, config).await;
    let heap = node.create(&space(), public()).await.unwrap();
    heap.put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    drop(heap);
    node.close().await;
    drop(dev);
    let store = reopens(&live, "after close returned");
    assert!(
        store.get(&crate::store::Kind::SPACE.of(&space())).is_some(),
        "the reopened store holds the space"
    );
}

/// The same after a stop at once and a restart (the second run starts unclean and recovers
/// its own entries in a task), then `close`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_after_an_unclean_restart_releases_the_store() {
    let (_dir, live) = on_disk();
    let mut dev = solo().await;
    dev.store = Arc::new(BackendStore::open_fjall(&live).unwrap());
    let mut config = cfg();
    config.settle = std::time::Duration::from_secs(30);
    let (node, _) = boot(&dev, config.clone()).await;
    node.create(&space(), public()).await.unwrap();
    node.shutdown();
    drop(node);
    let (node, _) = boot(&dev, config).await;
    assert!(node.space(&space()).is_some(), "the space is held again");
    node.close().await;
    drop(dev);
    reopens(&live, "after close returned");
}
