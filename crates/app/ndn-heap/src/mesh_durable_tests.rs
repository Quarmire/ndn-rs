//! `put`'s default durability over real nodes (spec §4.7): what makes a lone writer's put
//! skip the flush, and what does not.

use super::*;

/// A reader that has announced itself in the space's sync group, and holds what the writer
/// signed, does not make the writer's default `put` skip the flush: the writer's device has
/// seen no entry of any other device, so nothing that recovery would ask for its lost entries
/// vouches for the reader (it signs nothing, and the group's unsigned vector, which names it
/// at counter 0 or forges any name, decides nothing). The default stays durable (spec §4.7).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_announced_reader_does_not_make_a_lone_writers_default_put_skip_the_flush() {
    let mut m = mesh(&["/alice/laptop", "/bob/laptop"]).await;
    let crash = Arc::new(CrashStore::new());
    m.devs[0].store = Arc::clone(&crash) as Arc<dyn DataStore>;
    let (alice, bob) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let heap = alice.create(&space(), public()).await.unwrap();
    heap.put(&n("/x"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    let theirs = bob.open(&space()).await.unwrap();
    eventually("the reader holds what the writer signed", || async {
        has(&theirs, "/x", "one").await
    })
    .await;

    let hold = crash.hold();
    let before = crash.syncs_started();
    let path = n("/y");
    let mut put = Box::pin(heap.put(&path, bytes("two"), PutOptions::default()));
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut put)
            .await
            .is_err(),
        "the default put returned before the flush that covers it, with a reader announced"
    );
    drop(hold);
    put.await.unwrap();
    assert!(
        crash.syncs_started() > before,
        "the put waited for a flush: the store was synced"
    );
}
