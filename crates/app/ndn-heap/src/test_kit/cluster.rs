#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use ndn_packet::Interest;
    use ndn_sync::{MultiSvs, ProducerVouch, SvsConfig, SyncHandle, SyncUpdate, spawn_multi_svs};
    use tokio::sync::mpsc;

    use super::*;
    use crate::test_kit::n;
    use crate::wire::sync_group_of;

    /// A device's membership of one SVS group, as the node joins one: its
    /// sync face registered for the owner's `<O>/32=sync` only, one driver
    /// over the face, the group's own name below that prefix.
    struct Member {
        _svs: MultiSvs,
        handle: SyncHandle,
    }

    async fn join(dev: &DeviceKit, owner: &Name, group: &Name) -> Member {
        dev.sync
            .register_prefix(&ndn_security::sync_group(owner))
            .await
            .expect("the sync face registers the owner's group prefix");
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        let svs = spawn_multi_svs(dev.name.clone(), out_tx, in_rx);
        let sync = Arc::clone(&dev.sync);
        tokio::spawn(async move {
            while let Some(pkt) = out_rx.recv().await {
                if sync.send(pkt).await.is_err() {
                    break;
                }
            }
        });
        let sync = Arc::clone(&dev.sync);
        tokio::spawn(async move {
            while let Some(pkt) = sync.recv().await {
                if Interest::decode(pkt.clone()).is_ok() && in_tx.send(pkt).await.is_err() {
                    break;
                }
            }
        });
        let cfg = SvsConfig {
            local_seq: 0,
            max_producers: 64,
            vouch: Some(ProducerVouch(Arc::new(|_| true))),
            ..SvsConfig::lan()
        };
        let handle = svs
            .join(group.clone(), cfg)
            .await
            .expect("the driver joins the group");
        Member { _svs: svs, handle }
    }

    async fn heard(m: &mut Member) -> (SyncUpdate, Duration) {
        let t = Instant::now();
        let update = tokio::time::timeout(Duration::from_secs(10), m.handle.recv())
            .await
            .expect("the notice arrived within ten seconds")
            .expect("the group is open");
        (update, t.elapsed())
    }

    /// D5: a space's sync group `<O>/32=sync/s/abc` needs no route and no
    /// strategy of its own: `carry(O)` on the engine and the sync face's
    /// registration of `<O>/32=sync` are enough for a Sync Interest to reach
    /// every other member of the group, and no device outside it.
    #[tokio::test]
    async fn t_sync_prefix() {
        let cluster = Cluster::new(&["/alice/laptop", "/alice/phone", "/bob/laptop"]).await;
        let (laptop, phone, bob) = (cluster.device(0), cluster.device(1), cluster.device(2));
        let alice_group = sync_group_of(&n("/alice/32=data/s/abc")).unwrap();
        let bob_group = sync_group_of(&n("/bob/32=data/s/abc")).unwrap();
        assert_eq!(alice_group, n("/alice/32=sync/s/abc"));

        let mut on_laptop = join(laptop, &n("/alice"), &alice_group).await;
        let mut on_phone = join(phone, &n("/alice"), &alice_group).await;
        let mut on_bob = join(bob, &n("/alice"), &alice_group).await;
        let mut bob_on_bobs = join(bob, &n("/bob"), &bob_group).await;
        let mut laptop_on_bobs = join(laptop, &n("/bob"), &bob_group).await;

        on_phone.handle.publish(alice_group.clone()).await.unwrap();
        let (to_laptop, took_laptop) = heard(&mut on_laptop).await;
        let (to_bob, took_bob) = heard(&mut on_bob).await;
        for update in [&to_laptop, &to_bob] {
            assert_eq!(update.name, phone.name, "the notice names its writer");
            assert_eq!(update.high_seq, 1, "and the counter it published");
        }
        eprintln!("notice latency across one engine: laptop {took_laptop:?}, bob {took_bob:?}");

        bob_on_bobs.handle.publish(bob_group.clone()).await.unwrap();
        let (to_laptop, _) = heard(&mut laptop_on_bobs).await;
        assert_eq!(to_laptop.name, bob.name);
        assert_eq!(to_laptop.high_seq, 1);

        // The phone is in Alice's group only: Bob's notice is no business of
        // its own, and its own group heard nothing from Bob's.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), on_phone.handle.recv())
                .await
                .is_err(),
            "a device outside a group hears nothing of it"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), bob_on_bobs.handle.recv())
                .await
                .is_err(),
            "a writer is not told of its own counter"
        );
    }
}
