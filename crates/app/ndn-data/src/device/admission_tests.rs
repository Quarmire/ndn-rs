//! Admission across a key's one log (spec §4, §6.1, §8): a seq is one
//! entry in every collection, and a folder cut keeps each seq in the
//! collection it was held in.

use super::test_kit::{
    Made, Unconnected, counts, device, give, id, key, log_share, n, refusal, version,
};
use super::*;
use crate::layer::Share;
use ndn_security::TrustSchema;
use ndn_sync::MemoryStore;

/// A device named `device`, on a forwarder that delivers nothing, holding
/// the trust contexts of Alice, Bob and Carol, owning nothing.
async fn reader(device: &str) -> Device {
    let device = n(device);
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    for ns in ["/alice", "/bob", "/carol"] {
        validator
            .adopt_context(Arc::new(SignedTrustContext::hierarchical(n(ns))))
            .unwrap();
    }
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519(device.clone().append("KEY").append("1"))
        .unwrap();
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        device,
        keys,
        validator,
        store,
        Config {
            first_look: Duration::from_millis(50),
            ..Config::new()
        },
    )
    .await
    .unwrap()
}

/// The newest entry of `owner`'s log, about `c`, as a reader fetches it.
fn newest(owner: &Device, c: &Name) -> Made {
    let seq = owner.inner.st.lock().head;
    let name = log_name(owner.name(), Some(c), seq);
    let packet = owner.inner.store.get(&name).expect("written and stored");
    let content = Data::decode(packet.clone())
        .unwrap()
        .content()
        .unwrap()
        .clone();
    Made {
        name,
        packet,
        key: key(&owner.name().to_string()),
        record: wire::decode_record(content).unwrap(),
    }
}

fn outside_cut(why: Option<Refusal>) -> bool {
    matches!(why, Some(Refusal::OutsideCut(_)))
}

/// SubstrateReview H1, exploit 1 (a regression of SealReview CUT-BYP-01):
/// Bob, removed from a folder whose cut kept his seq 1 in one collection
/// and seq 2 in another, signs seqs 1 and 2 again in other collections
/// under the folder — new names, so no same-name equivocation. A cut by
/// seq alone would admit them everywhere; it keeps each seq only in the
/// collection it was held in, at the owner and at a reader that has the
/// folder record off the wire.
#[tokio::test]
async fn a_removed_writer_signing_a_kept_seq_again_in_another_collection_is_refused_everywhere() {
    let owner = device().await;
    let other = reader("/carol/phone").await;
    let f = n("/alice/32=data/docs");
    let [c1, c2, c3] = ["plan", "notes", "later"].map(|x| f.clone().append(x));
    let share = |writers: &[&str]| Share {
        rule: Rule::Log,
        writers: writers.iter().map(|w| n(w)).collect(),
        readers: Vec::new(),
    };
    owner
        .share_folder(&f, share(&["/alice", "/bob"]).into())
        .await
        .unwrap();
    let kept = [
        version("/bob/phone", &c1, 1, &[]),
        version("/bob/phone", &c2, 2, &[]),
    ];
    for m in &kept {
        give(&owner, m);
    }
    owner
        .share_folder(&f, share(&["/alice"]).into())
        .await
        .unwrap();
    let record = newest(&owner, &f);
    // The reader holds the cut's manifest, as fetched by its full name.
    for (name, packet) in owner
        .inner
        .store
        .scan_under(&wire::cut_bytes_prefix(&record.name), 0)
    {
        other.inner.store.insert(name, packet);
    }
    give(&other, &record);
    for m in &kept {
        give(&other, m);
    }
    for dev in [&owner, &other] {
        for (m, c) in kept.iter().zip([&c1, &c2]) {
            assert_eq!(refusal(dev, &m.name), None, "what the cut kept stays");
            assert!(counts(
                dev,
                c,
                &id("/bob/phone", parse_log_name(&m.name).unwrap().seq)
            ));
        }
        for (c, seq) in [(&c3, 1), (&c2, 1), (&c1, 2), (&c3, 2)] {
            let again = version("/bob/phone", c, seq, &[]);
            give(dev, &again);
            assert!(
                outside_cut(refusal(dev, &again.name)),
                "seq {seq} signed again in {c}: {:?}",
                refusal(dev, &again.name)
            );
            assert!(!counts(dev, c, &id("/bob/phone", seq)));
        }
    }
    owner.shutdown();
    other.shutdown();
}

/// Whether a device may hold an epoch's key is the standing of the records
/// held here: its namespace is a listed reader, it is not, or the record
/// that would tell is not held (spec §9). `may_hold` is true only for the
/// first.
#[tokio::test]
async fn may_hold_judges_by_epoch_standing() {
    let owner = device().await;
    let sealed = n("/alice/32=data/trip/sealed");
    owner
        .share(
            &sealed,
            Share {
                readers: vec![Audience::Person(n("/alice"))],
                ..log_share()
            },
        )
        .await
        .unwrap();
    let epoch = owner.inner.st.lock().colls[&sealed]
        .members
        .as_ref()
        .unwrap()
        .epoch
        .clone()
        .unwrap();
    let st = owner.inner.st.lock();
    let asked = |c: &Name, who: &str, ns: &str| {
        let standing = owner.inner.epoch_standing(&st, c, &epoch, &n(who), &n(ns));
        let may = owner.inner.may_hold(&st, c, &epoch, &n(who), &n(ns));
        assert_eq!(may, standing == EpochStanding::In, "{who} of {ns}");
        standing
    };
    // The records are held here, so it is judged, not unknown.
    assert_eq!(asked(&sealed, "/alice/phone", "/alice"), EpochStanding::In);
    assert_eq!(asked(&sealed, "/bob/laptop", "/bob"), EpochStanding::Out);
    // A collection no record of is held says nothing.
    assert_eq!(
        asked(&n("/alice/32=data/other"), "/alice/phone", "/alice"),
        EpochStanding::NotHeld
    );
    drop(st);
    owner.shutdown();
}
