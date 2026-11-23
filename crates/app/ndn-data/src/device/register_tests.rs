//! The built-in register through the device: concurrent writes read one
//! winner on every device, whatever the order they arrive in, and a removal
//! is the newest value until someone puts again.

use super::folder_tests::{device as peer, relay};
use super::test_kit::*;
use super::*;
use crate::error::NextStep;
use crate::layer::Share;
use crate::merge::{NEWEST, winner};

fn notes() -> Name {
    n("/alice/32=data/trip/notes")
}

fn register_share() -> Share {
    Share {
        rule: Rule::Merge {
            function: n(NEWEST),
        },
        writers: vec![n("/alice"), n("/bob"), n("/carol")],
        readers: Vec::new(),
    }
}

/// `/alice/laptop`, owning `notes()` shared as a register.
async fn register_device() -> Device {
    let dev = device().await;
    dev.share(&notes(), register_share()).await.unwrap();
    dev
}

/// Version `seq` of `device` in `c`, made over nothing, carrying `bytes`
/// as the register's write.
fn write(device: &str, c: &Name, seq: u64, bytes: &[u8]) -> Made {
    let body = VersionBody {
        collection: c.clone(),
        parents: Parents::new(),
        type_id: options().type_id,
        seal: Seal { any_of: Vec::new() },
        keep: Keep::Forever,
        dated: Timestamp(1),
        rule: Some(n(NEWEST)),
        fields: Content::new(),
        op: Bytes::copy_from_slice(bytes),
        sealed: None,
        chunks: None,
    };
    made(device, c, seq, Record::Version(body))
}

/// The register's value as `get` reads it.
async fn value(dev: &Device, c: &Name) -> Bytes {
    match dev.get(c).await.unwrap().got {
        Got::State(s) => s.value.bytes().expect("a register value").clone(),
        other => panic!("not a state: {other:?}"),
    }
}

/// The value a writer outside a person's namespace leaves: zeros, then its
/// bytes.
fn by_zeros(bytes: &[u8]) -> Bytes {
    Bytes::from([&[0u8; 32][..], bytes].concat())
}

#[tokio::test]
async fn two_offline_writers_converge_on_the_highest_digest() {
    let c = notes();
    let (phone, tablet) = (
        write("/alice/phone", &c, 1, b"from the phone"),
        write("/alice/tablet", &c, 1, b"from the tablet"),
    );
    let digest = |m: &Made| wire::implicit_digest(&m.packet);
    let (dp, dt) = (digest(&phone), digest(&tablet));
    let expected = winner([
        (&dp, by_zeros(b"from the phone")),
        (&dt, by_zeros(b"from the tablet")),
    ])
    .unwrap();

    let (first, second) = (register_device().await, register_device().await);
    assert_eq!(value(&first, &c).await, Bytes::new(), "nothing written yet");
    give(&first, &phone);
    give(&first, &tablet);
    give(&second, &tablet);
    give(&second, &phone);

    assert_eq!(value(&first, &c).await, expected);
    assert_eq!(value(&second, &c).await, expected);
}

#[tokio::test]
async fn an_own_write_over_the_others_settles_it_whatever_the_digests() {
    let c = notes();
    let tablet = write("/alice/tablet", &c, 1, b"from the tablet");
    let dev = register_device().await;
    give(&dev, &tablet);
    assert_eq!(value(&dev, &c).await, by_zeros(b"from the tablet"));
    dev.put_op(&c, Bytes::from_static(b"mine"), options())
        .await
        .unwrap();
    // Made over the tablet's version (the state's frontier): it replaces it.
    assert_eq!(value(&dev, &c).await, by_zeros(b"mine"));
}

#[tokio::test]
async fn a_removal_is_the_newest_until_someone_puts_again() {
    let c = notes();
    let dev = register_device().await;
    dev.put_op(&c, Bytes::from_static(b"x"), options())
        .await
        .unwrap();
    assert_eq!(value(&dev, &c).await, by_zeros(b"x"));
    dev.put_op(&c, Bytes::new(), options()).await.unwrap();
    assert_eq!(
        value(&dev, &c).await,
        by_zeros(b""),
        "the removal is the newest: the writer's person and nothing"
    );
    dev.put_op(&c, Bytes::from_static(b"y"), options())
        .await
        .unwrap();
    assert_eq!(value(&dev, &c).await, by_zeros(b"y"));
}

#[tokio::test]
async fn a_register_takes_bytes_not_fields() {
    let c = notes();
    let dev = register_device().await;
    let put = dev
        .put(&c, Content::new().with("t", "x"), options())
        .await
        .unwrap_err();
    assert!(
        matches!(&put, DataError::BadRequest { why, .. } if why.contains("use put_op")),
        "{put}"
    );
    assert_eq!(value(&dev, &c).await, Bytes::new(), "nothing was written");
}

#[tokio::test]
async fn a_collection_whose_rule_names_another_function_is_held_and_never_read() {
    let c = n("/alice/32=data/trip/other");
    let dev = device().await;
    dev.share(
        &c,
        Share {
            rule: Rule::Merge {
                function: n("/merge/other/v=1"),
            },
            ..register_share()
        },
    )
    .await
    .unwrap();
    let read = dev.get(&c).await.unwrap_err();
    assert!(matches!(read, DataError::RuleUnknown { .. }), "{read}");
    assert_eq!(read.next(), NextStep::UpdateProgram);
    let put = dev
        .put(&c, Content::new().with("t", "x"), options())
        .await
        .unwrap_err();
    assert!(matches!(put, DataError::RuleUnknown { .. }), "{put}");
    let put_op = dev
        .put_op(&c, Bytes::from_static(b"x"), options())
        .await
        .unwrap_err();
    assert!(matches!(put_op, DataError::RuleUnknown { .. }), "{put_op}");
}

/// `laptop` writes `size` octets into the register `notes()`; `phone`, a
/// second device of the same person, is handed the records and version
/// `laptop` signed — and, by hand, its pieces only once it is asked to
/// look: the version is not applied before they are held, and then the
/// register reads exactly `by ‖ bytes` on both devices.
async fn a_large_value_reaches_a_second_device_in_pieces(size: usize, sealed: bool) {
    let c = notes();
    let laptop = peer("/alice/laptop", &["/alice"]).await;
    let phone = peer("/alice/phone", &["/alice"]).await;
    if !sealed {
        // Shared with no readers: nothing is sealed.
        laptop.share(&c, register_share()).await.unwrap();
    }
    let bytes: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
    let id = laptop
        .put_op(&c, Bytes::from(bytes.clone()), options())
        .await
        .unwrap();
    let name = log_name(laptop.name(), Some(&c), id.seq.0);
    let chunks = laptop.inner.st.lock().colls[&c].versions[&id]
        .chunks
        .expect("a large value travels in pieces");
    let head = laptop.inner.st.lock().head;
    for seq in 1..=head {
        assert_eq!(relay(&laptop, &phone, &c, seq), None, "seq {seq}");
    }
    if sealed {
        let (e, k) = {
            let st = laptop.inner.st.lock();
            let e = st.colls[&c]
                .members
                .as_ref()
                .unwrap()
                .epoch
                .clone()
                .unwrap();
            let k = st.keys.key(&c, &e).unwrap();
            (e, k)
        };
        assert!(phone.inner.st.lock().take_key(&c, &e, k));
    }
    let expected = by_zeros(&bytes);
    let read = |dev: &Device| {
        let st = dev.inner.st.lock();
        st.colls[&c].state.as_ref().unwrap().value()
    };
    // Held, but not applied: its pieces are not here yet.
    {
        let st = phone.inner.st.lock();
        assert!(st.colls[&c].versions.contains_key(&id), "admitted");
        assert!(!st.colls[&c].at().contains(&id), "it waits for its pieces");
        assert!(
            st.wanted_pieces(&c).iter().any(|(v, _)| *v == name),
            "its pieces are to be fetched"
        );
    }
    assert_eq!(read(&phone).bytes().unwrap().len(), 0, "nothing applied");
    for p in wire::piece_names(&name, &chunks) {
        phone
            .inner
            .store
            .insert(p.clone(), laptop.inner.store.get(&p).unwrap());
    }
    phone.inner.st.lock().pieces_arrived(&c, &name);
    assert!(phone.inner.st.lock().colls[&c].at().contains(&id));
    assert_eq!(read(&phone).bytes(), Some(&expected));
    assert_eq!(read(&laptop).bytes(), Some(&expected));
    laptop.shutdown();
    phone.shutdown();
}

#[tokio::test]
async fn a_register_value_of_16_kib_waits_for_its_pieces_then_reads_alike() {
    a_large_value_reaches_a_second_device_in_pieces(16 * 1024, false).await;
}

#[tokio::test]
async fn a_register_value_over_a_mebibyte_waits_for_its_pieces_then_reads_alike() {
    a_large_value_reaches_a_second_device_in_pieces((1 << 20) + 1, false).await;
}

#[tokio::test]
async fn a_sealed_register_value_in_pieces_opens_with_the_epoch_key() {
    a_large_value_reaches_a_second_device_in_pieces(16 * 1024, true).await;
    a_large_value_reaches_a_second_device_in_pieces((1 << 20) + 1, true).await;
}

#[tokio::test]
async fn an_empty_value_in_a_register_is_still_a_removal_after_a_large_one() {
    let (c, dev) = (notes(), register_device().await);
    dev.put_op(&c, Bytes::from(vec![9u8; 3 * wire::INLINE_MAX]), options())
        .await
        .unwrap();
    dev.put_op(&c, Bytes::new(), options()).await.unwrap();
    assert_eq!(value(&dev, &c).await, by_zeros(b""));
    dev.shutdown();
}
