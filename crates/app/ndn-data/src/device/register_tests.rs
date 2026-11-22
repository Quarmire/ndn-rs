//! The built-in register through the device: concurrent writes read one
//! winner on every device, whatever the order they arrive in, and a removal
//! is the newest value until someone puts again.

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
