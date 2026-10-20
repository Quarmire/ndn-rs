//! `/localhost/nfd/cs/list` end to end: a daemon's content store seeded
//! directly, listed by `MgmtClient::cs_list` over the management socket —
//! the client's command name, the daemon's parse → `list_erased` → dataset
//! (as many segments as it takes), and the client's segment fetch and
//! decode. Store enumeration is unit-tested in ndn-store.
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_ipc::MgmtClient;
use ndn_mgmt::{MgmtHandles, mount_management, run_face_listener};
use ndn_mgmt_wire::CsEntry;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_store::CsMeta;
use tokio_util::sync::CancellationToken;

/// A daemon (engine, management, listener on a socket in `dir`), and the
/// socket path.
async fn daemon(
    dir: &tempfile::TempDir,
) -> (
    ForwarderEngine,
    ndn_engine::ShutdownHandle,
    CancellationToken,
    String,
) {
    let sock = dir.path().join("mgmt.sock");
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    tokio::spawn(mount_management(
        &engine,
        cancel.clone(),
        Arc::new(ndn_config::ForwarderConfig::default()),
        None,
        MgmtHandles::default(),
    ));
    let sock_path = sock.to_str().expect("utf-8 path").to_owned();
    {
        let (path, engine, cancel) = (sock_path.clone(), engine.clone(), cancel.clone());
        tokio::spawn(async move { run_face_listener(&path, engine, cancel).await });
    }
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (engine, shutdown, cancel, sock_path)
}

/// Cache a signed Data named `uri`; returns its wire size.
async fn cache(engine: &ForwarderEngine, uri: &str, fresh: bool) -> u64 {
    let name: Name = uri.parse().unwrap();
    let data = DataBuilder::new(name.clone(), b"payload").sign_digest_sha256();
    let size = data.len() as u64;
    engine
        .cs()
        .insert_erased(
            data,
            Arc::new(name),
            CsMeta {
                stale_at: if fresh { u64::MAX } else { 0 },
                revocation_epoch: None,
            },
        )
        .await;
    size
}

#[tokio::test]
async fn cs_list_over_the_management_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (engine, shutdown, cancel, sock_path) = daemon(&dir).await;

    let mut held = Vec::new();
    for (uri, fresh) in [
        ("/app/b", true),
        ("/app/a", false),
        ("/app/c", true),
        ("/other/x", true),
    ] {
        held.push((uri, cache(&engine, uri, fresh).await));
    }
    let size = |uri: &str| held.iter().find(|h| h.0 == uri).unwrap().1;
    let entry = |uri: &str, fresh: bool| CsEntry {
        name: uri.parse().unwrap(),
        bytes: size(uri),
        fresh,
    };

    let client = MgmtClient::connect(&sock_path)
        .await
        .expect("connect to the management socket");
    let app: Name = "/app".parse().unwrap();
    let listing = client.cs_list(Some(&app), None, 2).await.expect("cs/list");
    assert_eq!(listing.total, 3, "every entry under /app counts");
    assert_eq!(
        listing.entries,
        vec![entry("/app/a", false), entry("/app/b", true)],
        "the first two in name order"
    );
    assert!(listing.more);

    let rest = client
        .cs_list(Some(&app), listing.next_after(), 2)
        .await
        .expect("cs/list");
    assert_eq!(rest.entries, vec![entry("/app/c", true)], "the next page");
    assert_eq!(rest.next_after(), None, "the last page");

    let everything = client.cs_list(None, None, 10).await.expect("cs/list");
    assert!(everything.total >= 4, "no prefix: the whole CS");
    assert!(
        everything.entries.contains(&entry("/other/x", true)),
        "no prefix lists outside /app too"
    );

    cancel.cancel();
    shutdown.shutdown().await;
}

/// Far more entries than one dataset segment carries: one call with a
/// large enough limit reads them all, and paging visits each exactly once.
#[tokio::test]
async fn a_listing_past_one_segment_is_read_whole_and_pages_cover_it_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (engine, shutdown, cancel, sock_path) = daemon(&dir).await;
    const HELD: usize = 500;
    let mut names = Vec::new();
    for i in 0..HELD {
        let uri = format!("/many/{i:040}");
        cache(&engine, &uri, true).await;
        names.push(uri.parse::<Name>().unwrap());
    }
    names.sort();

    let client = MgmtClient::connect(&sock_path)
        .await
        .expect("connect to the management socket");
    let many: Name = "/many".parse().unwrap();

    let whole = client
        .cs_list(Some(&many), None, u64::MAX)
        .await
        .expect("cs/list");
    assert_eq!(whole.total, HELD as u64);
    assert!(!whole.more);
    let listed: Vec<Name> = whole.entries.into_iter().map(|e| e.name).collect();
    assert_eq!(listed, names, "every entry, in name order, in one read");

    let mut paged = Vec::new();
    let mut after: Option<Name> = None;
    loop {
        let page = client
            .cs_list(Some(&many), after.as_ref(), 64)
            .await
            .expect("cs/list");
        assert_eq!(page.total, HELD as u64);
        assert!(page.entries.len() <= 64);
        after = page.next_after().cloned();
        paged.extend(page.entries.into_iter().map(|e| e.name));
        if after.is_none() {
            break;
        }
    }
    assert_eq!(paged, names, "the pages cover every entry exactly once");

    cancel.cancel();
    shutdown.shutdown().await;
}
