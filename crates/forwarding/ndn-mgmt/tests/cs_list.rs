//! `/localhost/nfd/cs/list` end to end: a daemon's content store seeded
//! directly, listed by `MgmtClient::cs_list` over the management socket —
//! the client's command name, the daemon's parse → `list_erased` → dataset,
//! and the client's decode. Store enumeration is unit-tested in ndn-store.
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_ipc::MgmtClient;
use ndn_mgmt::{MgmtHandles, mount_management, run_face_listener};
use ndn_mgmt_wire::CsEntry;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_store::CsMeta;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn cs_list_over_the_management_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
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

    let mut held = Vec::new();
    for (uri, fresh) in [
        ("/app/b", true),
        ("/app/a", false),
        ("/app/c", true),
        ("/other/x", true),
    ] {
        let name: Name = uri.parse().unwrap();
        let data = DataBuilder::new(name.clone(), b"payload").sign_digest_sha256();
        held.push((uri, data.len() as u64, fresh));
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
    let listing = client.cs_list(Some(&app), 2).await.expect("cs/list");
    assert_eq!(listing.total, 3, "every entry under /app counts");
    assert_eq!(
        listing.entries,
        vec![entry("/app/a", false), entry("/app/b", true)],
        "the first two in name order"
    );

    let everything = client.cs_list(None, 10).await.expect("cs/list");
    assert!(everything.total >= 4, "no prefix: the whole CS");
    assert!(
        everything.entries.contains(&entry("/other/x", true)),
        "no prefix lists outside /app too"
    );

    cancel.cancel();
    shutdown.shutdown().await;
}
