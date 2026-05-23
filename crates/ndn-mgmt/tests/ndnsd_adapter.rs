//! ARCH-7 / S15 — witness for the NDNSD adapter.
//!
//! Publishes service records via [`mount_ndnsd_discovery`] +
//! [`mount_ndnsd_service_info`], then expresses Consumer Interests at
//! the discovery + per-service prefixes and asserts the Data Content
//! matches the TLV produced by the encoder helpers.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig, InstallableProtocol, PostBuildQueue};
use ndn_face_local::InProcFace;
use ndn_mgmt::{
    NdnsdServiceInfo, encode_service_info, encode_service_list, mount_ndnsd_discovery,
    mount_ndnsd_service_info,
};
use ndn_packet::{Data, Name, encode::InterestBuilder};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const SUBSCRIBER_FACE_ID: FaceId = FaceId(99);

struct TestNdnsdInstaller {
    root: Name,
    records: Vec<NdnsdServiceInfo>,
    /// (identifier, info) for the per-service Producer.
    service_info: Option<(Vec<u8>, NdnsdServiceInfo)>,
}

impl InstallableProtocol for TestNdnsdInstaller {
    fn install(self: Arc<Self>, builder: &mut EngineBuilder, post: &mut PostBuildQueue) {
        let records = self.records.clone();
        mount_ndnsd_discovery(builder, post, self.root.clone(), move || records.clone());
        if let Some((id, info)) = self.service_info.clone() {
            mount_ndnsd_service_info(builder, post, self.root.clone(), &id, move || info.clone());
        }
    }
}

async fn run_subscribe(handle: &ndn_face_local::InProcHandle, prefix: Name) -> Bytes {
    let interest = InterestBuilder::new(prefix)
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(Duration::from_secs(2))
        .build();
    handle.send(interest).await.expect("send Interest");
    let wire = tokio::time::timeout(Duration::from_secs(2), handle.recv())
        .await
        .expect("response within 2s")
        .expect("response not None");
    let data = Data::decode(wire).expect("Data decode");
    data.content().cloned().unwrap_or(Bytes::new())
}

#[tokio::test]
async fn ndnsd_discovery_returns_published_records() {
    let (subscriber_face, subscriber_handle) = InProcFace::new(SUBSCRIBER_FACE_ID, 16);
    let root: Name = "/lab/services/printer".parse().unwrap();
    let records = vec![
        NdnsdServiceInfo::new("/lab/services/printer/floor3".parse().unwrap(), 60_000),
        NdnsdServiceInfo {
            announced_prefix: "/lab/services/printer/floor5".parse().unwrap(),
            freshness_ms: 30_000,
            details: vec![
                ("model".into(), "PrinterPro X100".into()),
                ("location".into(), "Floor 5 / West Wing".into()),
            ],
        },
    ];
    let installer = Arc::new(TestNdnsdInstaller {
        root: root.clone(),
        records: records.clone(),
        service_info: None,
    });

    let mut post = PostBuildQueue::new();
    let builder = EngineBuilder::new(EngineConfig::default())
        .face(subscriber_face)
        .install(installer, &mut post);
    let (engine, _shutdown) = builder.build().await.expect("engine build");
    let cancel = CancellationToken::new();
    post.apply(&engine, &cancel);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let discovery_name = root.append(b"NDNSD" as &[u8]).append(b"discovery" as &[u8]);
    let content = run_subscribe(&subscriber_handle, discovery_name).await;
    let expected = encode_service_list(&records);
    assert_eq!(
        content, expected,
        "NDNSD discovery Data carries the records list"
    );
    // Sanity: starts with NDNSD_SERVICE_INFO TLV type 0xE0.
    assert_eq!(content.as_ref().first(), Some(&0xE0));

    cancel.cancel();
}

#[tokio::test]
async fn ndnsd_per_service_info_returns_one_record() {
    let (subscriber_face, subscriber_handle) = InProcFace::new(SUBSCRIBER_FACE_ID, 16);
    let root: Name = "/lab/services/printer".parse().unwrap();
    let identifier = b"rcnn1".to_vec();
    let info = NdnsdServiceInfo {
        announced_prefix: "/lab/services/printer/rcnn1".parse().unwrap(),
        freshness_ms: 50_000,
        details: vec![
            ("description".into(), "faster rcnn".into()),
            ("release".into(), "inception_resnet_v2/1".into()),
        ],
    };
    let installer = Arc::new(TestNdnsdInstaller {
        root: root.clone(),
        records: vec![info.clone()],
        service_info: Some((identifier.clone(), info.clone())),
    });

    let mut post = PostBuildQueue::new();
    let builder = EngineBuilder::new(EngineConfig::default())
        .face(subscriber_face)
        .install(installer, &mut post);
    let (engine, _shutdown) = builder.build().await.expect("engine build");
    let cancel = CancellationToken::new();
    post.apply(&engine, &cancel);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let info_name = root
        .append(identifier.as_slice())
        .append(b"NDNSD" as &[u8])
        .append(b"service-info" as &[u8]);
    let content = run_subscribe(&subscriber_handle, info_name).await;
    let expected = encode_service_info(&info);
    assert_eq!(
        content, expected,
        "per-service Data carries the single info record"
    );
    assert_eq!(content.as_ref().first(), Some(&0xE0));

    cancel.cancel();
}
