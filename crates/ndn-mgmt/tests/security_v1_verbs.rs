//! Witness for the §7 dashboard-security-v1 mgmt verbs.
//!
//! Pins the wire contract for the four new entry points the
//! dashboard's security view consumes:
//!
//!   /localhost/nfd/security/policy-get        — public read
//!   /localhost/nfd/security/policy-set        — signed write
//!   /localhost/nfd/security/validation-stats  — public read
//!   /localhost/nfd/security/validate          — public read
//!
//! Wire shape per §11.10 (resolved as deferred): policy is
//! forwarder-internal config, JSON in `ControlParameters.uri`,
//! no canonical-form / hash-commitment constraint. The dashboard
//! computes its own content_hash locally when bridging policy
//! changes into the audit chain (see `security_chains.rs`).
//!
//! Reads are exempted from the SECURITY-module signed-command gate
//! (via the `is_public_dataset_verb` extension); writes (`policy-set`)
//! remain gated and surface as 403 UNAUTHORIZED when sent unsigned.
//! Handler-logic tests for the gated write path live as `#[cfg(test)]`
//! unit tests next to the handler in `lib.rs`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_config::{ControlParameters, ControlResponse};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_mgmt::{MgmtHandles, mount_management};
use ndn_packet::{Data, Name, encode::InterestBuilder};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const TEST_FACE_ID: FaceId = FaceId(7777);

async fn setup() -> (
    ndn_engine::ForwarderEngine,
    ndn_engine::ShutdownHandle,
    ndn_face_local::InProcHandle,
    CancellationToken,
) {
    let (test_face, test_handle) = InProcFace::new(TEST_FACE_ID, 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(test_face)
        .build()
        .await
        .expect("engine build");

    let cancel = CancellationToken::new();
    let mgmt_handles = MgmtHandles {
        extra_modules: Vec::new(),
        face_provisioners: Vec::new(),
        discovery_cfg: None,
        security_is_ephemeral: true,
        command_validator: None,
        localhop_command_validator: None,
        require_signed_commands: false,
        command_replay_cache: None,
        command_response_signer: None,
        log_inspector: None,
        coding_handler: None,
        rate_limit_handler: None,
        compute_handler: None,
        webtransport_status_handler: None,
        ble_handler: None,
        approval_handler: None,
        runtime_policy: None,
    };
    let fut = mount_management(
        &engine,
        cancel.clone(),
        None,
        Vec::new(),
        Arc::new(ndn_config::ForwarderConfig::default()),
        None,
        mgmt_handles,
    );
    tokio::spawn(fut);
    tokio::time::sleep(Duration::from_millis(50)).await;
    (engine, shutdown, test_handle, cancel)
}

fn build_mgmt_interest(module: &[u8], verb: &[u8], params: Option<&ControlParameters>) -> Bytes {
    let name = Name::root()
        .append(b"localhost")
        .append(b"nfd")
        .append(module)
        .append(verb);
    let mut builder = InterestBuilder::new(name)
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(Duration::from_millis(4000));
    if let Some(cp) = params {
        builder = builder.app_parameters(cp.encode().to_vec());
    }
    builder.build()
}

async fn recv_response(handle: &ndn_face_local::InProcHandle) -> Bytes {
    tokio::time::timeout(Duration::from_secs(2), handle.recv())
        .await
        .expect("response within 2s")
        .expect("response not None")
}

async fn send_verb(
    handle: &ndn_face_local::InProcHandle,
    module: &[u8],
    verb: &[u8],
    params: Option<&ControlParameters>,
) -> ControlResponse {
    let interest = build_mgmt_interest(module, verb, params);
    handle.send(interest).await.expect("send Interest");
    let data_wire = recv_response(handle).await;
    let data = Data::decode(data_wire).expect("Data decode");
    let content = data.content().cloned().unwrap_or_default();
    ControlResponse::decode(content).expect("ControlResponse decode")
}

/// `security/policy-get` returns the `MgmtAccessPolicy` JSON body and
/// pins the public-read auth exemption for security-inspection verbs.
#[tokio::test]
async fn policy_get_returns_json_body() {
    let (_engine, _shutdown, handle, cancel) = setup().await;

    let cr = send_verb(&handle, b"security", b"policy-get", None).await;
    assert!(
        cr.is_ok(),
        "policy-get must return 2xx; got {} {:?}",
        cr.status_code,
        cr.status_text
    );

    let body = cr.status_text;
    let value: serde_json::Value = serde_json::from_str(&body).expect("body is JSON");
    for field in [
        "ephemeral_allowed",
        "localhop_disabled",
        "replay_window_secs",
        "require_signed_commands",
        "validator_anchor",
    ] {
        assert!(
            value.get(field).is_some(),
            "missing field {field:?} in {value:?}"
        );
    }

    cancel.cancel();
}

/// `policy-set` stays gated by the SECURITY-module signing requirement;
/// an unsigned policy-set comes back as 403 UNAUTHORIZED. This pins
/// the boundary: reads exempt, writes signed.
#[tokio::test]
async fn policy_set_unsigned_is_rejected() {
    let (_engine, _shutdown, handle, cancel) = setup().await;

    let posture = r#"{"ephemeral_allowed":false,"localhop_disabled":true,"replay_window_secs":120,"require_signed_commands":true,"validator_anchor":null}"#;
    let cp = ControlParameters {
        uri: Some(posture.to_string()),
        ..Default::default()
    };
    let cr = send_verb(&handle, b"security", b"policy-set", Some(&cp)).await;
    assert_eq!(
        cr.status_code, 403,
        "unsigned policy-set must be 403; got {} {:?}",
        cr.status_code, cr.status_text
    );

    cancel.cancel();
}

/// `validation-stats` returns the §7 counter shape, even with no
/// validator wired. Lights up §4.3's chart's "no data" state.
#[tokio::test]
async fn validation_stats_zero_when_no_validator() {
    let (_engine, _shutdown, handle, cancel) = setup().await;

    let cr = send_verb(&handle, b"security", b"validation-stats", None).await;
    assert!(cr.is_ok(), "validation-stats must return 2xx");
    let body = cr.status_text;
    assert!(
        body.contains("validator_present=false"),
        "missing validator_present flag; got {body:?}"
    );
    assert!(
        body.contains("verified_per_sec=0"),
        "missing verified_per_sec; got {body:?}"
    );
    assert!(
        body.contains("rejected_per_sec=0"),
        "missing rejected_per_sec; got {body:?}"
    );

    cancel.cancel();
}

/// `validate` requires a Name; missing => 400.
#[tokio::test]
async fn validate_requires_name() {
    let (_engine, _shutdown, handle, cancel) = setup().await;

    let cr = send_verb(&handle, b"security", b"validate", None).await;
    assert_eq!(cr.status_code, 400);

    cancel.cancel();
}

/// `validate` returns 404 when no SecurityManager is wired — the
/// dashboard sidesheet renders this as "no anchor set installed."
#[tokio::test]
async fn validate_returns_404_without_security_manager() {
    let (_engine, _shutdown, handle, cancel) = setup().await;

    let cp = ControlParameters {
        name: Some(Name::root().append(b"lab").append(b"alice")),
        ..Default::default()
    };
    let cr = send_verb(&handle, b"security", b"validate", Some(&cp)).await;
    assert_eq!(
        cr.status_code, 404,
        "validate should be 404 without SecurityManager; got {} {:?}",
        cr.status_code, cr.status_text
    );

    cancel.cancel();
}

// ── Phase B step B witnesses ──────────────────────────────────────
//
// Pin the new wire shapes for `validation-stats` (counters + probe
// timestamp) and `validate` (real chain walk via `Validator::trace`).
// The setup() helper builds an engine WITHOUT a SecurityManager so
// these tests assert the cross-impl-compatible degrade paths; full
// chain-walk coverage lives in `ndn-security`'s validator tests.

/// `validation-stats` now exposes monotonic totals + a probe
/// timestamp so the dashboard can derive per-second rates client-side
/// without server windowing. The legacy `*_per_sec=0` lines stay on
/// the wire so older dashboards keep parsing.
#[tokio::test]
async fn validation_stats_exposes_totals_and_probe_ts() {
    let (_engine, _shutdown, handle, cancel) = setup().await;
    let cr = send_verb(&handle, b"security", b"validation-stats", None).await;
    assert!(cr.is_ok());
    let body = cr.status_text;
    assert!(
        body.contains("verified_total=0"),
        "missing verified_total; got {body:?}"
    );
    assert!(
        body.contains("rejected_total=0"),
        "missing rejected_total; got {body:?}"
    );
    assert!(
        body.contains("probe_unix_ns="),
        "missing probe_unix_ns; got {body:?}"
    );
    // Legacy fields remain — forward-compat with pre-Phase-B-B dashboards.
    assert!(body.contains("verified_per_sec=0"));
    assert!(body.contains("rejected_per_sec=0"));
    cancel.cancel();
}

/// `anchor-add` is gated — unsigned requests get 403 UNAUTHORIZED
/// regardless of body shape. Mirrors `policy_set_unsigned_is_rejected`.
#[tokio::test]
async fn anchor_add_unsigned_is_rejected() {
    let (_engine, _shutdown, handle, cancel) = setup().await;
    let cp = ControlParameters {
        name: Some(
            Name::root()
                .append(b"lab")
                .append(b"ca")
                .append(b"KEY")
                .append(b"k0"),
        ),
        uri: Some("00".to_string()),
        ..Default::default()
    };
    let cr = send_verb(&handle, b"security", b"anchor-add", Some(&cp)).await;
    assert_eq!(cr.status_code, 403);
    cancel.cancel();
}

/// `anchor-remove` is a security write — unsigned commands hit the
/// SECURITY-module gate and get 403 UNAUTHORIZED, mirroring the
/// existing `policy-set` test. The dashboard's gated-write path
/// surfaces this as "promotion not authorized."
#[tokio::test]
async fn anchor_remove_unsigned_is_rejected() {
    let (_engine, _shutdown, handle, cancel) = setup().await;
    let cr = send_verb(&handle, b"security", b"anchor-remove", None).await;
    assert_eq!(cr.status_code, 403);
    cancel.cancel();
}
