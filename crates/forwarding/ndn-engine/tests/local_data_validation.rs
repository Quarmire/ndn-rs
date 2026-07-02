//! Witness for the opt-in `require_data_validation` per-face policy.
//!
//! Local-scope faces (IPC/SHM/loopback) skip Data signature validation by
//! default — trusted by OS access control, the fast path. On a multi-tenant
//! host that is unsafe: a malicious/buggy local app can inject Data under any
//! name and have the forwarder serve it to another app (CS poisoning /
//! namespace spoofing). `ForwarderEngine::set_require_data_validation(face,
//! true)` opts a local face back into validation; with no validator configured
//! it fail-closes (drops) rather than serving unvalidated Data.
//!
//! See `data_pipeline` and `.claude/notes/partitioned-fwd-design-2026-05-24.md`.

use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_transport::FaceId;

const FACE_A: u64 = 1; // consumer
const FACE_B: u64 = 2; // producer (Local-scope in-proc face)

async fn recv_timeout(h: &InProcHandle) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_millis(300), h.recv())
        .await
        .ok()
        .flatten()
}

fn is_data(wire: &bytes::Bytes) -> bool {
    use ndn_packet::lp::LpPacket;
    const T_DATA: u8 = 0x06;
    if wire.first() == Some(&T_DATA) {
        return true;
    }
    if let Ok(lp) = LpPacket::decode(wire.clone())
        && let Some(frag) = lp.fragment
    {
        return frag.first() == Some(&T_DATA);
    }
    false
}

/// Drive Interest(A) → Data(B) through the engine; return whether consumer A
/// received the Data. `require_validation` toggles the policy on face B.
async fn consumer_receives_data(require_validation: bool) -> bool {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);
    // `Disabled` → no validator, so a require-validation face fail-closes
    // (drops). With the default accept-all validator a DigestSha256 Data would
    // self-validate and serve; the deterministic discriminator here is the
    // flag + fail-closed path. (The richer multi-tenant case — a trust schema
    // rejecting App X's Data under App Y's namespace — uses a real validator.)
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(ndn_security::SecurityProfile::Disabled)
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");

    if require_validation {
        engine.set_require_data_validation(FaceId(FACE_B), true);
    }
    engine
        .fib()
        .add_nexthop(&"/sec".parse::<Name>().unwrap(), FaceId(FACE_B), 0);

    // Consumer A Interest → forwarded to producer B (PIT entry in).
    let interest = InterestBuilder::new("/sec/data")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(interest).await.expect("inject interest");
    let _ = recv_timeout(&handle_b).await; // drain forwarded Interest at B

    // Producer B Data. No validator is configured, so it cannot be validated.
    let data = DataBuilder::new("/sec/data", b"payload").sign_digest_sha256();
    handle_b.send(data).await.expect("inject data");

    let got = recv_timeout(&handle_a).await.as_ref().is_some_and(is_data);
    shutdown.shutdown().await;
    got
}

#[tokio::test]
async fn local_data_served_by_default() {
    assert!(
        consumer_receives_data(false).await,
        "default: Local-face Data is served via the trusted fast path"
    );
}

#[tokio::test]
async fn require_validation_drops_unvalidated_local_data() {
    assert!(
        !consumer_receives_data(true).await,
        "require_data_validation on a Local face with no validator must drop \
         the Data (fail-closed), not serve it to the consumer"
    );
}
