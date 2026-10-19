//! `security/data-inspect` — what this node's validator says of the Data
//! under a name.
//!
//! The Data is fetched the way any app on the node fetches it: an Interest
//! (CanBePrefix) on a short-lived in-process consumer face of the engine, so
//! the content store answers when it holds one and the FIB forwards it
//! otherwise. The Data that answered is then validated with the engine's
//! validator — dispatched to the held trust context whose namespace covers
//! its name — walking its certificate chain to a trust anchor and fetching
//! the certificates it misses, all within the time the command gives
//! (`ExpirationPeriod`).
//!
//! Data from a local producer is delivered unvalidated by the forwarding
//! pipeline (local faces are exempt), so the verdict here is this node's own
//! check, whichever face answered. Data the pipeline refused never reaches
//! the consumer: the answer then reports the refusal (`data-refused`).
//!
//! Read only, but it makes this node express Interests and fetch
//! certificates on the caller's behalf, so it is not a public read: it goes
//! through the command gate (a local operator on the management socket, or
//! a command signed by a key the command trust anchors vouch for).

use std::time::Duration;

use ndn_app::{AppError, EngineAppExt};
use ndn_cert::report::{DataInspection, DataVerdict, Detail, TrustRefusal, code, detail_code};
use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::ControlParameters;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::meta_info::ContentType;
use ndn_packet::{Data, NackReason, Name, Refusal, SignatureType};
use ndn_security::cert_name::is_cert_name;
use ndn_security::safe_data::TrustPath;
use ndn_security::{Certificate, ValidationResult, Validator};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::MgmtResponse;

/// How long to wait for the Data and its certificates when the command
/// gives no `ExpirationPeriod`.
const DEFAULT_BUDGET: Duration = Duration::from_secs(4);
/// The longest wait a command may ask for.
const MAX_BUDGET: Duration = Duration::from_secs(60);

/// `security/data-inspect`: fetch the Data under `ControlParameters.name`,
/// validate it and answer [`DataInspection`] as JSON. `ExpirationPeriod`
/// (milliseconds) bounds the fetch and the validation together. Answered
/// deferred. A refusal is a [`TrustRefusal`]: `missing-parameter` without a
/// Name, `data-not-found` when nothing answered in time.
pub(super) fn security_data_inspect(
    params: ControlParameters,
    engine: &ForwarderEngine,
    cancel: &CancellationToken,
) -> MgmtResponse {
    let Some(name) = params.name else {
        return super::refused(&crate::missing_parameter(
            "data-inspect",
            "Name",
            "the name of the Data to inspect (a prefix: the Data that answers it is inspected)",
        ));
    };
    let budget = params
        .expiration_period
        .map_or(DEFAULT_BUDGET, Duration::from_millis)
        .clamp(Duration::from_millis(1), MAX_BUDGET);
    let engine = engine.clone();
    let face = cancel.child_token();
    MgmtResponse::Deferred(Box::pin(async move {
        super::json_answer(inspect(&engine, face, &name, budget).await)
    }))
}

/// Fetch the Data under `name` through `engine` on a consumer face tied to
/// `face` (torn down on return), and judge it, all within `budget`.
async fn inspect(
    engine: &ForwarderEngine,
    face: CancellationToken,
    name: &Name,
    budget: Duration,
) -> Result<DataInspection, TrustRefusal> {
    let deadline = Instant::now() + budget;
    let mut consumer = engine.app_consumer(face.clone());
    let _face = face.drop_guard();
    let wire = InterestBuilder::new(name.clone())
        .can_be_prefix()
        .lifetime(budget)
        .build();
    let validator = engine.validator();
    match consumer.fetch_wire(wire, budget).await {
        Ok(data) => Ok(inspect_data(&data, validator.as_deref(), deadline, budget).await),
        Err(AppError::Refused { reason }) => Ok(refused_inspection(
            name,
            reason,
            covering_namespace(validator.as_deref(), name),
        )),
        Err(e) => Err(not_found(name, budget, e)),
    }
}

/// The inspection of `data`: its facts, and the verdict of `validator`
/// (none: validation is disabled) reached before `deadline`.
async fn inspect_data(
    data: &Data,
    validator: Option<&Validator>,
    deadline: Instant,
    budget: Duration,
) -> DataInspection {
    let sig_info = data.sig_info();
    let signer = sig_info
        .and_then(|si| si.key_locator_name())
        .map(|key| key.to_string());
    let namespace = covering_namespace(validator, &data.name);
    let (valid_from, valid_until) = validity(data);
    let (verdict, detail, chain) = judge(
        data,
        validator,
        signer.as_deref(),
        namespace.as_deref(),
        deadline,
        budget,
    )
    .await;
    DataInspection {
        name: data.name.to_string(),
        signature_type: sig_info.map_or_else(String::new, |si| signature_type(si.sig_type)),
        signer,
        signed_at: sig_info
            .and_then(|si| si.sig_time)
            .map(|ms| iso(ms.saturating_mul(1_000_000))),
        content_type: content_type(
            data.meta_info()
                .map(|meta| meta.content_type)
                .unwrap_or_default(),
        ),
        freshness_ms: data
            .meta_info()
            .and_then(|meta| meta.freshness_period)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
        content_bytes: data.content().map_or(0, |c| c.len() as u64),
        valid_from,
        valid_until,
        namespace,
        verdict,
        detail,
        chain,
    }
}

/// The verdict on `data`, why, and the certificate names walked.
async fn judge(
    data: &Data,
    validator: Option<&Validator>,
    signer: Option<&str>,
    namespace: Option<&str>,
    deadline: Instant,
    budget: Duration,
) -> (DataVerdict, Detail, Vec<String>) {
    let Some(validator) = validator else {
        return (
            DataVerdict::Unchecked,
            Detail::new(
                detail_code::DATA_UNCHECKED,
                "this node validates nothing: the Data was not checked",
            ),
            Vec::new(),
        );
    };
    match tokio::time::timeout_at(deadline, validator.validate_chain(data)).await {
        Ok(ValidationResult::Valid(safe)) => match safe.trust_path() {
            TrustPath::DigestSha256 => (
                DataVerdict::Valid,
                Detail::new(
                    detail_code::DATA_DIGEST_ONLY,
                    "the Data carries a SHA-256 digest that matches: its bytes are intact, but \
                     no signer vouches for it",
                ),
                Vec::new(),
            ),
            TrustPath::CertChain(names) => (
                DataVerdict::Valid,
                valid_detail(signer, namespace),
                names.iter().map(Name::to_string).collect(),
            ),
            TrustPath::ExpectedContext { anchor } => (
                DataVerdict::Valid,
                valid_detail(signer, namespace),
                vec![anchor.to_string()],
            ),
            TrustPath::LocalFace { .. } => (
                DataVerdict::Valid,
                valid_detail(signer, namespace),
                Vec::new(),
            ),
        },
        Ok(ValidationResult::Invalid(e)) => (
            DataVerdict::Invalid,
            Detail::new(
                detail_code::DATA_INVALID,
                format!("the Data fails validation: {e}"),
            )
            .with("error", e),
            Vec::new(),
        ),
        // Pending, or still walking when the time ran out: name the first
        // certificate the cached walk misses.
        Ok(ValidationResult::Pending) | Err(_) => {
            let (_, missing) = validator.validate_chain_cached(data).await;
            let timeout_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
            let detail = match missing {
                Some(cert) => Detail::new(
                    detail_code::DATA_CHAIN_INCOMPLETE,
                    format!(
                        "the certificate {cert} on the Data's chain could not be had within \
                         {timeout_ms} ms"
                    ),
                )
                .with("certificate", cert),
                None => Detail::new(
                    detail_code::DATA_CHAIN_INCOMPLETE,
                    format!(
                        "a certificate on the Data's chain could not be had within {timeout_ms} ms"
                    ),
                ),
            };
            (
                DataVerdict::Pending,
                detail.with("timeout_ms", timeout_ms),
                Vec::new(),
            )
        }
    }
}

/// `data-valid`, with the signer and the trusted prefix vouching for it.
fn valid_detail(signer: Option<&str>, namespace: Option<&str>) -> Detail {
    let signer = signer.unwrap_or_default();
    let mut detail = match namespace {
        Some(ns) => Detail::new(
            detail_code::DATA_VALID,
            format!("signed by {signer}, whose chain reaches a trust anchor of {ns}"),
        )
        .with("namespace", ns),
        None => Detail::new(
            detail_code::DATA_VALID,
            format!("signed by {signer}, whose chain reaches a trust anchor"),
        ),
    };
    if !signer.is_empty() {
        detail = detail.with("signer", signer);
    }
    detail
}

/// The inspection of a Data this node's forwarder refused: only its name
/// and the refusal are known (a refused Data is not kept).
fn refused_inspection(name: &Name, reason: Refusal, namespace: Option<String>) -> DataInspection {
    DataInspection {
        name: name.to_string(),
        signature_type: String::new(),
        signer: None,
        signed_at: None,
        content_type: String::new(),
        freshness_ms: None,
        content_bytes: 0,
        valid_from: None,
        valid_until: None,
        namespace,
        verdict: if reason.is_final() {
            DataVerdict::Invalid
        } else {
            DataVerdict::Pending
        },
        detail: Detail::new(
            detail_code::DATA_REFUSED,
            format!(
                "this node's forwarder refused the Data that answered ({reason}): {}",
                reason.next_step()
            ),
        )
        .with("refusal", reason.as_str())
        .with("final", reason.is_final()),
        chain: Vec::new(),
    }
}

/// `data-not-found`: nothing under `name` answered within `budget`.
fn not_found(name: &Name, budget: Duration, error: AppError) -> TrustRefusal {
    let timeout_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
    let refusal = |why: String| {
        TrustRefusal::new(
            code::DATA_NOT_FOUND,
            format!("no Data under {name} reached this node within {timeout_ms} ms{why}"),
        )
        .with("name", name)
        .with("timeout_ms", timeout_ms)
    };
    match error {
        AppError::Timeout => refusal(String::new()),
        AppError::Nacked { reason } => {
            let nack = reason.map_or_else(|| "unspecified".to_owned(), nack_token);
            refusal(format!(" (Nack: {nack})")).with("nack", nack)
        }
        e => {
            let error = e.to_string();
            refusal(format!(": {error}")).with("error", error)
        }
    }
}

/// A Nack reason as a stable token.
fn nack_token(reason: NackReason) -> String {
    match reason {
        NackReason::NoRoute => "no-route".to_owned(),
        NackReason::Congestion => "congestion".to_owned(),
        NackReason::Duplicate => "duplicate".to_owned(),
        NackReason::NotYet => "not-yet".to_owned(),
        NackReason::Refused(r) => r.as_str().to_owned(),
        NackReason::Other(code) => code.to_string(),
    }
}

/// The namespace of the held trust context that governs `name` (the
/// longest covering it); `None` when only the ambient context does.
fn covering_namespace(validator: Option<&Validator>, name: &Name) -> Option<String> {
    let context = validator?.keyring().context_for(name);
    let namespace = context.namespace();
    (!namespace.is_empty()).then(|| namespace.to_string())
}

/// A certificate's ValidityPeriod bounds; `None` for a bound it does not
/// set, and for Data that is no certificate.
fn validity(data: &Data) -> (Option<String>, Option<String>) {
    if !is_cert_name(&data.name) {
        return (None, None);
    }
    match Certificate::decode(data) {
        Ok(cert) => (
            (cert.valid_from != 0).then(|| iso(cert.valid_from)),
            (cert.valid_until != u64::MAX).then(|| iso(cert.valid_until)),
        ),
        Err(_) => (None, None),
    }
}

/// `ns` (nanoseconds since the Unix epoch) as ISO 8601 basic, UTC.
fn iso(ns: u64) -> String {
    let basic = ndn_security::iso8601::format_iso_basic(ns);
    format!("{}Z", String::from_utf8_lossy(&basic))
}

fn signature_type(sig_type: SignatureType) -> String {
    match sig_type {
        SignatureType::DigestSha256 => "DigestSha256".to_owned(),
        SignatureType::SignatureSha256WithRsa => "RsaSha256".to_owned(),
        SignatureType::SignatureSha256WithEcdsa => "EcdsaSha256".to_owned(),
        SignatureType::SignatureHmacWithSha256 => "HmacSha256".to_owned(),
        SignatureType::SignatureEd25519 => "Ed25519".to_owned(),
        SignatureType::Other(6) => "DigestBlake3".to_owned(),
        SignatureType::Other(7) => "Blake3Keyed".to_owned(),
        SignatureType::Other(code) => code.to_string(),
    }
}

fn content_type(content_type: ContentType) -> String {
    match content_type {
        ContentType::Blob => "Blob".to_owned(),
        ContentType::Link => "Link".to_owned(),
        ContentType::Key => "Key".to_owned(),
        ContentType::Nack => "Nack".to_owned(),
        ContentType::Manifest => "Manifest".to_owned(),
        ContentType::PrefixAnn => "PrefixAnn".to_owned(),
        ContentType::Other(code) => code.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use ndn_engine::{EngineBuilder, EngineConfig};
    use ndn_packet::encode::DataBuilder;
    use ndn_security::{Ed25519Signer, SignWith, Signer, TrustSchema};

    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// A root anchor `/root/KEY/r`, a key `/root/p/KEY/k` it certified, a
    /// validator holding both, Data `/root/p/data` the key signed, and Data
    /// `/root/p/forged` it signed with the signature altered afterwards.
    async fn signed_setup() -> (Validator, Bytes, Bytes) {
        let root = Ed25519Signer::from_seed(&[41; 32], n("/root/KEY/r"));
        let root_cert = Data::decode(
            ndn_security::encode_cert_data(
                &n("/root/KEY/r/self/v1"),
                &root.public_key().unwrap(),
                &root,
                0,
                u64::MAX,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        let key = Ed25519Signer::from_seed(&[42; 32], n("/root/p/KEY/k"));
        let key_cert = Data::decode(
            ndn_security::encode_cert_data(
                &n("/root/p/KEY/k/root/v1"),
                &key.public_key().unwrap(),
                &root,
                0,
                u64::MAX,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        let validator = Validator::new(TrustSchema::accept_all());
        validator.add_trust_anchor(Certificate::decode(&root_cert).unwrap());
        validator
            .cert_cache()
            .insert(Certificate::decode(&key_cert).unwrap());
        let data = DataBuilder::new(n("/root/p/data"), b"hello")
            .freshness(Duration::from_secs(10))
            .sign_with_sync(&key)
            .unwrap();
        // Signed by the same key, then its signature altered.
        let mut forged = DataBuilder::new(n("/root/p/forged"), b"hello")
            .sign_with_sync(&key)
            .unwrap()
            .to_vec();
        *forged.last_mut().unwrap() ^= 0xFF;
        (validator, data, Bytes::from(forged))
    }

    fn later(budget: Duration) -> Instant {
        Instant::now() + budget
    }

    #[tokio::test]
    async fn a_valid_signed_data_reports_its_signer_and_chain() {
        let (validator, wire, _) = signed_setup().await;
        let data = Data::decode(wire).unwrap();
        let budget = Duration::from_secs(1);
        let got = inspect_data(&data, Some(&validator), later(budget), budget).await;
        assert_eq!(got.verdict, DataVerdict::Valid);
        assert_eq!(got.detail.code, detail_code::DATA_VALID);
        assert_eq!(got.name, "/root/p/data");
        assert_eq!(got.signature_type, "Ed25519");
        assert_eq!(got.signer.as_deref(), Some("/root/p/KEY/k"));
        assert_eq!(got.content_bytes, 5);
        assert_eq!(got.freshness_ms, Some(10_000));
        assert_eq!(got.content_type, "Blob");
        // Signer first, ending at the anchor.
        assert_eq!(got.chain.first().map(String::as_str), Some("/root/p/KEY/k"));
        assert!(got.chain.len() >= 2, "{:?}", got.chain);
        // Not a certificate: no validity.
        assert_eq!((got.valid_from, got.valid_until), (None, None));
    }

    #[tokio::test]
    async fn an_altered_signature_is_invalid_with_its_error() {
        let (validator, _, forged) = signed_setup().await;
        let data = Data::decode(forged).unwrap();
        let budget = Duration::from_secs(1);
        let got = inspect_data(&data, Some(&validator), later(budget), budget).await;
        assert_eq!(got.verdict, DataVerdict::Invalid);
        assert_eq!(got.detail.code, detail_code::DATA_INVALID);
        assert!(got.detail.param("error").is_some());
        assert!(got.chain.is_empty());
    }

    #[tokio::test]
    async fn a_missing_certificate_is_pending_and_named() {
        let stranger = Ed25519Signer::from_seed(&[43; 32], n("/root/q/KEY/x"));
        let data = Data::decode(
            DataBuilder::new(n("/root/q/data"), b"x")
                .sign_with_sync(&stranger)
                .unwrap(),
        )
        .unwrap();
        let validator = Validator::new(TrustSchema::accept_all());
        let budget = Duration::from_millis(200);
        let got = inspect_data(&data, Some(&validator), later(budget), budget).await;
        assert_eq!(got.verdict, DataVerdict::Pending);
        assert_eq!(got.detail.code, detail_code::DATA_CHAIN_INCOMPLETE);
        assert_eq!(got.detail.param("certificate"), Some("/root/q/KEY/x"));
    }

    #[tokio::test]
    async fn a_digest_is_integrity_only_and_no_validator_checks_nothing() {
        let data =
            Data::decode(DataBuilder::new(n("/open/data"), b"x").sign_digest_sha256()).unwrap();
        let budget = Duration::from_secs(1);
        let validator = Validator::new(TrustSchema::accept_all());
        let got = inspect_data(&data, Some(&validator), later(budget), budget).await;
        assert_eq!(got.verdict, DataVerdict::Valid);
        assert_eq!(got.detail.code, detail_code::DATA_DIGEST_ONLY);
        assert_eq!(got.signature_type, "DigestSha256");
        assert_eq!(got.signer, None);

        let got = inspect_data(&data, None, later(budget), budget).await;
        assert_eq!(got.verdict, DataVerdict::Unchecked);
        assert_eq!(got.detail.code, detail_code::DATA_UNCHECKED);
    }

    #[tokio::test]
    async fn a_certificate_reports_its_validity() {
        let root = Ed25519Signer::from_seed(&[44; 32], n("/root/KEY/r"));
        let from = 1_700_000_000u64 * 1_000_000_000;
        let until = 1_800_000_000u64 * 1_000_000_000;
        let cert = Data::decode(
            ndn_security::encode_cert_data(
                &n("/root/KEY/r/self/v1"),
                &root.public_key().unwrap(),
                &root,
                from,
                until,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        let budget = Duration::from_millis(200);
        let got = inspect_data(&cert, None, later(budget), budget).await;
        assert_eq!(got.valid_from.as_deref(), Some(iso(from).as_str()));
        assert_eq!(got.valid_until.as_deref(), Some(iso(until).as_str()));
        assert!(got.valid_from.unwrap().ends_with('Z'));
    }

    /// The verb makes the node fetch on the caller's behalf: never an
    /// unsigned public read, and no trust change either (the command gate).
    #[test]
    fn the_verb_goes_through_the_command_gate() {
        use ndn_mgmt_wire::nfd_command::{module, verb};
        assert!(!crate::auth::is_public_dataset_verb(
            module::SECURITY,
            verb::DATA_INSPECT
        ));
        assert!(!crate::auth::is_trust_admin_verb(
            module::SECURITY,
            verb::DATA_INSPECT
        ));
    }

    /// The ControlResponse the verb answers, awaited when deferred.
    async fn answer(resp: MgmtResponse) -> ndn_mgmt_wire::ControlResponse {
        match resp {
            MgmtResponse::Control(cr) => *cr,
            MgmtResponse::Deferred(pending) => pending.await,
            _ => panic!("expected a ControlResponse"),
        }
    }

    /// An engine validating with `validator`, with producers serving
    /// `served` (name, Data wire) on local faces.
    async fn engine_serving(
        validator: Validator,
        served: Vec<(Name, Bytes)>,
        cancel: &CancellationToken,
    ) -> (ForwarderEngine, ndn_engine::ShutdownHandle) {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .validator(Arc::new(validator))
            .build()
            .await
            .unwrap();
        for (prefix, wire) in served {
            let producer = engine.register_producer(prefix, cancel.child_token());
            tokio::spawn(async move {
                let _ = producer
                    .serve(move |_, responder| {
                        let wire = wire.clone();
                        async move {
                            let _ = responder.respond_bytes(wire).await;
                        }
                    })
                    .await;
            });
        }
        (engine, shutdown)
    }

    #[tokio::test]
    async fn the_verb_answers_valid_invalid_and_not_found() {
        let (validator, wire, forged) = signed_setup().await;
        let cancel = CancellationToken::new();
        let (engine, shutdown) = engine_serving(
            validator,
            vec![(n("/root/p/data"), wire), (n("/root/p/forged"), forged)],
            &cancel,
        )
        .await;
        let ask = |name: Option<&str>, ms: u64| ControlParameters {
            name: name.map(n),
            expiration_period: Some(ms),
            ..Default::default()
        };

        // Valid: served by a local producer, judged by this node's validator.
        let cr = answer(security_data_inspect(
            ask(Some("/root/p/data"), 2000),
            &engine,
            &cancel,
        ))
        .await;
        assert_eq!(cr.status_code, 200, "{}", cr.status_text);
        let got: DataInspection = serde_json::from_str(&cr.status_text).unwrap();
        assert_eq!(got.verdict, DataVerdict::Valid);
        assert_eq!(got.detail.code, detail_code::DATA_VALID);
        assert_eq!(got.name, "/root/p/data");

        // Invalid: the Data that answered fails validation (here, or already
        // in the forwarder's pipeline, which then refused it).
        let cr = answer(security_data_inspect(
            ask(Some("/root/p/forged"), 2000),
            &engine,
            &cancel,
        ))
        .await;
        assert_eq!(cr.status_code, 200, "{}", cr.status_text);
        let got: DataInspection = serde_json::from_str(&cr.status_text).unwrap();
        assert_eq!(got.verdict, DataVerdict::Invalid);
        assert!(
            [detail_code::DATA_INVALID, detail_code::DATA_REFUSED]
                .contains(&got.detail.code.as_str()),
            "{:?}",
            got.detail
        );

        // Not found: nothing answers the name in time.
        let cr = answer(security_data_inspect(
            ask(Some("/nobody/here"), 300),
            &engine,
            &cancel,
        ))
        .await;
        let refusal: TrustRefusal = serde_json::from_str(&cr.status_text).unwrap();
        assert_eq!(refusal.code, code::DATA_NOT_FOUND.code);
        assert_eq!(cr.status_code, code::DATA_NOT_FOUND.status_code);
        assert_eq!(refusal.param("name"), Some("/nobody/here"));

        // No Name: refused at once.
        let cr = answer(security_data_inspect(ask(None, 300), &engine, &cancel)).await;
        let refusal: TrustRefusal = serde_json::from_str(&cr.status_text).unwrap();
        assert_eq!(refusal.code, code::MISSING_PARAMETER.code);

        cancel.cancel();
        shutdown.shutdown().await;
    }
}
