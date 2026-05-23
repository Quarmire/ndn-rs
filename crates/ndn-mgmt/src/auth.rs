//! Command authentication, `SignatureTime` replay protection, and the
//! NFD-vs-extended-module signing gate.

use std::sync::Arc;

#[cfg(test)]
use crate::wire::build_mgmt_response_wire;
use ndn_config::ControlParameters;
#[cfg(test)]
use ndn_packet::Name;

/// Resolve a command's `ControlParameters` slot per NFD spec: CP appears
/// either in the Name's 5th component or in `ApplicationParameters`, never
/// both. Returns the resolved slot, `None` when absent, or an `Err`
/// describing why a malformed shape was rejected.
pub(crate) fn resolve_control_parameters(
    in_name: Option<ControlParameters>,
    in_app_params: Option<ControlParameters>,
) -> Result<Option<ControlParameters>, &'static str> {
    match (in_name, in_app_params) {
        (Some(_), Some(_)) => Err("ControlParameters present in both Name and AppParameters"),
        (Some(p), None) | (None, Some(p)) => Ok(Some(p)),
        (None, None) => Ok(None),
    }
}

/// Sliding `SignatureTime` window for signed-command replay defence
/// (mirrors ndn-cxx `ValidationPolicyCommandInterest`).
pub const COMMAND_SIG_TIME_TOLERANCE_MS: u64 = 120_000;

/// Per-signer last-accepted `SignatureTime`, keyed by the signer's
/// certificate `Name`.
pub type CommandReplayCache =
    Arc<std::sync::Mutex<std::collections::HashMap<ndn_packet::Name, u64>>>;

/// Decide whether `sig_time_ms` is acceptable given `now_ms` and the last
/// accepted timestamp for the same signer. Rejects missing values,
/// timestamps outside `±tolerance_ms`, and any `sig_time <= last_seen`
/// (replay or reorder).
pub(crate) fn check_sig_time(
    sig_time_ms: Option<u64>,
    now_ms: u64,
    last_seen: Option<u64>,
    tolerance_ms: u64,
) -> Result<u64, String> {
    let Some(sig_time) = sig_time_ms else {
        return Err("signed command missing SignatureTime header".to_string());
    };
    let delta = now_ms.abs_diff(sig_time);
    if delta > tolerance_ms {
        return Err(format!(
            "command SignatureTime {sig_time} ms is outside ±{tolerance_ms} ms window of now={now_ms}"
        ));
    }
    if let Some(last) = last_seen
        && sig_time <= last
    {
        return Err(format!(
            "command SignatureTime {sig_time} ms <= last accepted {last} ms (replay or reorder)"
        ));
    }
    Ok(sig_time)
}

/// `true` when `module` is an ndn-rs extension beyond NFD's canonical
/// set (`faces`, `fib`, `rib`, `cs`, `strategy-choice`, `status`).
/// Extensions expose privileged surface (key generation, schema edits,
/// route changes) and unconditionally require signed commands.
pub(crate) fn is_extended_module(module: &[u8]) -> bool {
    use ndn_config::nfd_command::module as m;
    let standard: [&[u8]; 6] = [m::FACES, m::FIB, m::RIB, m::CS, m::STRATEGY, m::STATUS];
    !standard.contains(&module)
}

/// Effective auth gate: extended modules always require signed commands;
/// standard modules follow the operator's `require_signed_commands` flag.
pub(crate) fn effective_require_signed(module: &[u8], require_signed_global: bool) -> bool {
    require_signed_global || is_extended_module(module)
}

/// Per NFD `daemon/mgmt/dispatcher.cpp`, `*/list` dataset verbs on the
/// canonical modules are public read-only queries; ndn-rs additionally
/// exposes the security read-only inspection surface (trust posture,
/// validation stats, trust-path tracing) so the dashboard can render
/// posture before any signing identity is configured. Writes
/// (`policy-set`, etc.) stay gated.
pub(crate) fn is_public_dataset_verb(module: &[u8], verb: &[u8]) -> bool {
    use ndn_config::nfd_command::{module as m, verb as v};
    let standard: [&[u8]; 6] = [m::FACES, m::FIB, m::RIB, m::CS, m::STRATEGY, m::STATUS];
    if standard.contains(&module) && verb == v::LIST {
        return true;
    }
    // ndn-rs-local read-only telemetry dataset (cross-layer link signals).
    if module == m::FACES && verb == v::LINK_QUALITY {
        return true;
    }
    if module == m::SECURITY
        && (verb == v::POLICY_GET || verb == v::VALIDATION_STATS || verb == v::VALIDATE)
    {
        return true;
    }
    false
}

/// Authorise a command Interest (mirrors NFD
/// `daemon/mgmt/command-authenticator.cpp`).
///
/// - `require_signed = false` — every Interest is permitted; unsigned
///   commands log a warning at the call site.
/// - `require_signed = true`, `validator = None` — every Interest is
///   rejected (the operator opted in but wired no trust anchors).
/// - `require_signed = true`, `validator = Some(v)` — the Interest
///   must be signed and `v.validate_interest` must return `Valid`.
/// - When `replay_cache` is `Some(_)`, the `SignatureTime` window is
///   enforced after the signature passes.
pub(crate) async fn authorize_command(
    interest: &ndn_packet::Interest,
    validator: Option<&ndn_security::Validator>,
    require_signed: bool,
    replay_cache: Option<&CommandReplayCache>,
) -> Result<(), String> {
    if !require_signed {
        if interest.sig_info().is_none() {
            tracing::warn!(
                target: "mgmt.security",
                name = %interest.name,
                "nfd-mgmt: unsigned command accepted (require_signed_commands=false; \
                 enable in config to enforce NFD command-authenticator parity)"
            );
        }
        return Ok(());
    }
    let Some(validator) = validator else {
        return Err("command authentication required but no validator is configured".to_string());
    };
    // DigestSha256 verifies byte integrity but carries no key identity.
    // Per NFD command-authenticator.cpp, only key-backed signature types
    // (Ed25519, ECDSA, RSA, BLAKE3) are accepted when a key validator is
    // present. DigestSha256-only Interests are treated as unsigned here.
    if matches!(
        interest.sig_info().map(|s| s.sig_type),
        None | Some(ndn_packet::SignatureType::DigestSha256)
    ) {
        return Err("command rejected: key-backed signature required \
             (DigestSha256 does not establish key identity)"
            .to_string());
    }
    use ndn_security::InterestValidationOutcome::*;
    match validator.validate_interest(interest).await {
        Valid => {}
        Invalid(e) => return Err(format!("invalid command signature: {e}")),
        Pending => return Err("signing certificate not yet resolved".to_string()),
    }

    // Replay protection requires a stable signer identity; reject any
    // signed command without a Name-shaped KeyLocator.
    if let Some(cache) = replay_cache {
        let sig_info = interest
            .sig_info()
            .ok_or_else(|| "signed command missing SignatureInfo for replay check".to_string())?;
        let signer = sig_info
            .key_locator_name()
            .ok_or_else(|| "signed command missing KeyLocator name for replay check".to_string())
            .map(|arc_name| arc_name.as_ref().clone())?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last_seen = cache
            .lock()
            .map_err(|_| "command replay cache poisoned".to_string())?
            .get(&signer)
            .copied();
        let accepted = check_sig_time(
            sig_info.sig_time,
            now_ms,
            last_seen,
            COMMAND_SIG_TIME_TOLERANCE_MS,
        )?;
        cache
            .lock()
            .map_err(|_| "command replay cache poisoned".to_string())?
            .insert(signer, accepted);
    }

    Ok(())
}

#[cfg(test)]
mod e01_tests {
    use super::*;
    use ndn_packet::Interest;
    use ndn_packet::encode::{InterestBuilder, encode_interest};
    use ndn_security::Validator;
    use ndn_security::trust_schema::{NamePattern, PatternComponent, SchemaRule, TrustSchema};

    fn open_schema() -> TrustSchema {
        let mut schema = TrustSchema::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
            key_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
        });
        schema
    }

    /// With `require_signed_commands = false`, every Interest dispatches
    /// even when unsigned.
    #[tokio::test]
    async fn e01_unsigned_command_passes_when_require_signed_false() {
        let cmd_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let interest = Interest::decode(encode_interest(&cmd_name, None)).unwrap();
        assert!(
            authorize_command(&interest, None, false, None)
                .await
                .is_ok()
        );
    }

    /// `require_signed_commands = true` with no validator wired rejects
    /// every command.
    #[tokio::test]
    async fn e01_unsigned_command_rejected_when_require_signed_true_no_validator() {
        let cmd_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let interest = Interest::decode(encode_interest(&cmd_name, None)).unwrap();
        assert!(
            authorize_command(&interest, None, true, None)
                .await
                .is_err()
        );
    }

    /// With a validator wired and `require_signed_commands = true`, an
    /// unsigned command is rejected.
    #[tokio::test]
    async fn e01_unsigned_command_rejected_when_validator_wired() {
        let cmd_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let interest = Interest::decode(encode_interest(&cmd_name, None)).unwrap();
        let validator = Validator::new(open_schema());
        assert!(
            authorize_command(&interest, Some(&validator), true, None)
                .await
                .is_err()
        );
    }

    /// DigestSha256-signed command is rejected when a key validator is
    /// wired; DigestSha256 establishes integrity only, not key identity.
    #[tokio::test]
    async fn e01_digest_sha256_rejected_when_validator_wired() {
        let cmd_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let wire = InterestBuilder::new(cmd_name)
            .app_parameters(bytes::Bytes::from_static(b"params"))
            .sign_digest_sha256();
        let interest = Interest::decode(wire).unwrap();
        let validator = Validator::new(open_schema());
        let result = authorize_command(&interest, Some(&validator), true, None).await;
        assert!(
            result.is_err(),
            "DigestSha256 must be rejected with a key validator"
        );
        assert!(
            result.unwrap_err().contains("key-backed"),
            "error message must explain why"
        );
    }

    /// A properly-signed command Interest dispatches when the validator's
    /// cert cache holds the signer's key.
    #[tokio::test]
    async fn e01_signed_command_passes_when_validator_wired() {
        use ndn_security::cert_cache::Certificate;
        use ndn_security::signer::{Ed25519Signer, Signer as _};

        let seed = [9u8; 32];
        let key_name: Name = "/operators/alice/KEY/k1".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let pubkey = signer.public_key_bytes();

        let cmd_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let wire = InterestBuilder::new(cmd_name)
            .app_parameters(bytes::Bytes::from_static(b"params"))
            .sign_sync(
                ndn_packet::SignatureType::SignatureEd25519,
                Some(&key_name),
                |region| signer.sign_sync(region).expect("ed25519 sign"),
            );
        let interest = Interest::decode(wire).unwrap();

        let validator = Validator::new(open_schema());
        validator.cert_cache().insert(Certificate {
            name: Arc::new(key_name),
            public_key: bytes::Bytes::copy_from_slice(&pubkey),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        });

        assert!(
            authorize_command(&interest, Some(&validator), true, None)
                .await
                .is_ok()
        );
    }

    // `/localhop/nfd/...` registration: mirrors NFD
    // `daemon/mgmt/rib-manager.cpp:340-355`. Each test pins one branch of
    // the localhop gate (unsigned reject, signed-with-cached-cert accept,
    // no-validator reject) at the gating-function level so the witness
    // runs under `cargo test` without a docker-compose harness.

    /// Unsigned `/localhop/nfd/...` Interests are rejected when a localhop
    /// validator is wired.
    #[tokio::test]
    async fn d01_localhop_unsigned_rejected() {
        let cmd_name: Name = "/localhop/nfd/rib/register".parse().unwrap();
        let interest = Interest::decode(encode_interest(&cmd_name, None)).unwrap();
        let validator = Validator::new(open_schema());
        // `/localhop` always requires signing in `run_ndn_mgmt_handler`.
        let result = authorize_command(&interest, Some(&validator), true, None).await;
        assert!(
            result.is_err(),
            "unsigned /localhop command must not authorize"
        );
    }

    /// `/localhop/nfd/...` signed by a key whose cert sits in the
    /// validator's `cert_cache` passes authorisation.
    #[tokio::test]
    async fn d02_localhop_signed_accepted() {
        use ndn_security::cert_cache::Certificate;
        use ndn_security::signer::{Ed25519Signer, Signer as _};

        let seed = [7u8; 32];
        let key_name: Name = "/demo/browser/d02/KEY/k1".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let pubkey = signer.public_key_bytes();

        let cmd_name: Name = "/localhop/nfd/rib/register".parse().unwrap();
        let wire = InterestBuilder::new(cmd_name)
            .app_parameters(bytes::Bytes::from_static(b"params"))
            .sign_sync(
                ndn_packet::SignatureType::SignatureEd25519,
                Some(&key_name),
                |region| signer.sign_sync(region).expect("ed25519 sign"),
            );
        let interest = Interest::decode(wire).unwrap();

        let validator = Validator::new(open_schema());
        validator.cert_cache().insert(Certificate {
            name: Arc::new(key_name),
            public_key: bytes::Bytes::copy_from_slice(&pubkey),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        });

        let result = authorize_command(&interest, Some(&validator), true, None).await;
        assert!(
            result.is_ok(),
            "signed /localhop command with cached cert must authorize, got: {result:?}"
        );
    }

    /// No localhop validator wired → every `/localhop/nfd/...` command is
    /// rejected; the wire path returns `STATUS_UNAUTHORIZED`.
    #[tokio::test]
    async fn d03_localhop_disabled_without_anchor() {
        let cmd_name: Name = "/localhop/nfd/rib/register".parse().unwrap();
        let interest = Interest::decode(encode_interest(&cmd_name, None)).unwrap();
        let result = authorize_command(&interest, None, true, None).await;
        let reason = result.expect_err("no validator must reject the command");
        assert!(
            reason.contains("no validator"),
            "rejection reason must explain why; got: {reason}"
        );
    }

    /// End-to-end replay protection: decoding the same signed Interest
    /// twice through a `CommandReplayCache` accepts on first dispatch and
    /// rejects on the second via the strictly-greater rule.
    #[tokio::test]
    async fn n10_replay_rejected_when_cache_enabled() {
        use ndn_security::cert_cache::Certificate;
        use ndn_security::signer::{Ed25519Signer, Signer as _};

        let seed = [13u8; 32];
        let key_name: Name = "/operators/n10/KEY/k0".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let pubkey = signer.public_key_bytes();

        // Both decoded Interests share one SigTime, so the second
        // dispatch is a true replay.
        let cmd_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let wire = InterestBuilder::new(cmd_name)
            .app_parameters(bytes::Bytes::from_static(b"params"))
            .sign_sync(
                ndn_packet::SignatureType::SignatureEd25519,
                Some(&key_name),
                |region| signer.sign_sync(region).expect("ed25519 sign"),
            );
        let interest = Interest::decode(wire.clone()).unwrap();
        let interest_replay = Interest::decode(wire).unwrap();

        let validator = Validator::new(open_schema());
        validator.cert_cache().insert(Certificate {
            name: Arc::new(key_name.clone()),
            public_key: bytes::Bytes::copy_from_slice(&pubkey),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        });

        let cache: CommandReplayCache =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        assert!(
            authorize_command(&interest, Some(&validator), true, Some(&cache))
                .await
                .is_ok(),
            "first signed command must be accepted"
        );

        let err = authorize_command(&interest_replay, Some(&validator), true, Some(&cache))
            .await
            .expect_err("replayed signed command must be rejected");
        assert!(
            err.contains("replay") || err.contains("reorder") || err.contains("SignatureTime"),
            "rejection reason should mention replay/reorder/SignatureTime, got: {err}"
        );
    }

    /// `build_mgmt_response_wire` falls back to `DigestSha256` when no
    /// signer is wired.
    #[test]
    fn n12_response_falls_back_to_digest_sha256_when_no_signer() {
        use ndn_packet::Data;
        let name: Name = "/localhost/nfd/status".parse().unwrap();
        let wire = build_mgmt_response_wire(&name, b"ok", None);
        let data = Data::decode(wire).expect("response Data must decode");
        let si = data.sig_info().expect("sig_info present");
        assert_eq!(
            si.sig_type,
            ndn_packet::SignatureType::DigestSha256,
            "no-signer path must fall back to DigestSha256"
        );
        assert!(
            si.key_locator.is_none(),
            "DigestSha256 must not carry KeyLocator"
        );
    }

    /// When a signer is wired, the response Data is signed with that
    /// signer's `sig_type()` and the SignatureInfo carries a KeyLocator
    /// naming the signer's cert (or key) name.
    #[tokio::test]
    async fn n12_response_uses_signer_when_wired() {
        use ndn_packet::Data;
        use ndn_security::signer::Ed25519Signer;

        let seed = [21u8; 32];
        let key_name: Name = "/operators/n12/KEY/k0".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());

        let name: Name = "/localhost/nfd/status".parse().unwrap();
        let wire = build_mgmt_response_wire(&name, b"ok", Some(&signer));
        let data = Data::decode(wire).expect("response Data must decode");
        let si = data.sig_info().expect("sig_info present");
        assert_eq!(
            si.sig_type,
            ndn_packet::SignatureType::SignatureEd25519,
            "signed response must label SignatureEd25519, not DigestSha256"
        );
        let kl = si.key_locator.as_ref().expect("KeyLocator must be set");
        assert_eq!(
            kl.to_string(),
            key_name.to_string(),
            "KeyLocator falls through to signer's key_name when no cert wired"
        );
    }

    /// `resolve_control_parameters` rejects CP in both locations, accepts
    /// either single location, and returns `None` when neither is present.
    #[test]
    fn n11_resolve_control_parameters_rejects_both_locations() {
        let cp1 = ControlParameters::default();
        let cp2 = ControlParameters::default();
        let err = resolve_control_parameters(Some(cp1), Some(cp2))
            .expect_err("CP in both locations must be rejected");
        assert!(err.contains("both"), "{err}");
    }

    #[test]
    fn n11_resolve_control_parameters_accepts_name_only() {
        let cp = ControlParameters::default();
        let out =
            resolve_control_parameters(Some(cp.clone()), None).expect("Name-only CP must accept");
        assert_eq!(out, Some(cp));
    }

    #[test]
    fn n11_resolve_control_parameters_accepts_app_params_only() {
        let cp = ControlParameters::default();
        let out = resolve_control_parameters(None, Some(cp.clone()))
            .expect("AppParams-only CP must accept");
        assert_eq!(out, Some(cp));
    }

    #[test]
    fn n11_resolve_control_parameters_no_cp_returns_none() {
        let out =
            resolve_control_parameters(None, None).expect("absent CP must produce None, not Err");
        assert_eq!(out, None);
    }

    /// Missing SignatureTime always rejected.
    #[test]
    fn n10_check_sig_time_rejects_missing() {
        let err = check_sig_time(None, 1_000, None, COMMAND_SIG_TIME_TOLERANCE_MS)
            .expect_err("missing SignatureTime must reject");
        assert!(err.contains("SignatureTime"), "{err}");
    }

    /// SignatureTime outside the ±tolerance window rejected.
    #[test]
    fn n10_check_sig_time_rejects_out_of_window() {
        let now = 10_000_000u64;
        let stale = now - (COMMAND_SIG_TIME_TOLERANCE_MS + 1);
        let future = now + (COMMAND_SIG_TIME_TOLERANCE_MS + 1);
        assert!(check_sig_time(Some(stale), now, None, COMMAND_SIG_TIME_TOLERANCE_MS).is_err());
        assert!(check_sig_time(Some(future), now, None, COMMAND_SIG_TIME_TOLERANCE_MS).is_err());
    }

    /// Fresh SignatureTime within window with no prior observation is
    /// accepted.
    #[test]
    fn n10_check_sig_time_accepts_fresh_in_window() {
        let now = 10_000_000u64;
        let sig = now - 1_000;
        let accepted = check_sig_time(Some(sig), now, None, COMMAND_SIG_TIME_TOLERANCE_MS)
            .expect("fresh in-window SignatureTime must accept");
        assert_eq!(accepted, sig);
    }

    /// Replay (same SignatureTime as last accepted) rejected per
    /// ndn-cxx `ValidationPolicyCommandInterest`'s strict-greater rule.
    #[test]
    fn n10_check_sig_time_rejects_replay() {
        let now = 10_000_000u64;
        let sig = now - 5_000;
        let _ = check_sig_time(Some(sig), now, None, COMMAND_SIG_TIME_TOLERANCE_MS).unwrap();
        let err = check_sig_time(Some(sig), now, Some(sig), COMMAND_SIG_TIME_TOLERANCE_MS)
            .expect_err("replay must reject");
        assert!(err.contains("replay") || err.contains("reorder"), "{err}");

        let stale_but_in_window = sig - 1;
        let err2 = check_sig_time(
            Some(stale_but_in_window),
            now,
            Some(sig),
            COMMAND_SIG_TIME_TOLERANCE_MS,
        )
        .expect_err("non-strictly-increasing must reject");
        assert!(
            err2.contains("replay") || err2.contains("reorder"),
            "{err2}"
        );
    }

    /// Strictly-greater SignatureTime within window accepted even when a
    /// prior observation exists for the same signer.
    #[test]
    fn n10_check_sig_time_accepts_strictly_greater() {
        let now = 10_000_000u64;
        let last = now - 5_000;
        let sig = last + 1;
        let accepted =
            check_sig_time(Some(sig), now, Some(last), COMMAND_SIG_TIME_TOLERANCE_MS).unwrap();
        assert_eq!(accepted, sig);
    }

    /// `is_extended_module` recognises the NFD-canonical set; everything
    /// else is an ndn-rs extension.
    #[test]
    fn e03_is_extended_module_classifies_correctly() {
        use ndn_config::nfd_command::module as m;
        for std_mod in [m::FACES, m::FIB, m::RIB, m::CS, m::STRATEGY, m::STATUS] {
            assert!(
                !is_extended_module(std_mod),
                "{} must NOT be extended",
                String::from_utf8_lossy(std_mod)
            );
        }
        for ext_mod in [
            m::SECURITY,
            m::ROUTING,
            m::DISCOVERY,
            m::NEIGHBORS,
            m::SERVICE,
            m::MEASUREMENTS,
            m::CONFIG,
            m::LOG,
        ] {
            assert!(
                is_extended_module(ext_mod),
                "{} MUST be extended",
                String::from_utf8_lossy(ext_mod)
            );
        }
    }

    /// Extended modules always require signed commands even when the
    /// operator left `require_signed_commands = false`.
    #[test]
    fn e03_effective_require_signed_forces_extended_modules() {
        use ndn_config::nfd_command::module as m;
        assert!(!effective_require_signed(m::RIB, false));
        assert!(effective_require_signed(m::RIB, true));
        assert!(effective_require_signed(m::SECURITY, false));
        assert!(effective_require_signed(m::ROUTING, false));
        assert!(effective_require_signed(m::CONFIG, false));
    }

    /// Unsigned `/localhost/nfd/security/...` Interest rejected even when
    /// the global `require_signed_commands` flag is `false`.
    #[tokio::test]
    async fn e03_unsigned_security_command_rejected_by_default() {
        use ndn_config::nfd_command::module as m;
        let cmd_name: Name = "/localhost/nfd/security/identity-generate".parse().unwrap();
        let interest = Interest::decode(encode_interest(&cmd_name, None)).unwrap();
        let global_flag = false;
        let effective = effective_require_signed(m::SECURITY, global_flag);
        assert!(effective, "extended module must escalate `require_signed`");
        assert!(
            authorize_command(&interest, None, effective, None)
                .await
                .is_err()
        );
    }
}
