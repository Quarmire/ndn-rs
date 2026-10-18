//! Renewing the device's certificates before they expire: on request
//! ([`renew_now`]) and on a timer ([`spawn_periodic`]).
//!
//! Every certificate a namespace CA issued to a device key the [`KeyVault`]
//! holds — a key `/<ns>/<role>/<device>/KEY/<id>` of a namespace whose trust
//! context the device holds — is renewed at its namespace's CA with
//! [`ndn_identity::renew_via_engine`]: the CA re-certifies the same key on
//! proof of the current certificate, with no invite ([`ndn_cert::renewal`]).
//! The renewal carries the certificate's issuer chain (walked from the
//! issuer certificates the vault kept first), so a later CA of the namespace
//! — after its root device was replaced through a recovery kit — renews a
//! certificate the earlier CA issued. The new certificate has a new name
//! (`<key>/NDNCERT/<version>`); the vault keeps it beside the old one (kept
//! until it expires) with its issuer chain, it is cached for validation and
//! served ([`crate::publish::OwnCertificates`]). The device keeps signing
//! with the same key and KeyLocator (the key name), which verifiers resolve
//! to the newest valid certificate, so nothing else changes.
//!
//! The timer follows [`RenewalSchedule`], the one renewal schedule: a
//! certificate is renewed once its remaining validity falls below a
//! [`RenewBefore`] threshold (a third of its lifetime by default). A
//! threshold at least the lifetime of the certificates the CA issues would
//! make each one due as it is issued: those are renewed once a third of
//! their lifetime is left, with a WARN, once. A key is not renewed again
//! before the certificate its last renewal issued is due. A failed attempt
//! is retried after a growing, jittered backoff (30–60 s, doubling up to
//! 30–60 min; 30–60 min after a refusal) and logged as a WARN with the days
//! the certificate has left; a vault that cannot be read is logged as a WARN
//! and retried likewise. A certificate that expired, a key the CA revoked
//! and a role it does not renew (guest, by default) cannot be renewed: the
//! device needs a new invite. An expired one is reported once, as an ERROR.

use std::sync::Arc;
use std::time::Duration;

use ndn_cert::report::{RenewalInfo, RenewalState, TrustRefusal};
use ndn_cert::roles::parse_device_key;
use ndn_identity::RenewBefore;
use ndn_identity::renewal::{Due, Failed, Now, RenewalSchedule};
use ndn_mgmt_wire::control_response::status;
use ndn_packet::{Data, Name};
use ndn_security::Certificate;
use tokio_util::sync::CancellationToken;

use crate::{KeyVault, Participant, iso, refusal};

/// The first scan runs this soon after start, once faces and routes are up.
const FIRST_CHECK_AFTER: Duration = Duration::from_secs(10);

impl Participant {
    /// Tell the renewal timer the device's certificates changed (a host
    /// kept one outside this crate), so it reads them again now.
    pub fn notify_certificates_changed(&self) {
        self.certificates_changed.notify_one();
    }
}

/// A certificate a namespace CA issued to one of the device's keys.
struct Held {
    key: Name,
    data: Data,
    cert: Certificate,
}

/// The certificates `vault` keeps for device keys `/<ns>/<role>/<device>`
/// of a namespace whose trust context `p` holds, issued by a CA
/// (`/<prefix>/CA/KEY/…`); none when the vault holds no key yet. Err: the
/// vault cannot be read (why, with where).
fn held_certificates(p: &Participant, vault: &dyn KeyVault) -> Result<Vec<Held>, String> {
    let namespaces: Vec<Name> = p
        .keyring()
        .contexts()
        .iter()
        .map(|c| c.namespace().clone())
        .collect();
    let mut held = Vec::new();
    for key in vault.keys()? {
        if !namespaces.iter().any(|ns| parse_device_key(ns, &key).is_some()) {
            continue;
        }
        let Some(wire) = vault.issued_certificate(&key)? else {
            continue;
        };
        let decoded = Data::decode(wire)
            .map_err(|e| e.to_string())
            .and_then(|data| Certificate::decode(&data).map(|cert| (data, cert)).map_err(|e| e.to_string()));
        let (data, cert) = match decoded {
            Ok(decoded) => decoded,
            Err(e) => {
                tracing::warn!(
                    target: "security",
                    key = %key,
                    keys = %vault.location(),
                    error = %e,
                    "the stored certificate of this key does not decode; it is not renewed"
                );
                continue;
            }
        };
        if ndn_cert::issuing_ca_prefix(&cert).is_some() {
            held.push(Held { key, data, cert });
        }
    }
    Ok(held)
}

/// Renew `held` and keep the new certificate: vault, validation cache,
/// served by name. The failure's state says whether retrying can help.
async fn renew_one(
    p: &Participant,
    vault: &dyn KeyVault,
    held: &Held,
) -> Result<Certificate, (RenewalState, String)> {
    let failed = |why: String| (RenewalState::Failed, why);
    if p.keyring().context_for(&held.cert.name).is_revoked(&held.cert.name) {
        return Err((
            RenewalState::Refused,
            format!(
                "the trust context of its namespace revokes {}; a revoked key is never renewed: \
                 enroll a new key with a new invite",
                held.key
            ),
        ));
    }
    let signer = vault
        .signer(&held.key)
        .map_err(|e| failed(format!("the key {} cannot sign: {e}", held.key)))?;
    // The issuer certificates the vault kept answer the walk of the current
    // certificate's chain first: after a recovery nobody else may serve the
    // earlier CA's certificate.
    let kept: Vec<Data> = vault
        .issuers()
        .into_iter()
        .filter_map(|wire| Data::decode(wire).ok())
        .collect();
    let issued = ndn_identity::renew_via_engine(p.engine(), p.keyring(), &held.data, &kept, signer)
        .await
        .map_err(|e| {
            let state = if e.is_final() {
                RenewalState::Refused
            } else {
                RenewalState::Failed
            };
            (state, e.to_string())
        })?;
    vault.store_certificate(&held.key, &issued.data).map_err(|e| {
        failed(format!(
            "the CA issued {}, but storing it in {} failed ({e}); the current certificate stays \
             in use until it expires",
            issued.cert.name,
            vault.location()
        ))
    })?;
    // The new certificate's issuer chain, kept and served as at enrollment.
    if let Err(e) = vault.keep_issuers(&issued.issuers) {
        tracing::warn!(
            target: "security",
            error = %e,
            "renewed, but the issuer certificates of its chain were not kept"
        );
    }
    if let Some(mgr) = p.engine().security() {
        mgr.cert_cache().insert(issued.cert.clone());
    }
    if let Some(own) = p.own_certs() {
        own.serve(issued.data.raw().clone());
        for issuer in &issued.issuers {
            own.serve(issuer.raw().clone());
        }
    }
    p.certificates_changed.notify_one();
    tracing::info!(
        target: "security",
        key = %held.key,
        previous = %held.cert.name,
        certificate = %issued.cert.name,
        valid_until = %iso(issued.cert.valid_until),
        "certificate renewed (same key); stored, served and signing with it"
    );
    Ok(issued.cert)
}

fn info(held: &Held, result: &Result<Certificate, (RenewalState, String)>) -> RenewalInfo {
    let mut info = RenewalInfo {
        key: held.key.to_string(),
        state: RenewalState::Renewed,
        previous: held.cert.name.to_string(),
        previous_valid_until: iso(held.cert.valid_until),
        certificate: None,
        valid_until: None,
        validity_secs: None,
        detail: String::new(),
    };
    match result {
        Ok(cert) => {
            info.certificate = Some(cert.name.to_string());
            info.valid_until = Some(iso(cert.valid_until));
            info.validity_secs =
                Some(cert.valid_until.saturating_sub(cert.valid_from) / 1_000_000_000);
        }
        Err((state, detail)) => {
            info.state = *state;
            info.detail = detail.clone();
        }
    }
    info
}

/// Renew every certificate a namespace CA issued to the device's keys now,
/// whatever their remaining validity.
pub async fn renew_now(
    p: &Participant,
    vault: &dyn KeyVault,
) -> Result<Vec<RenewalInfo>, TrustRefusal> {
    let _one_at_a_time = p.renewing.lock().await;
    let held = held_certificates(p, vault).map_err(|why| {
        refusal(
            status::SERVER_ERROR,
            format!("{why}: nothing was renewed. Make the PIB readable by this daemon, then renew again"),
        )
    })?;
    if held.is_empty() {
        return Err(refusal(
            status::NOT_FOUND,
            format!(
                "this node holds no certificate a namespace CA issued to it in {}: nothing to \
                 renew. Enroll first (`ndn-fwd enroll <invite>`)",
                vault.location()
            ),
        ));
    }
    let mut out = Vec::with_capacity(held.len());
    for h in &held {
        let result = renew_one(p, vault, h).await;
        if let Err((_, why)) = &result {
            tracing::warn!(target: "security", key = %h.key, error = %why, "certificate not renewed");
        }
        out.push(info(h, &result));
    }
    Ok(out)
}

/// Renew each held certificate on the [`RenewalSchedule`] for `before`,
/// until `cancel`. The first scan runs 10 s after start; a scan also runs
/// whenever the device's certificates change (an enrollment, a renewal,
/// [`Participant::notify_certificates_changed`]).
pub fn spawn_periodic(
    p: Arc<Participant>,
    vault: Arc<dyn KeyVault>,
    before: RenewBefore,
    cancel: CancellationToken,
) {
    tracing::info!(target: "security", renew_before = ?before, "renewing certificates before they expire");
    tokio::spawn(async move {
        let mut schedule = RenewalSchedule::new(before);
        let mut wait = FIRST_CHECK_AFTER;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
                _ = p.certificates_changed.notified() => {}
            }
            let held = match held_certificates(&p, vault.as_ref()) {
                Ok(held) => held,
                Err(why) => {
                    wait = schedule.unreadable();
                    tracing::warn!(
                        target: "security",
                        error = %why,
                        retry_in_secs = wait.as_secs(),
                        "no certificate is renewed while the PIB cannot be read; they expire unless \
                         it becomes readable"
                    );
                    continue;
                }
            };
            schedule.begin_scan(held.iter().map(|h| (&h.key, &*h.cert.name)));
            for h in &held {
                if schedule.first_short_lived(&h.key, &h.cert) {
                    tracing::warn!(
                        target: "security",
                        key = %h.key,
                        certificate = %h.cert.name,
                        validity_days = (h.cert.valid_until.saturating_sub(h.cert.valid_from)) / 86_400_000_000_000,
                        renew_before = ?before,
                        "[security] renew_before is at least the lifetime of the certificates this \
                         CA issues; renewing them once a third of their lifetime is left instead"
                    );
                }
                if schedule.check(&h.key, &h.cert, Now::current()) != Due::Now {
                    continue;
                }
                let result = {
                    let _one_at_a_time = p.renewing.lock().await;
                    renew_one(&p, vault.as_ref(), h).await
                };
                let (state, why) = match result {
                    Ok(issued) => {
                        schedule.renewed(&h.key, &h.cert, &issued);
                        continue;
                    }
                    Err(failure) => failure,
                };
                match schedule.failed(&h.cert, state == RenewalState::Refused, Now::current()) {
                    Failed::Expired => tracing::error!(
                        target: "security",
                        key = %h.key,
                        certificate = %h.cert.name,
                        expired_at = %iso(h.cert.valid_until),
                        "certificate expired and was not renewed in time: renewal needs a \
                         current certificate, so this device needs a new invite to enroll again"
                    ),
                    Failed::Retry {
                        attempts,
                        delay,
                        days_left,
                    } => tracing::warn!(
                        target: "security",
                        key = %h.key,
                        certificate = %h.cert.name,
                        days_left = %format!("{days_left:.1}"),
                        valid_until = %iso(h.cert.valid_until),
                        attempts,
                        retry_in_secs = delay.as_secs(),
                        error = %why,
                        "certificate renewal failed; the certificate works until it expires"
                    ),
                }
            }
            wait = schedule.wait();
        }
    });
}
