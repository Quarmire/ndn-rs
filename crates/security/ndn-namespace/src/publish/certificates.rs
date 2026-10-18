//! Serving the device's own certificates.
//!
//! A validator that meets Data this device signed follows its KeyLocator
//! (the key name, `/<id>/KEY/<key-id>`) and fetches the newest valid
//! certificate under it with CanBePrefix. The namespace CA serves every
//! certificate it issued, but only where routing reaches the CA; by NDN
//! convention a producer also makes its own certificate retrievable, so a
//! relay that routes a device's prefix toward the device resolves the chain
//! there as well. [`OwnCertificates`] serves, on one in-process face with a
//! FIB entry per key name:
//!
//! - the certificates the host keeps (a forwarder's PIB: every valid
//!   certificate of each key, a root device's CA and device certificates,
//!   the issuer certificates kept at enrollment and renewal — after the root
//!   device that ran the CA was replaced, nobody else may serve the earlier
//!   CA's certificate), and one an enrollment or a renewal adds while the
//!   device runs (a renewed certificate has its own name, so the old one
//!   stays retrievable by name while the key name resolves to the new one);
//! - every valid certificate the engine's key store caches for the key the
//!   device signs with, kept or not: an ephemeral identity serves its
//!   self-signed certificate, so a verifier resolves its KeyLocator here.
//!
//! Which certificate answers is [`ndn_security::CertSet`]'s rule. A
//! certificate that a held trust context revokes (its key, or the
//! certificate itself) is not served, and is withdrawn once a context
//! version revoking it is adopted.

use std::sync::{Arc, PoisonError, RwLock};

use bytes::Bytes;
use ndn_app::Producer;
use ndn_engine::ForwarderEngine;
use ndn_face::local::InProcFace;
use ndn_packet::{Data, Interest, NackReason, Name};
use ndn_security::cert_name::key_name_of;
use ndn_security::{CertSet, Certificate, Keyring, SecurityManager};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

/// The certificates this device serves, by certificate name.
pub struct OwnCertificates {
    engine: ForwarderEngine,
    face_id: FaceId,
    certs: RwLock<CertSet>,
}

impl OwnCertificates {
    /// Serve `stored` (the certificate Data the host keeps) and the
    /// certificates the engine's key store caches for `signing_key` (the
    /// key the device signs with) that `keyring` does not revoke, now and as
    /// long as `cancel` runs, and withdraw each one a context adopted later
    /// revokes.
    pub fn spawn(
        engine: &ForwarderEngine,
        stored: Vec<Bytes>,
        signing_key: Option<&Name>,
        keyring: &Keyring,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        let face_id = engine.faces().alloc_id();
        let (face, handle) = InProcFace::new(face_id, 64);
        engine.add_face(face, cancel);
        let own = Arc::new(Self {
            engine: engine.clone(),
            face_id,
            certs: RwLock::new(CertSet::new()),
        });
        let running = signing_key
            .zip(engine.security())
            .map(|(key, mgr)| running_certificates(&mgr, key))
            .unwrap_or_default();
        for wire in stored.into_iter().chain(running) {
            match Data::decode(wire.clone()) {
                Ok(cert) if keyring.context_for(&cert.name).is_revoked(&cert.name) => {
                    tracing::info!(
                        target: "security",
                        certificate = %cert.name,
                        "not serving a certificate the held trust context revokes"
                    );
                }
                Ok(_) => own.serve(wire),
                Err(e) => tracing::warn!(
                    target: "security",
                    error = %e,
                    "not serving an undecodable stored certificate"
                ),
            }
        }
        let weak = Arc::downgrade(&own);
        keyring.on_revocation(move |ctx, _| {
            if let Some(own) = weak.upgrade() {
                own.withdraw_where(|name| ctx.is_revoked(name));
            }
        });
        let served = Arc::downgrade(&own);
        let producer = Producer::from_handle(handle, Name::root());
        tokio::spawn(async move {
            let result = producer
                .serve(|interest, responder| {
                    let reply = served.upgrade().and_then(|own| own.answer(&interest));
                    async move {
                        let _ = match reply {
                            Some(wire) => responder.respond_bytes(wire).await,
                            None => responder.nack(NackReason::NoRoute).await,
                        };
                    }
                })
                .await;
            if let Err(e) = result {
                tracing::error!(target: "security", error = %e, "certificate server exited");
            }
        });
        own
    }

    /// Serve the certificate Data `wire` from now on, beside the other
    /// certificates of its key. A certificate already served under its name
    /// (several sources can hold the same one) is served once: no second
    /// entry, FIB route or log line.
    pub fn serve(&self, wire: Bytes) {
        let cert = match Data::decode(wire.clone())
            .map_err(|e| e.to_string())
            .and_then(|data| Certificate::decode(&data).map_err(|e| e.to_string()))
        {
            Ok(cert) => cert,
            Err(e) => {
                tracing::warn!(target: "security", error = %e, "not serving an undecodable certificate");
                return;
            }
        };
        let name = (*cert.name).clone();
        let key = key_name_of(&name);
        {
            // The route is added under the lock `withdraw_where` removes it
            // under, so the two never interleave.
            let mut certs = self.certs.write().unwrap_or_else(PoisonError::into_inner);
            let routed = certs.holds_key(&key);
            if !certs.insert(cert, wire) {
                return;
            }
            if !routed {
                self.engine.fib().add_nexthop(&key, self.face_id, 0);
            }
        }
        tracing::info!(target: "security", certificate = %name, "serving this node's certificate");
    }

    fn withdraw_where(&self, revoked: impl Fn(&Name) -> bool) {
        let mut certs = self.certs.write().unwrap_or_else(PoisonError::into_inner);
        let withdrawn = certs.remove_where(revoked);
        for name in &withdrawn {
            tracing::info!(
                target: "security",
                certificate = %name,
                "revoked: no longer serving this node's certificate"
            );
        }
        for key in withdrawn.iter().map(key_name_of) {
            if !certs.holds_key(&key) {
                self.engine.fib().remove_nexthop(&key, self.face_id);
            }
        }
    }

    /// The certificate `interest` asks for ([`CertSet::answer`]).
    fn answer(&self, interest: &Interest) -> Option<Bytes> {
        let certs = self.certs.read().unwrap_or_else(PoisonError::into_inner);
        certs.answer(interest.name.as_ref(), interest.selectors().can_be_prefix)
    }

    /// The newest certificate valid now this device serves under `name` (a
    /// key name or a certificate name).
    pub fn certificate(&self, name: &Name) -> Option<Certificate> {
        let certs = self.certs.read().unwrap_or_else(PoisonError::into_inner);
        certs.newest_valid(name).cloned()
    }

    /// This device's certificate of `key` and the issuer certificates it
    /// serves after it, nearest first ([`CertSet::chain_of`]): what a link
    /// hello carries, so the other device can validate it without fetching
    /// anything. Empty when it serves no valid certificate of `key`.
    pub fn chain_of(&self, key: &Name) -> Vec<Bytes> {
        let certs = self.certs.read().unwrap_or_else(PoisonError::into_inner);
        certs.chain_of(key)
    }
}

/// The certificate Data the engine's key store caches for `key`: every
/// valid one (an ephemeral identity's self-signed certificate, or one
/// issued for a kept key).
fn running_certificates(mgr: &SecurityManager, key: &Name) -> Vec<Bytes> {
    mgr.cert_cache()
        .all(key)
        .iter()
        .filter(|cert| cert.is_valid_now())
        .filter_map(Certificate::data_wire)
        .collect()
}
