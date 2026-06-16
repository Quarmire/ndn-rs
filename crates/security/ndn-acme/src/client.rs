//! RFC 8555 ACME order driver (DNS-01).

use std::sync::Arc;
use std::time::Duration;

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::cert_source::{AcmeConfig, CertMaterial};
use crate::dns::{DnsProvider, DnsRecord};

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("acme: {0}")]
    Acme(#[from] instant_acme::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("dns provider: {0}")]
    Dns(String),
    #[error("no DNS provider configured but ACME source selected")]
    NoDnsProvider,
    #[error("no DNS-01 challenge offered by ACME server")]
    NoDns01,
    #[error("order failed: {0}")]
    OrderFailed(String),
    #[error("{0}")]
    Other(String),
}

pub struct AcmeClient {
    cfg: AcmeConfig,
    account: Account,
    provider: Arc<dyn DnsProvider>,
}

impl AcmeClient {
    pub async fn new(cfg: &AcmeConfig, provider: Arc<dyn DnsProvider>) -> Result<Self, AcmeError> {
        let (account, _credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", cfg.email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            &cfg.directory_url,
            None,
        )
        .await?;

        Ok(Self {
            cfg: cfg.clone(),
            account,
            provider,
        })
    }

    /// Drives a full RFC 8555 order: authorize → challenge → finalize → poll.
    pub async fn issue(&self) -> Result<CertMaterial, AcmeError> {
        let identifier = Identifier::Dns(self.cfg.domain.clone());
        let mut order = self
            .account
            .new_order(&NewOrder {
                identifiers: &[identifier],
            })
            .await?;

        let authorizations = order.authorizations().await?;
        let mut placed_records: Vec<DnsRecord> = Vec::new();

        for authz in &authorizations {
            if !matches!(authz.status, AuthorizationStatus::Pending) {
                continue;
            }
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Dns01)
                .ok_or(AcmeError::NoDns01)?;

            let record_name = match &authz.identifier {
                Identifier::Dns(d) => format!("_acme-challenge.{d}"),
            };
            let key_auth = order.key_authorization(challenge);
            let record = DnsRecord {
                name: record_name,
                value: key_auth.dns_value(),
                ttl: 60,
            };
            self.provider
                .upsert_txt(&self.cfg.params, &record)
                .await
                .map_err(AcmeError::Dns)?;
            placed_records.push(record);

            order.set_challenge_ready(&challenge.url).await?;
        }

        // RFC 8555 §7.5.1 capped backoff while the server polls DNS.
        let mut backoff = Duration::from_secs(2);
        for _ in 0..30 {
            let state = order.refresh().await?;
            match state.status {
                OrderStatus::Pending | OrderStatus::Processing => {
                    debug!(target: "ndn_acme", status = ?state.status, "order pending");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
                OrderStatus::Ready => break,
                OrderStatus::Valid => break,
                OrderStatus::Invalid => {
                    return Err(AcmeError::OrderFailed(format!(
                        "order invalid: {:?}",
                        state.error
                    )));
                }
            }
        }

        let mut params = rcgen::CertificateParams::new(vec![self.cfg.domain.clone()])?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let key_pair = rcgen::KeyPair::generate()?;
        let csr = params.serialize_request(&key_pair)?;
        order.finalize(csr.der()).await?;

        let cert_chain_pem = loop {
            if let Some(pem) = order.certificate().await? {
                break pem.into_bytes();
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        };

        for r in placed_records {
            if let Err(e) = self.provider.delete_txt(&self.cfg.params, &r).await {
                warn!(target: "ndn_acme", %e, "failed to clean up DNS record");
            }
        }

        info!(target: "ndn_acme", domain = %self.cfg.domain, "ACME order succeeded");
        Ok(CertMaterial {
            cert_chain_pem,
            private_key_pem: key_pair.serialize_pem().into_bytes(),
        })
    }
}
