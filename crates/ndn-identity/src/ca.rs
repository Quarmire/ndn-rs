//! [`NdncertCa`] — a full NDNCERT CA that serves requests over the NDN network.
//!
//! Uses `ndn-app::Producer` to register under `/<prefix>/CA/*` and dispatches
//! to [`CaState`](ndn_cert::CaState) for protocol logic.

use std::sync::Arc;
use std::time::Duration;

use ndn_cert::{CaConfig, CaState, ChallengeHandler, HierarchicalPolicy, NamespacePolicy};
use ndn_packet::Name;
use ndn_security::SecurityManager;
use tracing::{debug, warn};

use crate::{error::IdentityError, identity::NdnIdentity};

/// Builder for [`NdncertCa`].
pub struct NdncertCaBuilder {
    prefix: Option<Name>,
    info: String,
    identity: Option<Arc<SecurityManager>>,
    challenges: Vec<Box<dyn ChallengeHandler>>,
    policy: Box<dyn NamespacePolicy>,
    default_validity: Duration,
    max_validity: Duration,
}

impl NdncertCaBuilder {
    fn new() -> Self {
        Self {
            prefix: None,
            info: "NDN Certificate Authority".to_string(),
            identity: None,
            challenges: Vec::new(),
            policy: Box::new(HierarchicalPolicy),
            default_validity: Duration::from_secs(86400),    // 24h
            max_validity: Duration::from_secs(365 * 86400),  // 1 year
        }
    }

    pub fn name(mut self, prefix: impl AsRef<str>) -> Result<Self, IdentityError> {
        let name: Name = prefix
            .as_ref()
            .parse()
            .map_err(|_| IdentityError::Name(prefix.as_ref().to_string()))?;
        self.prefix = Some(name);
        Ok(self)
    }

    pub fn info(mut self, info: impl Into<String>) -> Self {
        self.info = info.into();
        self
    }

    pub fn signing_identity(mut self, identity: &NdnIdentity) -> Self {
        self.identity = Some(identity.manager_arc());
        self
    }

    pub fn challenge(mut self, handler: impl ChallengeHandler + 'static) -> Self {
        self.challenges.push(Box::new(handler));
        self
    }

    pub fn policy(mut self, policy: impl NamespacePolicy + 'static) -> Self {
        self.policy = Box::new(policy);
        self
    }

    pub fn cert_lifetime(mut self, d: Duration) -> Self {
        self.default_validity = d;
        self
    }

    pub fn max_cert_lifetime(mut self, d: Duration) -> Self {
        self.max_validity = d;
        self
    }

    pub fn build(self) -> Result<NdncertCa, IdentityError> {
        let prefix = self
            .prefix
            .ok_or_else(|| IdentityError::Name("CA prefix not set".to_string()))?;
        let manager = self.identity.ok_or(IdentityError::NotEnrolled)?;

        if self.challenges.is_empty() {
            return Err(IdentityError::Enrollment(
                "at least one challenge handler is required".to_string(),
            ));
        }

        let config = CaConfig {
            prefix: prefix.clone(),
            info: self.info,
            default_validity: self.default_validity,
            max_validity: self.max_validity,
            challenges: self.challenges,
            policy: self.policy,
        };

        Ok(NdncertCa {
            state: Arc::new(CaState::new(config, manager)),
            prefix,
        })
    }
}

/// A running NDNCERT certificate authority.
///
/// Serves `/<prefix>/CA/INFO`, `/<prefix>/CA/NEW`, and
/// `/<prefix>/CA/CHALLENGE/<id>` Interests.
pub struct NdncertCa {
    state: Arc<CaState>,
    prefix: Name,
}

impl NdncertCa {
    pub fn builder() -> NdncertCaBuilder {
        NdncertCaBuilder::new()
    }

    /// The CA's NDN prefix.
    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    /// Serve NDNCERT requests using the provided Producer.
    ///
    /// This method runs indefinitely (until the Producer is dropped or errors).
    pub async fn serve(self, mut producer: ndn_app::Producer) -> Result<(), IdentityError> {
        let state = self.state.clone();
        let ca_prefix = self.prefix.clone();

        producer
            .serve(move |interest| {
                let state = state.clone();
                let ca_prefix = ca_prefix.clone();
                async move { handle_interest(&state, &ca_prefix, interest).await }
            })
            .await?;

        Ok(())
    }
}

async fn handle_interest(
    state: &CaState,
    ca_prefix: &Name,
    interest: ndn_packet::Interest,
) -> Option<bytes::Bytes> {
    let name = &*interest.name;
    let name_str = name.to_string();
    let ca_prefix_str = ca_prefix.to_string();

    debug!(name = %name_str, "NDNCERT: received Interest");

    let suffix = name_str
        .strip_prefix(&ca_prefix_str)
        .unwrap_or(&name_str);

    if suffix == "/CA/INFO" || suffix.ends_with("/CA/INFO") {
        let body = state.handle_info();
        return Some(bytes::Bytes::from(body));
    }

    if suffix.contains("/CA/NEW") {
        let body = interest
            .app_parameters()
            .cloned()
            .unwrap_or_default();
        match state.handle_new(&body).await {
            Ok(resp) => return Some(bytes::Bytes::from(resp)),
            Err(e) => {
                warn!(error = %e, "NDNCERT NEW failed");
                return None;
            }
        }
    }

    if suffix.contains("/CA/CHALLENGE/") {
        // Extract request ID from the last name component.
        let request_id = name
            .components()
            .last()
            .and_then(|c| std::str::from_utf8(&c.value).ok())
            .map(|s| s.to_string())?;

        let body = interest
            .app_parameters()
            .cloned()
            .unwrap_or_default();
        match state.handle_challenge(&request_id, &body).await {
            Ok(resp) => return Some(bytes::Bytes::from(resp)),
            Err(e) => {
                warn!(error = %e, "NDNCERT CHALLENGE failed");
                return None;
            }
        }
    }

    warn!(name = %name_str, "NDNCERT: unrecognised Interest");
    None
}
