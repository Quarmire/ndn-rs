//! The running device of a root operation reached over its management
//! socket ([`ndn_ipc::MgmtClient`]): [`MgmtDevice`], the one
//! [`RunningDevice`] every host that runs root operations next to a daemon
//! uses (the `ndn-fwd` CLI, an admin screen).
//!
//! Its refusals are coded ([`code`]) with the facts as params (`address`,
//! `error`, `status_code`, `reason`); a refusal the daemon answered keeps
//! the daemon's code and params, its sentence worded by the host
//! ([`MgmtDevice::worded_by`]) so the error chains a host shows read in its
//! words.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ndn_cert::report::{AdoptedContextInfo, ContextRefreshInfo, RefusalCode, TrustRefusal, code};
use ndn_ipc::{ForwarderError, MgmtClient};
use ndn_mgmt_wire::ControlResponse;
use ndn_mgmt_wire::control_response::status;
use ndn_packet::{Data, Name};
use ndn_trust_envelope::TrustEnvelope;

use super::RootError;
use super::device::{DeviceSession, Reach, RunningDevice};
use crate::admin::SinkError;

/// How long one request waits for the daemon to take a version handed
/// over (local work: verify, store, publish — after any other change of
/// the namespace running there). Without an answer the same version is
/// handed over again ([`crate::admin::hand_over`]).
pub const UPDATE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a request waits for the daemon to fetch the newest version of
/// a namespace, or to adopt one.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(60);

/// The host's sentence for a refusal the daemon answered.
type Words = Arc<dyn Fn(&TrustRefusal) -> String + Send + Sync>;

/// The daemon at a management socket, as the running device that takes the
/// versions a root operation signs.
pub struct MgmtDevice {
    socket: String,
    peer: String,
    words: Words,
    no_answer: Option<Box<dyn Fn(u64) + Send + Sync>>,
}

impl MgmtDevice {
    /// The daemon listening at `socket`. A refusal it answers keeps its own
    /// sentence unless [`worded_by`](Self::worded_by) words it.
    pub fn new(socket: impl Into<String>) -> Self {
        Self {
            socket: socket.into(),
            peer: "the running device".to_owned(),
            words: Arc::new(|refusal| refusal.reason.clone()),
            no_answer: None,
        }
    }

    /// What the host calls it at the start of a sentence (followed by "at"
    /// and the socket), e.g. "the daemon".
    pub fn named(mut self, peer: impl Into<String>) -> Self {
        self.peer = peer.into();
        self
    }

    /// Word each refusal the daemon answers with `words` (its sentence in
    /// the host's terms).
    pub fn worded_by(
        mut self,
        words: impl Fn(&TrustRefusal) -> String + Send + Sync + 'static,
    ) -> Self {
        self.words = Arc::new(words);
        self
    }

    /// Call `tell` before a version that got no answer in time is handed
    /// over again (to tell a person waiting).
    pub fn on_no_answer(mut self, tell: impl Fn(u64) + Send + Sync + 'static) -> Self {
        self.no_answer = Some(Box::new(tell));
        self
    }

    /// The management socket.
    pub fn socket(&self) -> &str {
        &self.socket
    }
}

#[async_trait::async_trait]
impl RunningDevice for MgmtDevice {
    fn address(&self) -> String {
        self.socket.clone()
    }

    fn peer(&self) -> String {
        format!("{} at {}", self.peer, self.socket)
    }

    async fn reach(&self) -> Result<Reach, RootError> {
        match MgmtClient::connect(&self.socket).await {
            Ok(client) => Ok(Reach::Running(Box::new(Session {
                client,
                socket: self.socket.clone(),
                words: self.words.clone(),
            }))),
            Err(ForwarderError::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                Ok(Reach::NotRunning {
                    error: e.to_string(),
                })
            }
            Err(e) => Err(RootError::new(
                code::DEVICE_UNREACHABLE,
                "the running device cannot be used",
            )
            .with("address", &self.socket)
            .with("error", &e)
            .caused_by(e)),
        }
    }

    fn no_answer_yet(&self, version: u64) {
        if let Some(tell) = &self.no_answer {
            tell(version);
        }
    }
}

/// One connection to the daemon.
struct Session {
    client: MgmtClient,
    socket: String,
    words: Words,
}

impl Session {
    /// The refusal the daemon answered in `resp` (worded by the host), else
    /// its status as an untyped refusal of `kind`.
    fn refused(&self, resp: &ControlResponse, kind: RefusalCode) -> TrustRefusal {
        let mut refusal = ndn_ipc::trust_refusal(resp).unwrap_or_else(|| {
            let mut refusal = TrustRefusal::new(kind, resp.status_text.clone());
            refusal.status_code = resp.status_code;
            refusal
        });
        refusal.reason = (self.words)(&refusal);
        refusal
    }

    /// `e`, an error of the exchange, as text: a refusal the daemon
    /// answered in the host's words.
    fn error_text(&self, e: &ForwarderError) -> String {
        match ndn_ipc::trust_refusal_in(e) {
            Some(refusal) => (self.words)(&refusal),
            None => e.to_string(),
        }
    }

    /// A failed exchange (`device-failed`), `error` saying how.
    fn failed(&self, error: impl std::fmt::Display) -> RootError {
        RootError::new(
            code::DEVICE_FAILED,
            "an exchange with the running device failed",
        )
        .with("address", &self.socket)
        .with("error", error)
    }
}

#[async_trait::async_trait]
impl DeviceSession for Session {
    async fn pib(&self) -> Result<PathBuf, RootError> {
        match self.client.security_identity_status().await {
            Ok(status) => Ok(PathBuf::from(status.pib_path)),
            Err(e) => Err(RootError::new(
                code::DEVICE_PIB_UNKNOWN,
                "the running device did not say which PIB it uses",
            )
            .with("address", &self.socket)
            .with("error", self.error_text(&e))
            .caused_by(e)),
        }
    }

    async fn take(&self, data: &Data) -> Result<ContextRefreshInfo, SinkError<RootError>> {
        match self
            .client
            .security_context_update(data.raw().clone(), UPDATE_TIMEOUT)
            .await
        {
            Ok(resp) if resp.is_ok() => {
                serde_json::from_str(&resp.status_text).map_err(|e| SinkError::Unreadable {
                    error: e.to_string(),
                    answer: resp.status_text.clone(),
                })
            }
            Ok(resp) => Err(SinkError::Refused(
                self.refused(&resp, code::HAND_OVER_REFUSED),
            )),
            Err(ForwarderError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                Err(SinkError::NoAnswer)
            }
            Err(e) => Err(SinkError::Failed(
                self.failed(self.error_text(&e)).caused_by(e),
            )),
        }
    }

    async fn refresh(&self, namespace: &Name) -> Result<Option<ContextRefreshInfo>, RootError> {
        let resp = self
            .client
            .security_context_refresh(Some(namespace), FETCH_TIMEOUT)
            .await
            .map_err(|e| self.failed(self.error_text(&e)).caused_by(e))?;
        if resp.is_ok() {
            let results: Vec<ContextRefreshInfo> = serde_json::from_str(&resp.status_text)
                .map_err(|e| {
                    self.failed(format!("unreadable answer ({e}): {}", resp.status_text))
                })?;
            return match results.into_iter().next() {
                Some(result) => Ok(Some(result)),
                None => Err(self.failed("it answered no refresh result")),
            };
        }
        if resp.status_code == status::NOT_FOUND {
            return Ok(None);
        }
        let refusal = self.refused(&resp, code::DEVICE_FAILED);
        Err(self
            .failed(format!(
                "it could not refresh {namespace} ({}): {}",
                resp.status_code, refusal.reason
            ))
            .with("status_code", resp.status_code)
            .with("reason", &refusal.reason))
    }

    async fn adopt(&self, namespace: &Name, fingerprint: &[u8; 32]) -> Result<u64, RootError> {
        let link = TrustEnvelope::Anchor {
            namespace: Some(namespace.to_string()),
            fingerprint: Some(*fingerprint),
            version: None,
            context_data: None,
            context_content: None,
        }
        .to_uri();
        let resp = self
            .client
            .security_context_adopt(&link, FETCH_TIMEOUT)
            .await
            .map_err(|e| self.failed(self.error_text(&e)).caused_by(e))?;
        if !resp.is_ok() {
            let refusal = self.refused(&resp, code::NEWEST_NOT_ADOPTED);
            return Err(RootError::new(
                code::NEWEST_NOT_ADOPTED,
                "adopting the namespace with the kit's expected fingerprint failed",
            )
            .with("namespace", namespace)
            .with("status_code", resp.status_code)
            .with("reason", &refusal.reason));
        }
        let info: AdoptedContextInfo = serde_json::from_str(&resp.status_text)
            .map_err(|e| self.failed(format!("unreadable answer ({e}): {}", resp.status_text)))?;
        Ok(info.version)
    }
}
