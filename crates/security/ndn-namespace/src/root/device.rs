//! The running device that uses the PIB a root operation works on, and
//! handing it the versions signed here.
//!
//! The host reaches it ([`RunningDevice`]: `ndn-fwd` over the daemon's
//! management socket); the rules are here: the device must use the same PIB
//! ([`ensure_same_pib`]) — a version made from the context stored there,
//! handed to a device of another PIB holding the same namespace, would be
//! adopted there while this PIB stays behind, and the next version made here
//! would be a second, different one with the same number; with no device
//! running the version is kept for its next start; the retry and undo rules
//! of [`crate::admin::hand_over`].

use std::path::{Path, PathBuf};

use ndn_cert::ContextBump;
use ndn_cert::report::{ContextRefreshInfo, code};
use ndn_packet::{Data, Name};

use super::RootError;
use crate::admin::{ContextUpdateSink, HandedOver, NewestSource, NotTaken, SinkError};
use crate::host::PibContextStore;

/// What reaching the running device found.
pub enum Reach {
    /// A device runs: one exchange session with it.
    Running(Box<dyn DeviceSession>),
    /// No device runs there (nothing listens); `error` says what the
    /// attempt found.
    NotRunning { error: String },
}

/// The running device (a daemon) that takes the versions a root operation
/// signs, as the host reaches it.
#[async_trait::async_trait]
pub trait RunningDevice: Send + Sync {
    /// Where it is reached (`ndn-fwd`: the management socket's path): a fact
    /// for refusals (`address` params).
    fn address(&self) -> String;

    /// The host's name for it, starting a sentence: what the neutral
    /// sentences of [`crate::admin::HandOverError`] call it.
    fn peer(&self) -> String {
        format!("the running device at {}", self.address())
    }

    /// Reach it afresh (a session that timed out is not reused). A refusal
    /// (`device-unreachable`: it runs but cannot be used) means nothing was
    /// handed over.
    async fn reach(&self) -> Result<Reach, RootError>;

    /// Called before `version` is handed over again after it got no answer
    /// in time (to tell a person waiting).
    fn no_answer_yet(&self, _version: u64) {}
}

/// One session with the running device.
#[async_trait::async_trait]
pub trait DeviceSession: Send + Sync {
    /// The PIB directory the device uses.
    async fn pib(&self) -> Result<PathBuf, RootError>;

    /// Hand it `data`, a signed version, once (`security/context-update`).
    async fn take(&self, data: &Data) -> Result<ContextRefreshInfo, SinkError<RootError>>;

    /// Refresh its held version of `namespace` by name; `None` when it holds
    /// none (`security/context-refresh`).
    async fn refresh(&self, namespace: &Name) -> Result<Option<ContextRefreshInfo>, RootError>;

    /// Adopt `namespace` from its anchor link with the expected
    /// `fingerprint`; the version adopted (`security/context-adopt`).
    async fn adopt(&self, namespace: &Name, fingerprint: &[u8; 32]) -> Result<u64, RootError>;
}

/// Refuse (`device-other-pib`) unless the device of `session`, at
/// `address`, uses the PIB at `pib_dir`.
pub async fn ensure_same_pib(
    session: &dyn DeviceSession,
    address: &str,
    pib_dir: &Path,
) -> Result<(), RootError> {
    let theirs = session.pib().await?;
    let canonical = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    if canonical(&theirs) != canonical(pib_dir) {
        return Err(RootError::new(
            code::DEVICE_OTHER_PIB,
            "the running device uses another PIB: what is made from this one must go to the \
             device that uses it",
        )
        .with("address", address)
        .with("device_pib", theirs.display())
        .with("pib", pib_dir.display()));
    }
    Ok(())
}

/// [`RunningDevice::reach`], a refusal naming `pib_dir` (`pib` param): the
/// PIB whose device was to be reached.
async fn reach_for(device: &dyn RunningDevice, pib_dir: &Path) -> Result<Reach, RootError> {
    device
        .reach()
        .await
        .map_err(|e| e.with("pib", pib_dir.display()))
}

/// Before the root is unlocked: refuse when the running device uses another
/// PIB (it must not take a version made from this one) or cannot be used.
/// No device running is no refusal: the version is kept for its next start.
pub async fn check_device(device: &dyn RunningDevice, pib_dir: &Path) -> Result<(), RootError> {
    match reach_for(device, pib_dir).await? {
        Reach::Running(session) => ensure_same_pib(&*session, &device.address(), pib_dir).await,
        Reach::NotRunning { .. } => Ok(()),
    }
}

/// A session with the running device that uses `pib_dir`, for an operation
/// that needs it running (`device-not-running` otherwise).
pub async fn session_on(
    device: &dyn RunningDevice,
    pib_dir: &Path,
) -> Result<Box<dyn DeviceSession>, RootError> {
    match reach_for(device, pib_dir).await? {
        Reach::Running(session) => {
            ensure_same_pib(&*session, &device.address(), pib_dir).await?;
            Ok(session)
        }
        Reach::NotRunning { error } => Err(RootError::new(
            code::DEVICE_NOT_RUNNING,
            "no device runs to do it: start it and retry",
        )
        .with("address", device.address())
        .with("error", error)),
    }
}

/// The running device that uses `pib_dir`, as the sink of
/// [`crate::admin::hand_over`]: each exchange reaches it afresh and checks
/// the PIB first.
struct SamePib<'a> {
    device: &'a dyn RunningDevice,
    pib_dir: &'a Path,
}

#[async_trait::async_trait]
impl ContextUpdateSink for SamePib<'_> {
    type Error = RootError;

    fn peer(&self) -> String {
        self.device.peer()
    }

    async fn hand_over(&self, data: &Data) -> Result<ContextRefreshInfo, SinkError<RootError>> {
        let session = match reach_for(self.device, self.pib_dir).await {
            Ok(Reach::Running(session)) => session,
            Ok(Reach::NotRunning { .. }) => return Err(SinkError::NotRunning),
            Err(e) => return Err(SinkError::NotReached(e)),
        };
        ensure_same_pib(&*session, &self.device.address(), self.pib_dir)
            .await
            .map_err(SinkError::NotReached)?;
        session.take(data).await
    }

    fn no_answer_yet(&self, version: u64) {
        self.device.no_answer_yet(version);
    }
}

/// Hand `bump`, signed here, to the running device that uses `pib_dir`,
/// which adopts it by the continuity rule, stores and publishes it; with no
/// device running, keep it in `pib_dir` for its next start
/// ([`crate::admin::hand_over`]: the same version again while unanswered,
/// undo only on a refusal).
pub async fn hand_over(
    device: &dyn RunningDevice,
    pib_dir: &Path,
    bump: &ContextBump,
) -> Result<HandedOver, NotTaken<RootError>> {
    let sink = SamePib { device, pib_dir };
    crate::admin::hand_over(&sink, &PibContextStore::new(pib_dir), bump).await
}

/// A hand-over's outcome for an operation that signed `version` after
/// `held_version`: refused → `version-not-taken`, unknown →
/// `hand-over-unknown`, both wrapping why; `params` are the operation's,
/// for the person to retry with.
pub(crate) fn settle(
    handed: Result<HandedOver, NotTaken<RootError>>,
    version: u64,
    held_version: u64,
    params: &[(&str, String)],
) -> Result<HandedOver, RootError> {
    handed.map_err(|not| not_taken(not, version, held_version, params))
}

/// A version not taken, as [`settle`] words it.
pub(crate) fn not_taken(
    not: NotTaken<RootError>,
    version: u64,
    held_version: u64,
    params: &[(&str, String)],
) -> RootError {
    let refused = match not {
        NotTaken::Refused(e) => RootError::wrapping(
            code::VERSION_NOT_TAKEN,
            "the running device did not take the new version: nothing changed",
            e,
        ),
        NotTaken::Unknown(e) => RootError::wrapping(
            code::HAND_OVER_UNKNOWN,
            "whether the running device took the new version is not known; once it is idle, \
             asking again settles it",
            e,
        ),
    };
    let mut refused = refused
        .with("version", version)
        .with("held_version", held_version);
    for (key, value) in params {
        refused = refused.with(key, value);
    }
    refused
}

/// A session as the [`NewestSource`] of [`crate::admin::fetch_newest`].
pub(crate) struct Newest<'a>(pub &'a dyn DeviceSession);

#[async_trait::async_trait]
impl NewestSource for Newest<'_> {
    type Error = RootError;

    async fn refresh(&self, namespace: &Name) -> Result<Option<ContextRefreshInfo>, RootError> {
        self.0.refresh(namespace).await
    }

    async fn adopt(&self, namespace: &Name, fingerprint: &[u8; 32]) -> Result<u64, RootError> {
        self.0.adopt(namespace, fingerprint).await
    }
}
