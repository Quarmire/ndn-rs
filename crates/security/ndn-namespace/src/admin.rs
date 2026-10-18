//! The root device's side: handing a version made outside the running
//! device to it, and the anti-fork check before a recovery.
//!
//! New versions of a namespace's trust context are signed where the root
//! (or a recovery kit) is unlocked — an operator's command, an app's admin
//! screen — never inside the running device, which only ever holds public
//! keys. The running device then adopts the version by the continuity rule,
//! stores and publishes it.
//!
//! # Hand-over ([`hand_over`])
//!
//! The outcome comes from the device's answer, never from a timeout. A
//! hand-over that gets no answer in time (the device may be busy with
//! another change of the namespace) is made again with **the same
//! version**, which the device answers once that version is decided: taken
//! (also when it took it already) or refused. [`HAND_OVER_FAILURES`]
//! transport failures in a row end it as [`NotTaken::Unknown`]. Only
//! [`NotTaken::Refused`] — nothing was handed over, or the device answered
//! that it did not take it — lets the caller undo what it made for the
//! version (a kit file, the keys of a recovered root); after
//! [`NotTaken::Unknown`] the device may still adopt it. With no running
//! device the version is kept in the [`ContextStore`] for its next start
//! ([`keep_for_next_start`]) — unless it is stored there already, byte for
//! byte (a device took it before it stopped).
//!
//! # Before a recovery ([`fetch_newest`])
//!
//! Recovering from an older version than the namespace serves would fork
//! it, so the running device first refreshes the held version by name
//! ([`newest_of`]: updated, current or upstream-older proceed; behind,
//! failed and "this is the root device" refuse; nothing answering refuses
//! unless the operator vouches that the held version is the newest). A
//! device holding no version adopts one only with the namespace's expected
//! fingerprint (a file kit carries it): a context fetched with nothing to
//! check it against could be a forgery listing the kit's public anchor.
//!
//! # What the host provides
//!
//! - a [`ContextUpdateSink`]: one exchange with the running device that
//!   takes a version (`ndn-fwd`: the `security/context-update` management
//!   verb over the daemon's socket, after checking the daemon uses the same
//!   PIB), sorted into a [`SinkError`] when it does not answer "taken";
//! - a [`NewestSource`]: the running device's refresh of a held namespace
//!   and its adoption from an anchor link (`security/context-refresh`,
//!   `security/context-adopt`);
//! - the [`ContextStore`] the running device loads at its start.
//!
//! Errors are the host's own type (`S::Error`), built from this module's
//! [`HandOverError`] / [`NewestRefusal`] where the rule itself refuses, so a
//! host keeps the error chains of its transport.

use std::fmt;

use ndn_cert::ContextBump;
use ndn_cert::report::{ContextRefreshInfo, RefreshState};
use ndn_packet::{Data, Name};

use crate::host::ContextStore;

/// How many transport failures in a row, other than a wait without an
/// answer, end a hand-over as [`NotTaken::Unknown`].
pub const HAND_OVER_FAILURES: usize = 2;

/// Why a version handed to the running device ([`hand_over`]) was not
/// taken.
#[derive(Debug)]
pub enum NotTaken<E> {
    /// Nothing was handed over, or the device answered that it did not
    /// adopt it: nothing changed there, so what was made for the version
    /// may be undone.
    Refused(E),
    /// Handed over, and no answer says what became of it: the device may
    /// still adopt it, so nothing made for it may be undone.
    Unknown(E),
}

impl<E> NotTaken<E> {
    /// Whether what was made for the version may be undone.
    pub fn is_refused(&self) -> bool {
        matches!(self, NotTaken::Refused(_))
    }

    pub fn into_inner(self) -> E {
        match self {
            NotTaken::Refused(e) | NotTaken::Unknown(e) => e,
        }
    }

    pub fn map<F>(self, f: impl FnOnce(E) -> F) -> NotTaken<F> {
        match self {
            NotTaken::Refused(e) => NotTaken::Refused(f(e)),
            NotTaken::Unknown(e) => NotTaken::Unknown(f(e)),
        }
    }
}

/// What became of a version [`hand_over`] took care of.
#[derive(Debug, Clone)]
pub enum HandedOver {
    /// The running device took it; what it did ([`ContextRefreshInfo::detail`]).
    Taken(ContextRefreshInfo),
    /// No device runs: the version is kept for its next start, at
    /// `location` ([`ContextStore::persist`]).
    Stored { location: String },
}

/// One exchange with the running device that did not end with "taken".
#[derive(Debug)]
pub enum SinkError<E> {
    /// No device runs to take it (nothing listens): nothing was handed over.
    NotRunning,
    /// The device could not be asked (not reachable, or not the device that
    /// uses this store): nothing was handed over in this exchange.
    NotReached(E),
    /// Handed over; the device answered that it did not take it.
    Refused { status_code: u64, reason: String },
    /// Handed over; no answer within the wait.
    NoAnswer,
    /// Handed over; the exchange failed without an answer.
    Failed(E),
    /// Handed over and answered "taken", but the answer could not be read.
    Unreadable { error: String, answer: String },
}

/// Where a version made outside the running device goes: see the
/// [module docs](self).
#[async_trait::async_trait]
pub trait ContextUpdateSink: Send + Sync {
    /// The host's error type.
    type Error: From<HandOverError> + fmt::Display + Send;

    /// Who takes the version, worded to start a sentence (`the daemon at
    /// /run/ndn-fwd.sock`).
    fn peer(&self) -> String;

    /// Hand `data`, a signed version, to the running device once, reaching
    /// it afresh (a connection that timed out is not reused).
    async fn hand_over(&self, data: &Data) -> Result<ContextRefreshInfo, SinkError<Self::Error>>;

    /// Called before `version` is handed over again after
    /// [`SinkError::NoAnswer`] (to say so to an operator waiting).
    fn no_answer_yet(&self, _version: u64) {}
}

/// Why [`hand_over`] did not end with the version taken, in this module's
/// words.
#[derive(Debug, Clone)]
pub enum HandOverError {
    Refused {
        peer: String,
        version: u64,
        status_code: u64,
        reason: String,
    },
    Unreadable {
        peer: String,
        version: u64,
        error: String,
        answer: String,
    },
    NoAnswer {
        peer: String,
        version: u64,
        failure: String,
    },
    /// No device runs, and the version could not be kept for its next start.
    NotStored(String),
}

impl fmt::Display for HandOverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandOverError::Refused {
                peer,
                version,
                status_code,
                reason,
            } => write!(
                f,
                "{peer} did not take v{version} ({status_code}): {reason}"
            ),
            HandOverError::Unreadable {
                peer,
                version,
                error,
                answer,
            } => write!(
                f,
                "{peer} answered for v{version} unreadably ({error}): {answer}"
            ),
            HandOverError::NoAnswer {
                peer,
                version,
                failure,
            } => write!(
                f,
                "handing v{version} to {peer} failed without an answer ({failure})"
            ),
            HandOverError::NotStored(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for HandOverError {}

fn unsure<E>(sent: bool, e: E) -> NotTaken<E> {
    if sent {
        NotTaken::Unknown(e)
    } else {
        NotTaken::Refused(e)
    }
}

/// Hand `bump`, a version signed outside the running device, to it through
/// `sink`; with no device running, keep it in `store` for its next start.
/// The retry and undo rules are in the [module docs](self).
pub async fn hand_over<S>(
    sink: &S,
    store: &dyn ContextStore,
    bump: &ContextBump,
) -> Result<HandedOver, NotTaken<S::Error>>
where
    S: ContextUpdateSink + ?Sized,
{
    let version = bump.context.version();
    let mut sent = false;
    let mut failures = 0;
    loop {
        let failure = match sink.hand_over(&bump.data).await {
            Ok(info) => return Ok(HandedOver::Taken(info)),
            Err(SinkError::NotRunning) => {
                return keep_for_next_start(store, bump)
                    .map(|location| HandedOver::Stored { location })
                    .map_err(|why| unsure(sent, HandOverError::NotStored(why).into()));
            }
            Err(SinkError::NotReached(e)) => return Err(unsure(sent, e)),
            Err(SinkError::Refused {
                status_code,
                reason,
            }) => {
                return Err(NotTaken::Refused(
                    HandOverError::Refused {
                        peer: sink.peer(),
                        version,
                        status_code,
                        reason,
                    }
                    .into(),
                ));
            }
            Err(SinkError::Unreadable { error, answer }) => {
                return Err(NotTaken::Unknown(
                    HandOverError::Unreadable {
                        peer: sink.peer(),
                        version,
                        error,
                        answer,
                    }
                    .into(),
                ));
            }
            Err(SinkError::NoAnswer) => {
                sent = true;
                sink.no_answer_yet(version);
                failures = 0;
                continue;
            }
            Err(SinkError::Failed(e)) => e,
        };
        sent = true;
        failures += 1;
        if failures >= HAND_OVER_FAILURES {
            return Err(NotTaken::Unknown(
                HandOverError::NoAnswer {
                    peer: sink.peer(),
                    version,
                    failure: failure.to_string(),
                }
                .into(),
            ));
        }
    }
}

/// No device runs: keep `bump` in `store` for its next start — unless a
/// device took it before it stopped (it is stored already, byte for byte).
/// Returns where it is kept.
pub fn keep_for_next_start(store: &dyn ContextStore, bump: &ContextBump) -> Result<String, String> {
    let stored = store
        .stored_versions(bump.context.namespace())?
        .into_iter()
        .find_map(|stored| {
            stored
                .read
                .ok()
                .is_some_and(|(_, data)| data.raw() == bump.data.raw())
                .then_some(stored.location)
        });
    match stored {
        Some(location) => Ok(location),
        None => store.persist(&bump.context, &bump.data),
    }
}

/// The version a recovery starts from ([`fetch_newest`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Newest {
    pub version: u64,
    /// Whether a node confirmed it is the newest: `false` only when nothing
    /// answered and the operator vouched for the held version.
    pub confirmed: bool,
}

/// Why a recovery may not start from the version the running device holds.
#[derive(Debug, Clone)]
pub enum NewestRefusal {
    /// A newer version exists than the one held.
    Behind {
        namespace: Name,
        held_version: u64,
        detail: String,
    },
    /// Nothing answered: whether the held version is the newest is unknown.
    Unreachable {
        namespace: Name,
        held_version: u64,
        detail: String,
    },
    /// The device holds the namespace root: nothing to recover.
    Source { namespace: Name },
    /// The newest version could not be fetched.
    Failed {
        namespace: Name,
        held_version: u64,
        detail: String,
    },
    /// The device holds no version, and there is no expected fingerprint to
    /// adopt one with.
    NotHeld { namespace: Name },
}

impl fmt::Display for NewestRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NewestRefusal::Behind {
                namespace,
                held_version,
                detail,
            } => write!(
                f,
                "{detail}. A newer version of {namespace} exists than the held v{held_version}: \
                 recovering from it would fork the namespace; refresh until it is held, then retry"
            ),
            NewestRefusal::Unreachable {
                namespace,
                held_version,
                detail,
            } => write!(
                f,
                "{detail}. Recovering from the held v{held_version} without knowing it is the \
                 newest could fork the namespace: give this device a face and a route toward a \
                 relay or member that holds it, then retry. If no other node holding {namespace} \
                 exists or can be reached, and you know no version newer than v{held_version} \
                 was made, retry with --from-held"
            ),
            NewestRefusal::Source { namespace } => write!(
                f,
                "this device holds the root of {namespace} (`ndn-fwd root-key status`): it is the \
                 root device, nothing to recover"
            ),
            NewestRefusal::Failed {
                namespace,
                held_version,
                detail,
            } => write!(
                f,
                "could not get the newest trust context of {namespace} by name ({detail}). \
                 Recovering from v{held_version} without knowing it is the newest would fork the \
                 namespace: make sure this device reaches the namespace (a face and a route \
                 toward a relay or member that holds it), then retry"
            ),
            NewestRefusal::NotHeld { namespace } => write!(
                f,
                "this device's daemon holds no trust context for {namespace}. Adopt it first \
                 with the namespace's anchor link (`ndn-fwd adopt <ndn-trust://anchor/…>`, the \
                 link `ndn-fwd init` printed), so the version recovered from is authenticated, \
                 then retry"
            ),
        }
    }
}

impl std::error::Error for NewestRefusal {}

/// The running device's view of a namespace's newest version, for
/// [`fetch_newest`].
#[async_trait::async_trait]
pub trait NewestSource: Send + Sync {
    /// The host's error type.
    type Error: From<NewestRefusal> + Send;

    /// Refresh the held version of `namespace` by name (under the
    /// continuity rule, as a refresh on request); `None` when the device
    /// holds no version of it.
    async fn refresh(&self, namespace: &Name) -> Result<Option<ContextRefreshInfo>, Self::Error>;

    /// Adopt `namespace` from its anchor link carrying the expected
    /// `fingerprint`; the version adopted.
    async fn adopt(&self, namespace: &Name, fingerprint: &[u8; 32]) -> Result<u64, Self::Error>;
}

/// The anti-fork decision on a refresh of the held version of `namespace`:
/// a recovery starts from the newest version only. `from_held`: the
/// operator vouches that no version newer than the held one exists, for
/// when nothing answers.
pub fn newest_of(
    namespace: &Name,
    refresh: &ContextRefreshInfo,
    from_held: bool,
) -> Result<Newest, NewestRefusal> {
    let refused = |detail: &str| (namespace.clone(), refresh.held_version, detail.to_string());
    match refresh.state {
        RefreshState::Updated | RefreshState::Current | RefreshState::UpstreamOlder => Ok(Newest {
            version: refresh.version,
            confirmed: true,
        }),
        RefreshState::Unreachable if from_held => Ok(Newest {
            version: refresh.held_version,
            confirmed: false,
        }),
        RefreshState::Behind => {
            let (namespace, held_version, detail) = refused(&refresh.detail);
            Err(NewestRefusal::Behind {
                namespace,
                held_version,
                detail,
            })
        }
        RefreshState::Unreachable => {
            let (namespace, held_version, detail) = refused(&refresh.detail);
            Err(NewestRefusal::Unreachable {
                namespace,
                held_version,
                detail,
            })
        }
        RefreshState::Source => Err(NewestRefusal::Source {
            namespace: namespace.clone(),
        }),
        RefreshState::Failed => {
            let (namespace, held_version, detail) = refused(&refresh.detail);
            Err(NewestRefusal::Failed {
                namespace,
                held_version,
                detail,
            })
        }
    }
}

/// Make the running device hold the newest version of `namespace`, fetched
/// by name ([`newest_of`]); a device holding none adopts it only with the
/// namespace's expected fingerprint `kit_fingerprint` (a file kit's).
pub async fn fetch_newest<S>(
    source: &S,
    namespace: &Name,
    kit_fingerprint: Option<[u8; 32]>,
    from_held: bool,
) -> Result<Newest, S::Error>
where
    S: NewestSource + ?Sized,
{
    if let Some(refresh) = source.refresh(namespace).await? {
        return Ok(newest_of(namespace, &refresh, from_held)?);
    }
    let Some(fingerprint) = kit_fingerprint else {
        return Err(NewestRefusal::NotHeld {
            namespace: namespace.clone(),
        }
        .into());
    };
    let version = source.adopt(namespace, &fingerprint).await?;
    Ok(Newest {
        version,
        confirmed: true,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ndn_security::{SecurityManager, SignedTrustContext};
    use parking_lot::Mutex;

    use super::*;
    use crate::host::{PibContextStore, StoredContext};

    #[derive(Debug)]
    struct Error(String);

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl From<HandOverError> for Error {
        fn from(e: HandOverError) -> Self {
            Error(e.to_string())
        }
    }

    impl From<NewestRefusal> for Error {
        fn from(e: NewestRefusal) -> Self {
            Error(e.to_string())
        }
    }

    type Answer = Result<(), SinkError<Error>>;

    /// A running device answering with `answers`, one per exchange.
    struct FakeDevice {
        answers: Mutex<VecDeque<Answer>>,
        sent: Mutex<Vec<bytes::Bytes>>,
        waits: AtomicUsize,
    }

    impl FakeDevice {
        fn new(answers: impl IntoIterator<Item = Answer>) -> Self {
            FakeDevice {
                answers: Mutex::new(answers.into_iter().collect()),
                sent: Mutex::new(Vec::new()),
                waits: AtomicUsize::new(0),
            }
        }
    }

    fn taken(version: u64) -> ContextRefreshInfo {
        ContextRefreshInfo {
            namespace: "/home/bob".into(),
            state: RefreshState::Updated,
            held_version: version - 1,
            version,
            revoked: Vec::new(),
            detail: format!("took v{version}"),
        }
    }

    #[async_trait::async_trait]
    impl ContextUpdateSink for FakeDevice {
        type Error = Error;

        fn peer(&self) -> String {
            "the device".into()
        }

        async fn hand_over(&self, data: &Data) -> Result<ContextRefreshInfo, SinkError<Error>> {
            self.sent.lock().push(data.raw().clone());
            let answer = self.answers.lock().pop_front().expect("an answer");
            answer.map(|()| taken(1))
        }

        fn no_answer_yet(&self, _version: u64) {
            self.waits.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A store beside a PIB that counts what it persists, or refuses to.
    struct CountingStore {
        inner: PibContextStore,
        persisted: AtomicUsize,
        refuse: bool,
    }

    impl ContextStore for CountingStore {
        fn location(&self) -> String {
            self.inner.location()
        }
        fn persist(&self, ctx: &SignedTrustContext, data: &Data) -> Result<String, String> {
            if self.refuse {
                return Err("the disk is full".into());
            }
            self.persisted.fetch_add(1, Ordering::SeqCst);
            self.inner.persist(ctx, data)
        }
        fn stored_contexts(&self) -> Result<Vec<StoredContext>, String> {
            self.inner.stored_contexts()
        }
        fn stored_versions(&self, namespace: &Name) -> Result<Vec<StoredContext>, String> {
            self.inner.stored_versions(namespace)
        }
        fn holds_root_key(&self, ctx: &SignedTrustContext) -> bool {
            self.inner.holds_root_key(ctx)
        }
    }

    fn store(dir: &std::path::Path, refuse: bool) -> CountingStore {
        CountingStore {
            inner: PibContextStore::new(dir),
            persisted: AtomicUsize::new(0),
            refuse,
        }
    }

    fn bump() -> ContextBump {
        let init = ndn_cert::init_namespace(&SecurityManager::new(), &"/home/bob".parse().unwrap())
            .unwrap();
        let (context, _) = ndn_cert::open_signed_context(&init.context_data).unwrap();
        ContextBump {
            context,
            data: init.context_data,
            added: Vec::new(),
        }
    }

    async fn run(answers: Vec<Answer>) -> (Result<HandedOver, NotTaken<Error>>, FakeDevice) {
        let dir = tempfile::tempdir().unwrap();
        let device = FakeDevice::new(answers);
        let out = hand_over(&device, &store(dir.path(), false), &bump()).await;
        (out, device)
    }

    fn failed() -> Answer {
        Err(SinkError::Failed(Error("connection reset".into())))
    }

    #[tokio::test]
    async fn a_version_without_an_answer_is_handed_over_again_unchanged() {
        let answers = vec![
            Err(SinkError::NoAnswer),
            Err(SinkError::NoAnswer),
            failed(),
            Err(SinkError::NoAnswer),
            failed(),
            Ok(()),
        ];
        let (out, device) = run(answers).await;
        assert!(matches!(out, Ok(HandedOver::Taken(_))));
        let sent = device.sent.lock();
        assert_eq!(sent.len(), 6);
        assert!(sent.iter().all(|wire| wire == &sent[0]), "the same version");
        assert_eq!(device.waits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn failures_in_a_row_leave_it_unknown() {
        let (out, _) = run(vec![failed(), failed()]).await;
        let Err(NotTaken::Unknown(e)) = out else {
            panic!("unknown")
        };
        assert_eq!(
            e.0,
            "handing v1 to the device failed without an answer (connection reset)"
        );
    }

    #[tokio::test]
    async fn refused_only_when_nothing_was_handed_over_or_the_device_says_so() {
        let not_reached = || Err(SinkError::NotReached(Error("another PIB".into())));
        let refused = || {
            Err(SinkError::Refused {
                status_code: 409,
                reason: "not newer".into(),
            })
        };
        let unreadable = || {
            Err(SinkError::Unreadable {
                error: "eof".into(),
                answer: "{".into(),
            })
        };
        for (answers, refusal) in [
            (vec![not_reached()], true),
            (vec![failed(), not_reached()], false),
            (vec![Err(SinkError::NoAnswer), not_reached()], false),
            (vec![refused()], true),
            (vec![Err(SinkError::NoAnswer), refused()], true),
            (vec![unreadable()], false),
        ] {
            let (out, _) = run(answers).await;
            let not = out.err().expect("not taken");
            assert_eq!(not.is_refused(), refusal, "{}", not.into_inner());
        }
        let (out, _) = run(vec![refused()]).await;
        assert_eq!(
            out.err().unwrap().into_inner().0,
            "the device did not take v1 (409): not newer"
        );
    }

    #[tokio::test]
    async fn with_no_device_running_it_is_stored_once_for_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), false);
        let bump = bump();
        for _ in 0..2 {
            let device = FakeDevice::new([Err(SinkError::NotRunning)]);
            let out = hand_over(&device, &store, &bump).await;
            assert!(matches!(out, Ok(HandedOver::Stored { .. })));
        }
        assert_eq!(store.persisted.load(Ordering::SeqCst), 1, "stored once");
        let (held, data) = ndn_cert::read_stored_context(dir.path(), bump.context.namespace())
            .unwrap()
            .unwrap();
        assert_eq!((held.version(), data.raw()), (1, bump.data.raw()));

        // Not stored: refused before anything was handed over, unknown after.
        let refusing = self::store(dir.path(), true);
        let other = tempfile::tempdir().unwrap();
        let refusing_elsewhere = self::store(other.path(), true);
        let device = FakeDevice::new([Err(SinkError::NotRunning)]);
        assert!(
            hand_over(&device, &refusing, &bump).await.is_ok(),
            "stored already"
        );
        let device = FakeDevice::new([Err(SinkError::NotRunning)]);
        let not = hand_over(&device, &refusing_elsewhere, &bump)
            .await
            .err()
            .unwrap();
        assert!(not.is_refused());
        assert_eq!(not.into_inner().0, "the disk is full");
        let device = FakeDevice::new([failed(), Err(SinkError::NotRunning)]);
        let not = hand_over(&device, &refusing_elsewhere, &bump)
            .await
            .err()
            .unwrap();
        assert!(!not.is_refused());
    }

    /// A running device whose refresh answers `refresh`, adopting `adopts`.
    struct FakeSource {
        refresh: Option<ContextRefreshInfo>,
        adopted: Mutex<Option<[u8; 32]>>,
    }

    #[async_trait::async_trait]
    impl NewestSource for FakeSource {
        type Error = Error;

        async fn refresh(&self, _: &Name) -> Result<Option<ContextRefreshInfo>, Error> {
            Ok(self.refresh.clone())
        }

        async fn adopt(&self, _: &Name, fingerprint: &[u8; 32]) -> Result<u64, Error> {
            *self.adopted.lock() = Some(*fingerprint);
            Ok(7)
        }
    }

    fn refreshed(state: RefreshState) -> ContextRefreshInfo {
        ContextRefreshInfo {
            namespace: "/home/bob".into(),
            state,
            held_version: 3,
            version: 4,
            revoked: Vec::new(),
            detail: "what answered".into(),
        }
    }

    #[test]
    fn a_recovery_starts_from_the_newest_version_only() {
        let ns: Name = "/home/bob".parse().unwrap();
        let newest = |state, from_held| newest_of(&ns, &refreshed(state), from_held);
        for state in [
            RefreshState::Updated,
            RefreshState::Current,
            RefreshState::UpstreamOlder,
        ] {
            assert_eq!(
                newest(state, false).unwrap(),
                Newest {
                    version: 4,
                    confirmed: true
                }
            );
        }
        assert_eq!(
            newest(RefreshState::Unreachable, true).unwrap(),
            Newest {
                version: 3,
                confirmed: false
            }
        );
        assert!(matches!(
            newest(RefreshState::Unreachable, false),
            Err(NewestRefusal::Unreachable { .. })
        ));
        for state in [
            RefreshState::Behind,
            RefreshState::Source,
            RefreshState::Failed,
        ] {
            assert!(newest(state, true).is_err(), "{state:?}");
        }
    }

    #[tokio::test]
    async fn a_device_holding_nothing_adopts_only_with_the_expected_fingerprint() {
        let ns: Name = "/home/bob".parse().unwrap();
        let source = FakeSource {
            refresh: None,
            adopted: Mutex::new(None),
        };
        let refused = fetch_newest(&source, &ns, None, true).await.unwrap_err();
        assert!(refused.0.contains("holds no trust context for /home/bob"));
        assert!(source.adopted.lock().is_none());
        let newest = fetch_newest(&source, &ns, Some([9; 32]), false)
            .await
            .unwrap();
        assert_eq!((newest.version, newest.confirmed), (7, true));
        assert_eq!(*source.adopted.lock(), Some([9; 32]));

        let held = FakeSource {
            refresh: Some(refreshed(RefreshState::Current)),
            adopted: Mutex::new(None),
        };
        assert_eq!(
            fetch_newest(&held, &ns, Some([9; 32]), false)
                .await
                .unwrap()
                .version,
            4
        );
        assert!(held.adopted.lock().is_none(), "held: never adopted");
    }
}
