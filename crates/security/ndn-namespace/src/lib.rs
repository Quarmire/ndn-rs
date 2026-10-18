//! Taking part in personal NDN namespaces, as a library any forwarder or
//! app links: the same rules wherever they run.
//!
//! A device in a namespace `/<ns>` holds the namespace's trust context
//! (signed by its root, versioned), a device key `/<ns>/<role>/<device>/KEY/<id>`
//! certified by the namespace's CA, and follows the namespace as it changes.
//! This crate composes the protocol steps of `ndn-cert` and `ndn-identity`
//! into what such a device does:
//!
//! - [`keep`]: keep a version adopted into the keyring — the namespace's CA
//!   on this device follows its revocations, it is stored, published and
//!   handed to the namespace's sync group; take a version made on this
//!   device (`apply_update`); adopt a namespace from its anchor link.
//! - [`refresh`]: check held contexts for newer versions (continuity rule,
//!   the "behind" rule against versions verified over sync), periodically.
//! - [`enroll`]: enroll with an invite, or ask for an admin's approval
//!   (durable request, verification code), and install the certificate.
//! - [`approval_wait`]: wait for an admin's decision on a request, with a
//!   held status Interest at the CA, and finish the enrollment.
//! - [`approver`]: as an admin device, list and decide pending requests.
//! - [`renewal`]: renew the device's certificates before they expire.
//! - [`publish`]: serve held trust contexts by name (RDR) and the device's
//!   own certificates.
//! - [`sync`]: the namespaces' sync groups, which push each new version.
//! - [`admin`]: the root device's side — hand a version made offline to the
//!   running device (retry / undo rule), and the anti-fork check before a
//!   recovery.
//!
//! # What a host provides
//!
//! A host — a forwarder daemon, an app embedding an engine — builds one
//! [`Participant`] from:
//!
//! - an [`ndn_engine::ForwarderEngine`] with routes toward the namespaces
//!   (every exchange goes out through it on an in-process face);
//! - the [`ndn_security::Keyring`] the engine's validator dispatches on
//!   (the trust contexts held);
//! - a [`ContextStore`]: where held context versions are kept
//!   ([`PibContextStore`] keeps them beside a PIB);
//! - optionally a running [`publish::PublishedContexts`] and
//!   [`publish::OwnCertificates`] (serving by name), a [`sync::ContextSync`],
//!   and the namespace CA's [`ndn_cert::CaState`] when the device runs one.
//!
//! and passes a [`KeyVault`] — where device keys and certificates are kept,
//! and how the running device switches to a new key — to each operation
//! that touches keys. Every operation answers with the plain report types of
//! [`ndn_cert::report`] or a [`TrustRefusal`] (an HTTP-like status code and
//! a reason that says what to do); the host maps them to its own surface
//! (management verbs, FFI types).
//!
//! The host keeps its process lifecycle: it spawns the periodic tasks
//! ([`refresh::spawn_periodic`], [`renewal::spawn_periodic`],
//! [`approval_wait::spawn_status_watch`]) with a cancellation token.

pub mod admin;
pub mod approval_wait;
pub mod approver;
pub mod enroll;
pub mod host;
pub mod keep;
pub mod publish;
pub mod refresh;
pub mod renewal;
pub mod sync;

use std::sync::Arc;

use ndn_cert::CaState;
use ndn_engine::ForwarderEngine;
use ndn_security::{Keyring, SignedTrustContext};

pub use host::{
    Activation, ContextStore, KeyUnavailable, KeyVault, PibContextStore, StoredContext,
};
pub use ndn_cert::report::{
    AdoptedContextInfo, ContextRefreshInfo, EnrollOutcome, EnrollRequest, EnrolledInfo,
    PendingEnrollInfo, RefreshState, RenewalInfo, RenewalState, TrustRefusal,
};

/// What a [`Participant`] is built from: see the [crate docs](crate).
pub struct ParticipantParts {
    pub engine: ForwarderEngine,
    /// The keyring the engine's validator dispatches against.
    pub keyring: Arc<Keyring>,
    pub store: Arc<dyn ContextStore>,
    /// Publishes every version kept; `None`: nothing is published.
    pub publisher: Option<publish::PublishedContexts>,
    /// Serves the device's certificates; an enrolled or renewed one is
    /// added to it.
    pub own_certs: Option<Arc<publish::OwnCertificates>>,
    /// The namespaces' sync groups: every version kept is handed to them.
    pub sync: Option<sync::ContextSync>,
    /// The namespace CA this device runs: it follows every version of its
    /// namespace's trust context this device keeps.
    pub ca: Option<Arc<CaState>>,
}

/// A device taking part in personal namespaces: the engine and keyring it
/// works through, what it keeps and serves, and the locks that order its
/// trust changes.
pub struct Participant {
    engine: ForwarderEngine,
    keyring: Arc<Keyring>,
    store: Arc<dyn ContextStore>,
    publisher: Option<publish::PublishedContexts>,
    own_certs: Option<Arc<publish::OwnCertificates>>,
    sync: Option<sync::ContextSync>,
    ca: Option<Arc<CaState>>,
    /// One enrollment at a time.
    pub(crate) enrolling: tokio::sync::Mutex<()>,
    /// Held while a context is stored and published, so of two concurrent
    /// adoptions of one namespace the store and the publisher end up with
    /// the version the keyring holds, never an older one.
    pub(crate) keeping: std::sync::Mutex<()>,
    /// One context change made on this device at a time
    /// ([`keep::apply_update`]), so none works from a version another is
    /// replacing. A refresh takes no lock: it adopts only if the version it
    /// fetched against is still held.
    pub(crate) context_change: tokio::sync::Mutex<()>,
    /// One certificate renewal at a time.
    pub(crate) renewing: tokio::sync::Mutex<()>,
    /// Woken whenever the device's certificates change (an enrollment, a
    /// renewal), so the renewal timer reads them again.
    pub(crate) certificates_changed: tokio::sync::Notify,
    /// Woken when the device records a new request for an admin's
    /// approval, so the status watch waits on it at once.
    pub(crate) requests_changed: tokio::sync::Notify,
}

impl Participant {
    pub fn new(parts: ParticipantParts) -> Self {
        let ParticipantParts {
            engine,
            keyring,
            store,
            publisher,
            own_certs,
            sync,
            ca,
        } = parts;
        Self {
            engine,
            keyring,
            store,
            publisher,
            own_certs,
            sync,
            ca,
            enrolling: tokio::sync::Mutex::new(()),
            keeping: std::sync::Mutex::new(()),
            context_change: tokio::sync::Mutex::new(()),
            renewing: tokio::sync::Mutex::new(()),
            certificates_changed: tokio::sync::Notify::new(),
            requests_changed: tokio::sync::Notify::new(),
        }
    }

    pub fn engine(&self) -> &ForwarderEngine {
        &self.engine
    }

    pub fn keyring(&self) -> &Arc<Keyring> {
        &self.keyring
    }

    pub fn store(&self) -> &dyn ContextStore {
        self.store.as_ref()
    }

    pub fn publisher(&self) -> Option<&publish::PublishedContexts> {
        self.publisher.as_ref()
    }

    pub fn own_certs(&self) -> Option<&Arc<publish::OwnCertificates>> {
        self.own_certs.as_ref()
    }

    pub fn sync(&self) -> Option<&sync::ContextSync> {
        self.sync.as_ref()
    }

    pub fn ca(&self) -> Option<&Arc<CaState>> {
        self.ca.as_ref()
    }

    /// The trust context this device holds for `namespace`.
    pub fn held_context(&self, namespace: &ndn_packet::Name) -> Option<Arc<SignedTrustContext>> {
        self.keyring
            .contexts()
            .into_iter()
            .find(|c| c.namespace() == namespace)
    }
}

/// A [`TrustRefusal`] with `status_code` and `reason`.
pub fn refusal(status_code: u64, reason: impl Into<String>) -> TrustRefusal {
    TrustRefusal {
        status_code,
        reason: reason.into(),
    }
}

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `ns` (nanoseconds since the Unix epoch) as ISO 8601 basic, UTC.
pub fn iso(ns: u64) -> String {
    let basic = ndn_security::iso8601::format_iso_basic(ns);
    format!("{}Z", String::from_utf8_lossy(&basic))
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
