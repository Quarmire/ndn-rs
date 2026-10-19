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
//! - [`root`]: root-device operations — make a namespace, revoke, recovery
//!   kits, recover, move the root key, update the schema — with the host's
//!   secret entry and running device behind traits, typed outcomes and
//!   coded refusals.
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
//!   and the [`ndn_cert::CaState`] of each namespace CA the device runs;
//! - its [`HostWords`] for its own log lines: how the person at the device
//!   does what a log line asks of them, in the host's own terms — its
//!   commands or app actions, its configuration, where it keeps keys.
//!   [`HostWords::default`] is neutral.
//!
//! and passes a [`KeyVault`] — where device keys and certificates are kept,
//! and how the running device switches to a new key — to each operation
//! that touches keys. Every operation answers with the plain report types of
//! [`ndn_cert::report`] or a [`TrustRefusal`]: a stable code with its
//! parameters (catalogued in [`ndn_cert::report::code`] and
//! `ndn-rs/docs/specs/mgmt-trust.md`) and a neutral sentence, and prose
//! inside an outcome is a [`Detail`] the same way. Nothing the library
//! answers names a host's commands, configuration or storage: a client
//! words its own message from the code — [`HostWords::render`] and
//! [`HostWords::render_detail`] rebuild the library's sentences with the
//! client's phrases.
//!
//! The host keeps its process lifecycle: it spawns the periodic tasks
//! ([`refresh::spawn_periodic`], [`renewal::spawn_periodic`],
//! [`approval_wait::spawn_status_watch`]) with a cancellation token.

pub mod admin;
pub mod approval_wait;
pub mod approver;
pub mod enroll;
mod events;
pub mod host;
pub mod keep;
pub mod membership;
pub mod publish;
pub mod refresh;
pub mod renewal;
pub mod root;
pub mod sync;
mod words;

use std::sync::Arc;

use ndn_cert::CaState;
use ndn_engine::ForwarderEngine;
use ndn_security::{Keyring, SignedTrustContext};

pub use host::{
    Activation, ContextStore, KeyUnavailable, KeyVault, PibContextStore, StoredContext,
};
pub use ndn_cert::report::{
    AdoptedContextInfo, ContextRefreshInfo, Detail, EnrollOutcome, EnrollRequest, EnrolledInfo,
    MembershipChange, MembershipEvent, MembershipInfo, MembershipRelation, PendingEnrollInfo,
    RefreshState, RenewalInfo, RenewalState, TrustEvent, TrustRefusal, code, detail_code,
};
pub use words::HostWords;

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
    /// The namespace CAs this device runs (one per namespace whose root it
    /// holds and serves a CA of): each follows every version of its
    /// namespace's trust context this device keeps.
    pub cas: Vec<Arc<CaState>>,
    /// How the person at the device does what the host's log lines ask of
    /// them, in the host's terms (only logs quote them: refusals and
    /// details are neutral, worded by each client).
    pub words: HostWords,
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
    cas: Vec<Arc<CaState>>,
    words: HostWords,
    /// One enrollment at a time per namespace: enrolling in one namespace
    /// (or an approval in it landing) never waits on, nor changes, another.
    enroll_locks: parking_lot::Mutex<std::collections::HashMap<ndn_packet::Name, EnrollLock>>,
    /// Held while an installed identity is recorded as the vault's default
    /// and handed to the host, so of two installs in different namespaces
    /// only the first of a device without an identity becomes its node
    /// identity.
    pub(crate) installing: parking_lot::Mutex<()>,
    /// Trust changes, as they happen ([`events`](Self::events)).
    events: tokio::sync::broadcast::Sender<TrustEvent>,
    /// What the device last saw of each namespace it holds, to tell an
    /// adoption, a revocation of its certificate and a root change apart.
    pub(crate) seen:
        parking_lot::Mutex<std::collections::HashMap<ndn_packet::Name, membership::Seen>>,
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
            cas,
            words,
        } = parts;
        Self {
            engine,
            keyring: Arc::clone(&keyring),
            store,
            publisher,
            own_certs,
            sync,
            cas,
            words,
            enroll_locks: parking_lot::Mutex::new(std::collections::HashMap::new()),
            installing: parking_lot::Mutex::new(()),
            events: tokio::sync::broadcast::channel(EVENTS_CAP).0,
            seen: parking_lot::Mutex::new(membership::seen_now(&keyring)),
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

    /// The CA this device runs for `namespace` (identity `<namespace>/CA`).
    pub fn ca_for(&self, namespace: &ndn_packet::Name) -> Option<&Arc<CaState>> {
        self.cas.iter().find(|ca| ca.is_ca_of(namespace))
    }

    /// Every CA this device runs.
    pub fn cas(&self) -> &[Arc<CaState>] {
        &self.cas
    }

    /// The host's words, for its own log lines.
    pub fn words(&self) -> &HostWords {
        &self.words
    }

    /// A receiver of every [`TrustEvent`] this device makes from now on: a
    /// trust-context version kept, an enrollment finished, a certificate
    /// renewed or not, its membership in a namespace changed — for the
    /// host's change notifications (a forwarder serves them on
    /// `/localhost/nfd/security/notifications`). A receiver that falls more
    /// than a few hundred events behind loses the oldest
    /// (`RecvError::Lagged`); the listing verbs have the state
    /// ([`membership::memberships`] for memberships).
    pub fn events(&self) -> tokio::sync::broadcast::Receiver<TrustEvent> {
        self.events.subscribe()
    }

    /// Tell every [`events`](Self::events) receiver of `event` (none:
    /// dropped).
    pub(crate) fn emit(&self, event: TrustEvent) {
        let _ = self.events.send(event);
    }

    /// The trust context this device holds for `namespace`.
    pub fn held_context(&self, namespace: &ndn_packet::Name) -> Option<Arc<SignedTrustContext>> {
        self.keyring
            .contexts()
            .into_iter()
            .find(|c| c.namespace() == namespace)
    }

    /// The enrollment lock of `namespace`: one enrollment at a time in it.
    pub(crate) fn enroll_lock(&self, namespace: &ndn_packet::Name) -> EnrollLock {
        Arc::clone(
            self.enroll_locks
                .lock()
                .entry(namespace.clone())
                .or_default(),
        )
    }

    /// Tell the host of a membership change ([`TrustEvent::MembershipChanged`]).
    pub(crate) fn publish_membership(&self, event: MembershipEvent) {
        tracing::info!(
            target: "security",
            namespace = %event.namespace,
            relation = %event.relation,
            change = ?event.change,
            "membership changed"
        );
        self.emit(TrustEvent::MembershipChanged(event));
    }
}

/// One namespace's enrollment lock ([`Participant::enroll_lock`]).
pub(crate) type EnrollLock = Arc<tokio::sync::Mutex<()>>;

/// How many trust events a slow receiver may fall behind.
const EVENTS_CAP: usize = 256;

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
