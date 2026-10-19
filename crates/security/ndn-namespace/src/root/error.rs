//! [`RootError`]: a root operation's refusal, and how the refusals of the
//! `ndn-cert` steps it composes map to codes.

use std::error::Error as StdError;
use std::fmt;

use ndn_cert::report::{RefusalCode, TrustRefusal, code};
use ndn_cert::{
    BumpError, ContextStoreError, NamespaceInitError, PolicyError, RecoveryError, RevocationError,
    RootDeviceError, RootStoreError, SchemaPlanError,
};

use crate::admin::{HandOverError, NewestRefusal};

/// The failure underneath a refusal.
pub type Source = Box<dyn StdError + Send + Sync + 'static>;

/// Why a root operation did not do what was asked: a [`TrustRefusal`]
/// (stable code, params, next step, neutral sentence) and, when a library
/// step or the host refused underneath, that error as
/// [`source`](StdError::source) — a host that shows error chains shows it,
/// one that words codes ignores it. A refusal that wraps another names it in
/// the `cause` param and carries its params; [`cause`](Self::cause) is the
/// wrapped one.
#[derive(Debug)]
pub struct RootError {
    pub refusal: TrustRefusal,
    source: Option<Source>,
}

impl RootError {
    /// A refusal of `kind` with the neutral sentence `reason`.
    pub fn new(kind: RefusalCode, reason: impl Into<String>) -> Self {
        Self {
            refusal: TrustRefusal::new(kind, reason),
            source: None,
        }
    }

    /// With the parameter `key` = `value`.
    pub fn with(mut self, key: &str, value: impl fmt::Display) -> Self {
        self.refusal = self.refusal.with(key, value);
        self
    }

    /// With `source` as the failure underneath.
    pub fn caused_by(mut self, source: impl Into<Source>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// A refusal of `kind` because of `inner`: its code as the `cause`
    /// param, its params kept (the outer ones win), it as the source.
    pub fn wrapping(kind: RefusalCode, reason: impl Into<String>, inner: RootError) -> Self {
        let refusal =
            TrustRefusal::new(kind, reason).with_cause(&inner.refusal.code, &inner.refusal.params);
        Self {
            refusal,
            source: Some(Box::new(inner)),
        }
    }

    /// Whether this is a refusal of `kind`.
    pub fn is(&self, kind: RefusalCode) -> bool {
        self.refusal.is(kind)
    }

    /// The parameter `key`, if set.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.refusal.param(key)
    }

    /// The refusal this one wraps ([`wrapping`](Self::wrapping)).
    pub fn cause(&self) -> Option<&RootError> {
        self.source.as_deref()?.downcast_ref()
    }

    /// The failure underneath, if any.
    pub fn underlying(&self) -> Option<&(dyn StdError + Send + Sync + 'static)> {
        self.source.as_deref()
    }

    /// The refusal and the failure underneath.
    pub fn into_parts(self) -> (TrustRefusal, Option<Source>) {
        (self.refusal, self.source)
    }
}

impl fmt::Display for RootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.refusal.reason)
    }
}

impl StdError for RootError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn StdError + 'static))
    }
}

/// `e` as a refusal of `kind` with `reason`, caused by `e`.
fn sourced<E: StdError + Send + Sync + 'static>(
    kind: RefusalCode,
    reason: impl Into<String>,
    e: E,
) -> RootError {
    RootError::new(kind, reason).caused_by(e)
}

/// A local failure, caused by `e`.
pub(crate) fn local<E: StdError + Send + Sync + 'static>(e: E) -> RootError {
    let error = e.to_string();
    sourced(
        code::ROOT_LOCAL_FAILURE,
        "a local failure stopped the operation",
        e,
    )
    .with("error", error)
}

impl From<RootStoreError> for RootError {
    fn from(e: RootStoreError) -> Self {
        use RootStoreError as E;
        let refused = match &e {
            E::UnlockNeeded {
                kind,
                key,
                location,
            } => RootError::new(
                code::SECRET_NEEDED,
                "the root store needs its secret for this operation",
            )
            .with("secret", root_secret_param(kind.unlock()))
            .with("key", key)
            .with("store", kind)
            .with("location", location),
            E::WrongPassphrase { path } => {
                RootError::new(code::WRONG_SECRET, "the passphrase does not open the root")
                    .with("secret", "root-passphrase")
                    .with("path", path.display())
            }
            E::Yubikey(error) => {
                RootError::new(code::TOKEN_FAILED, "the token failed").with("error", error)
            }
            E::TokenInUse { serial, holds } => RootError::new(
                code::TOKEN_IN_USE,
                "the token holds a key the new one must not share a token with",
            )
            .with("serial", serial)
            .with("holds", holds),
            E::SlotInUse {
                serial,
                slot,
                state,
            } => RootError::new(
                code::SLOT_IN_USE,
                "generating a key in that slot would destroy the one it holds",
            )
            .with("serial", serial)
            .with("slot", slot)
            .with("state", state),
            E::KeychainUnavailable { reason } => {
                RootError::new(code::KEYCHAIN_UNAVAILABLE, "no OS keychain is reachable")
                    .with("reason", reason)
            }
            E::KeychainEntryMissing {
                service,
                account,
                path,
            } => RootError::new(
                code::KEYCHAIN_ENTRY_MISSING,
                "the OS keychain holds no entry for the sealed root",
            )
            .with("service", service)
            .with("account", account)
            .with("path", path.display()),
            E::NotBuilt { kind, feature } => RootError::new(
                code::ROOT_STORE_NOT_BUILT,
                "this build has no support for that root store",
            )
            .with("store", kind)
            .with("feature", feature),
            E::SeveralRoots { pib, held } => RootError::new(
                code::SEVERAL_NAMESPACES,
                "the key storage holds the roots of several namespaces: name the namespace",
            )
            .with("pib", pib)
            .with("namespaces", held.join(","))
            .with("count", held.len()),
            E::Unmovable { from, to, reason } => {
                RootError::new(code::ROOT_STORE_UNMOVABLE, "the root cannot be moved there")
                    .with("from", from)
                    .with("to", to)
                    .with("reason", reason)
            }
            E::Secret(_) => RootError::new(code::SECRET_UNAVAILABLE, "no secret was given"),
            other => RootError::new(code::ROOT_STORE_FAILED, "the root store is unusable")
                .with("error", other),
        };
        refused.caused_by(e)
    }
}

/// The `secret` param of a root store's unlock kind.
pub(crate) fn root_secret_param(kind: ndn_cert::RootUnlockKind) -> &'static str {
    match kind {
        ndn_cert::RootUnlockKind::Pin => "root-pin",
        _ => "root-passphrase",
    }
}

impl From<RootDeviceError> for RootError {
    fn from(e: RootDeviceError) -> Self {
        use RootDeviceError as E;
        let e = match e {
            E::RootStore(e) => return e.into(),
            E::Kit(e) => return e.into(),
            E::Store(e) => return e.into(),
            other => other,
        };
        let refused = match &e {
            E::NoRoot { pib, work } => RootError::new(
                code::NOT_ROOT_DEVICE,
                "this device holds no namespace root: do this on the root device",
            )
            .with("pib", pib.display())
            .with("operation", work),
            E::NotHeld { pib, namespace } => RootError::new(
                code::NAMESPACE_NOT_HELD,
                "no trust context of the namespace is held: adopt it first",
            )
            .with("pib", pib.display())
            .with("namespace", namespace),
            E::NoLongerRoot {
                key,
                namespace,
                version,
            } => RootError::new(
                code::NO_LONGER_ROOT,
                "this device's root is no anchor of the held version: it is no longer the root \
                 device",
            )
            .with("key", key)
            .with("namespace", namespace)
            .with("version", version),
            E::NoContext { pib } => RootError::new(
                code::NO_NAMESPACE_HELD,
                "no trust context is held: name the namespace",
            )
            .with("pib", pib.display()),
            E::SeveralContexts { pib, held } => RootError::new(
                code::SEVERAL_NAMESPACES,
                "several trust contexts are held: name the namespace",
            )
            .with("pib", pib.display())
            .with("namespaces", held.join(","))
            .with("count", held.len()),
            E::NoRootOf {
                pib,
                namespace,
                held,
                work,
            } => RootError::new(
                code::OTHER_NAMESPACE_ROOT,
                "this device holds the roots of other namespaces only: do this on the \
                 namespace's root device",
            )
            .with("pib", pib.display())
            .with("namespace", held.join(","))
            .with("requested", namespace)
            .with("operation", work),
            // Handed to their own mapping above.
            E::RootStore(_) | E::Store(_) | E::Kit(_) => return local(e),
        };
        refused.caused_by(e)
    }
}

impl From<ContextStoreError> for RootError {
    fn from(e: ContextStoreError) -> Self {
        local(e)
    }
}

impl From<RecoveryError> for RootError {
    fn from(e: RecoveryError) -> Self {
        use RecoveryError as E;
        let e = match e {
            E::RootStore(e) => return e.into(),
            E::Init(e) => return e.into(),
            other => other,
        };
        let refused = match &e {
            E::BadWords(error) => {
                RootError::new(code::BAD_RECOVERY_WORDS, "the recovery words are refused")
                    .with("error", error)
            }
            E::NotAKit { path, reason } => {
                RootError::new(code::NOT_A_KIT, "the file is not a recovery kit")
                    .with("path", path)
                    .with("reason", reason)
            }
            E::WrongKitPassphrase { path } => RootError::new(
                code::WRONG_SECRET,
                "the kit passphrase does not open the kit",
            )
            .with("secret", "kit-passphrase")
            .with("path", path),
            E::OtherNamespace { kit, requested } => RootError::new(
                code::KIT_OTHER_NAMESPACE,
                "the kit recovers another namespace",
            )
            .with("kit", kit)
            .with("namespace", requested),
            E::NotARecoveryAnchor {
                key,
                namespace,
                version,
                ..
            } => RootError::new(
                code::KIT_NOT_AN_ANCHOR,
                "the kit's key is no recovery anchor of the held version; nothing was signed",
            )
            .with("key", key)
            .with("namespace", namespace)
            .with("version", version),
            E::SignerNotAnAnchor {
                key,
                namespace,
                version,
            } => RootError::new(
                code::SIGNER_NOT_AN_ANCHOR,
                "the signing key is no anchor of the held version",
            )
            .with("key", key)
            .with("namespace", namespace)
            .with("version", version),
            E::KeptKitsNeedCompromised => RootError::new(
                code::KEPT_KITS_NEED_COMPROMISED,
                "kits to keep are named only when the old root is compromised",
            ),
            E::AlreadyRootDevice {
                pib,
                namespace,
                kind,
            } => RootError::new(
                code::ALREADY_ROOT_DEVICE,
                "this device holds a namespace root already: recover on a replacement device",
            )
            .with("pib", pib)
            .with("namespace", namespace)
            .with("store", kind),
            E::CaPresent { path } => RootError::new(
                code::CA_PRESENT,
                "this device holds a CA identity: recover on a device that runs no CA",
            )
            .with("path", path.display()),
            E::CoversAnchor { name, .. } => RootError::new(
                code::REVOKE_REFUSED,
                "the key covers an anchor of the new version",
            )
            .with("name", name)
            .with("error", &e),
            E::Yubikey(error) => {
                RootError::new(code::TOKEN_FAILED, "the token failed").with("error", error)
            }
            E::KitFirmwareTooOld { firmware } => RootError::new(
                code::KIT_TOKEN_TOO_OLD,
                "the token's firmware cannot hold a recovery kit",
            )
            .with("firmware", firmware),
            E::Role(error) => {
                RootError::new(code::ROOT_BAD_REQUEST, "a name is refused").with("error", error)
            }
            _ => return local(e),
        };
        refused.caused_by(e)
    }
}

impl From<NamespaceInitError> for RootError {
    fn from(e: NamespaceInitError) -> Self {
        use NamespaceInitError as E;
        let e = match e {
            E::RootStore(e) => return e.into(),
            other => other,
        };
        let refused = match &e {
            E::AlreadyInitialized {
                namespace,
                pib,
                what,
            } => RootError::new(
                code::ALREADY_INITIALIZED,
                "the namespace is initialized here already; its root is not replaced unless \
                 forced",
            )
            .with("namespace", namespace)
            .with("pib", pib)
            .with("what", what),
            E::Role(error) => {
                RootError::new(code::ROOT_BAD_REQUEST, "a name is refused").with("error", error)
            }
            _ => return local(e),
        };
        refused.caused_by(e)
    }
}

impl From<RevocationError> for RootError {
    fn from(e: RevocationError) -> Self {
        use RevocationError as E;
        let e = match e {
            E::RootDevice(e) => return e.into(),
            other => other,
        };
        let refused = match &e {
            E::OutsideNamespace { name, held } => RootError::new(
                code::REVOKE_OUTSIDE_NAMESPACE,
                "the name is outside every namespace this device holds the root of; nothing was \
                 signed",
            )
            .with("name", name)
            .with("namespace", held.join(",")),
            E::NamespaceCa { name, namespace } => RootError::new(
                code::REVOKE_NAMESPACE_CA,
                "the namespace CA is not revoked; revoke devices one by one. Nothing was signed",
            )
            .with("name", name)
            .with("namespace", namespace),
            E::NoneIssued { pib, name } => RootError::new(
                code::REVOKE_NONE_ISSUED,
                "the namespace CA issued no certificate under that name; nothing was signed",
            )
            .with("pib", pib.display())
            .with("name", name),
            E::Refused(bump) => return bump_refusal(bump).caused_by(e),
            // `RootDevice` is handed to its own mapping above.
            E::CaStore { .. } | E::RootDevice(_) => return local(e),
        };
        refused.caused_by(e)
    }
}

/// The refusal of a [`BumpError`], without its source.
fn bump_refusal(e: &BumpError) -> RootError {
    use BumpError as E;
    match e {
        E::NotAnAnchor {
            key,
            namespace,
            version,
        } => RootError::new(
            code::SIGNER_NOT_AN_ANCHOR,
            "the signing key is no anchor of the held version",
        )
        .with("key", key)
        .with("namespace", namespace)
        .with("version", version),
        E::NotAKeyOfNamespace { name, .. } | E::CoversRoot { name, .. } => {
            RootError::new(code::REVOKE_REFUSED, "that key may not be revoked")
                .with("name", name)
                .with("error", e)
        }
        E::Narrowing {
            namespace,
            version,
            removed,
        } => narrowing(namespace, *version, "rules", removed),
        E::LinkNarrowing {
            namespace,
            version,
            narrowed,
            ..
        } => narrowing(namespace, *version, "link", narrowed),
        E::RelayNarrowing {
            namespace,
            version,
            dropped,
        } => narrowing(namespace, *version, "relays", dropped),
        other => RootError::new(
            code::ROOT_LOCAL_FAILURE,
            "a local failure stopped the operation",
        )
        .with("error", other),
    }
}

fn narrowing(namespace: &str, version: u64, what: &str, removed: &[String]) -> RootError {
    RootError::new(
        code::SCHEMA_NARROWING,
        "the update narrows what devices may do; it is signed only with consent to narrow",
    )
    .with("namespace", namespace)
    .with("version", version)
    .with("what", what)
    .with("removed", removed.join("; "))
}

impl From<BumpError> for RootError {
    fn from(e: BumpError) -> Self {
        bump_refusal(&e).caused_by(e)
    }
}

impl From<PolicyError> for RootError {
    fn from(e: PolicyError) -> Self {
        let error = e.to_string();
        sourced(
            code::NAMESPACE_POLICY_REFUSED,
            "the stated namespace policy is refused",
            e,
        )
        .with("error", error)
    }
}

impl From<SchemaPlanError> for RootError {
    fn from(e: SchemaPlanError) -> Self {
        let refused = match &e {
            SchemaPlanError::Schema { namespace, reason } => RootError::new(
                code::SCHEMA_NOT_GENERATED,
                "the namespace's schema could not be generated; nothing was signed",
            )
            .with("namespace", namespace)
            .with("error", reason),
            SchemaPlanError::Policy(policy) => RootError::new(
                code::NAMESPACE_POLICY_REFUSED,
                "the stated namespace policy is refused; nothing was signed",
            )
            .with("error", policy),
            SchemaPlanError::Change(bump) => bump_refusal(bump),
        };
        refused.caused_by(e)
    }
}

impl From<HandOverError> for RootError {
    fn from(e: HandOverError) -> Self {
        let refusal = e.refusal();
        RootError {
            refusal,
            source: Some(Box::new(e)),
        }
    }
}

impl From<NewestRefusal> for RootError {
    fn from(e: NewestRefusal) -> Self {
        let refusal = e.refusal();
        RootError {
            refusal,
            source: Some(Box::new(e)),
        }
    }
}
