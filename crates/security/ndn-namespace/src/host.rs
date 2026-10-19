//! What a host provides: where trust contexts are kept ([`ContextStore`])
//! and where device keys and their certificates are kept ([`KeyVault`]).
//!
//! Both are narrow and synchronous: each method is one local storage step,
//! and every protocol rule — which version wins, when a key is deleted,
//! which certificate is renewed — stays in this crate. A method that fails
//! says why in words that end up in a [`TrustRefusal`](ndn_cert::report::TrustRefusal)
//! reason or a log line.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::{RequestStore, RootStore};
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, FilePib, SignedTrustContext, Signer};

use crate::HostWords;

/// One stored trust-context version, read back and re-verified, or why it
/// could not be.
pub struct StoredContext {
    /// Where it is kept, for a log line (a file path, a database key).
    pub location: String,
    pub read: Result<(SignedTrustContext, Data), String>,
}

/// Where the trust contexts a device holds are kept, so it holds them again
/// after a restart and serves every version it went through.
///
/// [`PibContextStore`] keeps them beside a PIB (`<pib>/contexts/`) and reads
/// the PIB's root store. A host that persists elsewhere (an app handing each
/// version to its platform storage) implements this itself.
pub trait ContextStore: Send + Sync {
    /// Where the store is, worded to end "fix …" in a refusal (`the PIB
    /// directory (/var/lib/ndn/pib)`).
    fn location(&self) -> String;

    /// Keep version `ctx` (signed Data `data`, byte for byte) as a version
    /// of its namespace, and as the namespace's newest unless a newer one is
    /// kept: storing versions in any order never moves the newest back.
    /// Returns where it is kept.
    fn persist(&self, ctx: &SignedTrustContext, data: &Data) -> Result<String, String>;

    /// The newest stored version of every namespace.
    fn stored_contexts(&self) -> Result<Vec<StoredContext>, String>;

    /// Every stored version of `namespace`, oldest first.
    fn stored_versions(&self, namespace: &Name) -> Result<Vec<StoredContext>, String>;

    /// Whether this device holds the root key of `ctx`'s namespace (the key
    /// of one of its anchors): it is the namespace's root device, where new
    /// versions are made, and never fetches them. Public keys only; the
    /// root key stays locked.
    fn holds_root_key(&self, ctx: &SignedTrustContext) -> bool;
}

/// A [`ContextStore`] beside a PIB: `<pib>/contexts/`
/// ([`ndn_cert::context_store`]) and the PIB's root stores, one per
/// namespace whose root it holds ([`ndn_cert::RootStore::open_all`]). Its
/// location is worded with the host's [`HostWords::key_storage_dir`]
/// ([`PibContextStore::with_words`]).
#[derive(Debug, Clone)]
pub struct PibContextStore {
    root: PathBuf,
    /// What the host calls the directory, as something to fix.
    called: String,
}

impl PibContextStore {
    pub fn new(pib_root: impl Into<PathBuf>) -> Self {
        Self {
            root: pib_root.into(),
            called: HostWords::default().key_storage_dir,
        }
    }

    /// The store with its location worded in the host's `words`.
    pub fn with_words(mut self, words: &HostWords) -> Self {
        self.called = words.key_storage_dir.clone();
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// One stored context file as [`ndn_cert::read_stored_contexts`] reads it.
type StoredRead = (
    PathBuf,
    Result<(SignedTrustContext, Data), ndn_cert::ContextStoreError>,
);

fn stored(list: Vec<StoredRead>) -> Vec<StoredContext> {
    list.into_iter()
        .map(|(path, read)| StoredContext {
            location: path.display().to_string(),
            read: read.map_err(|e| e.to_string()),
        })
        .collect()
}

impl ContextStore for PibContextStore {
    fn location(&self) -> String {
        format!("{} ({})", self.called, self.root.display())
    }

    fn persist(&self, ctx: &SignedTrustContext, data: &Data) -> Result<String, String> {
        ndn_cert::persist_context(&self.root, ctx, data)
            .map(|path| path.display().to_string())
            .map_err(|e| e.to_string())
    }

    fn stored_contexts(&self) -> Result<Vec<StoredContext>, String> {
        ndn_cert::read_stored_contexts(&self.root)
            .map(stored)
            .map_err(|e| e.to_string())
    }

    fn stored_versions(&self, namespace: &Name) -> Result<Vec<StoredContext>, String> {
        ndn_cert::read_stored_versions(&self.root, namespace)
            .map(stored)
            .map_err(|e| {
                format!(
                    "{} ({e})",
                    ndn_cert::context_versions_dir(&self.root, namespace).display()
                )
            })
    }

    fn holds_root_key(&self, ctx: &SignedTrustContext) -> bool {
        let Ok(pib) = FilePib::open(&self.root) else {
            return false;
        };
        RootStore::any_holds_anchor_of(&pib, ctx).unwrap_or(false)
    }
}

/// Why a key a request or a certificate was made with cannot sign.
#[derive(Debug, Clone)]
pub enum KeyUnavailable {
    /// It is gone (deleted, never kept): nothing can be certified for it.
    Gone(String),
    /// It cannot be read now (storage unreadable, locked): try again later.
    Unreadable(String),
}

impl std::fmt::Display for KeyUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gone(why) | Self::Unreadable(why) => f.write_str(why),
        }
    }
}

/// What a newly installed identity changes on the running device, as its
/// host decides ([`KeyVault::activate`]). Per namespace: the device's
/// identities in other namespaces are never touched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Activation {
    /// Whether the device signs the namespace's Data with the new key from
    /// now on.
    pub signing_now: bool,
    /// Whether the new identity became the node identity (the device had no
    /// persistent identity before).
    pub node_identity: bool,
    /// What changes only at the next start, and why (empty: nothing).
    pub at_next_start: Vec<String>,
}

/// Where a device's keys and their certificates are kept.
///
/// Every key this crate generates is a device key
/// `/<ns>/<role>/<device>/KEY/<id>`; the private key never leaves the
/// vault (a [`Signer`] signs with it). A forwarder implements it over its
/// PIB; an app over its sealed key storage.
pub trait KeyVault: Send + Sync {
    /// Where the keys are, for messages (a PIB path, a storage directory).
    fn location(&self) -> String;

    /// The identity the device loads by default — its node identity, when
    /// its configuration names none — if any. Err: the vault cannot be
    /// opened (why).
    fn default_identity(&self) -> Result<Option<Name>, String>;

    /// The node identity the running device signs its own traffic as
    /// (management, discovery, links), if it has a persistent one. A host
    /// whose configuration can name another than the vault's default
    /// overrides this.
    fn node_identity(&self) -> Option<Name> {
        self.default_identity().ok().flatten()
    }

    /// The records of the device's requests for an admin's approval
    /// ([`ndn_cert::RequestStore`]), kept beside the keys they were made
    /// with. Err: why they cannot be opened.
    fn request_store(&self) -> Result<RequestStore, String>;

    /// Generate a new key named `key` and keep it.
    fn generate(&self, key: &Name) -> Result<Arc<dyn Signer>, String>;

    /// Make sure `key`, generated for a request now pending at a CA, is
    /// kept until the request ends: it is called before the request's
    /// record is saved (a record whose key is missing could never finish).
    /// A vault whose [`generate`](Self::generate) already keeps the key
    /// does nothing.
    fn keep_pending(&self, key: &Name) -> Result<(), String>;

    /// The signer of a key the vault keeps. [`KeyUnavailable::Gone`] says
    /// where it is gone from (`gone from the PIB (…)`).
    fn signer(&self, key: &Name) -> Result<Arc<dyn Signer>, KeyUnavailable>;

    /// Delete `key` and whatever is kept for it.
    fn discard(&self, key: &Name) -> Result<(), String>;

    /// Keep the certificate `cert` (a certificate Data) the CA issued for
    /// `key`, beside the certificates kept for it before.
    fn store_certificate(&self, key: &Name, cert: &Data) -> Result<(), String>;

    /// Make `identity` the one the device loads by default: its node
    /// identity. An enrollment calls it only when the vault has no default
    /// identity (the device's first identity); otherwise only an operator
    /// changes it.
    fn make_default(&self, identity: &Name) -> Result<(), String>;

    /// Keep the issuer certificates of a certificate's chain: they are
    /// served with the device's certificates and sent with a renewal.
    fn keep_issuers(&self, issuers: &[Data]) -> Result<(), String>;

    /// The issuer certificates kept ([`keep_issuers`](Self::keep_issuers)).
    fn issuers(&self) -> Vec<Bytes>;

    /// The keys the vault holds. A vault that does not exist yet holds none.
    fn keys(&self) -> Result<Vec<Name>, String>;

    /// The current certificate of `key`, if one is kept.
    fn certificate(&self, key: &Name) -> Option<Certificate>;

    /// The newest certificate a CA issued for `key` (a certificate Data),
    /// if one is kept.
    fn issued_certificate(&self, key: &Name) -> Result<Option<Bytes>, String>;

    /// Have the running device sign `identity`'s Data with `key` (its
    /// `signer`) from now on, beside its other identities, as the host
    /// allows, once its certificate is installed — and, when
    /// `first_identity` (the vault had no default identity before this
    /// enrollment), sign the device's own traffic as it too.
    fn activate(
        &self,
        identity: &Name,
        key: &Name,
        signer: Arc<dyn Signer>,
        first_identity: bool,
    ) -> Activation;
}
